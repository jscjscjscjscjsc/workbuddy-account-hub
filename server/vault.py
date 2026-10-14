# -*- coding: utf-8 -*-
"""
WorkBuddy 账号保险库（vault）—— 纯标准库实现。

设计要点
--------
WorkBuddy 桌面端把"我是谁"落盘在这几处：

  1. storage/skeleton/account-snapshot.json   当前登录账号的指纹（uid / 手机号 / 版本）
  2. Local Settings/CodeBuddyExtension/Data/Public/auth/workbuddy-desktop.info
                                              **真正的会话令牌**（accessToken / refreshToken），
                                              $wbEncrypted 信封 + AES-256-GCM ⇒ 在 ~/.workbuddy 之外
  3. app/session/Network/Cookies              Chromium 的 Cookie 库（"免验证码切换"要用的那部分）
  4. connectors/<uid>/、plugin-account-state/<uid>.json、storage/user-<uid>*、per-uid 分区

只要在每个账号"仍处于登录态"时把上面这套文件整套快照下来，
以后把某一份快照写回去，App 就直接是那个账号 —— 不需要短信验证码。

快照以 **zip 单文件** 保存（`保险库/<手机号>__<uid前8位>.zip`），
好处是：原子写入、无需删除目录、便于拷贝/备份。元数据统一放在 `保险库/index.json`。

令牌是怎么解出来的（第 8.5 节）
--------------------------------
`workbuddy-desktop.info` 的字段是 `$wbEncrypted` 信封 + AES-256-GCM。密钥是本机的
**at-rest 主密钥**，它只存在于 WorkBuddy 进程内部，落盘只有被包裹过的 `~/.workbuddy/keyblob`。
取钥办法：用 `ELECTRON_RUN_AS_NODE=1 WorkBuddy.exe wbkey.js` 调 WorkBuddy 自带原生绑定
`electron_browser_workbuddy_storage.loggerGet()`，拿到 `atRestSecretKey`（44 字符 canonical base64）。
随后 `key = sha256(secret)`、`keyId = sha256(key).hexdigest()[:16]`，AAD 按官方 `Pe()` 规则复刻
（`WB-AAD\x00` + framing=field + scheme=sym-v1 + suite + keyId + field id），
最终用纯 Python 的 BCrypt AES-GCM 解出令牌。密钥只缓存在本机 `.atrest.json`，不外传。

硬约束
------
`app/session/Network/Cookies` 在 App 运行期间被**独占锁定**（ERROR_SHARING_VIOLATION），
非管理员既读不到也写不进。但加密会话文件 `workbuddy-desktop.info` **没有锁**。所以：

  * 收录(collect) 随时可做；App 运行中会缺 Cookies 副本，退出后收录才完整；
  * 切换(restore) 因为要写 Cookies，必须在 WorkBuddy 退出后进行；
  * 签到(checkin) 用的是解密出来的 accessToken，**App 开着也能签到**。

本模块不依赖任何第三方库：DPAPI 走 crypt32，AES-GCM 走 bcrypt(Windows CNG)。
"""

import os
import re
import sys
import json
import time
import glob
import struct
import datetime
import base64
import shutil
import zipfile
import sqlite3
import hashlib
import tempfile
import subprocess
import urllib.request
import urllib.error
import ctypes
import ctypes.wintypes as wt
import threading
import functools
from pathlib import Path

# --------------------------------------------------------------------------
# 路径
# --------------------------------------------------------------------------

HOME = os.environ.get("WBH_HOME") or os.path.expanduser("~")
WB = os.path.join(HOME, ".workbuddy")
APP_SESSION = os.path.join(WB, "app", "session")
SNAPSHOT = os.path.join(WB, "storage", "skeleton", "account-snapshot.json")
COOKIES = os.path.join(APP_SESSION, "Network", "Cookies")
LOCAL_STATE = os.path.join(APP_SESSION, "Local State")

HERE = os.path.join(os.path.dirname(sys.executable), "server") if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE) if os.path.basename(HERE) == "server" else HERE
VAULT_DIR = os.environ.get("WBH_VAULT_DIR") or os.path.join(ROOT, "保险库")

API_BASES = ["https://www.workbuddy.cn", "https://copilot.tencent.com"]

APP_EXE = "WorkBuddy.exe"

MEMBER_COOKIES = "app/session/Network/Cookies"
MEMBER_LOCAL_STATE = "app/session/Local State"

# ---- 会话令牌真正的落点（在 ~/.workbuddy 之外） ----------------------------
# WorkBuddy 把 OIDC 会话（accessToken / refreshToken / 手机号）加密写在
#   <用户目录>\Local Settings\CodeBuddyExtension\Data\Public\auth\workbuddy-desktop.info
# 快照里用 "@auth/<文件名>" 表示这些"域外"文件。
LOCAL_SETTINGS = os.path.join(HOME, "Local Settings")
AUTH_FILE_NAME = "workbuddy-desktop.info"
AUTH_MEMBER_PREFIX = "@auth/"
WBKEY_JS = "wbkey.js"

VAULT_LOCK = threading.RLock()

def serialized_mutation(fn):
    @functools.wraps(fn)
    def call(*args, **kwargs):
        if not VAULT_LOCK.acquire(timeout=3):
            return {"ok": False, "reason": "另一项收录或切换正在进行，请稍后重试"}
        try:
            return fn(*args, **kwargs)
        finally:
            VAULT_LOCK.release()
    return call


# --------------------------------------------------------------------------
# 小工具
# --------------------------------------------------------------------------

def now_ms():
    return int(time.time() * 1000)


def vault_root():
    os.makedirs(VAULT_DIR, exist_ok=True)
    return VAULT_DIR


def safe_label(label):
    keep = [ch for ch in str(label) if ch.isalnum() or ch in "-_.@"]
    return "".join(keep)[:40] or "account"


def snapshot_path(uid, nickname=None):
    return os.path.join(vault_root(), "%s__%s.zip" % (safe_label(nickname or uid[:8]), uid[:8]))


# --------------------------------------------------------------------------
# 元数据索引
# --------------------------------------------------------------------------

def _index_path():
    return os.path.join(vault_root(), "index.json")


def load_index():
    p = _index_path()
    if not os.path.isfile(p):
        return {"version": 1, "entries": {}}
    try:
        with open(p, "r", encoding="utf-8") as f:
            d = json.load(f)
        if not isinstance(d, dict) or "entries" not in d:
            return {"version": 1, "entries": {}}
        return d
    except Exception:
        return {"version": 1, "entries": {}}


def save_index(idx):
    p = _index_path()
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(idx, f, ensure_ascii=False, indent=2)
    os.replace(tmp, p)


def list_entries():
    """保险库里所有账号条目（按收录时间倒序）。"""
    idx = load_index()
    out = []
    for uid, e in idx["entries"].items():
        e = dict(e)
        e["uid"] = uid
        e["zip"] = snapshot_path(uid, e.get("nickname"))
        e["zipExists"] = os.path.isfile(e["zip"])
        if e.get("hasCookies") and not e["zipExists"]:
            e["hasCookies"] = False
        out.append(e)
    out.sort(key=lambda x: -(x.get("collectedAt") or 0))
    return out


def find_entry(uid):
    for e in list_entries():
        if e.get("uid") == uid:
            return e
    return None


def upsert_entry(uid, patch):
    idx = load_index()
    e = idx["entries"].get(uid, {})
    e.update(patch)
    e["uid"] = uid
    idx["entries"][uid] = e
    save_index(idx)
    return e


# --------------------------------------------------------------------------
# 1. 账号指纹：本机当前登录的是谁
# --------------------------------------------------------------------------

def read_snapshot():
    try:
        with open(SNAPSHOT, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None
    node = data.get("primary") if isinstance(data, dict) else None
    return node if isinstance(node, dict) else None


def live_account():
    """本机当前登录账号（桌面端权威记录）。"""
    node = read_snapshot()
    if not node:
        return None
    return {
        "uid": node.get("uid") or "",
        "nickname": node.get("nickname") or "",
        "type": node.get("type") or "personal",
        "editionType": node.get("editionType") or "",
        "isPro": bool(node.get("isPro")),
        "isAdmin": bool(node.get("isAdmin")),
        "savedAt": node.get("savedAt") or 0,
        "source": "account-snapshot.json",
    }


_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def historical_uids():
    """从磁盘痕迹推断本机历史上出现过的其它 uid。"""
    uids = set()
    conn = os.path.join(WB, "connectors")
    if os.path.isdir(conn):
        for name in os.listdir(conn):
            if _UUID.match(name):
                uids.add(name)
    st = os.path.join(WB, "storage")
    if os.path.isdir(st):
        for name in os.listdir(st):
            m = re.match(r"user-([0-9a-f\-]{36})", name)
            if m:
                uids.add(m.group(1))
    pas = os.path.join(WB, "plugin-account-state")
    if os.path.isdir(pas):
        for name in os.listdir(pas):
            if name.endswith(".json") and len(name) == 41:
                uids.add(name[:-5])
    return uids


def legacy_owner_uid():
    try:
        with open(os.path.join(WB, "settings.json"), "r", encoding="utf-8") as f:
            data = json.load(f)
        return (data.get("claw") or {}).get("legacyOwnerUid") or ""
    except Exception:
        return ""


# --------------------------------------------------------------------------
# 2. 运行状态判断
# --------------------------------------------------------------------------

def cookies_readable():
    """能打开 Network/Cookies 就说明 App 已退出（未被独占锁定）。"""
    try:
        with open(COOKIES, "rb") as f:
            f.read(32)
        return True
    except Exception:
        return False


def app_running():
    """优先用进程表判断；失败则回退到 Cookies 锁探测。"""
    try:
        flags = 0x08000000  # CREATE_NO_WINDOW
        out = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq %s" % APP_EXE, "/NH"],
            capture_output=True, text=True, timeout=8, creationflags=flags,
        ).stdout or ""
        return APP_EXE.lower() in out.lower()
    except Exception:
        return not cookies_readable()


# ---- 定位 WorkBuddy.exe（用于切换后一键启动） ----

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
_k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
_k32.OpenProcess.restype = wt.HANDLE
_k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
_k32.CloseHandle.argtypes = [wt.HANDLE]
_k32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]


class _PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_char * 260),
    ]

_k32.Process32First.argtypes = [wt.HANDLE, ctypes.POINTER(_PROCESSENTRY32)]
_k32.Process32Next.argtypes = [wt.HANDLE, ctypes.POINTER(_PROCESSENTRY32)]


def _app_path_file():
    return os.path.join(vault_root(), ".app_path.txt")


def _cache_app_exe(p):
    try:
        with open(_app_path_file(), "w", encoding="utf-8") as f:
            f.write(p)
    except Exception:
        pass


def _cached_app_exe():
    try:
        with open(_app_path_file(), "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return ""


def find_app_exe():
    """先按进程找，再查缓存，最后扫常见安装位置。"""
    try:
        TH32CS_SNAPPROCESS = 0x02
        INVALID = ctypes.c_void_p(-1).value
        snap = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap and snap != INVALID:
            try:
                entry = _PROCESSENTRY32()
                entry.dwSize = ctypes.sizeof(entry)
                ok = _k32.Process32First(snap, ctypes.byref(entry))
                while ok:
                    if entry.szExeFile.decode("mbcs", "replace").lower() == APP_EXE.lower():
                        h = _k32.OpenProcess(0x1000, False, entry.th32ProcessID)
                        if h:
                            try:
                                buf = ctypes.create_unicode_buffer(1024)
                                n = wt.DWORD(1024)
                                if _k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)):
                                    p = buf.value
                                    if p and os.path.isfile(p):
                                        _cache_app_exe(p)
                                        return p
                            finally:
                                _k32.CloseHandle(h)
                    ok = _k32.Process32Next(snap, ctypes.byref(entry))
            finally:
                _k32.CloseHandle(snap)
    except Exception:
        pass

    cached = _cached_app_exe()
    if cached and os.path.isfile(cached):
        return cached

    for c in [
        os.environ.get("WBH_APP_EXE", ""),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "WorkBuddy", "WorkBuddy.exe"),
        os.path.join(os.environ.get("PROGRAMFILES", ""), "WorkBuddy", "WorkBuddy.exe"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "WorkBuddy", "WorkBuddy.exe"),
    ]:
        if c and os.path.isfile(c):
            _cache_app_exe(c)
            return c
    return ""


def launch_app():
    if app_running():
        return {"ok": True, "already": True, "reason": "WorkBuddy 已经在运行"}
    exe = find_app_exe()
    if not exe:
        return {"ok": False, "reason": "没有找到 WorkBuddy.exe，请手动打开 WorkBuddy"}
    try:
        subprocess.Popen([exe], cwd=os.path.dirname(exe), close_fds=True)
        return {"ok": True, "exe": exe, "reason": "已启动 WorkBuddy"}
    except Exception as e:
        return {"ok": False, "reason": "启动失败：%s" % e, "exe": exe}


# --------------------------------------------------------------------------
# 3. 登录态文件集清单
# --------------------------------------------------------------------------

def state_spec(uid):
    """返回 [(kind, relative_path)]，kind: f=文件, d=目录树, g=通配目录/文件。"""
    return [
        ("f", MEMBER_COOKIES),
        ("f", "app/session/Network/Cookies-journal"),
        ("d", "app/session/Local Storage"),
        ("d", "app/session/Session Storage"),
        ("f", MEMBER_LOCAL_STATE),
        ("f", "storage/skeleton/account-snapshot.json"),
        ("f", "keyblob"),
        ("d", "connectors/%s" % uid),
        ("f", "plugin-account-state/%s.json" % uid),
        ("d", "storage/user-%s" % uid),
        ("d", "storage/user-%s-personal" % uid),
        ("g", "app/session/Partitions/wb-webview-%s-*" % uid),
        # ★ 会话令牌本体（在 ~/.workbuddy 之外，用 @auth/ 前缀标识）
        ("f", AUTH_MEMBER_PREFIX + AUTH_FILE_NAME),
        ("g", AUTH_MEMBER_PREFIX + AUTH_FILE_NAME + ".*"),
    ]


def auth_dir():
    """定位 WorkBuddy 的 auth 目录（存放加密会话文件）。"""
    cands = [
        os.path.join(LOCAL_SETTINGS, "CodeBuddyExtension", "Data", "Public", "auth"),
        os.path.join(LOCAL_SETTINGS, "CodeBuddyExtension", "Data", "Public"),
        os.path.join(HOME, "AppData", "Local", "CodeBuddyExtension", "Data", "Public", "auth"),
    ]
    for c in cands:
        if c and os.path.isdir(c):
            return c
    return cands[0]


def live_auth_path():
    return os.path.join(auth_dir(), AUTH_FILE_NAME)


def _member_name(abs_p):
    """把绝对路径映射成快照成员名（@auth/ 前缀表示域外文件）。"""
    ap = os.path.abspath(abs_p)
    ad = os.path.abspath(auth_dir())
    if ap == ad or ap.startswith(ad + os.sep):
        return AUTH_MEMBER_PREFIX + os.path.relpath(ap, ad).replace(os.sep, "/")
    return os.path.relpath(ap, WB).replace(os.sep, "/")


def _expand(kind, rel):
    out = []
    if rel.startswith(AUTH_MEMBER_PREFIX):
        name = rel[len(AUTH_MEMBER_PREFIX):]
        base = auth_dir()
        if kind == "g":
            for p in sorted(glob.glob(os.path.join(base, name.replace("/", os.sep)))):
                if os.path.isfile(p) or os.path.isdir(p):
                    out.append(p)
            return out
        p = os.path.join(base, name.replace("/", os.sep))
        if os.path.exists(p):
            out.append(p)
        return out
    if kind == "g":
        for p in glob.glob(os.path.join(WB, rel.replace("/", os.sep))):
            if os.path.isdir(p):
                out.append(p)
        return out
    p = os.path.join(WB, rel.replace("/", os.sep))
    if os.path.exists(p):
        out.append(p)
    return out


_RANK = {"f": 0, "d": 1, "g": 2}

# 这些与"登录态"无关：纯缓存 / 锁文件 / 临时日志，排除后快照更小、更干净
_SKIP_SUBSTR = ("/Cache/", "/Code Cache/", "/GPUCache/", "/DawnGraphiteCache/",
                "/DawnWebGPUCache/", "/Shared Dictionary/", "/Crashpad/", "/blob_storage/",
                "/Service Worker/CacheStorage/", "/Cache_Data/")
_SKIP_NAMES = {"LOCK", "lockfile"}


def _skip_member(member):
    if os.path.basename(member) in _SKIP_NAMES:
        return True
    if member.endswith("-journal") and not member.endswith("Cookies-journal"):
        return True
    low = "/" + member
    return any(s in low for s in _SKIP_SUBSTR)


def iter_state_files(uid=None):
    """遍历登录态文件集，yield (相对路径, 绝对路径, 是否目录)。"""
    uid = uid or (live_account() or {}).get("uid") or ""
    seen = set()
    items = []
    for kind, rel in state_spec(uid):
        for abs_p in _expand(kind, rel):
            items.append((_RANK.get(kind, 3), rel, abs_p, os.path.isdir(abs_p)))
    items.sort(key=lambda x: (x[0], x[1]))
    for _r, rel, abs_p, is_dir in items:
        if is_dir:
            for r, _dd, fs in os.walk(abs_p):
                for fn in fs:
                    p = os.path.join(r, fn)
                    m = _member_name(p)
                    if m in seen or _skip_member(m):
                        continue
                    seen.add(m)
                    yield m, p, False
        else:
            m = _member_name(abs_p)
            if m in seen:
                continue
            seen.add(m)
            yield m, abs_p, False


def state_inventory(uid=None):
    """列出将要纳入快照的文件/目录，附带大小与可读性。"""
    uid = uid or (live_account() or {}).get("uid") or ""
    items = []
    for kind, rel in state_spec(uid):
        for abs_p in _expand(kind, rel):
            if os.path.isfile(abs_p):
                m = _member_name(abs_p)
                if _skip_member(m):
                    continue
                try:
                    sz = os.path.getsize(abs_p)
                    with open(abs_p, "rb") as f:
                        f.read(1)
                    ok = True
                except Exception:
                    sz, ok = -1, False
                items.append({"rel": m, "size": sz, "readable": ok, "isFile": True})
            elif os.path.isdir(abs_p):
                n = tot = locked = 0
                for r, _d, fs in os.walk(abs_p):
                    for fn in fs:
                        p = os.path.join(r, fn)
                        m = _member_name(p)
                        if _skip_member(m):
                            continue
                        n += 1
                        try:
                            tot += os.path.getsize(p)
                            with open(p, "rb") as f:
                                f.read(1)
                        except Exception:
                            locked += 1
                items.append({"rel": _member_name(abs_p),
                              "size": tot, "readable": locked == 0, "isFile": False,
                              "files": n, "locked": locked})
    return items


# --------------------------------------------------------------------------
# 4. 收录（capture -> zip）
# --------------------------------------------------------------------------

@serialized_mutation
def collect(uid=None, nickname=None):
    """
    把本机当前登录态整套快照成 `保险库/<手机号>__<uid8>.zip`。

    返回 {ok, reason, uid, nickname, files, bytes, hasCookies, missing:[...], zip}
    """
    acct = live_account()
    uid = uid or (acct or {}).get("uid")
    if not uid:
        return {"ok": False, "reason": "本机没有检测到已登录账号（account-snapshot.json 为空）"}

    if not acct or uid != acct.get("uid"):
        return {"ok": False, "reason": "只能收录当前实际登录的账号，不能覆盖其他账号快照"}

    nickname = nickname or (acct or {}).get("nickname") or uid[:8]
    zpath = snapshot_path(uid, nickname)
    tmp_zip = zpath + ".tmp"

    files = []
    missing = []
    total_in = 0
    has_cookies = False
    has_session = False

    with zipfile.ZipFile(tmp_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for member, abs_p, _d in iter_state_files(uid):
            try:
                st = os.stat(abs_p)
                zf.write(abs_p, member)
                files.append(member)
                total_in += st.st_size
                if member == MEMBER_COOKIES:
                    has_cookies = True
                if member == AUTH_MEMBER_PREFIX + AUTH_FILE_NAME:
                    has_session = True
            except Exception as e:
                missing.append("%s (%s)" % (member, type(e).__name__))

    if not files:
        try:
            os.remove(tmp_zip)
        except Exception:
            pass
        return {"ok": False, "reason": "没有采集到任何登录态文件"}

    # A switch/refresh during collection must never overwrite a different account.
    try:
        with zipfile.ZipFile(tmp_zip) as check_zip:
            auth = json.loads(check_zip.read(AUTH_MEMBER_PREFIX + AUTH_FILE_NAME))
            if (auth.get("account") or {}).get("uid") != uid:
                raise ValueError("登录身份在收录期间发生变化")
    except Exception:
        os.remove(tmp_zip)
        return {"ok": False, "reason": "未取得与当前账号一致的认证文件，原快照已保留，请重新收录"}
    os.replace(tmp_zip, zpath)
    size = os.path.getsize(zpath)

    meta = {
        "nickname": nickname,
        "type": (acct or {}).get("type", "personal"),
        "editionType": (acct or {}).get("editionType", ""),
        "isPro": (acct or {}).get("isPro", False),
        "collectedAt": now_ms(),
        "accountSavedAt": (acct or {}).get("savedAt", 0),
        "files": len(files),
        "bytes": total_in,
        "zipBytes": size,
        "hasCookies": has_cookies,
        "hasSession": has_session,
        "missingCount": len(missing),
        "missing": missing[:20],
        "source": "自动收录（本机登录态快照）",
        "needsRecollect": not (has_cookies and has_session),
    }
    upsert_entry(uid, meta)

    reason = "已收录登录态快照（%d 个文件）" % len(files)
    if not has_session:
        reason = ("已收录 %d 个文件，但**没找到加密会话文件**（%s）——"
                  "签到/切换会缺令牌。" % (len(files), live_auth_path()))
    elif not has_cookies:
        reason = ("已收录 %d 个文件（含加密会话），但 WorkBuddy 正在运行，"
                  "Network/Cookies 被独占锁定；签到已可用，若要完整切换建议退出 App 后再收录一次。"
                  % len(files))
    return {"ok": True, "reason": reason, "uid": uid, "nickname": nickname,
            "zip": zpath, "files": len(files), "bytes": total_in, "zipBytes": size,
            "hasCookies": has_cookies, "hasSession": has_session, "missing": missing}


def register_known(uid, nickname=None, note=""):
    """把没有快照的历史账号登记进保险库（仅身份，无登录态）。"""
    e = find_entry(uid)
    if e and e.get("collectedAt"):
        return e
    return upsert_entry(uid, {
        "nickname": nickname or (e or {}).get("nickname") or uid[:8],
        "type": "personal",
        "editionType": (e or {}).get("editionType", ""),
        "isPro": False,
        "registeredAt": (e or {}).get("registeredAt", now_ms()),
        "collectedAt": (e or {}).get("collectedAt", 0),
        "files": (e or {}).get("files", 0),
        "bytes": (e or {}).get("bytes", 0),
        "hasCookies": False,
        "needsRecollect": True,
        "source": note or "本机历史痕迹",
    })


def forget(uid):
    """从保险库移除某账号（删除对应的一个 zip + 索引条目）。"""
    e = find_entry(uid)
    if not e:
        return {"ok": False, "reason": "保险库里没有这个账号"}
    z = snapshot_path(uid, e.get("nickname"))
    removed = False
    if os.path.isfile(z):
        try:
            os.remove(z)          # 单文件删除，不触发批量删除保护
            removed = True
        except Exception as ex:
            return {"ok": False, "reason": "删除快照失败：%s" % ex}
    idx = load_index()
    idx["entries"].pop(uid, None)
    save_index(idx)
    return {"ok": True, "removed": removed, "nickname": e.get("nickname")}


# --------------------------------------------------------------------------
# 5. 切换（restore）
# --------------------------------------------------------------------------

@serialized_mutation
def restore(uid):
    """把保险库里的登录态写回工作目录。要求 WorkBuddy 已退出。"""
    if app_running() or not cookies_readable():
        return {"ok": False,
                "reason": "WorkBuddy 正在运行，登录态文件被锁定。请先完全退出 WorkBuddy"
                          "（右下角托盘图标 → 退出），再切换。"}

    e = find_entry(uid)
    if not e:
        return {"ok": False, "reason": "保险库里没有这个账号"}
    z = snapshot_path(uid, e.get("nickname"))
    if not os.path.isfile(z):
        return {"ok": False, "reason": "该账号没有收录到登录态快照，无法免验证码切换。"}

    written = 0
    errors = []
    auth_files = 0
    with zipfile.ZipFile(z, "r") as zf:
        for member in zf.namelist():
            if member.endswith("/"):
                continue
            if member.startswith(AUTH_MEMBER_PREFIX):
                safe = os.path.normpath(member[len(AUTH_MEMBER_PREFIX):]).replace("\\", "/")
                base = auth_dir()
            else:
                safe = os.path.normpath(member).replace("\\", "/")
                base = WB
            if safe.startswith("../") or safe.startswith("/") or ":" in safe:
                errors.append("非法路径 %s" % member)
                continue
            dst = os.path.join(base, safe.replace("/", os.sep))
            try:
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with zf.open(member) as src, open(dst, "wb") as out:
                    shutil.copyfileobj(src, out)
                written += 1
                if member.startswith(AUTH_MEMBER_PREFIX):
                    auth_files += 1
            except Exception as ex:
                errors.append("%s (%s)" % (member, type(ex).__name__))

    # 清掉"登出标记"：否则 App 启动时会认为用户已登出，从而忽略刚还原的会话
    cleared = _clear_logout_markers()

    # 清掉不属于目标 uid 的 webview 分区（改名归档，不物理删除）
    part_root = os.path.join(APP_SESSION, "Partitions")
    if os.path.isdir(part_root):
        archive = os.path.join(vault_root(), ".retired_partitions")
        for name in os.listdir(part_root):
            if name.startswith("wb-webview-") and ("-%s-" % uid) not in name:
                src = os.path.join(part_root, name)
                try:
                    os.makedirs(archive, exist_ok=True)
                    dst = os.path.join(archive, "%d_%s" % (now_ms(), name))
                    shutil.move(src, dst)
                except Exception:
                    pass

    upsert_entry(uid, {"lastRestoredAt": now_ms()})
    return {"ok": True, "uid": uid, "nickname": e.get("nickname"), "written": written,
            "authFiles": auth_files, "clearedLogoutMarkers": cleared, "errors": errors,
            "reason": "已还原登录态（含加密会话文件 %d 个），启动 WorkBuddy 即为该账号（无需短信验证码）"
                      % auth_files}


def _clear_logout_markers():
    """删除 auth 目录下形如 workbuddy-desktop*.logout* 的登出标记。"""
    d = auth_dir()
    if not os.path.isdir(d):
        return 0
    n = 0
    try:
        names = os.listdir(d)
    except Exception:
        return 0
    for fn in names:
        if not fn.startswith(AUTH_FILE_NAME):
            continue
        low = fn.lower()
        if "logout" not in low and not low.endswith(".marker"):
            continue
        try:
            os.remove(os.path.join(d, fn))
            n += 1
        except Exception:
            pass
    return n


# --------------------------------------------------------------------------
# 6. 从快照里取成员（签到用）
# --------------------------------------------------------------------------

def vault_member(uid, member):
    """从保险库 zip 里取出某个成员，返回 bytes 或 None。"""
    e = find_entry(uid)
    if not e:
        return None
    z = snapshot_path(uid, e.get("nickname"))
    if not os.path.isfile(z):
        return None
    try:
        with zipfile.ZipFile(z, "r") as zf:
            try:
                return zf.read(member)
            except KeyError:
                return None
    except Exception:
        return None


def vault_members_matching(uid, prefix):
    """列出 zip 里以 prefix 开头的成员名。"""
    e = find_entry(uid)
    if not e:
        return []
    z = snapshot_path(uid, e.get("nickname"))
    if not os.path.isfile(z):
        return []
    try:
        with zipfile.ZipFile(z, "r") as zf:
            return [n for n in zf.namelist() if n.startswith(prefix)]
    except Exception:
        return []


# --------------------------------------------------------------------------
# 7. Cookie 解密（DPAPI 主密钥 + AES-256-GCM）
# --------------------------------------------------------------------------

_crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
_bcrypt = ctypes.WinDLL("bcrypt", use_last_error=True)


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def dpapi_unprotect(data):
    bin_ = _DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data, len(data)),
                                             ctypes.POINTER(ctypes.c_char)))
    bout = _DATA_BLOB()
    if not _crypt32.CryptUnprotectData(ctypes.byref(bin_), None, None, None, None, 0,
                                       ctypes.byref(bout)):
        raise OSError("CryptUnprotectData err=%d" % ctypes.get_last_error())
    return ctypes.string_at(bout.pbData, bout.cbData)


def dpapi_protect(data):
    bin_ = _DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data, len(data)),
                                             ctypes.POINTER(ctypes.c_char)))
    bout = _DATA_BLOB()
    if not _crypt32.CryptProtectData(ctypes.byref(bin_), None, None, None, None, 0,
                                     ctypes.byref(bout)):
        raise OSError("CryptProtectData err=%d" % ctypes.get_last_error())
    return ctypes.string_at(bout.pbData, bout.cbData)


class _GCM(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.ULONG), ("dwInfoVersion", wt.ULONG),
        ("pbNonce", ctypes.POINTER(ctypes.c_ubyte)), ("cbNonce", wt.ULONG),
        ("pbAuthData", ctypes.POINTER(ctypes.c_ubyte)), ("cbAuthData", wt.ULONG),
        ("pbTag", ctypes.POINTER(ctypes.c_ubyte)), ("cbTag", wt.ULONG),
        ("pbMacContext", ctypes.POINTER(ctypes.c_ubyte)), ("cbMacContext", wt.ULONG),
        ("cbAAD", wt.ULONG), ("cbData", ctypes.c_ulonglong), ("dwFlags", wt.ULONG),
    ]


def _gcm_ctx():
    h_alg = wt.HANDLE()
    if _bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(h_alg), "AES", None, 0):
        raise OSError("BCryptOpenAlgorithmProvider failed")
    mb = ctypes.create_string_buffer("ChainingModeGCM".encode("utf-16-le") + b"\x00\x00")
    _bcrypt.BCryptSetProperty(h_alg, "ChainingMode", mb, len(mb), 0)
    objlen = wt.ULONG()
    _bcrypt.BCryptGetProperty(h_alg, "ObjectLength", ctypes.byref(objlen),
                              ctypes.sizeof(objlen), ctypes.byref(wt.ULONG()), 0)
    return h_alg, objlen.value


def _gcm_key(h_alg, objlen, key):
    """
    生成对称密钥句柄。

    ⚠️ 这里有个必须记住的坑：**密钥对象就住在 objbuf 这块内存里**，
    h_key 只是指向它。所以 objbuf 必须和句柄一起返回、由调用方持有到用完为止；
    一旦提前回收（例如函数返回后被 GC），句柄就成了野指针，
    继续用会直接段错误（表现为进程毫无征兆地崩掉）。
    """
    objbuf = ctypes.create_string_buffer(objlen)
    h_key = wt.HANDLE()
    kb = ctypes.create_string_buffer(key, len(key))
    if _bcrypt.BCryptGenerateSymmetricKey(h_alg, ctypes.byref(h_key), objbuf, objlen,
                                          kb, len(key), 0):
        raise OSError("BCryptGenerateSymmetricKey failed")
    return h_key, objbuf


def aes_gcm_decrypt(key, nonce, ct, tag, aad=None):
    h_alg, objlen = _gcm_ctx()
    h_key, keep = _gcm_key(h_alg, objlen, key)   # keep 全程持有，不能只留 h_key
    nbuf = ctypes.create_string_buffer(nonce, len(nonce))
    tbuf = ctypes.create_string_buffer(tag, len(tag))
    cb = ctypes.create_string_buffer(ct, len(ct))
    ob = ctypes.create_string_buffer(len(ct) + 16)
    info = _GCM()
    info.cbSize = ctypes.sizeof(info)
    info.dwInfoVersion = 1
    info.pbNonce = ctypes.cast(nbuf, ctypes.POINTER(ctypes.c_ubyte))
    info.cbNonce = len(nonce)
    info.pbTag = ctypes.cast(tbuf, ctypes.POINTER(ctypes.c_ubyte))
    info.cbTag = len(tag)
    info.cbData = len(ct)
    abuf = None
    if aad:
        abuf = ctypes.create_string_buffer(aad, len(aad))
        info.pbAuthData = ctypes.cast(abuf, ctypes.POINTER(ctypes.c_ubyte))
        info.cbAuthData = len(aad)
    outlen = wt.ULONG()
    r = _bcrypt.BCryptDecrypt(h_key, cb, len(ct), ctypes.byref(info), None, 0,
                              ob, len(ct) + 16, ctypes.byref(outlen), 0)
    _bcrypt.BCryptDestroyKey(h_key)
    _bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)
    del keep
    if r:
        raise OSError("BCryptDecrypt failed rc=%d" % r)
    return ob.raw[:outlen.value]


def aes_gcm_encrypt(key, nonce, pt, aad=None):
    """返回 (ciphertext, tag)。aad 用于 WB-AAD 信封（写回登录身份时用）。"""
    h_alg, objlen = _gcm_ctx()
    h_key, keep = _gcm_key(h_alg, objlen, key)   # 同上：keep 必须活到用完
    nbuf = ctypes.create_string_buffer(nonce, len(nonce))
    tbuf = ctypes.create_string_buffer(16)
    pb = ctypes.create_string_buffer(pt, len(pt))
    ob = ctypes.create_string_buffer(len(pt) + 16)
    info = _GCM()
    info.cbSize = ctypes.sizeof(info)
    info.dwInfoVersion = 1
    info.pbNonce = ctypes.cast(nbuf, ctypes.POINTER(ctypes.c_ubyte))
    info.cbNonce = len(nonce)
    info.pbTag = ctypes.cast(tbuf, ctypes.POINTER(ctypes.c_ubyte))
    info.cbTag = 16
    info.cbData = len(pt)
    abuf = None
    if aad:
        abuf = ctypes.create_string_buffer(aad, len(aad))
        info.pbAuthData = ctypes.cast(abuf, ctypes.POINTER(ctypes.c_ubyte))
        info.cbAuthData = len(aad)
    outlen = wt.ULONG()
    r = _bcrypt.BCryptEncrypt(h_key, pb, len(pt), ctypes.byref(info), None, 0,
                              ob, len(pt) + 16, ctypes.byref(outlen), 0)
    _bcrypt.BCryptDestroyKey(h_key)
    _bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)
    del keep
    if r:
        raise OSError("BCryptEncrypt failed rc=%d" % r)
    return ob.raw[:outlen.value], tbuf.raw[:16]


def local_state_key_from_bytes(data):
    """从 Local State 的原始字节里解出（DPAPI 保护的）Cookie 主密钥。"""
    obj = json.loads(data.decode("utf-8", "replace"))
    enc = base64.b64decode(obj["os_crypt"]["encrypted_key"])
    if enc[:5] == b"DPAPI":
        return dpapi_unprotect(enc[5:])
    if enc[:4] == b"APPB":
        raise OSError("Cookie 使用 App-Bound 加密（APPB），当前无法离线解密")
    raise OSError("未知的 encrypted_key 前缀: %r" % enc[:5])


def local_state_key(local_state_path=None):
    p = local_state_path or LOCAL_STATE
    with open(p, "rb") as f:
        return local_state_key_from_bytes(f.read())


def _as_bytes(v):
    """sqlite 可能按列类型返回 str 或 bytes / None，统一成 bytes。"""
    if v is None:
        return b""
    if isinstance(v, bytes):
        return v
    if isinstance(v, bytearray):
        return bytes(v)
    return str(v).encode("utf-8", "replace")


def read_cookie_db_bytes(data, master):
    """解析 Cookies 库字节，返回 [{host,name,value,path,secure,httpOnly,expires}]。"""
    tmp = os.path.join(tempfile.gettempdir(), "wbck_%d.db" % now_ms())
    with open(tmp, "wb") as f:
        f.write(data)
    rows = []
    try:
        con = sqlite3.connect(tmp)
        cur = con.cursor()
        cur.execute("SELECT host_key,name,encrypted_value,value,path,is_secure,is_httponly,expires_utc "
                    "FROM cookies ORDER BY host_key,name")
        for host, name, ev, val, path, sec, ho, exp in cur.fetchall():
            # value 列在 Chromium 里是 TEXT（大多数为空），可能是 str
            if isinstance(val, str):
                v = val
            else:
                vb = _as_bytes(val)
                v = vb.decode("utf-8", "replace") if vb else ""
            if not v:
                evb = _as_bytes(ev)
                if evb[:3] in (b"v10", b"v11") and len(evb) > 31:
                    try:
                        v = aes_gcm_decrypt(master, evb[3:15], evb[15:-16],
                                            evb[-16:]).decode("utf-8", "replace")
                    except Exception:
                        v = ""
            rows.append({"host": host, "name": name, "value": v, "path": path,
                         "secure": bool(sec), "httpOnly": bool(ho), "expires": exp or 0})
        con.close()
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass
    return rows


def read_cookie_db(cookies_path, master):
    with open(cookies_path, "rb") as f:
        return read_cookie_db_bytes(f.read(), master)


# --------------------------------------------------------------------------
# 8. 会话提取
# --------------------------------------------------------------------------

_SESSION_NAME_HINT = re.compile(r"(token|auth|session|ticket|skey|sid|uid|login|cred)", re.I)
_JWT = re.compile(r"^eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$")
_LONG = re.compile(r"^[A-Za-z0-9_\-\.]{40,}$")


def extract_session(cookies):
    """从 Cookie 列表里推断出调用加油站接口所需的凭据。"""
    relevant = [c for c in cookies
                if "workbuddy" in c["host"] or "tencent" in c["host"] or "codebuddy" in c["host"]]

    user_id = ""
    bearer_cands = []
    device_token = ""

    for c in relevant:
        name, value = c["name"], c["value"]
        if not value:
            continue
        low = name.lower()
        if low in ("x-user-id", "user_id", "userid", "uid") and not user_id:
            user_id = value
        if low in ("x-device-token", "device_token", "devicetoken") and not device_token:
            device_token = value
        if _SESSION_NAME_HINT.search(name) or _JWT.match(value) or _LONG.match(value):
            bearer_cands.append((name, value, c["host"]))

    def header_for(host_filter):
        return "; ".join("%s=%s" % (c["name"], c["value"])
                         for c in relevant if host_filter(c["host"]) and c["value"])

    cands = []
    for host_filter, tag in ((lambda h: "workbuddy" in h, "workbuddy"),
                             (lambda h: True, "all")):
        hdr = header_for(host_filter)
        if hdr:
            cands.append({"mode": "cookie", "label": "Cookie(%s)" % tag, "cookie": hdr,
                          "bearer": "", "user_id": user_id, "device_token": device_token})
    for name, value, host in bearer_cands[:8]:
        cands.append({"mode": "bearer", "label": "Bearer(%s@%s)" % (name, host), "bearer": value,
                      "cookie": header_for(lambda h: "workbuddy" in h) or header_for(lambda h: True),
                      "user_id": user_id, "device_token": device_token})

    return {
        "user_id": user_id,
        "device_token": device_token,
        "cookie_header": header_for(lambda h: "workbuddy" in h) or header_for(lambda h: True),
        "bearer_candidates": [{"name": n, "value": v, "host": h} for n, v, h in bearer_cands[:12]],
        "candidates": cands,
    }


# --------------------------------------------------------------------------
# 8.5 at-rest 主密钥 + 加密会话文件（令牌真正的来源）
# --------------------------------------------------------------------------
#
# WorkBuddy 的 OIDC 会话（accessToken / refreshToken / 手机号）加密存在
#   <用户目录>\Local Settings\CodeBuddyExtension\Data\Public\auth\workbuddy-desktop.info
# 里的每个敏感字段都是
#   {"suite":1,"keyId":"<16hex>","nonce":b64,"authTag":b64,"ciphertext":b64}
# 用 AES-256-GCM 解：key = sha256(atRestSecretKey)，AAD 由厂商规则拼装（见 wb_aad）。
# atRestSecretKey 由编译进 WorkBuddy.exe 的原生绑定保管，用 wbkey.js 取出。

_WB_AAD_TAG = b"WB-AAD\x00"
_WB_FRAME_TAG = {"file": "WBEF1", "field": "WBEV1", "record": "WBER1", "stream": "WBES1"}
_WB_FRAME_ID = {"file": 1, "field": 2, "record": 3, "stream": 4}


def _wb_u32(n):
    return struct.pack(">I", n)


def _wb_str(s):
    if isinstance(s, str):
        s = s.encode("utf-8")
    return _wb_u32(len(s)) + s


def wb_aad(key_id, suite, framing, scheme="sym-v1", sequence=None, final=None):
    """按 WorkBuddy 的 WB-AAD 规则构造附加认证数据。"""
    seq = b"\x00" if sequence is None else (b"\x01" + struct.pack(">Q", sequence))
    fin = 0 if final is None else (2 if final else 1)
    return (_WB_AAD_TAG + b"\x01" + _wb_str(_WB_FRAME_TAG[framing]) + _wb_str(scheme)
            + _wb_u32(suite) + _wb_str(key_id) + bytes([_WB_FRAME_ID[framing]]) + seq
            + bytes([fin]))


def wb_key_from_secret(secret):
    return hashlib.sha256(secret.encode("utf-8")).digest()


def wb_key_id(key):
    return hashlib.sha256(key).hexdigest()[:16]


def _atrest_cache_path():
    return os.path.join(vault_root(), ".atrest.json")


def at_rest_secret(force=False):
    """取本机 at-rest 主密钥（设备级、与账号无关），带缓存。"""
    cp = _atrest_cache_path()
    if not force and os.path.isfile(cp):
        try:
            with open(cp, "r", encoding="utf-8") as f:
                d = json.load(f)
            s = d.get("secret")
            if isinstance(s, str) and len(s) == 44:
                return {"ok": True, "secret": s, "cached": True}
        except Exception:
            pass
    exe = find_app_exe()
    if not exe:
        return {"ok": False, "reason": "找不到 WorkBuddy.exe，无法读取本机密钥"}
    script = os.path.join(HERE, WBKEY_JS)
    if not os.path.isfile(script):
        return {"ok": False, "reason": "缺少 %s（随本程序一起发布）" % WBKEY_JS}
    env = dict(os.environ)
    env["ELECTRON_RUN_AS_NODE"] = "1"
    try:
        p = subprocess.run([exe, script], capture_output=True, timeout=40, env=env,
                           cwd=os.path.dirname(script))
    except Exception as e:
        return {"ok": False, "reason": "调用原生密钥接口失败：%s: %s" % (type(e).__name__, e)}
    out = (p.stdout or b"").decode("utf-8", "replace").strip()
    info = _json_or_text(out)
    if not isinstance(info, dict) or not info.get("ok"):
        reason = info.get("reason") if isinstance(info, dict) else (out[:160] or "无输出")
        return {"ok": False, "reason": "原生密钥接口返回异常：%s" % reason}
    secret = info["secret"]
    try:
        with open(cp, "w", encoding="utf-8") as f:
            json.dump({"secret": secret, "fetchedAt": now_ms(), "exe": exe}, f)
    except Exception:
        pass
    return {"ok": True, "secret": secret, "cached": False}


def wb_unwrap_field(secret, node):
    """解开一个 $wbEncrypted 字段信封，返回明文 str。"""
    env = json.loads(base64.b64decode(node["envelope"]).decode("utf-8"))
    key = wb_key_from_secret(secret)
    pt = aes_gcm_decrypt(key,
                         base64.b64decode(env["nonce"]),
                         base64.b64decode(env["ciphertext"]),
                         base64.b64decode(env["authTag"]),
                         wb_aad(env["keyId"], env["suite"], "field"))
    return pt.decode("utf-8")


def parse_auth_bytes(data, secret):
    """解析 workbuddy-desktop.info 内容，解出账号信息与令牌。"""
    doc = json.loads(data.decode("utf-8", "replace"))
    acct = doc.get("account") or {}
    auth = doc.get("auth") or {}

    def u(node):
        if not isinstance(node, dict) or node.get("$wbEncrypted") != 1:
            return node
        try:
            return wb_unwrap_field(secret, node)
        except Exception:
            return None

    return {
        "uid": acct.get("uid") or "",
        "phone": u(acct.get("phoneNumber")),
        "nickname": u(acct.get("nickname")),
        "uin": acct.get("uin"),
        "accessToken": u(auth.get("accessToken")),
        "refreshToken": u(auth.get("refreshToken")),
        "tokenType": auth.get("tokenType") or "Bearer",
        "expiresAt": auth.get("expiresAt"),
        "refreshExpiresAt": auth.get("refreshExpiresAt"),
        "domain": auth.get("domain") or "",
        "lastRefreshTime": auth.get("lastRefreshTime"),
        "raw": doc,
    }


def _secret_or_error():
    s = at_rest_secret()
    if not s.get("ok"):
        return None, s.get("reason") or "无法取得本机密钥"
    return s["secret"], None


def auth_info_live():
    """读本机当前加密会话（App 运行时也可读：该文件没有独占锁）。"""
    p = live_auth_path()
    if not os.path.isfile(p):
        return {"ok": False, "reason": "没有找到本机加密会话文件：%s" % p}
    secret, err = _secret_or_error()
    if err:
        return {"ok": False, "reason": err}
    try:
        with open(p, "rb") as f:
            return dict(parse_auth_bytes(f.read(), secret), ok=True, source="本机会话")
    except Exception as e:
        return {"ok": False, "reason": "解析会话文件失败：%s: %s" % (type(e).__name__, e)}


def auth_info_from_vault(uid):
    """从保险库快照里取出该账号的加密会话并解密。"""
    names = [n for n in vault_members_matching(uid, AUTH_MEMBER_PREFIX)
             if n.rsplit("/", 1)[-1].startswith(AUTH_FILE_NAME)]
    if not names:
        return {"ok": False, "reason": "快照里没有加密会话文件，请在登录状态下重新『收录本机账号』"}
    names.sort(key=len)
    data = vault_member(uid, names[0])
    if not data:
        return {"ok": False, "reason": "无法从快照读取会话文件"}
    secret, err = _secret_or_error()
    if err:
        return {"ok": False, "reason": err}
    try:
        info = dict(parse_auth_bytes(data, secret), ok=True, source="保险库")
        reason = identity_error(info, uid)
        if reason:
            return {"ok": False, "reason": reason}
        return info
    except Exception as e:
        return {"ok": False, "reason": "解密快照会话失败：%s: %s" % (type(e).__name__, e)}


def identity_error(info, uid):
    if not uid or info.get("uid") != uid:
        return "认证快照属于其他账号，已阻止串号查询；请重新验证登录该手机号"
    token = info.get("accessToken") or ""
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (ValueError, IndexError, TypeError):
        return "无法核对登录凭据身份，请重新验证登录"
    if claims.get("sub") != uid:
        return "登录凭据与目标账号不一致，已阻止查询；请重新验证登录"
    return None


def auth_info_for(uid, prefer_live=True):
    """取某账号的令牌：先试本机当前会话，再试保险库。"""
    tried = []
    if prefer_live:
        info = auth_info_live()
        if info.get("ok") and info.get("accessToken") and (not uid or info.get("uid") == uid):
            return info
        tried.append("本机：%s" % (info.get("reason") or ("uid %s 与 %s 不匹配"
                                                       % (info.get("uid"), uid))))
    if uid:
        info = auth_info_from_vault(uid)
        if info.get("ok") and info.get("accessToken") and info.get("uid") == uid:
            return info
        tried.append("保险库：%s" % info.get("reason"))
    return {"ok": False, "reason": "；".join(tried) or "没有可用令牌", "tried": tried}


# --------------------------------------------------------------------------
# 9. 真实加油站接口
# --------------------------------------------------------------------------

def http_json(base, path, method="POST", token=None, uid=None, cookie=None, body=None,
              timeout=15, device_token=None):
    url = base.rstrip("/") + path
    data = None
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Origin": base,
        "Referer": base + "/",
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) WorkBuddy/5.7.6 Chrome/138.0.0.0 Safari/537.36"),
    }
    if token:
        headers["Authorization"] = token if token.lower().startswith("bearer ") else ("Bearer " + token)
    if uid:
        headers["X-User-Id"] = uid
    if device_token:
        headers["X-Device-Token"] = device_token
    if cookie:
        headers["Cookie"] = cookie
    if body is not None and method.upper() != "GET":
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"status": resp.status, "text": resp.read().decode("utf-8", "replace"), "url": url}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "text": e.read().decode("utf-8", "replace"), "url": url}
    except Exception as e:
        return {"status": 0, "text": "%s: %s" % (type(e).__name__, e), "url": url}


def _json_or_text(text):
    try:
        return json.loads(text)
    except Exception:
        return None


def probe_session(cand, base=None):
    """用一条候选凭据打一次只读的状态接口，判断是否有效。"""
    bases = [base] if base else API_BASES
    last = None
    for b in bases:
        r = http_json(b, "/v2/billing/meter/checkin-activity-status", "POST",
                      token=(cand.get("bearer") or None),
                      uid=(cand.get("user_id") or None),
                      cookie=(cand.get("cookie") or None),
                      device_token=(cand.get("device_token") or None), body={})
        j = _json_or_text(r["text"])
        if r["status"] == 200 and isinstance(j, dict):
            return {"ok": True, "base": b, "cand": cand, "raw": j, "status": r["status"]}
        last = {"ok": False, "base": b, "cand": cand, "raw": j, "status": r["status"],
                "text": r["text"][:200]}
    return last or {"ok": False, "reason": "所有候选凭据均被拒绝（401/403）", "cand": cand}


def normalize_status(raw):
    """把接口返回规整成界面用的字段（兼容真实接口与旧版字段名）。"""
    if not isinstance(raw, dict):
        return {"raw": raw}
    node = raw.get("data") if isinstance(raw.get("data"), dict) else raw

    def g(*names):
        for n in names:
            if n in node and node[n] is not None:
                return node[n]
        return None

    def as_bool(v):
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return v != 0
        if isinstance(v, str):
            return v.strip().lower() in ("true", "1", "yes")
        return None

    def as_int(v):
        try:
            return int(v)
        except Exception:
            return None

    return {
        "checkedToday": as_bool(g("today_checked_in", "todayCheckedIn", "todayChecked",
                                  "checkedIn", "checked_in", "signed", "isChecked",
                                  "checkinStatus", "hasCheckedIn")),
        "todayPoints": as_int(g("today_credit", "todayCredit", "todayPoints", "points",
                                "reward", "rewardPoints", "checkinPoints")),
        "continuousDays": as_int(g("streak_days", "streakDays", "continuousDays", "continuous",
                                   "streak", "continuousCheckinDays")),
        "totalPoints": as_int(g("total_credits", "totalCredits", "totalPoints", "balance",
                                "total", "pointsBalance")),
        # 真实接口的附加信息（Buddy 加油站）
        "active": as_bool(g("active")),
        "dailyCredit": as_int(g("daily_credit", "dailyCredit")),
        "weekCheckinDays": as_int(g("week_checkin_days", "weekCheckinDays")),
        "weekProgress": g("week_progress", "weekProgress"),
        "checkinDates": g("checkin_dates", "checkinDates") or [],
        "activityName": g("activity_name", "activityName"),
        "themeName": g("theme_name", "themeName"),
        "season": as_int(g("season")),
        "startTime": g("start_time", "startTime"),
        "endTime": g("end_time", "endTime"),
        "claimText": g("claim_button_text", "claimButtonText"),
        "raw": raw,
    }


# --------------------------------------------------------------------------
# 10. 会话缓存 + 签到
# --------------------------------------------------------------------------

def _session_cache_path():
    return os.path.join(vault_root(), ".session_cache.json")


def session_for(uid, force=False):
    """
    取某账号的可用会话。

    令牌来源：优先本机加密会话文件，其次保险库快照里的那份。
    两者都用本机 at-rest 主密钥解密，因此 **WorkBuddy 开着也能签到**。

    返回 {ok, base, cand:{bearer,user_id}, phone, expiresAt, source}
    """
    uid = uid or (live_account() or {}).get("uid") or ""
    if not uid:
        return {"ok": False, "reason": "没有指定账号"}

    cp = _session_cache_path()
    cache = {}
    if os.path.isfile(cp):
        try:
            with open(cp, "r", encoding="utf-8") as f:
                cache = json.load(f)
        except Exception:
            cache = {}
    c = cache.get(uid) or {}

    info = auth_info_for(uid)
    if not info.get("ok") or not info.get("accessToken"):
        return {"ok": False, "reason": info.get("reason") or "无法取得该账号的令牌",
                "tried": info.get("tried")}

    mismatch = identity_error(info, uid)
    if mismatch:
        return {"ok": False, "reason": mismatch}

    cand = {
        "label": "加密会话(%s)" % (info.get("domain") or "workbuddy"),
        "bearer": info["accessToken"],
        "user_id": info.get("uid") or uid,
        "cookie": "",
        "device_token": "",
    }

    # 10 分钟内验证过就不再打扰接口，直接复用上次成功的 base
    fresh = bool(c.get("verifiedAt")) and c["verifiedAt"] > now_ms() - 10 * 60 * 1000
    base = (c.get("base") if fresh else None) or API_BASES[0]
    if not fresh:
        ok = False
        last = None
        for b in ([base] + [x for x in API_BASES if x != base]):
            r = http_json(b, "/v2/billing/meter/checkin-activity-status", "POST",
                          token=cand["bearer"], uid=cand["user_id"], body={})
            j = _json_or_text(r["text"])
            last = r
            if r["status"] == 200 and isinstance(j, dict) and j.get("code") in (0, None):
                base = b
                ok = True
                break
        if not ok:
            st = (last or {}).get("status")
            txt = ((last or {}).get("text") or "")[:200]
            reason = "令牌被接口拒绝（HTTP %s）" % st
            if st == 401 or st == 403:
                reason += "：令牌已失效，请在 WorkBuddy 里打开一次该账号让客户端刷新，然后重新收录。"
            else:
                reason += "：%s" % txt
            return {"ok": False, "reason": reason, "status": st,
                    "tokenLen": len(cand["bearer"]), "expiresAt": info.get("expiresAt")}

    try:
        with VAULT_LOCK:
            if os.path.isfile(cp):
                try:
                    cache = json.loads(Path(cp).read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    cache = {}
            cache[uid] = {"base": base, "verifiedAt": now_ms(), "phone": info.get("phone"),
                          "expiresAt": info.get("expiresAt"), "source": info.get("source")}
            atomic_bytes(cp, json.dumps(cache, ensure_ascii=False).encode("utf-8"))
    except Exception:
        pass

    return {"ok": True, "base": base, "cand": cand, "phone": info.get("phone"),
            "expiresAt": info.get("expiresAt"), "source": info.get("source"),
            "cached": fresh}


def checkin_status_for(uid):
    sess = session_for(uid)
    if not sess.get("ok"):
        return sess
    r = http_json(sess["base"], "/v2/billing/meter/checkin-activity-status", "POST",
                  token=sess["cand"]["bearer"], uid=sess["cand"]["user_id"], body={})
    j = _json_or_text(r["text"])
    if r["status"] != 200:
        return {"ok": False, "status": r["status"], "reason": "状态查询失败",
                "text": r["text"][:300]}
    return {"ok": True, "status": normalize_status(j), "raw": j, "base": sess["base"],
            "phone": sess.get("phone"), "source": sess.get("source")}


def do_checkin(uid):
    """执行真实每日签到（用解密出来的令牌，App 开着也能签）。"""
    sess = session_for(uid)
    if not sess.get("ok"):
        return {"ok": False, "reason": sess.get("reason"), "tried": sess.get("tried")}
    r = http_json(sess["base"], "/v2/billing/meter/daily-checkin", "POST",
                  token=sess["cand"]["bearer"], uid=sess["cand"]["user_id"], body={})
    j = _json_or_text(r["text"])
    code = j.get("code") if isinstance(j, dict) else None
    msg = ""
    if isinstance(j, dict):
        msg = j.get("msg") or j.get("message") or (j.get("data") or {}).get("msg") or ""
    # 10001 / 1001 = 今天已签到（幂等，视为成功）
    if code in (10001, 1001, "10001", "1001") or "已签到" in msg:
        return {"ok": True, "already": True, "status": r["status"], "raw": j, "base": sess["base"],
                "message": msg or "今天已签到，明天再来", "phone": sess.get("phone")}
    if r["status"] != 200 or code not in (0, None):
        return {"ok": False, "status": r["status"], "code": code,
                "reason": msg or ("签到接口返回 %s" % r["status"]),
                "text": r["text"][:300]}
    return {"ok": True, "status": r["status"], "raw": j, "base": sess["base"],
            "message": msg or "签到成功", "phone": sess.get("phone"),
            "credits": (j.get("data") or {}).get("today_credit") if isinstance(j, dict) else None}


# --------------------------------------------------------------------------
# 11. 体检
# --------------------------------------------------------------------------

def diagnose():
    acct = live_account()
    inv = state_inventory((acct or {}).get("uid"))
    entries = list_entries()
    return {
        "wbDir": WB,
        "wbDirExists": os.path.isdir(WB),
        "appRunning": app_running(),
        "cookiesReadable": cookies_readable(),
        "cookiesPath": COOKIES,
        "cookiesExists": os.path.isfile(COOKIES),
        "liveAccount": acct,
        "legacyOwnerUid": legacy_owner_uid(),
        "historicalUids": sorted(historical_uids()),
        "vaultDir": VAULT_DIR,
        "vaultEntries": entries,
        "stateInventory": inv,
        "localStateExists": os.path.isfile(LOCAL_STATE),
        "appExe": find_app_exe(),
        # 会话令牌相关
        "authDir": auth_dir(),
        "authFile": live_auth_path(),
        "authFileExists": os.path.isfile(live_auth_path()),
        "atRestSecretCached": os.path.isfile(_atrest_cache_path()),
        "wbkeyJs": os.path.join(HERE, WBKEY_JS),
    }


# --------------------------------------------------------------------------
# 12. 会话（对话）
# --------------------------------------------------------------------------

PROJECTS = os.path.join(WB, "projects")


def list_conversations(limit=200):
    """扫 ~/.workbuddy/projects/<工作区>/<sessionId>.jsonl。"""
    out = []
    if not os.path.isdir(PROJECTS):
        return out
    for ws in os.listdir(PROJECTS):
        d = os.path.join(PROJECTS, ws)
        if not os.path.isdir(d):
            continue
        for fn in os.listdir(d):
            if not fn.endswith(".jsonl"):
                continue
            p = os.path.join(d, fn)
            try:
                st = os.stat(p)
            except Exception:
                continue
            title = ""
            uid = ""
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    for i, line in enumerate(f):
                        if i > 60:
                            break
                        if not uid:
                            m = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                                          r"[0-9a-f]{4}-[0-9a-f]{12}", line)
                            if m:
                                uid = m.group(0)
                        if not title:
                            try:
                                obj = json.loads(line)
                                for key in ("title", "summary", "name"):
                                    if isinstance(obj, dict) and obj.get(key):
                                        title = str(obj[key])[:60]
                                        break
                            except Exception:
                                pass
            except Exception:
                pass
            out.append({"sessionId": fn[:-6], "workspace": ws,
                        "title": title or "(无标题)", "uid": uid,
                        "mtime": int(st.st_mtime * 1000), "size": st.st_size, "path": p})
    out.sort(key=lambda x: -x["mtime"])
    return out[:limit]


# --------------------------------------------------------------------------
# 13. at-rest 加密：把登录身份写回去（「轻量切换」用）
# --------------------------------------------------------------------------

def _b64e(b):
    return base64.b64encode(b).decode("ascii")


def wb_wrap_field(secret, plaintext):
    """把明文字符串包成 $wbEncrypted 字段信封（wb_unwrap_field 的逆运算）。"""
    key = wb_key_from_secret(secret)
    kid = wb_key_id(key)
    nonce = os.urandom(12)
    ct, tag = aes_gcm_encrypt(key, nonce, plaintext.encode("utf-8"),
                              wb_aad(kid, 1, "field"))
    env = {"suite": 1, "keyId": kid, "nonce": _b64e(nonce),
           "authTag": _b64e(tag), "ciphertext": _b64e(ct)}
    return {"$wbEncrypted": 1,
            "envelope": _b64e(json.dumps(env, separators=(",", ":")).encode("utf-8"))}


def hot_switch_supported():
    """Inspect the installed client, rather than assuming an old extracted version."""
    try:
        exe = find_app_exe()
        archive = os.path.join(os.path.dirname(exe), "resources", "app.asar")
        with open(archive, "rb") as f:
            _, header_size, _, json_size = struct.unpack("<IIII", f.read(16))
            if json_size > 32 * 1024 * 1024:
                return False
            node = json.loads(f.read(json_size))["files"]["main"]["files"]["file-authentication-storage.js"]
            if node.get("unpacked") or int(node["size"]) > 2 * 1024 * 1024:
                return False
            f.seek(8 + header_size + int(node["offset"]))
            code = f.read(int(node["size"])).decode("utf-8")
        return all(name in code for name in ("initializeWatcher", "handleExternalChange", "reconcileExternalState", "emitSession"))
    except (OSError, ValueError, KeyError, TypeError):
        return False


def atomic_bytes(path, data):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".wbh-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.remove(temp)


def observed_account(uid):
    return (live_account() or {}).get("uid") == uid


@serialized_mutation
def restore_identity_only(uid, timeout=10):
    """Atomically publish auth; a running client must acknowledge its own snapshot."""
    if not uid or not find_entry(uid):
        return {"ok": False, "reason": "未找到已收录的目标账号"}
    running = app_running()
    if running and observed_account(uid):
        return {"ok": True, "uid": uid, "mode": "hot", "verified": True,
                "reason": "WorkBuddy 已经登录该账号，无需重复切换"}
    if running and not hot_switch_supported():
        return {"ok": False, "reason": "当前 WorkBuddy 版本未检测到身份热加载支持；未改动登录文件，请更新客户端或退出后切换"}
    if running:
        try:
            active = [s for s in list_sessions(limit=300)
                      if s.get("live") and s.get("normalized") in INFLIGHT_STATUSES]
        except Exception:
            return {"ok": False, "reason": "暂时无法确认客户端任务状态；未改动认证，请稍后重试"}
        if active:
            return {"ok": False, "busy": True, "reason": "WorkBuddy 仍有任务正在输出，请等任务完成后切换；无需关闭客户端"}
    ent = find_entry(uid) or {}
    names = [n for n in vault_members_matching(uid, AUTH_MEMBER_PREFIX)
             if n == AUTH_MEMBER_PREFIX + AUTH_FILE_NAME]
    auth_bytes = vault_member(uid, names[0]) if names else None
    if not auth_bytes:
        return {"ok": False, "reason": "该账号没有完整认证文件，请重新登录并收录"}
    secret, err = _secret_or_error()
    if err:
        return {"ok": False, "reason": err}
    try:
        info = parse_auth_bytes(auth_bytes, secret)
        if info.get("uid") != uid or not info.get("accessToken"):
            raise ValueError("账号不匹配或访问凭据无法解密")
        access, refresh = _to_ms(info.get("expiresAt")), _to_ms(info.get("refreshExpiresAt"))
        if (refresh and refresh <= now_ms()) or (access and access <= now_ms() and not refresh):
            raise ValueError("登录凭据已过期，请重新登录并收录")
    except Exception as error:
        return {"ok": False, "reason": "目标认证校验失败：%s" % error}
    dst = live_auth_path()
    original = Path(dst).read_bytes() if os.path.isfile(dst) else None
    original_snapshot = Path(SNAPSHOT).read_bytes() if os.path.isfile(SNAPSHOT) else None
    old_uid = (live_account() or {}).get("uid")
    backup_dir = os.path.join(vault_root(), "认证文件备份")
    os.makedirs(backup_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S") + "-%d" % time.time_ns()
    backed = []
    if original is not None:
        backup = os.path.join(backup_dir, stamp + ".info")
        atomic_bytes(backup, original); backed.append(backup)
    if original_snapshot is not None:
        atomic_bytes(os.path.join(backup_dir, stamp + "-account-snapshot.json"), original_snapshot)
    # An active logout is not overridden behind the client's back.
    marker = dst + ".logout"
    if running and os.path.exists(marker):
        return {"ok": False, "reason": "客户端正在退出登录，请完成登录后重试；原认证文件未改动"}
    wrote = False
    try:
        if not running:
            _clear_logout_markers()
        atomic_bytes(dst, auth_bytes)
        wrote = True
        if running:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                # Never write this snapshot ourselves during hot switching: the
                # daemon's own account publication is the acknowledgement.
                if observed_account(uid):
                    live = auth_info_live()
                    if live.get("ok") and live.get("uid") == uid and live.get("accessToken"):
                        _log_session_fix("switch-identity", {"uid": uid, "mode": "hot", "verified": True})
                        return {"ok": True, "uid": uid, "mode": "hot", "verified": True,
                                "backup": backed, "reason": "客户端已确认新账号，WorkBuddy 保持打开；已有对话和项目未改动"}
                time.sleep(0.2)
            raise TimeoutError("客户端未在限定时间内确认新账号")
        data = vault_member(uid, "storage/skeleton/account-snapshot.json")
        if not data or (json.loads(data).get("primary") or {}).get("uid") != uid:
            raise ValueError("目标账号快照缺失或不一致")
        atomic_bytes(SNAPSHOT, data)
        _log_session_fix("switch-identity", {"uid": uid, "mode": "cold", "verified": False})
        return {"ok": True, "uid": uid, "mode": "cold", "verified": False, "backup": backed,
                "snapshot": True, "reason": "目标身份已写入，启动 WorkBuddy 后生效"}
    except Exception as error:
        rollback = False
        if wrote:
            try:
                current = json.loads(Path(dst).read_bytes())
                if (current.get("account") or {}).get("uid") == uid:
                    if original is not None:
                        atomic_bytes(dst, original)
                    else:
                        os.remove(dst)
                    if not running and original_snapshot is not None:
                        atomic_bytes(SNAPSHOT, original_snapshot)
                    rollback = True
            except Exception:
                pass
        return {"ok": False, "uid": uid, "mode": "hot" if running else "cold",
                "rolledBack": rollback, "backup": backed,
                "reason": str(error) + ("；原认证已恢复" if rollback else "；请检查客户端实际账号，原认证备份已保留")}


# --------------------------------------------------------------------------
# 14. 令牌有效期（长期使用的命门）
# --------------------------------------------------------------------------

def _to_ms(v):
    """把接口/文件里的时间统一成毫秒时间戳；认不出来返回 None。"""
    if v is None or v == "":
        return None
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        n = float(v)
        if n > 1e12:          # 毫秒
            return int(n)
        if n > 1e9:           # 秒
            return int(n * 1000)
        return None
    if isinstance(v, str):
        s = v.strip()
        if s.isdigit():
            return _to_ms(int(s))
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%d"):
            try:
                return int(time.mktime(time.strptime(s, fmt)) * 1000)
            except Exception:
                continue
        try:
            return int(datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)
        except Exception:
            return None
    return None


def token_expiry(uid=None):
    """读该账号令牌的有效期，给出剩余天数与预警等级。"""
    uid = uid or (live_account() or {}).get("uid")
    info = auth_info_for(uid) if uid else auth_info_live()
    if not info.get("ok"):
        return {"ok": False, "reason": info.get("reason") or "取不到该账号的会话"}
    acc = _to_ms(info.get("expiresAt"))
    ref = _to_ms(info.get("refreshExpiresAt"))
    now = now_ms()

    def days(ms):
        return None if ms is None else round((ms - now) / 86400000.0, 1)

    acc_d, ref_d = days(acc), days(ref)
    level = "ok"
    hint = ""
    if ref_d is not None:
        if ref_d <= 0:
            level, hint = "dead", "续期凭证已过期，必须在该账号登录状态下重新收录一次"
        elif ref_d <= 3:
            level, hint = "danger", "续期凭证 %.1f 天后过期，建议尽快在客户端打开一次该账号" % ref_d
        elif ref_d <= 10:
            level, hint = "warn", "续期凭证 %.1f 天后过期，记得定期在客户端用它一下" % ref_d
    if level == "ok" and acc_d is not None and acc_d <= 0:
        level = "stale"
        hint = "当前令牌已过期（续期凭证还有 %.1f 天）；在客户端打开一次该账号即可自动续上" % (ref_d or 0)
    return {
        "ok": True, "uid": uid, "source": info.get("source"),
        "accessExpiresAt": acc, "accessRemainDays": acc_d,
        "refreshExpiresAt": ref, "refreshRemainDays": ref_d,
        "lastRefreshTime": _to_ms(info.get("lastRefreshTime")),
        "level": level, "hint": hint,
        "deadline": ref if ref else acc,
    }


# --------------------------------------------------------------------------
# 15. 积分资源与到期时间（真实接口 /v2/billing/meter/get-user-resource）
# --------------------------------------------------------------------------

CREDIT_PATH = "/v2/billing/meter/get-user-resource"
CREDIT_SUMMARY_PATH = "/billing/meter/get-user-resource-summary"


def credit_for(uid, force=False):
    """查某账号的积分资源：剩余量、总量、到期时间、套餐名。"""
    sess = session_for(uid, force=force)
    if not sess.get("ok"):
        return {"ok": False, "reason": sess.get("reason"), "tried": sess.get("tried")}
    if sess.get("cand", {}).get("user_id") != uid:
        return {"ok": False, "reason": "积分查询身份不匹配，已拒绝显示"}
    # Match the desktop client's current-cycle balance, not historical capacity.
    summary_response = http_json(sess["base"], CREDIT_SUMMARY_PATH, "POST",
                  token=sess["cand"]["bearer"], uid=uid, body={}, timeout=8)
    summary = _json_or_text(summary_response["text"])
    if (summary_response["status"] != 200 or not isinstance(summary, dict)
            or summary.get("code") != 0 or not isinstance(summary.get("data"), dict)
            or not isinstance(summary["data"].get("Packages"), list)):
        return {"ok": False, "reason": "官方当前积分查询失败（HTTP %s），未显示旧余额" % summary_response["status"]}
    from decimal import Decimal, InvalidOperation
    try:
        summary_packages = summary["data"]["Packages"]
        remain_total = sum((Decimal(p["CycleRemainCapacity"]) for p in summary_packages), Decimal(0))
        size_total = sum((Decimal(p["CycleTotalCapacity"]) for p in summary_packages), Decimal(0))
        if not remain_total.is_finite() or not size_total.is_finite():
            raise ValueError("non-finite credits")
    except (KeyError, TypeError, InvalidOperation, ValueError):
        return {"ok": False, "reason": "官方积分响应格式异常，未显示估算余额"}
    r = http_json(sess["base"], CREDIT_PATH, "POST",
                  token=sess["cand"]["bearer"], uid=sess["cand"]["user_id"],
                  body={}, timeout=4)
    j = _json_or_text(r["text"])
    if r["status"] != 200 or not isinstance(j, dict) or j.get("code") not in (0, None):
        j = {}
    data = (((j.get("data") or {}).get("Response") or {}).get("Data")) or {}
    accts = data.get("Accounts") or []
    now = now_ms()
    packs = []
    for a in accts:
        if a.get("CapacityType") == 4:
            continue
        remain = a.get("CapacityRemainPrecise", a.get("CapacityRemain")) or 0
        size = a.get("CapacitySizePrecise", a.get("CapacitySize")) or 0
        try:
            remain = float(remain)
        except Exception:
            remain = 0.0
        try:
            size = float(size)
        except Exception:
            size = 0.0
        end = _to_ms(a.get("DeductionEndTime")) or _to_ms(a.get("ExpiredTime")) \
            or _to_ms(a.get("CycleEndTime"))
        left = None if end is None else round((end - now) / 86400000.0, 1)
        if (left is not None and left <= 0) or a.get("Status") == 2:
            continue
        packs.append({
            "name": a.get("PackageName") or a.get("ProductName") or "-",
            "product": a.get("ProductName") or "",
            "remain": remain, "size": size,
            "cycleStart": a.get("CycleStartTime") or "",
            "cycleEnd": a.get("CycleEndTime") or "",
            "endAt": end, "daysLeft": left,
            "urgent": (left is not None and left <= 7 and remain > 0),
            "expired": (left is not None and left <= 0),
            "status": a.get("Status"),
        })
    packs.sort(key=lambda p: (p["endAt"] is None, p["endAt"] or 0))
    usable = [p for p in packs if p["remain"] > 0 and not p["expired"]]
    nearest = usable[0] if usable else None
    return {
        "ok": True, "uid": uid, "verifiedUid": sess["cand"]["user_id"], "queriedAt": now,
        "phone": sess.get("phone"),
        "totalRemain": float(remain_total), "totalSize": float(size_total),
        "balanceSource": CREDIT_SUMMARY_PATH,
        "packageCount": len(packs), "packages": packs,
        "nearestEndAt": nearest["endAt"] if nearest else None,
        "nearestDaysLeft": nearest["daysLeft"] if nearest else None,
        "nearestName": nearest["name"] if nearest else None,
        "urgent": bool(nearest and nearest["urgent"]),
        "raw": summary,
    }


# --------------------------------------------------------------------------
# 16. 会话状态（修复「对话结束后界面一直显示正在运行」）
# --------------------------------------------------------------------------
#
# 客户端里真正决定这个显示的是 workbuddy.db 的 sessions.status，取值：
#   planning / working → 界面归类为「运行中」
#   pending            → 界面同样归类为「运行中」（客户端 turnSeq=0 时派生出来的值）
#   completed / failed / error / terminated / archived → 已结束
#
# 客户端把一次对话的状态写在 main/server.js 的 SessionManager 里，
# 正常结束时落回 completed；但只要有一条结束路径没落回（例如它把「完成」延后
# 等一个永远不来的信号），DB 里就一直是 working，界面便一直显示「正在运行」。
# 客户端自己唯一的自愈是「重启后超过 30 分钟才降级」，因此我们补一个矫正器。

WB_DB = os.path.join(WB, "workbuddy.db")
PROJECTS_DIR = os.path.join(WB, "projects")

RUNNING_STATUSES = ("planning", "working", "pending")
INFLIGHT_STATUSES = ("planning", "working")

# 判定「这一轮还活着」的空闲阈值：客户端每写一句话就会刷新会话正文文件，
# 所以正文文件长时间没动，就说明这一轮早已不在跑。
LIVE_IDLE_SECONDS = 180


def _session_fix_log_path():
    return os.path.join(vault_root(), "session_fixes.json")


def _log_session_fix(kind, detail):
    try:
        p = _session_fix_log_path()
        try:
            with open(p, "r", encoding="utf-8") as f:
                arr = json.load(f)
            if not isinstance(arr, list):
                arr = []
        except Exception:
            arr = []
        arr.append({"ts": now_ms(), "kind": kind, "detail": detail})
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(arr[-300:], f, ensure_ascii=False, indent=2)
        os.replace(tmp, p)
    except Exception:
        pass


def session_fix_log():
    try:
        with open(_session_fix_log_path(), "r", encoding="utf-8") as f:
            arr = json.load(f)
        return arr if isinstance(arr, list) else []
    except Exception:
        return []


def session_body_path(sid):
    hits = glob.glob(os.path.join(PROJECTS_DIR, "*", sid + ".jsonl"))
    if not hits:
        return None
    hits.sort(key=lambda p: -os.path.getmtime(p))
    return hits[0]


def list_sessions(limit=60):
    """
    读会话表并给出「界面会怎么归类」。
    返回 [{id,title,status,normalized,display,updatedAt,lastActivityAt,
           bodyMtime,idleSeconds,live,stuck,isBackgroundAutomation,cwd}]
    """
    if not os.path.isfile(WB_DB):
        return []
    con = sqlite3.connect(WB_DB, timeout=8)
    try:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "select id, cwd, title, custom_title, status, created_at, updated_at, "
            "last_activity_at, deleted_at, is_background_automation "
            "from sessions where deleted_at is null "
            "order by coalesce(last_activity_at, updated_at, created_at) desc limit ?",
            (int(limit),)).fetchall()
    finally:
        con.close()

    out = []
    now = time.time() * 1000
    for r in rows:
        st = (r["status"] or "").strip()
        low = st.lower()
        bm = None
        p = session_body_path(r["id"])
        if p:
            try:
                bm = int(os.path.getmtime(p) * 1000)
            except Exception:
                bm = None
        idle = None if bm is None else round((now - bm) / 1000.0, 1)
        live = bool(idle is not None and idle < LIVE_IDLE_SECONDS)
        if low == "pending":
            display = "运行中"
        elif low in ("planning", "working"):
            display = "运行中"
        elif low == "archived":
            display = "已归档"
        elif low == "completed":
            display = "已完成"
        elif low in ("failed", "error"):
            display = "出错"
        elif low == "terminated":
            display = "已中断"
        else:
            display = st or "未知"
        stuck = (low in INFLIGHT_STATUSES) and (not live)
        out.append({
            "id": r["id"], "title": r["title"] or r["custom_title"] or "(无标题)",
            "status": st, "normalized": low, "display": display,
            "cwd": r["cwd"],
            "createdAt": r["created_at"], "updatedAt": r["updated_at"],
            "lastActivityAt": r["last_activity_at"],
            "bodyMtime": bm, "idleSeconds": idle, "live": live,
            "stuck": stuck,
            "isBackgroundAutomation": bool(r["is_background_automation"]),
        })
    return out


def stuck_sessions(limit=200, max_idle=None):
    """挑出「还在显示运行中、但其实早就结束」的会话。"""
    th = LIVE_IDLE_SECONDS if max_idle is None else max_idle
    out = []
    for s in list_sessions(limit=limit):
        if s["isBackgroundAutomation"]:
            continue
        if s["normalized"] not in INFLIGHT_STATUSES:
            continue
        idle = s["idleSeconds"]
        if idle is None:
            # 找不到正文文件：退回用 DB 的更新时间判断
            base = s["lastActivityAt"] or s["updatedAt"] or s["createdAt"]
            idle = round((time.time() * 1000 - base) / 1000.0, 1) if base else None
        if idle is None or idle >= th:
            s = dict(s, idleUsed=idle)
            out.append(s)
    return out


def _backup_db(keep=5):
    """在改库之前做一次一致性备份（SQLite 官方 backup API，避开 WAL 未落盘的问题）。"""
    d = os.path.join(vault_root(), "数据备份")
    os.makedirs(d, exist_ok=True)
    dst = os.path.join(d, "workbuddy-%s.db" % time.strftime("%Y%m%d-%H%M%S"))
    src = sqlite3.connect(WB_DB, timeout=10)
    try:
        out = sqlite3.connect(dst)
        try:
            src.backup(out)
        finally:
            out.close()
    finally:
        src.close()
    files = sorted(glob.glob(os.path.join(d, "workbuddy-*.db")))
    for old in files[:-keep]:
        try:
            os.remove(old)
        except Exception:
            pass
    return dst


def reconcile_stuck_sessions(max_idle=None, dry_run=True, limit=200):
    """
    把「卡在运行中」的会话矫正为已完成，界面就不会再显示正在运行。
    - 只动 planning / working（pending 表示在等你输入，不动）
    - 只有在正文文件长时间没更新（默认 3 分钟）时才动
    - 改库前先备份；只改状态仍是 planning/working 的行（防止把刚重启的轮次误改）
    """
    targets = [s for s in stuck_sessions(limit=limit, max_idle=max_idle)
               if s["normalized"] in INFLIGHT_STATUSES]
    preview = [{"id": s["id"], "title": s["title"], "status": s["status"],
                "display": s["display"], "idleSeconds": s.get("idleUsed", s["idleSeconds"]),
                "cwd": s["cwd"]} for s in targets]
    if dry_run:
        return {"ok": True, "dryRun": True, "count": len(targets), "targets": preview}

    if not targets:
        return {"ok": True, "dryRun": False, "count": 0, "targets": [], "reason": "没有需要矫正的会话"}

    backup = _backup_db()
    now = now_ms()
    fixed, skipped = [], []
    con = sqlite3.connect(WB_DB, timeout=10)
    try:
        cur = con.cursor()
        for s in targets:
            cur.execute(
                "update sessions set status='completed', updated_at=? "
                "where id=? and lower(status) in ('planning','working')",
                (now, s["id"]))
            if cur.rowcount == 1:
                fixed.append({"id": s["id"], "title": s["title"], "from": s["status"]})
            else:
                skipped.append({"id": s["id"], "title": s["title"],
                                "reason": "状态已变化（可能重新跑起来了）"})
        con.commit()
    finally:
        con.close()

    _log_session_fix("reconcile", {"fixed": fixed, "skipped": skipped, "backup": backup})
    return {"ok": True, "dryRun": False, "count": len(fixed), "fixed": fixed,
            "skipped": skipped, "backup": backup,
            "reason": "已矫正 %d 个会话的状态%s" % (
                len(fixed), "；%d 个因状态已变化而跳过" % len(skipped) if skipped else "")}


# --------------------------------------------------------------------------
# 14. 跨账号对话共享（让"积分不够了换个账号接着跑同一个任务"成为现实）
# --------------------------------------------------------------------------
# 客户端「列出会话」的 SQL 逐字是（app.asar!/main/handlers.js → LocalConversationsImpl）：
#
#     SELECT ... FROM sessions
#     WHERE transport = 'local'
#       AND deleted_at IS NULL
#       AND (user_id = ? OR user_id = '')          -- ? = 当前登录账号
#       AND (status IS NULL OR status != 'archived')
#
# 关键在那句 `OR user_id = ''` —— 这是客户端自己预留的「公共会话」通道：
# user_id 为空字符串的会话，对**每一个**账号都可见、可读、可写
# （列表 / 详情 / 改未读 / 改状态 / 软删除，七处用的都是同一条条件）。
#
# 所以：把 user_id 置空 = 这条对话变成公共的 = 换任何账号登录都能看到并接着往下做。
# 而且只改「归属」，**不动 cwd**，所以对话依然留在它原来的工作区文件夹下。
#
# 两条安全垫（已实测）：
#   · sessions 的云端同步 upsert 带 `WHERE transport = 'cloud'` 守卫，更新字段清单里
#     不含 user_id ⇒ 手工改过的 local 行不会被云同步覆盖。
#   · 数据库是 WAL 模式 ⇒ WorkBuddy 开着也能安全地做短事务写入。

PUBLIC_UID = ""


def _share_log_path():
    return os.path.join(vault_root(), "session_share.json")


def _log_share(action, payload):
    try:
        p = _share_log_path()
        try:
            with open(p, "r", encoding="utf-8") as f:
                arr = json.load(f)
            if not isinstance(arr, list):
                arr = []
        except Exception:
            arr = []
        rec = {"ts": now_ms(), "action": action}
        rec.update(payload)
        arr.append(rec)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(arr[-200:], f, ensure_ascii=False, indent=2)
        os.replace(tmp, p)
    except Exception:
        pass


def share_log(limit=20):
    try:
        with open(_share_log_path(), "r", encoding="utf-8") as f:
            arr = json.load(f)
        return arr[-limit:] if isinstance(arr, list) else []
    except Exception:
        return []


def _norm_ws(cwd):
    """把两种写法的 cwd 归一到同一个工作区键（Windows 路径大小写不敏感）。"""
    if not cwd:
        return "(无工作区)"
    return str(cwd).replace("\\", "/").rstrip("/").lower()


def ws_label(cwd):
    """给界面看的工作区名字，如 Desktop\\Vibe oding → Vibe oding。"""
    if not cwd:
        return "(无工作区)"
    s = str(cwd).replace("\\", "/").rstrip("/")
    parts = [p for p in s.split("/") if p]
    if not parts:
        return s
    last = parts[-1]
    # 只有「时间戳文件夹」这种没信息量的名字才带上上一层
    if re.match(r"^\d{4}-\d{2}-\d{2}", last) and len(parts) >= 2:
        return "/".join(parts[-2:])
    return last


def list_all_sessions(limit=1000):
    """
    列出**所有账号**的会话（含归属），用于「对话共享」管理。
    返回 [{id,title,uid,cwd,workspace,wsKey,status,transport,shared,sharable,lastActivityAt}]
    """
    if not os.path.isfile(WB_DB):
        return []
    con = sqlite3.connect(WB_DB, timeout=8)
    try:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "select id, cwd, title, custom_title, user_id, status, transport, "
            "created_at, updated_at, last_activity_at "
            "from sessions where deleted_at is null "
            "order by coalesce(last_activity_at, updated_at, created_at) desc limit ?",
            (int(limit),)).fetchall()
    finally:
        con.close()

    out = []
    for r in rows:
        cwd = r["cwd"]
        uid = r["user_id"] or ""
        is_local = (r["transport"] == "local")
        out.append({
            "id": r["id"],
            "title": r["title"] or r["custom_title"] or "(无标题)",
            "uid": uid,
            "cwd": cwd or "",
            "workspace": ws_label(cwd),
            "wsKey": _norm_ws(cwd),
            "status": (r["status"] or ""),
            "transport": r["transport"],
            # 只有 local 行有「公共」通道；cloud 行的查询里没有 OR user_id = ''
            "sharable": is_local,
            "shared": is_local and uid == "",
            "lastActivityAt": r["last_activity_at"] or r["updated_at"] or r["created_at"],
        })
    return out


def share_summary():
    """轻量概览（给 /api/state 用）。"""
    rows = list_all_sessions(limit=1000)
    local = [r for r in rows if r["sharable"]]
    shared = [r for r in local if r["shared"]]
    groups = {}
    for r in local:
        g = groups.setdefault(r["wsKey"], {"label": r["workspace"], "total": 0, "shared": 0})
        g["total"] += 1
        if r["shared"]:
            g["shared"] += 1
    glist = sorted(groups.values(), key=lambda x: (-x["total"], x["label"]))
    return {
        "total": len(local),
        "shared": len(shared),
        "private": len(local) - len(shared),
        "unsharable": len(rows) - len(local),
        "groups": glist[:40],
    }


def share_overview(limit=1000):
    """完整概览（给对话共享面板用）。"""
    s = share_summary()
    s["sessions"] = list_all_sessions(limit=limit)
    s["log"] = share_log(8)
    return s


def _clear_sidebar_snapshots():
    """
    侧边栏有一份**按账号**存的列表缓存 ~/.workbuddy/<uid>/sidebar-list-snapshot.json。
    改完归属后让它失效，列表才会按新归属重建（重建时读的是数据库）。
    安全做法：改名归档（.stale），不删除，随时可还原。
    """
    out = []
    for p in glob.glob(os.path.join(WB, "*", "sidebar-list-snapshot.json")):
        try:
            dst = p + ".stale"
            if os.path.exists(dst):
                os.remove(dst)
            os.replace(p, dst)
            out.append(os.path.relpath(p, WB))
        except Exception:
            pass
    return out


def share_sessions(mode="public", ids=None, workspace=None, target_uid=None,
                   dry_run=True, limit=1000):
    """
    跨账号对话共享。只改 sessions.user_id —— 不动 cwd，不动正文文件。

      mode='public'    user_id 置空  → 所有账号都能看到这条对话（推荐）
      mode='handover'  user_id 改成 target_uid → 移交给某个账号（原账号不再可见）
      mode='restore'   按最近一次共享记录把归属还原回去
    """
    mode = (mode or "public").lower()

    if mode == "restore":
        return _restore_share(dry_run=dry_run)

    rows = list_all_sessions(limit=limit)
    local = [r for r in rows if r["sharable"]]

    if workspace:
        want = _norm_ws(workspace)
        local = [r for r in local if r["wsKey"] == want]

    if mode == "public":
        targets = [r for r in local if not r["shared"]]
    elif mode == "handover":
        if not target_uid:
            return {"ok": False, "reason": "移交模式缺少目标账号 uid"}
        targets = [r for r in local if r["uid"] != target_uid]
    else:
        return {"ok": False, "reason": "未知模式：%s" % mode}

    if ids:
        want = set(ids)
        targets = [r for r in targets if r["id"] in want]

    preview = [{"id": r["id"], "title": r["title"], "uid": r["uid"],
                "workspace": r["workspace"], "cwd": r["cwd"]} for r in targets]

    if dry_run:
        return {"ok": True, "dryRun": True, "mode": mode, "count": len(targets),
                "targets": preview[:80],
                "reason": "将处理 %d 条对话" % len(targets)}

    if not targets:
        return {"ok": True, "dryRun": False, "mode": mode, "count": 0,
                "done": [], "failed": [], "backup": None,
                "reason": "没有需要处理的对话（可能已经全部共享）"}

    backup = _backup_db()
    new_uid = PUBLIC_UID if mode == "public" else target_uid
    before, done, failed = {}, [], []
    con = sqlite3.connect(WB_DB, timeout=15)
    try:
        con.execute("PRAGMA busy_timeout=15000")
        cur = con.cursor()
        for r in targets:
            # 带上「当前归属还必须是我读到的那个」这个前置条件，
            # 万一期间客户端自己改了归属，就跳过而不是覆盖。
            cur.execute(
                "update sessions set user_id = ? "
                "where id = ? and transport = 'local' and deleted_at is null "
                "and coalesce(user_id, '') = ?",
                (new_uid, r["id"], r["uid"]))
            if cur.rowcount == 1:
                before[r["id"]] = r["uid"]
                done.append({"id": r["id"], "title": r["title"], "workspace": r["workspace"]})
            else:
                failed.append({"id": r["id"], "reason": "归属已被改动，跳过"})
        con.commit()
    finally:
        con.close()

    _log_share(mode, {"count": len(done), "before": before, "backup": backup,
                      "targetUid": target_uid})
    touched = _clear_sidebar_snapshots()

    if mode == "public":
        reason = "已共享 %d 条对话 —— 所有账号都能看到并接着做" % len(done)
    else:
        reason = "已移交 %d 条对话" % len(done)
    if failed:
        reason += "；%d 条跳过" % len(failed)
    return {"ok": True, "dryRun": False, "mode": mode, "count": len(done),
            "done": done[:80], "failed": failed, "backup": backup,
            "snapshotsCleared": touched, "reason": reason}


def _restore_share(dry_run=True):
    """按最近一次「设为公共」的记录，把归属还原回原账号。"""
    rec = None
    for r in reversed(share_log(50)):
        if r.get("action") == "public" and r.get("before"):
            rec = r
            break
    if not rec:
        return {"ok": False, "reason": "没有找到可撤销的共享记录"}

    before = rec.get("before") or {}
    targets = [{"id": k, "uid": v} for k, v in before.items()]
    if dry_run:
        return {"ok": True, "dryRun": True, "mode": "restore", "count": len(targets),
                "targets": targets[:80],
                "reason": "将还原 %d 条对话的归属" % len(targets)}

    backup = _backup_db()
    done = []
    con = sqlite3.connect(WB_DB, timeout=15)
    try:
        con.execute("PRAGMA busy_timeout=15000")
        cur = con.cursor()
        for t in targets:
            # 只还原「现在仍然是公共」的那些，避免把后来的改动覆盖掉
            cur.execute(
                "update sessions set user_id = ? "
                "where id = ? and transport = 'local' and deleted_at is null "
                "and coalesce(user_id, '') = ''",
                (t["uid"], t["id"]))
            if cur.rowcount == 1:
                done.append(t["id"])
        con.commit()
    finally:
        con.close()

    _log_share("restore", {"count": len(done), "backup": backup})
    _clear_sidebar_snapshots()
    return {"ok": True, "dryRun": False, "mode": "restore", "count": len(done),
            "backup": backup, "reason": "已还原 %d 条对话的归属" % len(done)}


def auto_share_new(limit=1000):
    """
    后台用：把还没共享的本地会话自动设为公共。
    「把所有登录过的账号拼接起来」这件事，靠它保持长期有效 ——
    否则每新开一个对话都要手动点一次。
    """
    return share_sessions(mode="public", dry_run=False, limit=limit)
