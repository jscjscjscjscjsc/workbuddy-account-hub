# -*- coding: utf-8 -*-
"""
WorkBuddy 账号管理台 · 本地服务（纯标准库）

设计原则：**不做手工粘贴凭据**。本机登录过的账号由服务端自动识别、自动收录。

端点
----
  GET  /                  界面
  GET  /api/state         总状态：账号列表 + 本机状态 + 运行日志
  GET  /api/diagnose      环境体检（目录、进程、锁、历史 uid、文件清单）
  GET  /api/log           最近事件
  GET  /api/conversations 本机会话列表（按文件扫）
  GET  /api/sessions      会话状态列表（界面为什么显示"正在运行"）
  GET  /api/shared        跨账号对话共享概览（含每条对话的归属与工作区）
  GET  /api/credits       各账号积分剩余与到期时间（按紧迫度排序）
  POST /api/collect       收录（把当前登录态整套快照进保险库）
  POST /api/switch        完整切换到某账号（整套登录态，要求 App 已退出）
  POST /api/switch-lite   轻量切换（只换登录身份，共享同一份对话/项目数据）
  POST /api/share-sessions 跨账号对话共享：public（设为公共）/ handover / restore
  POST /api/status        查询某账号加油站签到状态
  POST /api/checkin       某账号签到
  POST /api/checkin-all   全部账号签到
  POST /api/token         查询某账号令牌有效期（access / refresh 剩余天数）
  POST /api/fix-sessions  矫正"卡在运行中"的会话（默认 dryRun 预览）
  POST /api/probe         强制重新探测某账号的会话凭据
  POST /api/settings      开关自动签到 / 自动收录 / 自动矫正会话 / 自动共享对话
  DEL  /api/account       从保险库移除某账号
"""

import os
import sys
import json
import time
import socket
import shutil
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.join(os.path.dirname(sys.executable), "server") if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE) if os.path.basename(HERE) == "server" else HERE
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import vault  # noqa: E402
import lifecycle
import phone_login

PORT = int(os.environ.get("WBH_PORT") or 8770)
LOG_MAX = 400


def now_ms():
    return int(time.time() * 1000)

STATE = {
    "log": [],
    "settings": {"autoCheckin": False, "autoCollect": True, "autoFixSessions": False,
                 "autoShare": False, "lastAutoCheckin": "", "lastAutoFix": ""},
    "startedAt": int(time.time() * 1000),
}
STATE_LOCK = threading.Lock()


def _settings_path():
    return os.path.join(vault.vault_root(), "settings.json")


def load_settings():
    """把界面上的开关持久化到 保险库/settings.json，重启服务后依然生效。"""
    defaults = {"autoCheckin": False, "autoCollect": True, "autoFixSessions": False,
                "autoShare": False, "lastAutoCheckin": "", "lastAutoFix": ""}
    try:
        with open(_settings_path(), "r", encoding="utf-8") as f:
            disk = json.load(f)
        if isinstance(disk, dict):
            for k in defaults:
                if k in disk:
                    defaults[k] = disk[k]
    except Exception:
        pass
    return defaults


def save_settings():
    try:
        tmp = _settings_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(STATE["settings"], f, ensure_ascii=False, indent=2)
        os.replace(tmp, _settings_path())
    except Exception:
        pass


# --------------------------------------------------------------------------
# 日志
# --------------------------------------------------------------------------

def push_log(kind, detail):
    with STATE_LOCK:
        STATE["log"].append({"ts": int(time.time() * 1000), "kind": kind, "detail": detail})
        if len(STATE["log"]) > LOG_MAX:
            del STATE["log"][: len(STATE["log"]) - LOG_MAX]


# --------------------------------------------------------------------------
# 账号列表
# --------------------------------------------------------------------------

# 令牌有效期缓存（纯本地解密，很便宜，但仍做个短缓存避免每次轮询都解一遍）
TOKEN_CACHE = {}
TOKEN_TTL = 30 * 1000


def token_all(force=False):
    """给每个账号附上令牌有效期（access / refresh 还剩几天）。"""
    out = {}
    for a in build_accounts():
        uid = a["uid"]
        if not a.get("canCheckin"):
            out[uid] = {"ok": False, "reason": "该账号还没收录登录态"}
            continue
        c = TOKEN_CACHE.get(uid)
        if not force and c and now_ms() - c.get("_at", 0) < TOKEN_TTL:
            out[uid] = c
            continue
        try:
            r = vault.token_expiry(uid)
        except Exception as e:
            r = {"ok": False, "reason": "读取令牌有效期失败：%s" % e}
        r = dict(r)
        r["_at"] = now_ms()
        TOKEN_CACHE[uid] = r
        out[uid] = r
    return out


def _caps(e):
    """
    能力标记：
      签到     —— 看加密会话（hasSession）
      切换     —— 轻量切换只换登录身份，看 hasSession；完整切换要回写整套登录态，看 hasCookies
    """
    has_ck = bool(e.get("hasCookies"))
    has_ss = bool(e.get("hasSession"))
    return {
        "hasCookies": has_ck,
        "hasSession": has_ss,
        "canCheckin": has_ss or has_ck,
        "canSwitchLite": has_ss,
        "canSwitchFull": has_ck,
        "canSwitch": has_ss or has_ck,
        "needsRecollect": not (has_ck and has_ss),
    }


# --------------------------------------------------------------------------
# 积分资源缓存（每个账号查询要走网络，做一个短缓存）
# --------------------------------------------------------------------------

CREDIT_CACHE = {}
CREDIT_TTL = 60 * 1000

# 会话状态自动矫正：多久检查一次、判定"卡住"的静默阈值（秒）
FIX_INTERVAL_SEC = 300
AUTO_FIX_IDLE_SEC = 600

# 自动共享对话：多久扫一次有没有还没共享的新对话
SHARE_INTERVAL_SEC = 60


def credit_all(force=False):
    """查一遍所有账号的积分剩余与到期时间，按紧迫度排序。"""
    def query(a):
        uid = a["uid"]
        if not a.get("canCheckin"):
            r = {"ok": False, "reason": "没有可用令牌，请先收录该账号"}
        else:
            c = CREDIT_CACHE.get(uid)
            if not force and c and now_ms() - c.get("_at", 0) < CREDIT_TTL:
                r = dict(c)
            else:
                try:
                    r = dict(vault.credit_for(uid, force=force))
                except Exception:
                    r = {"ok": False, "reason": "官方积分查询未完成，请刷新重试"}
                r["_at"] = now_ms()
                CREDIT_CACHE[uid] = r
        return {**r, "uid": uid, "nickname": a["nickname"], "isCurrent": a.get("isCurrent")}

    with ThreadPoolExecutor(max_workers=4) as pool:
        out = list(pool.map(query, build_accounts()))

    def key(x):
        # 取到积分的排前面（0），按"最先到期"升序；取不到的排最后（1）
        d = x.get("nearestDaysLeft")
        return (0 if x.get("ok") else 1, d if d is not None else 9999)

    out.sort(key=key)
    return out


def build_accounts():
    """把『本机当前登录账号』与『保险库里已收录的账号』合并成一份列表。"""
    live = vault.live_account() or {}
    entries = {e.get("uid"): e for e in vault.list_entries()}
    legacy = vault.legacy_owner_uid()

    out = []
    # 1) 本机当前登录账号（永远排第一）
    if live.get("uid"):
        e = entries.get(live["uid"], {})
        out.append({
            "uid": live["uid"],
            "nickname": live.get("nickname") or e.get("nickname") or live["uid"][:8],
            "editionType": live.get("editionType") or e.get("editionType", ""),
            "isPro": live.get("isPro"),
            "isCurrent": True,
            "collected": bool(e.get("collectedAt")),
            "collectedAt": e.get("collectedAt", 0),
            "source": e.get("source", "本机当前登录"),
            **_caps(e),
        })

    # 2) 保险库里其它账号
    for uid, e in sorted(entries.items(), key=lambda kv: -(kv[1].get("collectedAt") or 0)):
        if uid == live.get("uid"):
            continue
        out.append({
            "uid": uid,
            "nickname": e.get("nickname") or uid[:8],
            "editionType": e.get("editionType", ""),
            "isPro": e.get("isPro", False),
            "isCurrent": False,
            "collected": bool(e.get("collectedAt")),
            "collectedAt": e.get("collectedAt", 0),
            "source": e.get("source", ""),
            **_caps(e),
        })

    # 3) 只在磁盘留痕、既没登录也没收录的历史身份
    known = {a["uid"] for a in out}
    for uid in sorted(vault.historical_uids()):
        if uid in known:
            continue
        out.append({
            "uid": uid,
            "nickname": uid[:8],
            "editionType": "",
            "isPro": False,
            "isCurrent": False,
            "collected": False,
            "hasCookies": False,
            "collectedAt": 0,
            "needsRecollect": True,
            "isLegacy": uid == legacy,
            "source": "本机历史痕迹（未收录登录态）",
        })
    return out


TOKEN_REFRESH_LOCK = threading.Lock()

def refresh_tokens_async():
    if not TOKEN_REFRESH_LOCK.acquire(blocking=False):
        return
    def worker():
        try:
            token_all()
        except Exception:
            push_log("error", "令牌状态刷新失败，稍后重试")
        finally:
            TOKEN_REFRESH_LOCK.release()
    threading.Thread(target=worker, daemon=True).start()

def do_state():
    refresh_tokens_async()
    acct = vault.live_account()
    try:
        share = vault.share_summary()
    except Exception:
        share = {"total": 0, "shared": 0, "private": 0, "unsharable": 0, "groups": []}
    return {
        "accounts": build_accounts(),
        "tokens": dict(TOKEN_CACHE),
        "liveAccount": acct,
        "appRunning": vault.app_running(),
        "cookiesReadable": vault.cookies_readable(),
        "vaultDir": vault.VAULT_DIR,
        "wbDir": vault.WB,
        "share": share,
        "settings": STATE["settings"],
        "startedAt": STATE["startedAt"],
        "log": STATE["log"][-120:],
    }


# --------------------------------------------------------------------------
# 后台：自动收录 + 自动签到
# --------------------------------------------------------------------------

def auto_loop():
    last_try = None      # (uid, mode)；mode="partial" 运行中收录 / "full" 退出后完整收录
    _last_fix_try = [0.0]
    _last_share_try = [0.0]
    while True:
        try:
            time.sleep(15)
            acct = vault.live_account()
            running = vault.app_running()

            # ---- 自动收录 ----
            # 加密会话文件（令牌来源）无锁 ⇒ App 运行中也能收录；Cookies 只在退出后可读。
            # 所以采用两段式：运行中先收一份（签到立刻可用），退出后再补一份完整的（切换可用）。
            if STATE["settings"].get("autoCollect", True) and acct:
                uid = acct.get("uid")
                mode = "partial" if running else "full"
                saved_at = acct.get("savedAt") or 0
                e = vault.find_entry(uid) or {}
                stale = (not e.get("collectedAt")) or (e.get("accountSavedAt", 0) < saved_at)
                weak = (not e.get("hasSession")) or (mode == "full" and not e.get("hasCookies"))
                if (stale or weak) and last_try != (uid, mode):
                    r = vault.collect(uid, acct.get("nickname"))
                    if r.get("ok"):
                        last_try = (uid, mode)
                        bits = []
                        if r.get("hasSession"):
                            bits.append("含加密会话，签到可用")
                        else:
                            bits.append("缺加密会话")
                        bits.append("含 Cookies 副本" if r.get("hasCookies")
                                    else "缺 Cookies 副本（免验证码切换需退出后收录）")
                        push_log("collect", "自动收录 %s（%s）：%d 个文件，%s" % (
                            acct.get("nickname") or uid[:8], mode, r.get("files", 0), "；".join(bits)))

            # ---- 自动矫正「卡在运行中」的会话 ----
            # 根因：客户端的轮次收尾被延后去等一个永远不会再来的团队空闲信号，
            # 于是数据库里的状态一直是 working，界面就永远显示"正在运行"。
            # 客户端自己的自愈要等重启后 30 分钟，这里我们用"正文文件多久没动"
            # 这个更可靠的判据，把长时间没动静、状态却还是运行中的会话矫正掉。
            # 阈值取保守的 10 分钟：真正在跑的轮次会不断刷新正文文件，不会被误伤；
            # 万一是误判，客户端随后发来的状态信号也会把它改回去。
            if STATE["settings"].get("autoFixSessions", False):
                now_ts = time.time()
                if now_ts - _last_fix_try[0] > FIX_INTERVAL_SEC:
                    _last_fix_try[0] = now_ts
                    try:
                        stuck = vault.stuck_sessions(max_idle=AUTO_FIX_IDLE_SEC)
                        if stuck:
                            r = vault.reconcile_stuck_sessions(max_idle=AUTO_FIX_IDLE_SEC)
                            if r.get("count"):
                                names = "、".join((s.get("title") or s["id"][:8])[:14] for s in stuck[:3])
                                push_log("fix-sessions", "自动矫正 %d 个卡住的会话：%s"
                                         % (r["count"], names))
                                STATE["settings"]["lastAutoFix"] = time.strftime("%Y-%m-%d %H:%M:%S")
                                save_settings()
                    except Exception:
                        push_log("error", "自动矫正会话异常：" + traceback.format_exc(limit=2))

            # ---- 自动共享对话 ----
            # 「把本机所有登录过的账号拼成一台机器」这件事必须长期有效：
            # 每新开一个对话，它的归属都写着当前账号；不自动置空的话，
            # 换个账号就又看不到了。所以这里定期把还没共享的本地会话设为公共。
            # 实测：数据库是 WAL 模式，WorkBuddy 开着也能安全做短事务写入。
            if STATE["settings"].get("autoShare", False):
                now_ts = time.time()
                if now_ts - _last_share_try[0] > SHARE_INTERVAL_SEC:
                    _last_share_try[0] = now_ts
                    try:
                        if vault.share_summary().get("private"):
                            r = vault.share_sessions(mode="public", dry_run=False)
                            if r.get("count"):
                                push_log("share", "自动共享 %d 条对话（所有账号均可继续）" % r["count"])
                    except Exception:
                        push_log("error", "自动共享对话异常：" + traceback.format_exc(limit=2))

            # ---- 自动签到 ----
            if STATE["settings"].get("autoCheckin"):
                today = time.strftime("%Y-%m-%d")
                if STATE["settings"].get("lastAutoCheckin") != today:
                    results = []
                    for a in build_accounts():
                        if a.get("canCheckin"):
                            r = vault.do_checkin(a["uid"])
                            results.append([a["nickname"], bool(r.get("ok")),
                                            r.get("message") or r.get("reason")])
                    push_log("checkin", "自动签到：" + json.dumps(results, ensure_ascii=False))
                    STATE["settings"]["lastAutoCheckin"] = today
                    save_settings()
        except Exception:
            push_log("error", "后台任务异常：" + traceback.format_exc(limit=2))


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

class HubServer(ThreadingHTTPServer):
    allow_reuse_address = os.name != "nt"
    request_queue_size = 64
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    server_version = "WBAccountHub/2.0"

    def log_message(self, fmt, *args):
        pass

    # ---- 基础设施 ----
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1:%d" % self.server.server_port)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Private-Network", "true")

    def _send(self, code, payload, ctype="application/json; charset=utf-8"):
        if isinstance(payload, (dict, list)):
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        elif isinstance(payload, str):
            body = payload.encode("utf-8")
        else:
            body = payload
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _read_body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0:
                return {}
            raw = self.rfile.read(n).decode("utf-8", "replace")
            return json.loads(raw) if raw.strip() else {}
        except Exception:
            return {}

    def _static(self, path):
        if path in ("/", "/index.html"):
            f = os.path.join(ROOT, "index.html")
        else:
            return self._send(404, {"error": "not found"})
        if not os.path.isfile(f):
            return self._send(404, {"error": "not found", "path": path})
        ext = os.path.splitext(f)[1].lower()
        ctype = {".html": "text/html; charset=utf-8",
                 ".js": "application/javascript; charset=utf-8",
                 ".css": "text/css; charset=utf-8",
                 ".json": "application/json; charset=utf-8",
                 ".svg": "image/svg+xml", ".png": "image/png"}.get(ext, "application/octet-stream")
        with open(f, "rb") as fh:
            self._send(200, fh.read(), ctype)

    # ---- 分发 ----
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self._cors()
        self.end_headers()

    def do_GET(self):
        if not self._local_request():
            return self._send(403, {"ok": False, "reason": "仅允许本机管理台访问"})
        u = urlparse(self.path)
        if u.path.startswith("/api/"):
            try:
                return self._api_get(u.path, parse_qs(u.query))
            except Exception:
                return self._send(500, {"error": traceback.format_exc(limit=3)})
        return self._static(u.path)

    def _local_request(self):
        allowed = {"127.0.0.1:%d" % self.server.server_port, "localhost:%d" % self.server.server_port}
        if self.headers.get("Host") not in allowed:
            return False
        origin = self.headers.get("Origin")
        return not origin or origin in {"http://" + host for host in allowed}

    def do_POST(self):
        if not self._local_request():
            return self._send(403, {"ok": False, "reason": "仅允许本机管理台发起操作"})
        u = urlparse(self.path)
        try:
            return self._api_post(u.path, self._read_body())
        except Exception:
            return self._send(500, {"error": traceback.format_exc(limit=3)})

    def do_DELETE(self):
        if not self._local_request():
            return self._send(403, {"ok": False, "reason": "仅允许本机管理台发起操作"})
        u = urlparse(self.path)
        try:
            body = self._read_body()
            if u.path == "/api/account":
                qs = parse_qs(u.query)
                uid = body.get("uid") or (qs.get("uid") or [""])[0]
                r = vault.forget(uid)
                if r.get("ok"):
                    push_log("forget", "已从保险库移除 %s" % r.get("nickname"))
                return self._send(200 if r.get("ok") else 404, r)
            return self._send(404, {"error": "unknown endpoint"})
        except Exception:
            return self._send(500, {"error": traceback.format_exc(limit=3)})

    # ---- GET ----
    def _api_get(self, path, qs):
        if path == "/api/state":
            return self._send(200, do_state())
        if path == "/api/health":
            return self._send(200, {"ok": True, "service": lifecycle.SERVICE, "project": lifecycle.PROJECT, "revision": lifecycle.REVISION, "pid": os.getpid(), "ts": now_ms()})
        if path == "/api/log":
            return self._send(200, {"log": STATE["log"][-200:]})
        if path == "/api/diagnose":
            return self._send(200, vault.diagnose())
        if path == "/api/conversations":
            return self._send(200, {"conversations": vault.list_conversations()})
        if path == "/api/sessions":
            try:
                limit = int((qs.get("limit") or ["60"])[0])
            except Exception:
                limit = 60
            rows = vault.list_sessions(limit=max(1, min(limit, 300)))
            stuck = [s for s in rows if s.get("stuck")]
            return self._send(200, {
                "ok": True,
                "sessions": rows,
                "runningCount": sum(1 for s in rows if s.get("display") == "运行中"),
                "stuckCount": len(stuck),
                "liveThresholdSec": vault.LIVE_IDLE_SECONDS,
                "fixLog": vault.session_fix_log()[-20:],
            })
        if path == "/api/shared":
            try:
                return self._send(200, vault.share_overview())
            except Exception:
                return self._send(200, {"total": 0, "shared": 0, "private": 0,
                                        "unsharable": 0, "groups": [], "sessions": [],
                                        "log": [], "error": traceback.format_exc(limit=2)})
        if path == "/api/credits":
            force = (qs.get("force") or ["0"])[0] in ("1", "true", "yes")
            return self._send(200, {"ok": True, "credits": credit_all(force=force),
                                    "ttlMs": CREDIT_TTL})
        if path == "/api/token":
            uid = (qs.get("uid") or [""])[0] or None
            return self._send(200, vault.token_expiry(uid))
        return self._send(404, {"error": "unknown endpoint", "path": path})

    # ---- POST ----
    def _api_post(self, path, body):
        if path in ("/api/login/send-sms", "/api/login/sms-status", "/api/login/verify"):
            try:
                if path.endswith("send-sms"):
                    result = phone_login.begin_send(body.get("phone"))
                elif path.endswith("sms-status"):
                    result = phone_login.sms_status(body.get("phone"))
                else:
                    result = phone_login.verify(body.get("phone"), body.get("code"))
                if path.endswith("verify") and result.get("ok"):
                    CREDIT_CACHE.pop(result.get("uid"), None)
                    TOKEN_CACHE.pop(result.get("uid"), None)
            except Exception as error:
                result = {"ok": False, "reason": "验证登录未完成：%s" % str(error)[:200]}
            return self._send(200, result)
        if path == "/api/service-stop":
            lifecycle.RUNTIME.mkdir(exist_ok=True)
            (lifecycle.RUNTIME / "stop.request").write_text("stop", encoding="utf-8")
            self._send(200, {"ok": True, "reason": "管理台已停止；WorkBuddy 保持运行"})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        if path == "/api/collect":
            acct = vault.live_account() or {}
            uid = body.get("uid") or acct.get("uid")
            if not uid:
                return self._send(400, {"ok": False, "reason": "本机没有检测到已登录账号"})
            r = vault.collect(uid, acct.get("nickname") or body.get("nickname"))
            push_log("collect", r.get("reason", ""))
            return self._send(200, r)

        if path == "/api/switch":
            uid = body.get("uid")
            if not uid:
                return self._send(400, {"ok": False, "reason": "缺少 uid"})
            r = vault.restore(uid)
            push_log("switch", "切换到 %s：%s" % (uid[:8], r.get("reason", "")))
            return self._send(200, r)

        if path == "/api/switch-lite":
            uid = body.get("uid")
            if not uid:
                return self._send(400, {"ok": False, "reason": "缺少 uid"})
            r = vault.restore_identity_only(uid)
            push_log("switch", "轻量切换 → %s：%s" % (uid[:8], r.get("reason", "")))
            return self._send(200, r)

        if path == "/api/status":
            uid = body.get("uid")
            if not uid:
                return self._send(400, {"ok": False, "reason": "缺少 uid"})
            return self._send(200, vault.checkin_status_for(uid))

        if path == "/api/checkin":
            uid = body.get("uid")
            if not uid:
                return self._send(400, {"ok": False, "reason": "缺少 uid"})
            r = vault.do_checkin(uid)
            push_log("checkin", "%s：%s" % (uid[:8], r.get("message") or r.get("reason")))
            return self._send(200, r)

        if path == "/api/checkin-all":
            results = []
            for a in build_accounts():
                if not a.get("canCheckin"):
                    results.append({"uid": a["uid"], "nickname": a["nickname"], "ok": False,
                                    "reason": "没有收录到加密会话文件，无法签到"})
                    continue
                r = vault.do_checkin(a["uid"])
                r.update({"uid": a["uid"], "nickname": a["nickname"]})
                results.append(r)
            push_log("checkin", "批量签到 %d 个账号" % len(results))
            return self._send(200, {"ok": True, "results": results})

        if path == "/api/credits":
            force = bool(body.get("force"))
            return self._send(200, {"ok": True, "credits": credit_all(force=force),
                                    "ttlMs": CREDIT_TTL})

        if path == "/api/share-sessions":
            mode = (body.get("mode") or "public").lower()
            dry = body.get("dryRun")
            dry = True if dry is None else bool(dry)
            r = vault.share_sessions(
                mode=mode,
                ids=body.get("ids"),
                workspace=body.get("workspace"),
                target_uid=body.get("targetUid"),
                dry_run=dry)
            if not dry and r.get("ok") and r.get("count"):
                push_log("share", r.get("reason", ""))
            return self._send(200, r)

        if path == "/api/fix-sessions":
            dry = body.get("dryRun")
            dry = True if dry is None else bool(dry)
            try:
                max_idle = body.get("maxIdleSeconds")
                max_idle = None if max_idle is None else float(max_idle)
            except Exception:
                max_idle = None
            r = vault.reconcile_stuck_sessions(dry_run=dry, max_idle=max_idle)
            if not dry and r.get("count"):
                push_log("fix-sessions", r.get("reason", ""))
            return self._send(200, r)

        if path == "/api/probe":
            uid = body.get("uid")
            if not uid:
                return self._send(400, {"ok": False, "reason": "缺少 uid"})
            r = vault.session_for(uid, force=True)
            return self._send(200, r)

        if path == "/api/launch-app":
            r = vault.launch_app()
            push_log("launch", r.get("reason", ""))
            return self._send(200, r)

        if path == "/api/settings":
            for k in ("autoCheckin", "autoCollect", "autoFixSessions", "autoShare"):
                if k in body:
                    STATE["settings"][k] = bool(body[k])
            save_settings()
            return self._send(200, {"ok": True, "settings": STATE["settings"]})

        return self._send(404, {"error": "unknown endpoint", "path": path})


# --------------------------------------------------------------------------
# 启动
# --------------------------------------------------------------------------

def already_running(port):
    return bool(lifecycle.health(port))

def bind_server(port):
    for candidate in range(port, port + 20):
        if already_running(candidate):
            return None, candidate
        try:
            return HubServer(("127.0.0.1", candidate), Handler), candidate
        except OSError:
            continue
    raise OSError("20 个候选端口均无法绑定")

def main():
    STATE["settings"] = load_settings()
    try:
        srv, port = bind_server(PORT)
    except OSError as error:
        print("无法启动管理台：", error, flush=True)
        return 1
    if srv is None:
        return 0
    lifecycle.ready(port)
    if os.environ.get("WBH_BACKGROUND") != "0":
        threading.Thread(target=auto_loop, daemon=True).start()
    push_log("boot", "服务启动，端口 %d" % port)
    print("WorkBuddy 账号管理台 已启动 http://127.0.0.1:%d/" % port, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
