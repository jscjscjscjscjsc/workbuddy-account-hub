"""Service identity, readiness and detached process supervision."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

ROOT = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent.parent
RUNTIME = ROOT / "运行日志"
PROJECT = hashlib.sha256(str(ROOT).casefold().encode("utf-8")).hexdigest()[:16]
SERVICE = "WBAccountHub"
REVISION = hashlib.sha256(b"".join((ROOT / name).read_bytes() for name in
    ("server/server.py", "server/vault.py", "server/phone_login.py", "server/lifecycle.py", "index.html"))).hexdigest()[:16]


def health(port, timeout=0.3):
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"http://127.0.0.1:{port}/api/health", timeout=timeout) as response:
            value = json.loads(response.read(4096))
        return value if value.get("ok") and value.get("service") == SERVICE and value.get("project") == PROJECT else None
    except (OSError, ValueError):
        return None


def find_service(port):
    candidates = list(range(port, port + 20))
    try:
        saved = json.loads((RUNTIME / "service.json").read_text(encoding="utf-8"))["port"]
        if saved in candidates:
            candidates.remove(saved); candidates.insert(0, saved)
    except (OSError, ValueError, KeyError):
        pass
    for candidate in candidates:
        if health(candidate):
            return candidate
    return None


def ready(port):
    RUNTIME.mkdir(exist_ok=True)
    temp = RUNTIME / f"service.{os.getpid()}.tmp"
    temp.write_text(json.dumps({"port": port, "pid": os.getpid(), "project": PROJECT}), encoding="utf-8", newline="\n")
    os.replace(temp, RUNTIME / "service.json")


def stop_service(port):
    if not health(port):
        return False
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/service-stop", data=b"{}",
                                 headers={"Content-Type":"application/json"}, method="POST")
    try:
        with opener.open(req, timeout=3) as response:
            return bool(json.load(response).get("ok"))
    except (OSError, ValueError):
        return False


def spawn_supervisor():
    RUNTIME.mkdir(exist_ok=True)
    flags = subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS if os.name == "nt" else 0
    command = [sys.executable, "--supervise"] if getattr(sys, "frozen", False) else [sys.executable, "-u", str(ROOT / "launch.py"), "--supervise"]
    return subprocess.Popen(command,
                            cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, close_fds=True, creationflags=flags)


def supervise():
    import msvcrt
    RUNTIME.mkdir(exist_ok=True)
    with (RUNTIME / "supervisor.lock").open("a+b") as lock:
        lock.seek(0)
        if not lock.read(1):
            lock.write(b"1"); lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return 0
        failures = 0
        stop = RUNTIME / "stop.request"
        stop.unlink(missing_ok=True)
        while failures < 5:
            logfile = RUNTIME / "service.log"
            if logfile.exists() and logfile.stat().st_size > 2 * 1024 * 1024:
                os.replace(logfile, RUNTIME / "service.previous.log")
            with logfile.open("ab", buffering=0) as log:
                started = time.monotonic()
                env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", "PYTHONFAULTHANDLER": "1"}
                command = [sys.executable, "--serve"] if getattr(sys, "frozen", False) else [sys.executable, "-u", str(ROOT / "server/server.py")]
                child = subprocess.Popen(command,
                                         cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                         stdout=log, stderr=log, close_fds=True,
                                         creationflags=subprocess.CREATE_NO_WINDOW)
                code = child.wait()
                if code == 0 or stop.exists():
                    stop.unlink(missing_ok=True)
                    return 0
                failures = 0 if time.monotonic() - started >= 60 else failures
                failures += 1
                log.write(f"\nService exited ({code}); restart {failures}/5\n".encode())
            time.sleep(min(2 ** failures, 10))
        return 1
