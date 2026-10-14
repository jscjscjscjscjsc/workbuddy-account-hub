"""Portable executable smoke test; isolated home/vault, no real account changes."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
BUILT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "dist/WorkBuddyAccountHub"
with tempfile.TemporaryDirectory(prefix="wbh-portable-") as temp:
    fixture = Path(temp) / "Portable"
    shutil.copytree(BUILT, fixture, ignore=shutil.ignore_patterns("__pycache__"))
    home = Path(temp) / "home"
    home.mkdir()
    with socket.socket() as candidate:
        candidate.bind(("127.0.0.1", 0))
        base = candidate.getsockname()[1]
    project = hashlib.sha256(str(fixture.resolve()).casefold().encode()).hexdigest()[:16]
    env = {**os.environ, "WBH_PORT": str(base), "WBH_HOME": str(home),
           "WBH_VAULT_DIR": str(Path(temp) / "vault"), "WBH_BACKGROUND": "0",
           "PATH": ""}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    port = None
    def get(path):
        with opener.open(f"http://127.0.0.1:{port}{path}", timeout=2) as response:
            return response.read()
    try:
        result = subprocess.run([str(fixture / "WorkBuddyAccountHub.exe"), "--no-browser"],
            cwd=fixture, env=env, timeout=35)
        assert result.returncode == 0
        value = json.loads((fixture / "运行日志/service.json").read_text(encoding="utf-8"))
        port = value["port"]
        health = json.loads(get("/api/health"))
        assert health["project"] == project
        assert b"sendLoginSms" in get("/")
        state = json.loads(get("/api/state"))
        assert state["accounts"] == []
        assert state["settings"]["autoShare"] is False
        assert state["settings"]["autoFixSessions"] is False
        print("PASS: portable EXE launches with an empty PATH and serves the UI")
        print("PASS: clean installation has no accounts; automatic conversation changes disabled")
    finally:
        if port is not None:
            req = urllib.request.Request(f"http://127.0.0.1:{port}/api/service-stop", data=b"{}",
                headers={"Content-Type": "application/json"})
            with opener.open(req, timeout=3) as response:
                assert json.load(response)["ok"]
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try: get("/api/health")
                except OSError: break
                time.sleep(.1)
            else: raise AssertionError("fixture service did not stop")
            time.sleep(.5)
            print("PASS: portable fixture service stopped")
