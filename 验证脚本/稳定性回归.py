"""Isolated filesystem/HTTP regressions; never touches a real account or WorkBuddy."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server"))
import vault
import server
import lifecycle
if os.environ.get("WBH_TEST_VAULT"):
    spec = importlib.util.spec_from_file_location("baseline_vault", os.environ["WBH_TEST_VAULT"])
    vault = importlib.util.module_from_spec(spec); spec.loader.exec_module(vault)

OLD = "11111111-1111-1111-1111-111111111111"
NEW = "22222222-2222-2222-2222-222222222222"


class Switching(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wbh-isolated-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.auth = self.root / "auth/session.info"
        self.snapshot = self.root / "wb/storage/skeleton/account-snapshot.json"
        self.auth.parent.mkdir(parents=True); self.snapshot.parent.mkdir(parents=True)
        self.old = json.dumps({"account": {"uid": OLD}, "auth": {"accessToken": "fixture-old"}}).encode()
        self.target = {"account": {"uid": NEW}, "auth": {"accessToken": "fixture-target", "expiresAt": int(time.time()*1000)+60000}}
        self.auth.write_bytes(self.old)
        self.snapshot.write_text(json.dumps({"primary": {"uid": OLD}}), encoding="utf-8")
        self.members = {"@auth/workbuddy-desktop.info": json.dumps(self.target).encode(),
                        "storage/skeleton/account-snapshot.json": json.dumps({"primary": {"uid": NEW}}).encode()}
        def parse(data, secret):
            value = json.loads(data)
            return {"uid": value.get("account", {}).get("uid"), **value.get("auth", {})}
        mocks = {
            "WB": str(self.root / "wb"), "SNAPSHOT": str(self.snapshot), "VAULT_DIR": str(self.root / "vault"),
            "find_entry": lambda uid: {"uid": uid, "nickname": "fixture"} if uid == NEW else None,
            "vault_members_matching": lambda *a: list(self.members), "vault_member": lambda uid, member: self.members.get(member),
            "live_auth_path": lambda: str(self.auth), "auth_dir": lambda: str(self.auth.parent),
            "_secret_or_error": lambda: ("fixture", None), "parse_auth_bytes": parse,
            "app_running": lambda: True, "_log_session_fix": lambda *a: None,
            "list_sessions": lambda **kwargs: [],
        }
        if hasattr(vault, "hot_switch_supported"):
            mocks["hot_switch_supported"] = lambda: True
        self.mock = patch.multiple(vault, **mocks); self.mock.start(); self.addCleanup(self.mock.stop)

    def test_hot_ack_without_snapshot_write(self):
        def daemon():
            deadline = time.monotonic() + 1
            while self.auth.read_bytes() == self.old and time.monotonic() < deadline:
                time.sleep(.01)
            if self.auth.read_bytes() != self.old:
                self.snapshot.write_text(json.dumps({"primary": {"uid": NEW}}), encoding="utf-8")
        watcher = threading.Thread(target=daemon); watcher.start()
        try:
            result = vault.restore_identity_only(NEW)
        finally:
            watcher.join(2)
        self.assertTrue(result["ok"], result.get("reason"))
        self.assertEqual(result.get("mode"), "hot")
        self.assertTrue(result.get("verified"))
        self.assertEqual(json.loads(self.auth.read_bytes())["account"]["uid"], NEW)

    def test_timeout_rolls_back_and_never_claims_success(self):
        result = vault.restore_identity_only(NEW, timeout=.05)
        self.assertFalse(result["ok"]); self.assertTrue(result["rolledBack"])
        self.assertEqual(self.auth.read_bytes(), self.old)
        self.assertEqual(json.loads(self.snapshot.read_bytes())["primary"]["uid"], OLD)

    def test_missing_uid_rejected_before_write(self):
        self.target["account"] = {}
        self.members["@auth/workbuddy-desktop.info"] = json.dumps(self.target).encode()
        with patch.object(vault, "app_running", return_value=False):
            result = vault.restore_identity_only(NEW)
        self.assertFalse(result["ok"])
        self.assertEqual(self.auth.read_bytes(), self.old)

    def test_expired_rejected_before_write(self):
        self.target["auth"]["expiresAt"] = int(time.time()*1000)-1000
        self.members["@auth/workbuddy-desktop.info"] = json.dumps(self.target).encode()
        with patch.object(vault, "app_running", return_value=False):
            result = vault.restore_identity_only(NEW)
        self.assertFalse(result["ok"]); self.assertIn("过期", result["reason"])
        self.assertEqual(self.auth.read_bytes(), self.old)

    def test_unknown_account_rejected(self):
        self.assertFalse(vault.restore_identity_only("unknown")["ok"])
        self.assertEqual(self.auth.read_bytes(), self.old)

    def test_no_hot_support_no_mutation(self):
        with patch.object(vault, "hot_switch_supported", return_value=False):
            self.assertFalse(vault.restore_identity_only(NEW)["ok"])
        self.assertEqual(self.auth.read_bytes(), self.old)

    def test_cold_switch_and_backup(self):
        with patch.object(vault, "app_running", return_value=False):
            result = vault.restore_identity_only(NEW)
        self.assertTrue(result["ok"]); self.assertEqual(result["mode"], "cold")
        self.assertEqual(Path(result["backup"][0]).read_bytes(), self.old)
        self.assertEqual(json.loads(self.snapshot.read_bytes())["primary"]["uid"], NEW)

    def test_cold_missing_snapshot_rolls_back(self):
        del self.members["storage/skeleton/account-snapshot.json"]
        with patch.object(vault, "app_running", return_value=False):
            result = vault.restore_identity_only(NEW)
        self.assertFalse(result["ok"])
        self.assertEqual(self.auth.read_bytes(), self.old)

    def test_snapshot_only_cannot_fake_hot_ack(self):
        with patch.object(vault, "observed_account", side_effect=[False]+[True]*20), patch.object(vault, "auth_info_live", return_value={"ok": True, "uid": OLD}):
            result = vault.restore_identity_only(NEW, timeout=.05)
        self.assertFalse(result["ok"]); self.assertEqual(self.auth.read_bytes(), self.old)

    def test_other_identity_is_not_overwritten_on_timeout(self):
        third = json.dumps({"account": {"uid": "third"}}).encode()
        def change():
            deadline = time.monotonic() + 2
            while self.auth.read_bytes() == self.old and time.monotonic() < deadline:
                time.sleep(.005)
            self.auth.write_bytes(third)
        thread = threading.Thread(target=change); thread.start()
        result = vault.restore_identity_only(NEW, timeout=.3); thread.join(2)
        self.assertFalse(result["ok"]); self.assertFalse(result["rolledBack"])
        self.assertEqual(self.auth.read_bytes(), third)

    def test_collect_cannot_overwrite_other_account(self):
        result = vault.collect(NEW)
        self.assertFalse(result["ok"])
        self.assertEqual(self.auth.read_bytes(), self.old)

    def test_active_task_blocks_without_closing_app(self):
        with patch.object(vault, "list_sessions", return_value=[{"live":True,"normalized":"working"}]):
            result = vault.restore_identity_only(NEW)
        self.assertFalse(result["ok"]); self.assertTrue(result["busy"])
        self.assertEqual(self.auth.read_bytes(), self.old)


class HTTP(unittest.TestCase):
    def setUp(self):
        self.srv = server.HubServer(("127.0.0.1", 0), server.Handler)
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True); self.thread.start()
        self.addCleanup(self.cleanup)
        self.base = "http://127.0.0.1:%d" % self.srv.server_port
    def cleanup(self):
        self.srv.shutdown(); self.srv.server_close(); self.thread.join(2)
    def test_health_identifies_project(self):
        self.assertEqual(lifecycle.health(self.srv.server_port)["project"], lifecycle.PROJECT)
    def test_private_files_not_served(self):
        for path in ("/server/vault.py", "/保险库/index.json", "/../保险库/index.json"):
            encoded = urllib.parse.quote(path)
            with self.assertRaises(urllib.error.HTTPError):
                urllib.request.urlopen(self.base+encoded, timeout=2)
    def test_foreign_listener_is_not_our_service(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        class Foreign(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200); self.end_headers(); self.wfile.write(b'{"ok":true}')
            def log_message(self,*a): pass
        foreign = ThreadingHTTPServer(("127.0.0.1",0),Foreign)
        thread=threading.Thread(target=foreign.serve_forever,daemon=True);thread.start()
        try:
            self.assertIsNone(lifecycle.health(foreign.server_port))
            self.assertFalse(server.already_running(foreign.server_port))
        finally: foreign.shutdown();foreign.server_close();thread.join(2)
    def test_bind_reports_actual_port(self):
        with socket.socket() as busy:
            busy.bind(("127.0.0.1",0));busy.listen()
            srv, port=server.bind_server(busy.getsockname()[1])
            try:
                self.assertIsNotNone(srv);self.assertNotEqual(port,busy.getsockname()[1])
                self.assertEqual(port,srv.server_port)
            finally:srv.server_close()

if __name__ == "__main__": unittest.main(verbosity=2)
