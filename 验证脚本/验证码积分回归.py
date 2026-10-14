"""Isolated SMS latency and current-cycle credits regressions; no real SMS."""
import json
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))
import phone_login
import vault

UID = "11111111-1111-1111-1111-111111111111"
PHONE = "13800000000"


class SMS(unittest.TestCase):
    def setUp(self):
        phone_login.SMS_JOBS.clear()
        phone_login.PENDING.clear()

    def test_slow_official_response_does_not_block_or_duplicate(self):
        release = threading.Event()
        done = threading.Event()
        calls = []
        def slow(phone):
            calls.append(phone)
            release.wait(2)
            return {"ok": True, "reason": "sent", "retryAfter": 60}
        with patch.object(phone_login, "send", side_effect=slow):
            started = time.monotonic()
            self.assertTrue(phone_login.begin_send(PHONE)["pending"])
            self.assertLess(time.monotonic() - started, .2)
            self.assertTrue(phone_login.begin_send(PHONE)["pending"])
            release.set()
            for _ in range(100):
                if not phone_login.sms_status(PHONE)["pending"]:
                    done.set(); break
                time.sleep(.01)
            self.assertTrue(done.is_set())
            self.assertTrue(phone_login.sms_status(PHONE)["ok"])
            self.assertEqual(calls, [PHONE])

    def test_bad_phone_starts_no_request(self):
        with patch.object(phone_login, "send") as send:
            with self.assertRaises(ValueError):
                phone_login.begin_send("123")
            send.assert_not_called()

    def test_failed_request_is_reported_without_success(self):
        with patch.object(phone_login, "send", side_effect=ValueError("official refused")):
            phone_login.begin_send(PHONE)
            for _ in range(100):
                value = phone_login.sms_status(PHONE)
                if not value["pending"]: break
                time.sleep(.01)
            self.assertFalse(value["ok"])
            self.assertEqual(value["reason"], "official refused")

    def test_delivered_code_can_be_verified_after_service_restart(self):
        with patch.object(phone_login, "request", return_value={"fixture": True}) as request, patch.object(phone_login, "save_verified", return_value={"ok": True}):
            self.assertTrue(phone_login.verify(PHONE, "123456")["ok"])
            self.assertEqual(request.call_args.args[0], "/v2/plugin/login/token")


class Credits(unittest.TestCase):
    def query(self, summary, detail=None, status=200, candidate_uid=UID):
        session = {"ok": True, "base": "https://www.workbuddy.cn",
                   "cand": {"user_id": candidate_uid, "bearer": "fixture"}}
        responses = [{"status": status, "text": json.dumps(summary)},
                     {"status": 200, "text": json.dumps(detail or {})}]
        with patch.object(vault, "session_for", return_value=session), patch.object(vault, "http_json", side_effect=responses) as http:
            result = vault.credit_for(UID)
            if candidate_uid != UID: http.assert_not_called()
            return result

    def test_current_cycle_summary_overrides_historical_capacity(self):
        summary = {"code": 0, "data": {"Packages": [
            {"CycleRemainCapacity": "1100.900002", "CycleTotalCapacity": "2000"},
            {"CycleRemainCapacity": "0", "CycleTotalCapacity": "500"}]}}
        detail = {"code": 0, "data": {"Response": {"Data": {"Accounts": [
            {"CapacityType": 4, "CapacityRemainPrecise": "500", "CapacitySizePrecise": "500"},
            {"CapacityType": 1, "Status": 2, "CapacityRemainPrecise": "100"},
            {"CapacityType": 1, "CapacityRemainPrecise": "1100.900002"}]}}}}
        value = self.query(summary, detail)
        self.assertTrue(value["ok"])
        self.assertEqual(value["totalRemain"], 1100.900002)
        self.assertEqual(value["packageCount"], 1)
        self.assertEqual(value["verifiedUid"], UID)

    def test_empty_official_packages_are_real_zero(self):
        value = self.query({"code": 0, "data": {"Packages": []}})
        self.assertTrue(value["ok"])
        self.assertEqual(value["totalRemain"], 0)

    def test_missing_packages_does_not_become_fake_zero(self):
        self.assertFalse(self.query({"code": 0, "data": {}})["ok"])

    def test_unauthorized_does_not_return_previous_balance(self):
        self.assertFalse(self.query({}, status=401)["ok"])

    def test_other_account_is_rejected_before_network(self):
        self.assertFalse(self.query({}, candidate_uid="another-account")["ok"])

    def test_invalid_number_does_not_become_fake_zero(self):
        self.assertFalse(self.query({"code": 0, "data": {"Packages": [
            {"CycleRemainCapacity": "NaN", "CycleTotalCapacity": "2000"}]}})["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
