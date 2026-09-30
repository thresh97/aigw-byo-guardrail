import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "webhook"))
os.environ["TOKEN"] = "t0ken"
os.environ["POLICY"] = json.dumps({
    "ip_headers": ["cf-connecting-ip", "x-real-ip"],
    "allow_cidrs": ["192.0.2.0/24", "198.51.100.7/32"],
    "deny_cidrs": ["192.0.2.128/25"],
    "header_rules": [{"header": "x-app", "deny": "blockme"}, {"header": "x-dept", "require": "^(eng|finance)$"}],
})
import handler  # noqa: E402


def call(headers, body=None):
    r = handler.handler({"headers": headers, "body": json.dumps(body or {"eventType": "beforeRequestHook"})}, None)
    return r["statusCode"], json.loads(r["body"])


OK = {"x-guardrail-token": "t0ken", "cf-connecting-ip": "192.0.2.10", "x-dept": "eng"}


class Handler(unittest.TestCase):
    def test_bad_token(self):
        self.assertEqual(call({**OK, "x-guardrail-token": "nope"})[0], 401)
        self.assertEqual(call({k: v for k, v in OK.items() if k != "x-guardrail-token"})[0], 401)

    def test_allowed_ip(self):
        self.assertEqual(call(OK), (200, {"verdict": True, "data": {"reason": "ok"}}))

    def test_ip_outside_allowlist(self):
        _, b = call({**OK, "cf-connecting-ip": "8.8.8.8"})
        self.assertFalse(b["verdict"])
        self.assertIn("not in allow_cidrs", b["data"]["reason"])

    def test_deny_beats_allow(self):
        self.assertFalse(call({**OK, "cf-connecting-ip": "192.0.2.200"})[1]["verdict"])

    def test_fallback_ip_header_and_bad_values(self):
        h = {**OK, "cf-connecting-ip": "garbage", "x-real-ip": "198.51.100.7"}
        self.assertTrue(call(h)[1]["verdict"])

    def test_no_ip_fails_closed(self):
        h = {k: v for k, v in OK.items() if k != "cf-connecting-ip"}
        self.assertFalse(call(h)[1]["verdict"])

    def test_header_names_case_insensitive(self):
        self.assertTrue(call({"X-Guardrail-Token": "t0ken", "CF-Connecting-IP": "192.0.2.10", "X-Dept": "finance"})[1]["verdict"])

    def test_header_deny_and_require(self):
        self.assertFalse(call({**OK, "x-app": "probe-app-blockme"})[1]["verdict"])
        self.assertTrue(call({**OK, "x-app": "chat-assistant"})[1]["verdict"])
        self.assertFalse(call({**OK, "x-dept": "sales"})[1]["verdict"])


if __name__ == "__main__":
    unittest.main()
