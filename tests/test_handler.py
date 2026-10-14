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


class TrustedHops(unittest.TestCase):
    def ip(self, xff, hops):
        p = handler.load_policy(json.dumps({"ip_headers": ["x-forwarded-for"], "trusted_hops": hops}))
        return handler.client_ip({"x-forwarded-for": xff}, p["ip_headers"], p["trusted_hops"])[1]

    def test_leftmost_by_default(self):
        self.assertEqual(str(self.ip("192.0.2.10, 198.51.100.7", 0)), "192.0.2.10")

    def test_from_the_right(self):
        self.assertEqual(str(self.ip("192.0.2.10, 198.51.100.7", 1)), "198.51.100.7")
        self.assertEqual(str(self.ip("192.0.2.10, 198.51.100.7, 203.0.113.9", 2)), "198.51.100.7")

    def test_too_short_fails_closed(self):
        self.assertIsNone(self.ip("198.51.100.7", 2))
        p = handler.load_policy(json.dumps({"ip_headers": ["x-forwarded-for"], "trusted_hops": 2,
                                            "allow_cidrs": ["198.51.100.0/24"]}))
        self.assertFalse(handler.evaluate({"x-forwarded-for": "198.51.100.7"}, p)[0])

    def test_spoofed_left_entry_ignored(self):
        p = handler.load_policy(json.dumps({"ip_headers": ["x-forwarded-for"], "trusted_hops": 1,
                                            "deny_cidrs": ["198.51.100.7/32"]}))
        self.assertFalse(handler.evaluate({"x-forwarded-for": "192.0.2.10, 198.51.100.7"}, p)[0])

    def test_payload_logged_only_when_enabled(self):
        body = {"eventType": "beforeRequestHook", "request": {"json": {"secret": "s3"}}}
        for on in (False, True):
            handler.LOG_PAYLOAD = on
            with self.assertLogs(level="INFO") as logs:
                call(OK, body)
            entry = json.loads(logs.records[-1].getMessage())
            self.assertEqual("request" in entry, on)
        handler.LOG_PAYLOAD = False


class ToolPolicy(unittest.TestCase):
    POL = json.dumps({"eng-l1": ["echo"], "hr-shared-l1": ["whoami"], "ws-b/hr-shared-l1": ["get_canary"]})

    def verdict(self, server, tool, ws="ws-a", pol=POL):
        md = {"mcpServerId": server, "mcpWorkspaceId": ws, "mcpToolName": tool}
        return call({**OK, "x-tool-policy": pol}, {"eventType": "beforeRequestHook", "metadata": md})[1]

    def test_allowed_and_denied(self):
        self.assertTrue(self.verdict("eng-l1", "echo")["verdict"])
        b = self.verdict("eng-l1", "danger")
        self.assertFalse(b["verdict"])
        self.assertIn("not allowed on eng-l1", b["data"]["reason"])

    def test_unknown_server_denied(self):
        self.assertFalse(self.verdict("eng-l2", "echo")["verdict"])

    def test_no_substring_or_prefix_match(self):
        self.assertFalse(self.verdict("eng-l10", "echo")["verdict"])
        self.assertFalse(self.verdict("eng-l1", "ech")["verdict"])

    def test_workspace_key_wins(self):
        self.assertTrue(self.verdict("hr-shared-l1", "whoami")["verdict"])
        self.assertFalse(self.verdict("hr-shared-l1", "whoami", ws="ws-b")["verdict"])
        self.assertTrue(self.verdict("hr-shared-l1", "get_canary", ws="ws-b")["verdict"])

    def test_malformed_denied(self):
        for pol in ("{", "[]", '{"eng-l1": "echo"}', '{"eng-l1": [1]}'):
            b = self.verdict("eng-l1", "echo", pol=pol)
            self.assertFalse(b["verdict"], pol)
            self.assertIn("malformed", b["data"]["reason"])

    def test_no_mcp_metadata_denied(self):
        self.assertFalse(call({**OK, "x-tool-policy": self.POL})[1]["verdict"])

    def test_off_without_header(self):
        md = {"mcpServerId": "x", "mcpToolName": "y"}
        self.assertTrue(call(OK, {"eventType": "beforeRequestHook", "metadata": md})[1]["verdict"])

    def test_other_rules_still_apply(self):
        md = {"mcpServerId": "eng-l1", "mcpToolName": "echo"}
        h = {**OK, "x-tool-policy": self.POL, "x-app": "blockme"}
        self.assertFalse(call(h, {"eventType": "beforeRequestHook", "metadata": md})[1]["verdict"])


if __name__ == "__main__":
    unittest.main()
