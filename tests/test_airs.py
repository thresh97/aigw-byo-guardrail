import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "webhook"))
import airs  # noqa: E402

# Payload shapes as a hybrid gateway (2.27.0) sends them for an MCP tools/call.
META = {"mcpServerId": "docs", "mcpWorkspaceId": "ws-1", "mcpToolName": "search", "_user": "alice"}
REQ = {"json": {"name": "search", "arguments": {"query": "naïve café", "opts": {"limit": 3, "tags": ["a"]}}},
       "text": "{\"query\":\"na\\u00efve caf\\u00e9\"}"}
BEFORE = {"eventType": "beforeRequestHook", "requestType": "mcpToolCall", "provider": "mcp", "metadata": META,
          "request": REQ, "response": {"json": {}, "text": "", "statusCode": None}}
AFTER = {**BEFORE, "eventType": "afterRequestHook",
         "response": {"json": {"content": [{"type": "text", "text": "result text"}]}, "text": "result text", "statusCode": 200}}
LLM = {"eventType": "beforeRequestHook", "requestType": "messages", "provider": "anthropic", "metadata": {}}


def cfg(**kw):
    return airs.load_config(json.dumps({"profile": "p", **kw}))


class Poster:
    def __init__(self, status=200, res=None, err=None):
        self.ret, self.calls = (status, res, err), []

    def __call__(self, url, key, body, timeout):
        self.calls.append({"url": url, "key": key, "body": body, "timeout": timeout})
        return self.ret


ALLOW = {"action": "allow", "category": "benign", "scan_id": "s1", "report_id": "r1"}
BLOCK = {"action": "block", "category": "malicious", "scan_id": "s2", "report_id": "r2",
         "prompt_detected": {"injection": True}}


class Config(unittest.TestCase):
    def test_off_when_unset(self):
        self.assertIsNone(airs.load_config(""))
        self.assertIsNone(airs.load_config(None))

    def test_defaults(self):
        c = cfg()
        self.assertEqual((c["input_profile"], c["output_profile"], c["content"], c["fail_open"]), ("p", "p", "tool_event", False))
        self.assertEqual(c["url"], "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request")

    def test_split_profiles_and_validation(self):
        c = airs.load_config(json.dumps({"input_profile": "in", "output_profile": "out"}))
        self.assertEqual((c["input_profile"], c["output_profile"]), ("in", "out"))
        for bad in ({}, {"input_profile": "in"}, {"profile": "p", "content": "x"}, {"profile": "p", "fail": "maybe"}):
            with self.assertRaises((ValueError, KeyError)):
                airs.load_config(json.dumps(bad))


class Build(unittest.TestCase):
    def test_input_text_is_unescaped(self):
        body, info = airs.build(BEFORE, cfg(content="text"))
        prompt = body["contents"][0]["prompt"]
        self.assertIn("query: naïve café", prompt)
        self.assertIn("opts.limit: 3", prompt)
        self.assertIn("opts.tags[0]: a", prompt)
        self.assertNotIn("\\u00", prompt)
        self.assertNotIn("response", body["contents"][0])
        self.assertEqual(info["hook"], "input")
        self.assertEqual(body["metadata"], {"app_name": "aigw-mcp-webhook", "app_user": "alice", "ai_model": "mcp:docs/search"})

    def test_output_text_has_args_and_result(self):
        body, info = airs.build(AFTER, cfg(content="text", input_profile="in", output_profile="out"))
        self.assertEqual(body["contents"][0]["response"], "result text")
        self.assertIn("query: naïve café", body["contents"][0]["prompt"])
        self.assertEqual(body["ai_profile"], {"profile_name": "out"})
        self.assertEqual(info["hook"], "output")

    def test_result_from_json_content_when_no_text(self):
        p = {**AFTER, "response": {"json": {"content": [{"type": "text", "text": "x"}, {"type": "image"}, {"type": "text", "text": "y"}]}}}
        self.assertEqual(airs.build(p, cfg(content="text"))[0]["contents"][0]["response"], "x\ny")

    def test_tool_event(self):
        b, _ = airs.build(BEFORE, cfg(content="tool_event"))
        te = b["contents"][0]["tool_event"]
        self.assertEqual(te["metadata"], {"ecosystem": "mcp", "method": "tools/call", "server_name": "docs", "tool_invoked": "search"})
        self.assertIn("naïve", te["input"])
        self.assertNotIn("output", te)
        a, _ = airs.build(AFTER, cfg(content="tool_event"))
        self.assertEqual(a["contents"][0]["tool_event"]["output"], "result text")
        self.assertNotIn("input", a["contents"][0]["tool_event"])

    def test_truncation_is_reported_and_utf8_safe(self):
        p = {**AFTER, "response": {"text": "é" * 100}}
        body, info = airs.build(p, cfg(content="text", max_bytes=51))
        self.assertEqual(body["contents"][0]["response"], "é" * 25)
        self.assertIn({"field": "response", "bytes": 200}, info["truncated"])


class Check(unittest.TestCase):
    def test_allow(self):
        post = Poster(res=ALLOW)
        v, reason, info = airs.check(BEFORE, cfg(timeout_ms=2500), "k", post)
        self.assertTrue(v)
        self.assertIn("scan_id s1", reason)
        self.assertEqual((post.calls[0]["key"], post.calls[0]["timeout"]), ("k", 2.5))
        self.assertEqual((info["action"], info["airs_status"], info["report_id"]), ("allow", 200, "r1"))

    def test_block(self):
        v, reason, info = airs.check(AFTER, cfg(), "k", Poster(res=BLOCK))
        self.assertFalse(v)
        self.assertIn("airs block (malicious) on output of search", reason)
        self.assertEqual(info["detected"], {"prompt_detected": {"injection": True}})

    def test_errors_fail_closed_by_default(self):
        for post in (Poster(403, None, '{"error":{"message":"Invalid API Key"}}'), Poster(None, None, "TimeoutError: timed out"),
                     Poster(200, {"unexpected": 1}), Poster(200, {"action": "maybe"})):
            v, reason, info = airs.check(BEFORE, cfg(), "k", post)
            self.assertFalse(v, reason)
            self.assertIn("failing closed", reason)
            self.assertIn("airs_error", info)
            self.assertEqual(info["result"], "error")
            self.assertIn("(no HTTP response)" if post.ret[0] is None else f"(HTTP {post.ret[0]})", reason)

    def test_errors_fail_open_when_set(self):
        v, reason, _ = airs.check(BEFORE, cfg(fail="open"), "k", Poster(403, None, "denied"))
        self.assertTrue(v)
        self.assertIn("(HTTP 403), failing open", reason)

    def test_missing_key_never_calls_airs(self):
        post = Poster(res=ALLOW)
        v, reason, _ = airs.check(BEFORE, cfg(), "", post)
        self.assertFalse(v)
        self.assertIn("AIRS_API_KEY is not set", reason)
        self.assertEqual(post.calls, [])

    def test_llm_requests_are_not_scanned(self):
        post = Poster(res=BLOCK)
        self.assertTrue(airs.check(LLM, cfg(), "k", post)[0])
        self.assertEqual(post.calls, [])


class HandlerWiring(unittest.TestCase):
    def test_handler_runs_airs_after_rules(self):
        os.environ.update(TOKEN="t0ken", POLICY="{}", AIRS=json.dumps({"profile": "p"}), AIRS_API_KEY="k")
        sys.modules.pop("handler", None)
        import handler
        try:
            orig, handler.airs.post = handler.airs.post, Poster(res=BLOCK)
            r = handler.handler({"headers": {"x-guardrail-token": "t0ken"}, "body": json.dumps(BEFORE)}, None)
            b = json.loads(r["body"])
            self.assertFalse(b["verdict"])
            self.assertEqual(b["data"]["stage"], "airs")
            a = b["data"]["airs"]
            self.assertEqual((a["result"], a["scan_id"], a["report_id"], a["category"], a["airs_status"]),
                             ("block", "s2", "r2", "malicious", 200))
            self.assertIn("latency_ms", a)
            self.assertNotIn("truncated", a)
            self.assertNotIn("naïve", r["body"])  # no tool arguments or results in the response
            handler.airs.post = Poster(None, None, "TimeoutError: timed out")
            with self.assertLogs(level="WARNING"):
                r = handler.handler({"headers": {"x-guardrail-token": "t0ken"}, "body": json.dumps(BEFORE)}, None)
            a = json.loads(r["body"])["data"]["airs"]
            self.assertEqual((a["result"], a["airs_error"]), ("error", "TimeoutError: timed out"))
            self.assertNotIn("airs_status", a)
            r = handler.handler({"headers": {"x-guardrail-token": "t0ken"}, "body": json.dumps(LLM)}, None)
            self.assertNotIn("airs", json.loads(r["body"])["data"])
            r = handler.handler({"headers": {"x-guardrail-token": "nope"}, "body": json.dumps(BEFORE)}, None)
            self.assertEqual(r["statusCode"], 401)
        finally:
            handler.airs.post = orig
            for k in ("AIRS", "AIRS_API_KEY"):
                os.environ.pop(k)
            sys.modules.pop("handler", None)


if __name__ == "__main__":
    unittest.main()
