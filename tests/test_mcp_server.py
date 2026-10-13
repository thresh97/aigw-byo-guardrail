import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp"))
os.environ["TOKEN"] = "t0ken"
import server  # noqa: E402

AUTH = {"x-mcp-token": "t0ken", "content-type": "application/json"}


def call(body, headers=None, path="/a/mcp", method="POST"):
    event = {"rawPath": path, "requestContext": {"http": {"method": method, "path": path}},
             "headers": AUTH if headers is None else headers, "body": json.dumps(body)}
    r = server.handler(event, None)
    return r["statusCode"], json.loads(r["body"]) if "body" in r else None


class McpServer(unittest.TestCase):
    def test_auth(self):
        self.assertEqual(call({"jsonrpc": "2.0", "id": 1, "method": "ping"}, headers={})[0], 401)

    def test_initialize(self):
        s, b = call({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}})
        self.assertEqual(s, 200)
        self.assertEqual(b["result"]["protocolVersion"], "2025-03-26")
        self.assertEqual(b["result"]["serverInfo"]["name"], "byo-probe-mcp-a")
        _, b = call({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "1999"}},
                    path="/b/mcp")
        self.assertEqual(b["result"]["protocolVersion"], server.PROTOCOL_VERSIONS[0])
        self.assertEqual(b["result"]["serverInfo"]["name"], "byo-probe-mcp-b")

    def test_notification_is_202(self):
        self.assertEqual(call({"jsonrpc": "2.0", "method": "notifications/initialized"}), (202, None))

    def test_tools(self):
        _, b = call({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertEqual([t["name"] for t in b["result"]["tools"]], ["echo", "get_canary", "danger", "whoami"])
        _, b = call({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                     "params": {"name": "echo", "arguments": {"text": "hi"}}})
        self.assertEqual(b["result"], {"content": [{"type": "text", "text": "hi"}], "isError": False})
        _, b = call({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "get_canary"}})
        self.assertEqual(b["result"]["content"][0]["text"], server.CANARY)

    def test_whoami_redacts(self):
        _, b = call({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "whoami"}},
                    headers={**AUTH, "authorization": "Bearer x", "x-user": "u1"})
        seen = json.loads(b["result"]["content"][0]["text"])
        self.assertEqual(seen["authorization"], "<redacted>")
        self.assertEqual(seen["x-mcp-token"], "<redacted>")
        self.assertEqual(seen["x-user"], "u1")

    def test_unknown(self):
        _, b = call({"jsonrpc": "2.0", "id": 6, "method": "resources/list"})
        self.assertEqual(b["error"]["code"], -32601)
        _, b = call({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "nope"}})
        self.assertTrue(b["result"]["isError"])

    def test_get_is_405(self):
        self.assertEqual(call({}, method="GET")[0], 405)


if __name__ == "__main__":
    unittest.main()
