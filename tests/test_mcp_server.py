import base64
import hashlib
import json
import os
import sys
import time
import unittest
from unittest import mock

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


# throwaway 1024-bit test key (signing happens here with pow(), the server only verifies)
N = 0xeed7b2fa401b3584f6915c1df4a8222a8f6f30988e5bbd0ae71f8f14f30c86fe9c26f4de6d82e9ae1c6340695c1b3efa9188971b84b416b501b68bb463e745e72e116e138d82c3636a1e4754b8b3f152dd049dc7393f55da71f5b68b0f36e2534db51f2fba8e730dc1e5367804d4c0873c7722b7f540795c2923ffa1d547cc61
D = 0xeabe1d2e502b6de28ce439014820a7d3e4bd87a9a8e1095fd9e0eea3cc6d97904eb10b2241c7d51c46d255d037b29fa76dba2da9e2378dc9c1314505badae79b755b75e1219a88220a4849061c0647ccef2ba9719196c49f4f350e6d1cd4e87d31d7506f53dcf20ac00faee759720e1acdc4317d29ddac8315b28a2f262a8631
ISS = "https://idp.example/realms/r"


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwt(claims=None, kid="k1", alg="RS256"):
    c = {"iss": ISS, "sub": "u1", "exp": int(time.time()) + 60, "groups": ["eng-l1"], **(claims or {})}
    signed = f"{b64(json.dumps({'alg': alg, 'kid': kid}).encode())}.{b64(json.dumps(c).encode())}"
    k = 128
    digest = server.SHA256_PREFIX + hashlib.sha256(signed.encode()).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(digest) - 3) + b"\x00" + digest
    return f"{signed}.{b64(pow(int.from_bytes(em, 'big'), D, N).to_bytes(k, 'big'))}"


def tool(name, headers, path):
    return call({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": name}}, headers=headers, path=path)


class Modes(unittest.TestCase):
    def setUp(self):
        jwk = {"kty": "RSA", "kid": "k1", "n": b64(N.to_bytes(128, "big")), "e": "AQAB"}
        patches = {"JWT_SERVERS": {"j"}, "OAUTH_SERVERS": {"o"}, "TOOL_AUTHZ": {"danger": ["eng-l2"], "*": ["eng-l1"]},
                   "_jwks": {"k1": jwk}}
        for k, v in patches.items():
            p = mock.patch.object(server, k, v)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.dict(os.environ, {"JWT_ISSUER": ISS, "JWT_AUDIENCE": ""})
        p.start()
        self.addCleanup(p.stop)

    def test_extra_tool(self):
        with mock.patch.object(server, "EXTRA_TOOL", "export_all"), \
                mock.patch.object(server, "TOOLS", server.TOOLS + [{"name": "export_all"}]):
            _, b = call({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            self.assertIn("export_all", [t["name"] for t in b["result"]["tools"]])
            self.assertEqual(tool("export_all", AUTH, "/a/mcp")[1]["result"]["content"][0]["text"], "export_all ran")

    def test_jwt_server_needs_both(self):
        self.assertEqual(tool("echo", AUTH, "/j/mcp")[0], 401)
        self.assertEqual(tool("echo", {"authorization": "Bearer " + jwt()}, "/j/mcp")[0], 401)
        s, b = tool("whoami", {**AUTH, "authorization": "Bearer " + jwt()}, "/j/mcp")
        self.assertEqual(s, 200)
        seen = json.loads(b["result"]["content"][0]["text"])
        self.assertEqual(seen["_jwt"]["sub"], "u1")
        self.assertEqual(seen["authorization"], "<redacted>")

    def test_bad_tokens(self):
        t = jwt()
        bad = {"tampered": t[:-4] + ("AAAA" if not t.endswith("AAAA") else "BBBB"),
               "expired": jwt({"exp": int(time.time()) - 1}), "iss": jwt({"iss": "https://evil"}),
               "kid": jwt(kid="nope"), "alg": jwt(alg="HS256"), "garbage": "x.y"}
        for why, tok in bad.items():
            self.assertEqual(tool("echo", {**AUTH, "authorization": tok}, "/j/mcp")[0], 401, why)

    def test_audience(self):
        with mock.patch.dict(os.environ, {"JWT_AUDIENCE": "mcp-probe"}):
            self.assertEqual(tool("echo", {**AUTH, "authorization": jwt({"aud": "gw"})}, "/j/mcp")[0], 401)
            self.assertEqual(tool("echo", {**AUTH, "authorization": jwt({"aud": ["gw", "mcp-probe"]})}, "/j/mcp")[0], 200)

    def test_tool_authz(self):
        h = {**AUTH, "authorization": jwt()}
        self.assertFalse(tool("echo", h, "/j/mcp")[1]["result"]["isError"])
        b = tool("danger", h, "/j/mcp")[1]
        self.assertTrue(b["result"]["isError"])
        self.assertIn("forbidden", b["result"]["content"][0]["text"])
        h2 = {**AUTH, "authorization": jwt({"groups": ["eng-l2"]})}
        self.assertFalse(tool("danger", h2, "/j/mcp")[1]["result"]["isError"])
        self.assertFalse(tool("danger", AUTH, "/a/mcp")[1]["result"]["isError"])  # no JWT server: no authz

    def test_oauth_server(self):
        s, _ = tool("echo", AUTH, "/o/mcp")
        self.assertEqual(s, 401)
        event = {"rawPath": "/o/mcp", "requestContext": {"http": {"method": "POST"}},
                 "headers": {"host": "probe.example"}, "body": "{}"}
        r = server.handler(event, None)
        self.assertEqual(r["headers"]["www-authenticate"],
                         'Bearer resource_metadata="https://probe.example/.well-known/oauth-protected-resource/o/mcp"')
        self.assertEqual(tool("echo", {"authorization": "Bearer " + jwt()}, "/o/mcp")[0], 200)

    def test_protected_resource_metadata(self):
        event = {"rawPath": "/.well-known/oauth-protected-resource/o/mcp", "headers": {"host": "probe.example"},
                 "requestContext": {"http": {"method": "GET"}}}
        r = server.handler(event, None)
        self.assertEqual(r["statusCode"], 200)
        self.assertEqual(json.loads(r["body"]), {"resource": "https://probe.example/o/mcp", "authorization_servers": [ISS],
                                                 "bearer_methods_supported": ["header"]})
        event["rawPath"] = "/.well-known/oauth-protected-resource/a/mcp"
        self.assertEqual(server.handler(event, None)["statusCode"], 404)


if __name__ == "__main__":
    unittest.main()
