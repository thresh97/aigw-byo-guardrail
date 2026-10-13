"""Probe MCP server for testing MCP guardrails through the AI Gateway, on a Lambda Function URL.

Streamable HTTP transport, stateless, JSON responses only (no SSE, no session id). The first path segment names the
server, so one function can stand in for several: /a/mcp and /b/mcp are two servers with the same tools.

Tools:
  echo(text)      returns text (argument inspection)
  get_canary()    returns a fixed marker string (response-side checks)
  danger(action)  returns what it would have done (rules aimed at one tool)
  whoami()        returns the headers this server received, auth values redacted (what the gateway forwards upstream)

Auth: if env TOKEN is set, requests must carry it in x-mcp-token (the MCP integration's static headers).
Every request is logged (method, tool, arguments, headers with auth values redacted).
"""

import base64
import hmac
import json
import logging
import os

log = logging.getLogger()
log.setLevel(logging.INFO)

TOKEN_HEADER = "x-mcp-token"
SECRET_HEADERS = {TOKEN_HEADER, "authorization", "x-portkey-api-key", "x-api-key", "cookie"}
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
CANARY = "BYO-PROBE-CANARY-7f3a"

TOOLS = [
    {"name": "echo", "description": "Return the given text unchanged.",
     "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}},
    {"name": "get_canary", "description": "Return a fixed marker string.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "danger", "description": "Pretend to perform a destructive action and say what it would have done.",
     "inputSchema": {"type": "object", "properties": {"action": {"type": "string"}}, "required": ["action"]}},
    {"name": "whoami", "description": "Return the HTTP headers this server received (auth values redacted).",
     "inputSchema": {"type": "object", "properties": {}}},
]


def redact(headers):
    return {k: ("<redacted>" if k in SECRET_HEADERS else v) for k, v in sorted(headers.items())}


def call_tool(name, args, headers):
    """Return (text, is_error)."""
    if name == "echo":
        return str(args.get("text", "")), False
    if name == "get_canary":
        return CANARY, False
    if name == "danger":
        return f"would have performed: {args.get('action', '')}", False
    if name == "whoami":
        return json.dumps(redact(headers)), False
    return f"unknown tool: {name}", True


def rpc(msg, server, headers):
    """Handle one JSON-RPC message. Return the response object, or None for a notification."""
    mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
    if mid is None:
        return None
    if method == "initialize":
        asked = params.get("protocolVersion")
        result = {
            "protocolVersion": asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": f"byo-probe-mcp-{server}", "version": "1"},
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        text, is_error = call_tool(params.get("name"), params.get("arguments") or {}, headers)
        result = {"content": [{"type": "text", "text": text}], "isError": is_error}
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def respond(status, body=None):
    r = {"statusCode": status, "headers": {"content-type": "application/json"}}
    if body is not None:
        r["body"] = json.dumps(body)
    return r


def handler(event, context):
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    http = (event.get("requestContext") or {}).get("http") or {}
    path = event.get("rawPath") or http.get("path") or "/"
    server = path.strip("/").split("/")[0] or "default"
    token = os.environ.get("TOKEN", "")
    if token and not hmac.compare_digest(headers.get(TOKEN_HEADER, ""), token):
        log.warning("rejected: bad or missing %s", TOKEN_HEADER)
        return respond(401, {"error": "unauthorized"})
    if http.get("method", "POST") != "POST":
        return respond(405, {"error": "only POST (no SSE stream)"})

    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode()
    try:
        msg = json.loads(raw)
    except ValueError:
        return respond(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})

    msgs = msg if isinstance(msg, list) else [msg]
    for m in msgs:
        p = m.get("params") or {}
        log.info(json.dumps({
            "server": server, "method": m.get("method"), "id": m.get("id"),
            "tool": p.get("name") if m.get("method") == "tools/call" else None,
            "arguments": p.get("arguments") if m.get("method") == "tools/call" else None,
            "headers": redact(headers),
        }))
    out = [r for r in (rpc(m, server, headers) for m in msgs) if r is not None]
    if not out:
        return respond(202)
    return respond(200, out if isinstance(msg, list) else out[0])
