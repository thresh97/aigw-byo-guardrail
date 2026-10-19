"""Portkey / Prisma AIRS AI Gateway webhook guardrail (default.webhook), on a Lambda Function URL or any
HTTP host (server.py wraps it for Kubernetes and docker).

The gateway POSTs {request, response, metadata, provider, requestType, eventType} and sends the
client headers listed in the guardrail's forwardHeaders. We answer {"verdict": bool}; false blocks
the request when the guardrail's deny action is on.

Policy (env POLICY, JSON):
  ip_headers    header names to read the client IP from, first present wins
  trusted_hops  0 (default): take the leftmost entry of a comma list. Only safe for a header a trusted edge sets
                whole (cf-connecting-ip on SaaS). N: take the Nth entry from the right, i.e. the one your Nth
                trusted proxy appended (x-forwarded-for behind a load balancer in append mode: 1). A shorter
                list has no trustworthy entry and fails closed. A Lambda Function URL keeps only the leftmost
                x-forwarded-for entry, so N > 0 needs a host that passes the header through (server.py).
  allow_cidrs   if non-empty, the client IP must be inside one of these
  deny_cidrs    the client IP must not be inside any of these
  header_rules  [{"header": name, "require": regex} | {"header": name, "deny": regex}]
MCP tool allowlist (per request, from header x-tool-policy, normally a static header in the guardrail check, so the
policy lives in the guardrail config and edits need no Lambda or MCP integration change):
  x-tool-policy {"<server slug>": [tool, ...], "<workspace>/<server slug>": [...]}
  The server comes from metadata.mcpServerId (the integration slug), the workspace from metadata.mcpWorkspaceId, the tool
  from metadata.mcpToolName. A "<workspace>/<slug>" key wins over a bare slug. Anything not listed is denied, and so is a
  server missing from the policy, a request without MCP metadata and a malformed policy. No header: the rule is off.
  Never list x-tool-policy in the guardrail's forwardHeaders (a client could then send its own policy).
MCP tool descriptor pinning (env PIN and PIN_HEADERS; off when PIN is unset): runs after the rules above pass. A tool that
is new on its server, or whose descriptor changed since it was first seen, is denied until approved. Optionally it also
scans descriptors with Prisma AIRS (env AIRS_LIST_API_KEY; blocked tools never join the baseline), learns new servers for
a while, and checks arguments and structuredContent against the pinned schemas. Config: pin.py.
Prisma AIRS scan of MCP tool calls (env AIRS and AIRS_API_KEY; off when AIRS is unset): runs after the rules above pass,
and an AIRS block denies. Config and behavior: airs.py.
Response data (the gateway shows it as responseData in the check result): reason, stage (the check that decided: policy,
tools, pin or airs), elapsed_ms (time spent in the webhook), and with AIRS an airs object: result (allow, block or
error), scan_id, report_id, category, airs_status, airs_error, latency_ms and the other AIRS_DATA fields, never content.
Auth: the gateway must send env TOKEN in x-guardrail-token (set in the guardrail's headers).
Every call logs the received header names (values of auth headers are dropped) so you can see
what the gateway actually forwards. Env LOG_PAYLOAD=1 also logs the request and response objects (prompt, tool
call and result content goes to the logs; leave it off outside testing).
"""

import base64
import hmac
import ipaddress
import json
import logging
import os
import re
import time

import airs
import pin

log = logging.getLogger()
log.setLevel(logging.INFO)

TOKEN_HEADER = "x-guardrail-token"
SECRET_HEADERS = {TOKEN_HEADER, "authorization", "x-portkey-api-key", "x-api-key", "cookie"}


def load_policy(raw):
    p = json.loads(raw or "{}")
    return {
        "ip_headers": [h.lower() for h in p.get("ip_headers", ["cf-connecting-ip"])],
        "trusted_hops": int(p.get("trusted_hops") or 0),
        "allow_cidrs": [ipaddress.ip_network(c, strict=False) for c in p.get("allow_cidrs", [])],
        "deny_cidrs": [ipaddress.ip_network(c, strict=False) for c in p.get("deny_cidrs", [])],
        "header_rules": [
            {"header": r["header"].lower(), "require": r.get("require"), "deny": r.get("deny")}
            for r in p.get("header_rules", [])
        ],
    }


def client_ip(headers, ip_headers, trusted_hops=0):
    """Return (header, ip) for the first ip header that holds a parseable address at the trusted position."""
    for h in ip_headers:
        v = headers.get(h)
        if not v:
            continue
        entries = [e.strip() for e in v.split(",")]
        if trusted_hops and len(entries) < trusted_hops:
            continue
        try:
            return h, ipaddress.ip_address(entries[-trusted_hops] if trusted_hops else entries[0])
        except ValueError:
            continue
    return None, None


def evaluate(headers, policy):
    """Return (verdict, reason). headers must have lowercase names."""
    if policy["allow_cidrs"] or policy["deny_cidrs"]:
        src, ip = client_ip(headers, policy["ip_headers"], policy["trusted_hops"])
        if ip is None:
            return False, f"no client ip in {policy['ip_headers']}"
        if any(ip in n for n in policy["deny_cidrs"]):
            return False, f"{src}={ip} in deny_cidrs"
        if policy["allow_cidrs"] and not any(ip in n for n in policy["allow_cidrs"]):
            return False, f"{src}={ip} not in allow_cidrs"
    for r in policy["header_rules"]:
        v = headers.get(r["header"])
        if r["require"] and not (v and re.search(r["require"], v)):
            return False, f"{r['header']} missing or not matching {r['require']!r}"
        if r["deny"] and v and re.search(r["deny"], v):
            return False, f"{r['header']} matches deny {r['deny']!r}"
    return True, "ok"


TOOL_POLICY_HEADER = "x-tool-policy"


def evaluate_tools(raw, metadata):
    """MCP tool allowlist. raw = the x-tool-policy header value. Return (verdict, reason)."""
    try:
        policy = json.loads(raw)
        if not isinstance(policy, dict) or not all(
                isinstance(v, list) and all(isinstance(t, str) for t in v) for v in policy.values()):
            raise ValueError("not an object of string lists")
    except ValueError as e:
        return False, f"malformed {TOOL_POLICY_HEADER}: {e}"
    m = metadata if isinstance(metadata, dict) else {}
    server, ws, tool = m.get("mcpServerId"), m.get("mcpWorkspaceId"), m.get("mcpToolName")
    if not server or not tool:
        return False, "no mcpServerId/mcpToolName in metadata"
    key = f"{ws}/{server}" if f"{ws}/{server}" in policy else server
    if key not in policy:
        return False, f"server {server} (workspace {ws}) not in {TOOL_POLICY_HEADER}"
    if tool not in policy[key]:
        return False, f"tool {tool} not allowed on {key}"
    return True, f"tool {tool} allowed on {key}"


POLICY = load_policy(os.environ.get("POLICY"))
LOG_PAYLOAD = os.environ.get("LOG_PAYLOAD", "") in ("1", "true")
AIRS = airs.load_config(os.environ.get("AIRS"))
PIN = pin.load_config(os.environ.get("PIN"))
PIN_HEADERS = pin.headers_from_env() if PIN else {}


# AIRS fields returned in data.airs (the gateway shows them as responseData.airs); never content
AIRS_DATA = ("result", "hook", "tool", "profile", "action", "category", "scan_id", "report_id", "detected",
             "airs_status", "airs_error", "latency_ms", "truncated")


def respond(status, body):
    return {"statusCode": status, "headers": {"content-type": "application/json"}, "body": json.dumps(body)}


def handler(event, context):
    t0 = time.monotonic()
    headers ={k.lower(): v for k, v in (event.get("headers") or {}).items()}
    if not hmac.compare_digest(headers.get(TOKEN_HEADER, ""), os.environ.get("TOKEN", "")):
        log.warning("rejected: bad or missing %s", TOKEN_HEADER)
        return respond(401, {"error": "unauthorized"})

    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode()
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = {}

    stage = "policy"
    verdict, reason = evaluate(headers, POLICY)
    if verdict and TOOL_POLICY_HEADER in headers:
        stage = "tools"
        verdict, reason = evaluate_tools(headers[TOOL_POLICY_HEADER], payload.get("metadata"))
    pinned = scan = None
    if verdict and PIN:
        stage = "pin"
        verdict, reason, pinned = pin.check(payload, PIN, PIN_HEADERS)
    if verdict and AIRS:
        stage = "airs"
        verdict, reason, scan = airs.check(payload, AIRS, os.environ.get("AIRS_API_KEY"))
    elapsed_ms = int((time.monotonic() - t0) * 1000)
    entry = {
        "verdict": verdict,
        "reason": reason,
        "stage": stage,
        "elapsed_ms": elapsed_ms,
        "eventType": payload.get("eventType"),
        "requestType": payload.get("requestType"),
        "provider": payload.get("provider"),
        "metadata": payload.get("metadata"),
        "headers": {k: ("<redacted>" if k in SECRET_HEADERS else v) for k, v in sorted(headers.items())},
    }
    if pinned:
        entry["pin"] = pinned
    if scan:
        entry["airs"] = scan
    if LOG_PAYLOAD:
        entry["payload_keys"] = sorted(payload)
        entry["request"] = payload.get("request")
        entry["response"] = payload.get("response")
    (log.warning if scan and scan.get("result") == "error" else log.info)(json.dumps(entry))
    data = {"reason": reason, "stage": stage, "elapsed_ms": elapsed_ms}
    if scan and scan.get("result"):
        data["airs"] = {k: scan[k] for k in AIRS_DATA if scan.get(k) not in (None, [], {})}
    return respond(200, {"verdict": verdict, "data": data})
