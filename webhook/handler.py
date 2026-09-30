"""Portkey / Prisma AIRS AI Gateway webhook guardrail (default.webhook), on a Lambda Function URL.

The gateway POSTs {request, response, metadata, provider, requestType, eventType} and sends the
client headers listed in the guardrail's forwardHeaders. We answer {"verdict": bool}; false blocks
the request when the guardrail's deny action is on.

Policy (env POLICY, JSON):
  ip_headers    header names to read the client IP from, first present wins
  allow_cidrs   if non-empty, the client IP must be inside one of these
  deny_cidrs    the client IP must not be inside any of these
  header_rules  [{"header": name, "require": regex} | {"header": name, "deny": regex}]
Auth: the gateway must send env TOKEN in x-guardrail-token (set in the guardrail's headers).
Every call logs the received header names (values of auth headers are dropped) so you can see
what the gateway actually forwards.
"""

import base64
import hmac
import ipaddress
import json
import logging
import os
import re

log = logging.getLogger()
log.setLevel(logging.INFO)

TOKEN_HEADER = "x-guardrail-token"
SECRET_HEADERS = {TOKEN_HEADER, "authorization", "x-portkey-api-key", "x-api-key", "cookie"}


def load_policy(raw):
    p = json.loads(raw or "{}")
    return {
        "ip_headers": [h.lower() for h in p.get("ip_headers", ["cf-connecting-ip"])],
        "allow_cidrs": [ipaddress.ip_network(c, strict=False) for c in p.get("allow_cidrs", [])],
        "deny_cidrs": [ipaddress.ip_network(c, strict=False) for c in p.get("deny_cidrs", [])],
        "header_rules": [
            {"header": r["header"].lower(), "require": r.get("require"), "deny": r.get("deny")}
            for r in p.get("header_rules", [])
        ],
    }


def client_ip(headers, ip_headers):
    """Return (header, ip) for the first ip header that holds a parseable address."""
    for h in ip_headers:
        v = headers.get(h)
        if not v:
            continue
        try:
            return h, ipaddress.ip_address(v.split(",")[0].strip())
        except ValueError:
            continue
    return None, None


def evaluate(headers, policy):
    """Return (verdict, reason). headers must have lowercase names."""
    if policy["allow_cidrs"] or policy["deny_cidrs"]:
        src, ip = client_ip(headers, policy["ip_headers"])
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


POLICY = load_policy(os.environ.get("POLICY"))


def respond(status, body):
    return {"statusCode": status, "headers": {"content-type": "application/json"}, "body": json.dumps(body)}


def handler(event, context):
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
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

    verdict, reason = evaluate(headers, POLICY)
    log.info(json.dumps({
        "verdict": verdict,
        "reason": reason,
        "eventType": payload.get("eventType"),
        "requestType": payload.get("requestType"),
        "provider": payload.get("provider"),
        "metadata": payload.get("metadata"),
        "headers": {k: ("<redacted>" if k in SECRET_HEADERS else v) for k, v in sorted(headers.items())},
    }))
    return respond(200, {"verdict": verdict, "data": {"reason": reason}})
