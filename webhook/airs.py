"""Prisma AIRS runtime scan for MCP tool calls, called from handler.py (no Lambda specifics, Python stdlib only).

The gateway calls the webhook twice per tools/call of a mapped tool: beforeRequestHook with the tool name and
arguments, afterRequestHook with the result as well. Each call is sent to the AIRS sync scan API, and an AIRS
"block" becomes verdict false, which the gateway turns into JSON-RPC -32446.

Config (env AIRS, JSON; the scan is off when AIRS is unset):
  profile         AIRS security profile name for both hooks
  input_profile   override for beforeRequestHook (tool arguments)
  output_profile  override for afterRequestHook (tool result)
  content         "tool_event" (default): the scan API's MCP content type (metadata server/tool, `input` or `output`).
                  Checked against the profile's tool-call / tool-response sections (per-content-type profiles).
                  "text": arguments as plain text in `prompt`, the result in `response`, as on the LLM path. AIRS
                  profiles can't enable prompt injection for `response`, so this misses injections in tool results
  fail            "closed" (default): an AIRS error, timeout or missing key blocks. "open": it allows (and logs)
  max_bytes       per content field, UTF-8 bytes (default 100000); longer content is cut and the cut is logged
  timeout_ms      AIRS request timeout (default 5000). Keep it below the guardrail check's own timeout
  base_url        default https://service.api.aisecurity.paloaltonetworks.com (pick your region's)
  app_name        AIRS metadata.app_name (default aigw-mcp-webhook); app_user comes from x-portkey-metadata `_user`
Env AIRS_API_KEY: the AIRS runtime API key (x-pan-token). Keep it out of AIRS and out of logs.
Requests that aren't MCP tool calls are passed through unscanned: use the gateway's native AIRS guardrail for LLM traffic.
"""

import json
import time
import urllib.error
import urllib.request

DEFAULT_BASE = "https://service.api.aisecurity.paloaltonetworks.com"
SCAN_PATH = "/v1/scan/sync/request"


def load_config(raw):
    if not raw:
        return None
    c = json.loads(raw)
    if not (c.get("profile") or (c.get("input_profile") and c.get("output_profile"))):
        raise ValueError("AIRS needs profile, or both input_profile and output_profile")
    if c.get("content", "tool_event") not in ("text", "tool_event"):
        raise ValueError("AIRS content must be text or tool_event")
    if c.get("fail", "closed") not in ("closed", "open"):
        raise ValueError("AIRS fail must be closed or open")
    return {
        "input_profile": c.get("input_profile") or c["profile"],
        "output_profile": c.get("output_profile") or c["profile"],
        "content": c.get("content", "tool_event"),
        "fail_open": c.get("fail", "closed") == "open",
        "max_bytes": int(c.get("max_bytes") or 100000),
        "timeout": int(c.get("timeout_ms") or 5000) / 1000,
        "url": (c.get("base_url") or DEFAULT_BASE).rstrip("/") + SCAN_PATH,
        "app_name": c.get("app_name") or "aigw-mcp-webhook",
    }


def cut(s, max_bytes):
    """Return (s cut to max_bytes UTF-8 bytes, original byte length)."""
    b = s.encode()
    return (s if len(b) <= max_bytes else b[:max_bytes].decode(errors="ignore")), len(b)


def args_text(tool, args):
    """Tool arguments as plain text: string values unescaped, one per line, so encoded or non-ASCII payloads reach
    AIRS as the client wrote them instead of inside JSON escapes."""
    lines = [f"tool: {tool}"]

    def walk(v, path):
        if isinstance(v, dict):
            for k, x in v.items():
                walk(x, f"{path}.{k}" if path else str(k))
        elif isinstance(v, list):
            for i, x in enumerate(v):
                walk(x, f"{path}[{i}]")
        elif isinstance(v, str):
            lines.append(f"{path}: {v}")
        elif v is not None:
            lines.append(f"{path}: {json.dumps(v)}")

    walk(args if isinstance(args, (dict, list)) else {"arguments": args}, "")
    return "\n".join(lines)


def result_text(response):
    """The tool result as text: the gateway's response.text, else the text parts of response.json.content."""
    if response.get("text"):
        return response["text"]
    j = response.get("json") or {}
    parts = [c.get("text", "") for c in j.get("content", []) if isinstance(c, dict) and c.get("type") == "text"]
    if parts:
        return "\n".join(parts)
    return json.dumps(j, ensure_ascii=False) if j else ""


def build(payload, cfg):
    """Return (scan request body, info) for one hook."""
    meta = payload.get("metadata") or {}
    req = (payload.get("request") or {}).get("json") or {}
    tool = meta.get("mcpToolName") or req.get("name") or "unknown"
    after = payload.get("eventType") == "afterRequestHook"
    info = {"hook": "output" if after else "input", "tool": tool, "server": meta.get("mcpServerId"), "truncated": []}

    def field(name, s):
        s, n = cut(s, cfg["max_bytes"])
        if n > cfg["max_bytes"]:
            info["truncated"].append({"field": name, "bytes": n})
        return s

    if cfg["content"] == "tool_event":
        te = {"metadata": {"ecosystem": "mcp", "method": "tools/call",
                           "server_name": meta.get("mcpServerId") or "unknown", "tool_invoked": tool}}
        if after:
            te["output"] = field("output", result_text(payload.get("response") or {}))
        else:
            te["input"] = field("input", json.dumps(req.get("arguments") or {}, ensure_ascii=False))
        content = {"tool_event": te}
    else:
        content = {"prompt": field("prompt", args_text(tool, req.get("arguments")))}
        if after:
            content["response"] = field("response", result_text(payload.get("response") or {}))

    body = {
        "ai_profile": {"profile_name": cfg["output_profile"] if after else cfg["input_profile"]},
        "metadata": {"app_name": cfg["app_name"], "app_user": str(meta.get("_user") or "mcp-client"),
                     "ai_model": f"mcp:{meta.get('mcpServerId') or 'unknown'}/{tool}"},
        "contents": [content],
    }
    return body, info


def post(url, key, body, timeout):
    """POST the scan. Return (http status, parsed body or None, error text or None)."""
    req = urllib.request.Request(url, json.dumps(body).encode(),
                                 {"content-type": "application/json", "x-pan-token": key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.load(r), None
    except urllib.error.HTTPError as e:
        return e.code, None, e.read().decode(errors="replace")[:300]
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        return None, None, f"{type(e).__name__}: {e}"


def check(payload, cfg, key, poster=None):
    """Return (verdict, reason, log info) for one webhook call."""
    if payload.get("requestType") != "mcpToolCall":
        return True, "airs: not an MCP tool call, not scanned", {"airs": "skipped"}
    body, info = build(payload, cfg)
    t = time.monotonic()
    if not key:
        status, res, err = None, None, "AIRS_API_KEY is not set"
    else:
        status, res, err = (poster or post)(cfg["url"], key, body, cfg["timeout"])
    info.update(airs_status=status, latency_ms=int((time.monotonic() - t) * 1000), profile=body["ai_profile"]["profile_name"])
    if err or not isinstance(res, dict) or res.get("action") not in ("allow", "block"):
        info.update(result="error", airs_error=err or f"unexpected response: {str(res)[:200]}")
        verdict = cfg["fail_open"]
        return verdict, f"airs error ({f'HTTP {status}' if status else 'no HTTP response'}), failing {'open' if verdict else 'closed'}: {info['airs_error']}", info
    info.update(result=res["action"], action=res["action"], category=res.get("category"), scan_id=res.get("scan_id"),
                report_id=res.get("report_id"), detected={k: v for k in ("prompt_detected", "response_detected",
                                                                           "tool_detected") if (v := res.get(k))})
    if res["action"] == "block":
        return False, f"airs block ({res.get('category')}) on {info['hook']} of {info['tool']}, scan_id {res.get('scan_id')}", info
    return True, f"airs allow on {info['hook']} of {info['tool']}, scan_id {res.get('scan_id')}", info
