"""MCP tool descriptor pinning (rug-pull detection) for MCP tool calls, called from handler.py. Python stdlib only.

The gateway runs MCP guardrails only on tools/call, never on tools/list, so the webhook fetches the server's tools/list
itself (normally through the gateway, so it pins what clients are actually served) and compares each tool with the
first version it saw:
  first seen     the server's whole tool list becomes its baseline (trust on first use), or `pinctl.py seed` sets it
                 from the onboarding pipeline before any call
  new tool       a tool that isn't in the baseline goes into the penalty box ("new"); calls to it are denied
  changed tool   a tool whose fingerprint differs from the baseline goes into the penalty box ("changed"); denied
The penalty box is sticky: changing the descriptor back doesn't release a tool, only `pinctl.py approve` does (it takes
the descriptor into the baseline). A tool that's no longer in tools/list is denied too. Every new penalty entry is
logged once as a "pin_drift" line, for alerting.

With `airs`, every tool version that would be trusted or is pending is scanned once with Prisma AIRS (name, title,
description, parameter descriptions and annotations, as text), and the latest result is kept per server and tool
(pinctl.py list / show). A version AIRS blocks never joins the baseline: it goes into the penalty box as "airs-blocked",
and `approve` needs --force. A failed scan is "airs-error" (with fail closed) and is retried at the next fetch. A clean
scan doesn't release anything by itself on a locked server: a human still approves. First sight of a server, and
learning mode, scan inline before trusting; on a locked server new and changed tools are denied anyway, so they're
scanned in the background.

Learning mode (`learn`, or `pinctl.py learn`): for a while, new and changed tools join the baseline by themselves
("pin_learned" lines) if their scan is clean, so a server can settle before it's locked. Tools that fail the scan are
kept out as above, and penalty entries from before aren't released. Schema validation only logs while learning. The
server locks itself when the period ends ("pin_locked"), or with `pinctl.py lock`.

Config (env PIN, JSON; pinning is off when PIN is unset):
  url           tools/list endpoint, with {workspace} and {server} replaced from the call's metadata (mcpWorkspaceId,
                mcpServerId). Through the gateway: "https://<gateway>/m/{workspace}/{server}/mcp". Required
  store         state file (default /data/pins.json). It must survive restarts (a lost file means trust on first use
                again) and be shared by every webhook process: one replica, on a persistent volume. Not on Lambda
  refresh_s     how long a fetched tools/list is reused (default 30). Detection delay is up to this (gateway 2.29.0
                passes tools/list through live)
  timeout_ms    per HTTP request to the MCP endpoint (default 3000). A fetch is three requests (initialize,
                notifications/initialized, tools/list), so keep 3 x this below the guardrail check's own timeout
  fail          "closed" (default): a failed fetch or state error denies. "open": allows (and logs)
  quarantine    "tool" (default): only the drifted tool is denied. "server": every tool on a server with drift is denied
                (a poisoned description can steer the model to misuse other tools)
  fields        descriptor fields in the fingerprint (default name, title, description, inputSchema, outputSchema,
                annotations)
  require_seed  true: a server without a baseline is denied instead of trusted on first use (default false)
  airs          scan descriptors with Prisma AIRS: {"profile": "<name>" (required), "content": "tool_event" (default:
                a tools/list tool event whose output is the descriptor as a JSON array, which AIRS checks for context
                poisoning per tool) or "prompt" (the descriptor as plain text, checked as a user prompt), "fail":
                "closed" (default) or "open", "app_name" (default aigw-mcp-descriptors), "max_bytes" (default 100000),
                "timeout_ms" (default 5000), "base_url"}. Scans run on the call path at first sight and in learning
                mode: keep them inside the guardrail check's timeout
  learn         {"duration_s": N}: a server first seen by a call starts in learning mode for N seconds (no duration_s:
                until `pinctl.py lock`). Unset (default): new servers are locked from the first call
  validate      checks a pinned tool's live call against its PINNED descriptor (schema.py), never the served one:
                {"input": mode, "output": mode, "unknown": "allow"|"deny"}. input: tools/call arguments against
                inputSchema (beforeRequestHook). output: the result's structuredContent against outputSchema
                (afterRequestHook; a result without structuredContent fails, tool errors (isError) and tools without
                an outputSchema are skipped). mode "off" (default), "log" (a "pin_validation" line, verdict unchanged)
                or "enforce" (deny). unknown: what a schema keyword the validator doesn't implement does, "allow"
                (default) or "deny"
Env PIN_HEADERS: JSON object of headers for the tools/list requests, e.g. {"x-portkey-api-key": "<key with mcp.invoke>"}.
It's a credential: keep it out of PIN and out of logs.
Env AIRS_LIST_API_KEY: the AIRS runtime API key for descriptor scans, separate from the tool call scans' AIRS_API_KEY
(its own app and profile in AIRS). Also a credential.
Requests that aren't MCP tool calls pass through unchecked.
"""

import contextlib
import copy
import fcntl
import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import airs
import schema

log = logging.getLogger()

DEFAULT_FIELDS = ["name", "title", "description", "inputSchema", "outputSchema", "annotations"]
PROTOCOL_VERSION = "2025-06-18"
MAX_PAGES = 50
VALIDATE_MODES = ("off", "log", "enforce")


def load_config(raw):
    if not raw:
        return None
    if os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        raise ValueError("PIN needs one persistent state file; Lambda instances don't share one")
    c = json.loads(raw)
    if not c.get("url"):
        raise ValueError("PIN needs url")
    if c.get("fail", "closed") not in ("closed", "open"):
        raise ValueError("PIN fail must be closed or open")
    if c.get("quarantine", "tool") not in ("tool", "server"):
        raise ValueError("PIN quarantine must be tool or server")
    a = c.get("airs")
    if a is not None and (not isinstance(a, dict) or not a.get("profile")
                          or a.get("content", "tool_event") not in ("tool_event", "prompt")
                          or a.get("fail", "closed") not in ("closed", "open")):
        raise ValueError("PIN airs needs profile; content tool_event or prompt; fail closed or open")
    learn = c.get("learn")
    if learn is not None and not isinstance(learn, dict):
        raise ValueError("PIN learn must be an object, e.g. {\"duration_s\": 86400}")
    v = c.get("validate") or {}
    if not isinstance(v, dict) or any(v.get(k, "off") not in VALIDATE_MODES for k in ("input", "output")) \
            or v.get("unknown", "allow") not in ("allow", "deny"):
        raise ValueError("PIN validate: input and output must be off, log or enforce; unknown allow or deny")
    return {
        "url": c["url"],
        "store": c.get("store") or "/data/pins.json",
        "refresh_s": float(c.get("refresh_s", 30)),
        "timeout": int(c.get("timeout_ms") or 3000) / 1000,
        "fail_open": c.get("fail", "closed") == "open",
        "quarantine": c.get("quarantine", "tool"),
        "fields": list(c.get("fields") or DEFAULT_FIELDS),
        "require_seed": bool(c.get("require_seed", False)),
        "validate": {"input": v.get("input", "off"), "output": v.get("output", "off"),
                     "unknown": v.get("unknown", "allow")},
        "airs": a and {
            "profile": a["profile"],
            "app_name": a.get("app_name") or "aigw-mcp-descriptors",
            "content": a.get("content", "tool_event"),
            "fail_open": a.get("fail", "closed") == "open",
            "max_bytes": int(a.get("max_bytes") or 100000),
            "timeout": int(a.get("timeout_ms") or 5000) / 1000,
            "url": (a.get("base_url") or airs.DEFAULT_BASE).rstrip("/") + airs.SCAN_PATH,
        },
        "learn": None if learn is None else {"duration_s": learn.get("duration_s")},
    }


def headers_from_env():
    h = json.loads(os.environ.get("PIN_HEADERS") or "{}")
    if not isinstance(h, dict):
        raise ValueError("PIN_HEADERS must be a JSON object")
    return {str(k): str(v) for k, v in h.items()}


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def descriptor(tool, fields):
    """The fingerprinted part of a tool: the configured fields that are present."""
    return {f: tool[f] for f in fields if f in tool}


def fingerprint(tool, fields):
    return hashlib.sha256(canonical(descriptor(tool, fields)).encode()).hexdigest()


# --- MCP client (Streamable HTTP; JSON or SSE responses) ---------------------------------------------------------

class FetchError(Exception):
    pass


def _post(url, headers, msg, timeout, session=None):
    """POST one JSON-RPC message. Return (response message or None, session id)."""
    h = {"content-type": "application/json", "accept": "application/json, text/event-stream", **headers}
    if session:
        h["mcp-session-id"] = session
        h["mcp-protocol-version"] = PROTOCOL_VERSION
    req = urllib.request.Request(url, data=json.dumps(msg).encode(), headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            sid = r.headers.get("mcp-session-id") or session
            body = r.read().decode()
            ctype = r.headers.get("content-type", "")
    except urllib.error.HTTPError as e:
        raise FetchError(f"{msg.get('method')}: HTTP {e.code}") from None
    except (urllib.error.URLError, OSError) as e:
        raise FetchError(f"{msg.get('method')}: {getattr(e, 'reason', e)}") from None
    if "id" not in msg or not body.strip():
        return None, sid
    for m in (_sse_messages(body) if "text/event-stream" in ctype else [json.loads(body)]):
        if isinstance(m, dict) and m.get("id") == msg["id"]:
            if "error" in m:
                raise FetchError(f"{msg['method']}: JSON-RPC error {m['error'].get('code')} {m['error'].get('message')}")
            return m.get("result") or {}, sid
    raise FetchError(f"{msg['method']}: no response with id {msg['id']}")


def _sse_messages(body):
    """JSON messages in an SSE body (one per event; multi-line data joined)."""
    out, data = [], []
    for line in body.splitlines() + [""]:
        if line.startswith("data:"):
            data.append(line[5:].lstrip())
        elif not line.strip() and data:
            try:
                out.append(json.loads("\n".join(data)))
            except ValueError:
                pass
            data = []
    return out


def list_tools(url, headers, timeout):
    """initialize + notifications/initialized + tools/list (all pages). Return the list of tool objects."""
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                       "clientInfo": {"name": "aigw-mcp-pin", "version": "1"}}}
    _, sid = _post(url, headers, init, timeout)
    _post(url, headers, {"jsonrpc": "2.0", "method": "notifications/initialized"}, timeout, sid)
    tools, cursor = [], None
    for page in range(MAX_PAGES):
        msg = {"jsonrpc": "2.0", "id": 2 + page, "method": "tools/list", "params": {"cursor": cursor} if cursor else {}}
        res, sid = _post(url, headers, msg, timeout, sid)
        if not isinstance(res.get("tools"), list):
            raise FetchError("tools/list: no tools array")
        tools += [t for t in res["tools"] if isinstance(t, dict) and isinstance(t.get("name"), str)]
        cursor = res.get("nextCursor")
        if not cursor:
            break
    else:
        raise FetchError(f"tools/list: more than {MAX_PAGES} pages")
    if sid:  # end the session; ignore failures
        with contextlib.suppress(Exception):
            urllib.request.urlopen(urllib.request.Request(
                url, headers={**headers, "mcp-session-id": sid}, method="DELETE"), timeout=timeout).close()
    return tools


# --- state file ---------------------------------------------------------------------------------------------------

class Store:
    """JSON state file: {"servers": {"<workspace>/<server>": {first_seen, seeded_by, mode, learn_until, tools: {...},
    penalty: {...}, airs: {...}}}}. tools[name] = {hash, descriptor, since}; penalty[name] = {kind: new|changed|
    airs-blocked|airs-error, hash, descriptor, since, last_seen, scan_id?}; airs[name] = the latest descriptor scan
    {hash, status: allow|block|error, action, category, detected, scan_id, report_id, profile, scanned_at, latency_ms,
    threats?, error?}; detected lists the detections that fired (e.g. "tool.injection", "prompt.injection"), threats
    AIRS's tool threat names (e.g. "context poisoning").
    Every access holds an exclusive flock on <store>.lock, so pinctl.py can edit it while the webhook runs."""

    def __init__(self, path):
        self.path = path

    @contextlib.contextmanager
    def open(self, write=True):
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path + ".lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                with open(self.path) as f:
                    state = json.load(f)
            except FileNotFoundError:
                state = {"servers": {}}
            before = copy.deepcopy(state) if write else None
            yield state
            if write and state != before:
                fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(self.path)), prefix=".pins-")
                with os.fdopen(fd, "w") as f:
                    json.dump(state, f, indent=1, sort_keys=True)
                os.replace(tmp, self.path)


def baseline(tools, fields, seeded_by):
    t = now_iso()
    return {"first_seen": t, "seeded_by": seeded_by, "penalty": {},
            "tools": {x["name"]: {"hash": fingerprint(x, fields), "descriptor": descriptor(x, fields), "since": t}
                      for x in tools}}


def new_server(seeded_by, cfg):
    """An empty server entry. A server first seen by a call starts in learning mode when PIN learn is set."""
    srv = {"first_seen": now_iso(), "seeded_by": seeded_by, "mode": "locked", "learn_until": None,
           "tools": {}, "penalty": {}, "airs": {}}
    if cfg.get("learn") is not None and seeded_by == "first-call":
        set_mode(srv, "learning", cfg["learn"]["duration_s"])
    return srv


def set_mode(srv, mode, duration_s=None):
    srv["mode"] = mode
    srv["learn_until"] = None if mode != "learning" or not duration_s else \
        (datetime.now(timezone.utc) + timedelta(seconds=float(duration_s))).strftime("%Y-%m-%dT%H:%M:%SZ")


def learning(srv):
    """True while srv learns; a learning period that has ended switches it to locked."""
    if srv.get("mode") != "learning":
        return False
    if srv.get("learn_until") and srv["learn_until"] <= now_iso():
        set_mode(srv, "locked")
        return False
    return True


def airs_kind(rec, cfg):
    """The penalty kind a descriptor scan forces on its tool version, or None."""
    if not rec or not cfg.get("airs"):
        return None
    if rec["status"] == "block":
        return "airs-blocked"
    if rec["status"] == "error" and not cfg["airs"]["fail_open"]:
        return "airs-error"
    return None


def reconcile(srv, tools, cfg, first=False):
    """Apply a served tools/list to srv. Return (drift, learned).

    Locked: new and changed tools go into the penalty box (kind new/changed, or airs-blocked/airs-error when their
    descriptor scan says so). Learning (or the first sight of a server): they go straight into the baseline, unless
    the scan blocked them or failed closed, or AIRS is on and they haven't been scanned. Learning doesn't release
    new/changed entries from before; a clean scan does release airs-blocked/airs-error ones."""
    t, drift, learned = now_iso(), [], []
    learn = first or learning(srv)
    for x in tools:
        name, h = x["name"], fingerprint(x, cfg["fields"])
        pinned, pen = srv["tools"].get(name), srv["penalty"].get(name)
        if pinned and pinned["hash"] == h and not pen:
            continue
        rec = (srv.get("airs") or {}).get(name)
        rec = rec if rec and rec["hash"] == h else None
        kind = airs_kind(rec, cfg)
        if pen:
            pen["last_seen"] = t
        if learn and kind is None and (rec or not cfg.get("airs")) and not (pen and pen["kind"] in ("new", "changed")):
            srv["tools"][name] = {"hash": h, "descriptor": descriptor(x, cfg["fields"]), "since": t}
            srv["penalty"].pop(name, None)
            learned.append({"tool": name, "kind": "changed" if pinned else "new", "hash": h,
                            "pinned_hash": pinned["hash"] if pinned else None})
            continue
        kind = kind or ("changed" if pinned else "new")
        if pen and pen["hash"] == h and pen["kind"] == kind:
            continue
        srv["penalty"][name] = {"kind": kind, "hash": h, "descriptor": descriptor(x, cfg["fields"]),
                                "since": pen["since"] if pen else t, "last_seen": t}
        if rec and rec.get("scan_id"):
            srv["penalty"][name]["scan_id"] = rec["scan_id"]
        drift.append({"tool": name, "kind": kind, "hash": h, "pinned_hash": pinned["hash"] if pinned else None,
                      "again": bool(pen)})
    return drift, learned


def diff(srv, tools, fields):
    """reconcile() for a locked server without AIRS: put new and changed tools into the penalty box."""
    return reconcile({**srv, "mode": "locked"}, tools, {"fields": fields, "airs": None})[0]


def log_changes(key, drift, learned, first=False):
    for d in drift:
        log.warning(json.dumps({"pin_drift": {"server": key, **d}}))
    if not first:
        for d in learned:
            log.info(json.dumps({"pin_learned": {"server": key, **d}}))


# --- AIRS scan of tool descriptors -------------------------------------------------------------------------------

def descriptor_text(tool):
    """The descriptor as plain text for AIRS: name, title, description, every parameter description, annotations."""
    lines = [f"tool: {tool.get('name')}"]
    for f in ("title", "description"):
        if tool.get(f):
            lines.append(f"{f}: {tool[f]}")

    def walk(sch, path):
        if not isinstance(sch, dict):
            return
        if path and isinstance(sch.get("description"), str):
            lines.append(f"{path}: {sch['description']}")
        for k, sub in (sch.get("properties") or {}).items() if isinstance(sch.get("properties"), dict) else ():
            walk(sub, f"{path}.{k}")
        if isinstance(sch.get("items"), dict):
            walk(sch["items"], f"{path}[]")

    for f in ("inputSchema", "outputSchema"):
        for k, sub in ((tool.get(f) or {}).get("properties") or {}).items() \
                if isinstance((tool.get(f) or {}).get("properties"), dict) else ():
            walk(sub, f"{f}.{k}")
    if tool.get("annotations"):
        lines.append(f"annotations: {canonical(tool['annotations'])}")
    return "\n".join(lines)


def scan_body(key, tool, cfg):
    """The scan request. tool_event: AIRS parses a tools/list output as a JSON array of tools (plain text or
    {"tools": [...]} get HTTP 400), so the served descriptor goes as is and can't be cut: over max_bytes raises
    ValueError."""
    a, name = cfg["airs"], tool.get("name")
    if a["content"] == "tool_event":
        out = json.dumps([tool], ensure_ascii=False)
        if len(out.encode()) > a["max_bytes"]:
            raise ValueError(f"descriptor is {len(out.encode())} bytes, over airs max_bytes {a['max_bytes']}")
        content = {"tool_event": {"metadata": {"ecosystem": "mcp", "method": "tools/list", "server_name": key,
                                               "tool_invoked": name}, "output": out}}
    else:
        content = {"prompt": airs.cut(descriptor_text(tool), a["max_bytes"])[0]}
    return {"ai_profile": {"profile_name": a["profile"]},
            "metadata": {"app_name": a["app_name"], "app_user": "pin-scan", "ai_model": f"mcp:{key}/{name}"},
            "contents": [content]}


def scan_descriptor(key, tool, cfg):
    """Scan one served tool version. Return its record for srv["airs"]."""
    a, t0 = cfg["airs"], time.monotonic()
    api_key = os.environ.get("AIRS_LIST_API_KEY")
    status, res, err = None, None, None
    try:
        body = scan_body(key, tool, cfg)
    except ValueError as e:
        err = str(e)
    if err is None:
        if not api_key:
            err = "AIRS_LIST_API_KEY is not set"
        else:
            status, res, err = airs.post(a["url"], api_key, body, a["timeout"])
    rec = {"hash": fingerprint(tool, cfg["fields"]), "profile": a["profile"], "scanned_at": now_iso(),
           "latency_ms": int((time.monotonic() - t0) * 1000)}
    if err or not isinstance(res, dict) or res.get("action") not in ("allow", "block"):
        rec.update(status="error", error=f"HTTP {status}: {err or str(res)[:200]}")
    else:
        rec.update(status=res["action"], action=res["action"], category=res.get("category"),
                   scan_id=res.get("scan_id"), report_id=res.get("report_id"), **detections(res))
    log.info(json.dumps({"airs_descriptor": {"server": key, "tool": tool.get("name"), "hash": rec["hash"][:12],
                                             **{k: rec.get(k) for k in ("status", "category", "detected", "threats", "scan_id",
                                                                        "latency_ms", "error") if k in rec}}}))
    return rec


def detections(res):
    """{detected: [...], threats: [...]} from a scan result: prompt_detected/response_detected flags, and for tool
    events tool_detected.summary (detections and threats)."""
    hits = {f"{k.split('_')[0]}.{d}" for k in ("prompt_detected", "response_detected")
            for d, on in (res.get(k) or {}).items() if on is True}
    summary = (res.get("tool_detected") or {}).get("summary") or {}
    hits |= {f"tool.{d}" for d, on in (summary.get("detections") or {}).items() if on is True}
    out = {"detected": sorted(hits)}
    if summary.get("threats"):
        out["threats"] = list(summary["threats"])
    return out


def scan_todo(srv, tools, cfg, force=None):
    """Served tool versions to scan: those not pinned as served and without a scan of that version (failed scans are
    retried). force: names to scan regardless."""
    if not cfg.get("airs"):
        return []
    srv, out = srv or {}, []
    for x in tools:
        name, h = x["name"], fingerprint(x, cfg["fields"])
        if force is not None:
            if name in force:
                out.append(x)
            continue
        pinned, pen = (srv.get("tools") or {}).get(name), (srv.get("penalty") or {}).get(name)
        rec = (srv.get("airs") or {}).get(name)
        if (pinned and pinned["hash"] == h and not pen) or \
                (rec and rec["hash"] == h and rec["status"] in ("allow", "block")):
            continue
        out.append(x)
    return out


def scan_all(key, tools, cfg):
    """Scan tools in parallel. Return {name: record}."""
    if not tools:
        return {}
    with ThreadPoolExecutor(min(8, len(tools))) as ex:
        return dict(zip([x["name"] for x in tools], ex.map(lambda x: scan_descriptor(key, x, cfg), tools)))


def record(srv, recs):
    srv.setdefault("airs", {}).update(recs)


_inflight = set()


def _spawn(fn):
    threading.Thread(target=fn, daemon=True).start()


def scan_later(key, tool, cfg):
    """Scan a tool version of a locked server in the background (its calls are denied meanwhile anyway)."""
    job = (key, tool["name"], fingerprint(tool, cfg["fields"]))
    with _cache_lock:
        if job in _inflight:
            return
        _inflight.add(job)

    def run():
        try:
            rec = scan_descriptor(key, tool, cfg)
            with _server_lock(key), Store(cfg["store"]).open() as state:
                srv = state["servers"].get(key)
                if srv is not None:
                    record(srv, {tool["name"]: rec})
                    hit = _cache.get(key)
                    log_changes(key, *reconcile(srv, hit[1] if hit else [tool], cfg))
        except Exception as e:  # a background job has nobody to report to but the log
            log.warning(json.dumps({"pin_error": {"server": key, "tool": tool["name"], "error": f"scan: {e}"}}))
        finally:
            with _cache_lock:
                _inflight.discard(job)

    _spawn(run)


def approve(srv, name, want_hash=None):
    """Move a penalty entry into the baseline. Return an error string, or None."""
    pen = srv["penalty"].get(name)
    if not pen:
        return f"{name} is not in the penalty box"
    if want_hash and not pen["hash"].startswith(want_hash):
        return f"{name} changed since you looked: its hash is now {pen['hash'][:12]}"
    srv["tools"][name] = {"hash": pen["hash"], "descriptor": pen["descriptor"], "since": now_iso()}
    del srv["penalty"][name]
    return None


# --- the check ----------------------------------------------------------------------------------------------------

_cache, _cache_lock, _server_locks = {}, threading.Lock(), {}


def _server_lock(key):
    with _cache_lock:
        return _server_locks.setdefault(key, threading.Lock())


def check(payload, cfg, headers, fetch=list_tools):
    """Return (verdict, reason, info). info is None for requests that aren't MCP tool calls."""
    if payload.get("requestType") != "mcpToolCall":
        return True, "ok", None
    m = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    server, ws, tool = m.get("mcpServerId"), m.get("mcpWorkspaceId"), m.get("mcpToolName")
    if not server or not tool:
        return False, "pin: no mcpServerId/mcpToolName in metadata", {"status": "error"}
    key = f"{ws}/{server}"
    info = {"server": key, "tool": tool}

    def fail(why):
        info.update(status="error", error=why)
        log.warning(json.dumps({"pin_error": {"server": key, "tool": tool, "error": why, "fail_open": cfg["fail_open"]}}))
        return (True, f"pin: {why} (fail open)", info) if cfg["fail_open"] else (False, f"pin: {why}", info)

    with _server_lock(key):
        hit = _cache.get(key)
        fresh = not hit or time.monotonic() - hit[0] >= cfg["refresh_s"]
        if fresh:
            url = cfg["url"].replace("{workspace}", urllib.parse.quote(str(ws), safe="")) \
                            .replace("{server}", urllib.parse.quote(str(server), safe=""))
            t0 = time.monotonic()
            try:
                tools = fetch(url, headers, cfg["timeout"])
            except (FetchError, ValueError) as e:
                return fail(f"tools/list failed: {e}")
            info["list_ms"] = int((time.monotonic() - t0) * 1000)
            _cache[key] = (time.monotonic(), tools)
        else:
            tools = hit[1]
        info["fetched"] = fresh

        later, inline, recs = [], False, {}
        try:
            if cfg.get("airs"):
                # first sight and learning scan inline, before anything is trusted; outside the state file lock
                with Store(cfg["store"]).open(write=False) as state:
                    srv = copy.deepcopy(state["servers"].get(key))
                inline = (srv is None and not cfg["require_seed"]) or (srv is not None and fresh and learning(srv))
                if inline:
                    recs = scan_all(key, scan_todo(srv, tools, cfg), cfg)
            with Store(cfg["store"]).open() as state:  # written only if it changed
                srv, first = state["servers"].get(key), False
                if srv is None:
                    if cfg["require_seed"]:
                        info["status"] = "unseeded"
                        return False, f"pin: server {key} has no baseline (require_seed)", info
                    srv = state["servers"][key] = new_server("first-call", cfg)
                    first = info["first_seen"] = True
                if fresh or first:
                    was = srv.get("mode")
                    if not learning(srv) and was == "learning":
                        log.info(json.dumps({"pin_locked": {"server": key, "reason": "learning period ended"}}))
                    record(srv, recs)
                    drift, learned = reconcile(srv, tools, cfg, first)
                    if first:
                        log.info(json.dumps({"pin_baseline": {"server": key, "tools": sorted(srv["tools"]),
                                                              "mode": srv["mode"]}}))
                    log_changes(key, drift, learned, first)
                    if not inline:
                        later = scan_todo(srv, tools, cfg)
                penalty = dict(srv["penalty"])
                pinned = (srv["tools"].get(tool) or {}).get("descriptor")
                is_learning = learning(srv)
                rec = (srv.get("airs") or {}).get(tool)
        except (OSError, ValueError, KeyError) as e:
            return fail(f"state error: {e}")
    for x in later:
        scan_later(key, x, cfg)
    if rec:
        info["airs"] = {k: rec.get(k) for k in ("status", "category", "scan_id")}

    current = {x["name"] for x in tools}
    if tool in penalty:
        p = penalty[tool]
        info.update(status=p["kind"], hash=p["hash"][:12])
        return False, f"pin: tool {tool} on {key} is {p['kind']} since {p['since']}" \
                      f"{', scan_id ' + p['scan_id'] if p.get('scan_id') else ''} (penalty box)", info
    if penalty and cfg["quarantine"] == "server":
        info.update(status="quarantined", penalty=sorted(penalty))
        return False, f"pin: server {key} quarantined, drift on {', '.join(sorted(penalty))}", info
    if tool not in current:
        info["status"] = "absent"
        return False, f"pin: tool {tool} is not in {key}'s tools/list", info
    info["status"] = "pinned"
    bad = validate_call(payload, cfg, pinned, is_learning, info)
    if bad:
        info["status"] = "invalid"
        return False, f"pin: {bad}", info
    return True, f"pin: tool {tool} matches its pinned descriptor", info


def validate_call(payload, cfg, pinned, learning, info):
    """Check the call's arguments or result against the pinned descriptor's schema. Return a deny reason, or None."""
    after = payload.get("eventType") == "afterRequestHook"
    hook = "output" if after else "input"
    mode, want = cfg["validate"][hook], "outputSchema" if after else "inputSchema"
    if mode == "off" or not isinstance(pinned, dict) or want not in pinned:
        return None
    tool = info["tool"]
    if after:
        res = (payload.get("response") or {}).get("json") or {}
        if res.get("isError"):
            return None
        if "structuredContent" not in res:
            errors, unsupported = ["no structuredContent but the tool declares outputSchema"], set()
        else:
            errors, unsupported = schema.validate(res["structuredContent"], pinned[want])
    else:
        args = ((payload.get("request") or {}).get("json") or {}).get("arguments")
        errors, unsupported = schema.validate({} if args is None else args, pinned[want])
    if unsupported and cfg["validate"]["unknown"] == "deny":
        errors = errors + [f"schema uses unsupported keywords: {', '.join(sorted(unsupported))}"]
    if mode == "enforce" and learning:
        mode = "log (learning)"
    info["validation"] = {"hook": hook, "errors": errors, "unsupported": sorted(unsupported), "mode": mode}
    if not errors:
        return None
    log.warning(json.dumps({"pin_validation": {"server": info["server"], "tool": tool, "hook": hook,
                                               "errors": errors, "mode": mode}}))
    if mode != "enforce":
        return None
    what = f"arguments of {tool} don't match its pinned inputSchema" if hook == "input" else \
        f"result of {tool} doesn't match its pinned outputSchema"
    return f"{what}: {'; '.join(errors[:3])}"
