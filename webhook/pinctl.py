"""Admin CLI for the descriptor pinning state (pin.py). Uses the same env PIN (store, url, fields) and PIN_HEADERS as the
webhook; run it where the webhook runs (docker compose exec / kubectl exec) or anywhere with the state file.

  python3 pinctl.py list                                  servers, mode, tool counts, AIRS summary, penalty box
  python3 pinctl.py show <ws>/<server> [tool]             pinned and pending descriptors, with a diff for changed tools
  python3 pinctl.py approve <ws>/<server> <tool> --hash <prefix>   release from the penalty box into the baseline
  python3 pinctl.py approve <ws>/<server> <tool>... | --all       the same without the hash check
  python3 pinctl.py seed <ws>/<server> [--force]          fetch tools/list now and make it the baseline (onboarding)
  python3 pinctl.py rescan <ws>/<server> [tool...]        scan the served descriptors with AIRS again now
  python3 pinctl.py learn <ws>/<server> [--for 12h]       learning mode: clean new and changed tools join the baseline
  python3 pinctl.py lock <ws>/<server>                    end learning mode: new and changed tools are denied again
  python3 pinctl.py reset <ws>/<server>                   forget the server: the next call trusts it on first use again

show, approve and rescan first fetch the server's tools/list, scan versions AIRS hasn't seen (with PIN airs) and update
the penalty box, so they act on what the server serves now, not on what the webhook last saw (a tool the publisher
already changed again would otherwise be approved in its old form). --offline skips the fetch. --hash guards against
approving a newer change than the one you reviewed (show prints the hash). approve refuses airs-blocked and airs-error
entries without --force. seed scans too: tools AIRS blocks go into the penalty box, not the baseline. --for takes
seconds or 90m, 12h, 7d; without it the server learns until `lock`. Exit status 1 on error. Changes apply to the next
webhook call, with no restart.
"""

import difflib
import json
import os
import sys
import urllib.parse

import pin


def pretty(d):
    return json.dumps(d, indent=2, sort_keys=True, ensure_ascii=False).splitlines()


def main(argv):
    cfg = pin.load_config(os.environ.get("PIN"))
    if not cfg:
        sys.exit("PIN is not set")
    store = pin.Store(cfg["store"])
    cmd, args = (argv[0] if argv else ""), argv[1:]
    flags = {a for a in args if a.startswith("--")}
    opts = {}
    for o in ("--hash", "--for"):
        if o in args:
            i = args.index(o)
            if i + 1 >= len(args):
                return err(f"{o} needs a value")
            opts[o], args = args[i + 1], args[:i] + args[i + 2:]
    want_hash = opts.get("--hash")
    args = [a for a in args if not a.startswith("--")]

    def fetch(key):
        ws, server = key.split("/", 1)
        url = cfg["url"].replace("{workspace}", urllib.parse.quote(ws, safe="")) \
                        .replace("{server}", urllib.parse.quote(server, safe=""))
        return pin.list_tools(url, pin.headers_from_env(), cfg["timeout"])

    def refresh(key, force=None):
        """Fetch tools/list, scan what AIRS hasn't seen (force: these names regardless) and apply it, as the webhook
        would."""
        if "--offline" in flags:
            return None
        try:
            tools = fetch(key)
        except pin.FetchError as e:
            return f"tools/list failed: {e} (--offline uses the stored state as is)"
        with store.open(write=False) as s:
            srv = s["servers"].get(key)
        if srv is None:
            return None
        if force == "all":
            force = {x["name"] for x in tools}
        recs = pin.scan_all(key, pin.scan_todo(srv, tools, cfg, force), cfg)
        with store.open() as s:
            if key in s["servers"]:
                pin.record(s["servers"][key], recs)
                pin.log_changes(key, *pin.reconcile(s["servers"][key], tools, cfg))
        return None

    def airs_line(rec, h):
        if rec and rec["hash"] == h:
            hits = rec.get("detected") or []
            return f"   airs: {rec['status']}" + (f" ({rec['category']})" if rec.get("category") else "") + \
                   (f" detected {', '.join(hits)}" if hits else "") + \
                   (f" ({', '.join(rec['threats'])})" if rec.get("threats") else "") + \
                   (f", scan_id {rec['scan_id']}" if rec.get("scan_id") else "") + \
                   (f", {rec['error']}" if rec.get("error") else "") + f", {rec['scanned_at']}"
        return "   airs: not scanned" if cfg.get("airs") else None

    if cmd == "list":
        with store.open(write=False) as s:
            for key, srv in sorted(s["servers"].items()):
                mode = srv.get("mode") or "locked"
                if mode == "learning":
                    mode += f" until {srv['learn_until']}" if srv.get("learn_until") else " until locked"
                print(f"{key}  {mode}, {len(srv['tools'])} pinned, first seen {srv['first_seen']} ({srv['seeded_by']})")
                recs = (srv.get("airs") or {}).values()
                if recs:
                    n = {st: sum(r["status"] == st for r in recs) for st in ("block", "error")}
                    print(f"  airs: scanned {len(recs)}, blocked {n['block']}, errors {n['error']}, "
                          f"last {max(r['scanned_at'] for r in recs)}")
                for name, p in sorted(srv["penalty"].items()):
                    print(f"  PENALTY {p['kind']:12} {name}  hash {p['hash'][:12]}  since {p['since']}")
        return 0

    if not args or "/" not in args[0]:
        print(__doc__, file=sys.stderr)
        return 1
    key = args[0]

    if cmd in ("show", "approve") and (e := refresh(key)):
        return err(e)

    if cmd == "rescan":
        if "--offline" in flags:
            return err("rescan needs the live tools/list")
        if not cfg.get("airs"):
            return err("PIN has no airs config")
        with store.open(write=False) as s:
            srv = s["servers"].get(key)
        if not srv:
            return err(f"{key}: no baseline")
        if e := refresh(key, force=set(args[1:]) or "all"):
            return err(e)
        with store.open(write=False) as s:
            srv = s["servers"][key]
            for name in sorted(args[1:] or srv.get("airs", {})):
                rec = srv.get("airs", {}).get(name)
                print(f"{name}: " + (f"{rec['status']} {rec.get('category') or ''} {rec.get('scan_id') or rec.get('error')}"
                                     if rec else "not served"))
        return 0

    if cmd in ("learn", "lock"):
        try:
            dur = parse_duration(opts.get("--for")) if cmd == "learn" else None
        except ValueError:
            return err(f"--for: bad duration {opts['--for']!r} (seconds, or 90m, 12h, 7d)")
        with store.open() as s:
            srv = s["servers"].get(key)
            if not srv:
                return err(f"{key}: no baseline")
            pin.set_mode(srv, "learning" if cmd == "learn" else "locked", dur)
            until = srv["learn_until"] or "locked by hand"
        print(f"{key}: learning until {until}" if cmd == "learn" else f"{key}: locked")
        return 0

    if cmd == "show":
        with store.open(write=False) as s:
            srv = s["servers"].get(key)
            if not srv:
                return err(f"{key}: no baseline")
            names = args[1:] or sorted(set(srv["tools"]) | set(srv["penalty"]))
            for name in names:
                t, p = srv["tools"].get(name), srv["penalty"].get(name)
                rec = (srv.get("airs") or {}).get(name)
                if p:
                    print(f"== {name}: PENALTY {p['kind']} since {p['since']}, hash {p['hash'][:12]}")
                    if line := airs_line(rec, p["hash"]):
                        print(line)
                    old = pretty(t["descriptor"]) if t else []
                    print("\n".join(difflib.unified_diff(old, pretty(p["descriptor"]), "pinned", "served", lineterm="")))
                    force = " --force" if p["kind"].startswith("airs-") else ""
                    print(f"approve: pinctl.py approve {key} {name} --hash {p['hash'][:12]}{force}")
                elif t:
                    print(f"== {name}: pinned since {t['since']}, hash {t['hash'][:12]}")
                    if line := airs_line(rec, t["hash"]):
                        print(line)
                    if args[1:]:
                        print("\n".join(pretty(t["descriptor"])))
                else:
                    print(f"== {name}: unknown")
        return 0

    if cmd == "approve":
        with store.open() as s:
            srv = s["servers"].get(key)
            if not srv:
                return err(f"{key}: no baseline")
            names = sorted(srv["penalty"]) if "--all" in flags else args[1:]
            if not names:
                return err("name a tool, or --all")
            if want_hash and len(names) != 1:
                return err("--hash takes exactly one tool")
            for name in names:
                p = srv["penalty"].get(name)
                if p and p["kind"].startswith("airs-") and "--force" not in flags:
                    why = f"was blocked by AIRS (scan_id {p.get('scan_id')})" if p["kind"] == "airs-blocked" else \
                        "has no clean AIRS scan (the scan failed)"
                    return err(f"{name} {why}; --force to approve anyway")
                e = pin.approve(srv, name, want_hash)
                if e:
                    return err(e)
                print(f"approved {name} on {key} (hash {srv['tools'][name]['hash'][:12]})")
        return 0

    if cmd == "seed":
        try:
            tools = fetch(key)
        except pin.FetchError as e:
            return err(f"tools/list failed: {e}")
        with store.open(write=False) as s:
            if key in s["servers"] and "--force" not in flags:
                return err(f"{key} already has a baseline (--force replaces it and clears its penalty box)")
        recs = pin.scan_all(key, pin.scan_todo(None, tools, cfg), cfg)
        with store.open() as s:
            srv = s["servers"][key] = pin.new_server("pinctl seed", cfg)
            pin.record(srv, recs)
            drift, _ = pin.reconcile(srv, tools, cfg, first=True)
        print(f"seeded {key}: {', '.join(sorted(srv['tools'])) or '(no tools)'}")
        for d in drift:
            print(f"  not seeded, {d['kind']}: {d['tool']}")
        return 0

    if cmd == "reset":
        with store.open() as s:
            if s["servers"].pop(key, None) is None:
                return err(f"{key}: no baseline")
        print(f"reset {key}")
        return 0

    print(__doc__, file=sys.stderr)
    return 1


def parse_duration(s):
    """Seconds from "3600", "90m", "12h" or "7d"; None stays None."""
    if s is None:
        return None
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    n = float(s[:-1]) * mult[s[-1]] if s and s[-1] in mult else float(s)
    if n <= 0:
        raise ValueError(s)
    return n


def err(msg):
    print(msg, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
