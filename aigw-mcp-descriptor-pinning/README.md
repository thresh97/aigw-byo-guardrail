# aigw-mcp-descriptor-pinning

Pins each MCP server's tool descriptors the first time the webhook sees the server, then denies calls to any tool that's **new** on the server or whose descriptor **changed**, until an admin approves it. This catches a "rug pull", where an approved server later changes a tool's description or schema (for example, to add hidden instructions for the model), and it catches tools a server adds silently. The code is [`webhook/pin.py`](../webhook/pin.py), with the admin CLI [`webhook/pinctl.py`](../webhook/pinctl.py). It runs inside the same [webhook](../webhook/handler.py) as the tool allowlist and the [AIRS scan](../aigw-mcp-airs-webhook/README.md), on a hybrid gateway.

> **Disclaimer:** This is a simple, art-of-the-possible example. It is **not** an official Palo Alto Networks or Portkey project, it is **not** a recommended or supported production design, and it comes with **no support**. Use it at your own risk, under the [MIT License](../LICENSE). It has no high availability and no scaling: one webhook replica owns one state file.

```
MCP client ──tools/call──► hybrid AI Gateway ──► upstream MCP server
                              │ guardrail: target mcp_tools, check default.webhook, deny
                              ▼
                        webhook ──tools/list (every refresh_s)──► https://<gateway>/m/{workspace}/{server}/mcp
                              │ compare each tool's fingerprint with the pinned one (state file /data/pins.json)
                              ▼
                        pinned → {"verdict": true}; new / changed / gone → {"verdict": false} → JSON-RPC -32446
```

**Why the webhook fetches `tools/list` itself.** The gateway runs MCP guardrails only on `tools/call`, never on `tools/list` (see [`aigw-byo-guardrail-mcp`](../aigw-byo-guardrail-mcp/README.md)), so a guardrail never sees the descriptors the client is given. The webhook gets them by asking the same gateway endpoint the clients use, with its own gateway API key, so it pins what clients are actually served (after the gateway's own filtering and caching).

## How it works

| Event | What happens | Calls to the tool |
|---|---|---|
| First call for a server (no baseline) | The whole `tools/list` becomes the server's baseline (trust on first use), logged as `pin_baseline`. With `require_seed: true`, the call is denied instead and the server must be seeded with `pinctl seed` | allowed (or denied with `require_seed`) |
| A tool that isn't in the baseline appears | It goes into the penalty box as `new`, logged once as `pin_drift` | denied |
| A pinned tool's fingerprint changes | It goes into the penalty box as `changed`, logged once as `pin_drift` | denied |
| The descriptor changes back | Nothing is released: the penalty box is sticky. Only `pinctl approve` releases a tool | still denied |
| A pinned tool disappears from `tools/list` | | denied ("not in tools/list") |
| `tools/list` fails or the state file can't be read | `pin_error` logged; `fail: closed` denies, `fail: open` allows | denied (default) |

The fingerprint is a SHA-256 of the canonical JSON of the tool's `name`, `title`, `description`, `inputSchema`, `outputSchema` and `annotations`, so any change to the description, the parameters or their descriptions, or the hints counts. With `quarantine: server`, drift on one tool denies every tool on that server, since a poisoned description can steer the model into misusing the server's other tools.

The client sees only `-32446` "Request blocked by guardrail". The reason ("tool sync_notes on ws/a is new since ... (penalty box)") and a `pin` object (`server`, `tool`, `status`, `hash`, `fetched`, `list_ms`) are in the webhook's log line for the call.

## What you need

- Everything in [`aigw-mcp-airs-webhook`](../aigw-mcp-airs-webhook/README.md) → What you need, except the AIRS key and profiles (pinning works with or without AIRS).
- A **gateway API key** for the webhook with the `mcp.invoke` scope, in a workspace that has the MCP servers to pin. It's sent as `x-portkey-api-key` on the `tools/list` requests.
- Outbound HTTPS from the webhook to the gateway.
- Docker or Kubernetes, with a **persistent volume** for the state file. Pinning refuses to start on Lambda: each Lambda instance would keep its own baseline.

## 1. Deploy the webhook with pinning on

Pinning settings go in env `PIN` (JSON), and the gateway key in env `PIN_HEADERS`. With `PIN` unset, the webhook doesn't pin.

| Setting | Default | Meaning |
|---|---|---|
| `url` | (required) | The `tools/list` endpoint; `{workspace}` and `{server}` are replaced from the call's `mcpWorkspaceId` and `mcpServerId`. Through the gateway: `https://<gateway>/m/{workspace}/{server}/mcp` |
| `store` | `/data/pins.json` | State file. It must survive restarts and be used by one webhook process only |
| `refresh_s` | `30` | How long a fetched `tools/list` is reused before the next fetch |
| `timeout_ms` | `3000` | Per HTTP request. A fetch is three requests (initialize, initialized, tools/list), so keep 3 × this below the guardrail check's `timeout` |
| `fail` | `closed` | `closed`: a failed fetch or state error denies. `open`: allows and logs |
| `quarantine` | `tool` | `tool`: only the drifted tool is denied. `server`: every tool on a server with drift is denied |
| `fields` | the six above | Descriptor fields in the fingerprint |
| `require_seed` | `false` | `true`: a server without a baseline is denied instead of trusted on first use |
| `airs` | off | Scan descriptors with Prisma AIRS (section 6) |
| `learn` | off | Learning mode for servers first seen by a call (section 6) |
| `validate` | off | Check live calls against the pinned schemas (section 6) |

`PIN_HEADERS` is a JSON object of headers, for example `{"x-portkey-api-key": "<key>"}`. It's a credential: it's kept out of `PIN` and out of the logs.

The tool allowlist runs before pinning and AIRS runs after it, so a call has to pass all three. Set `POLICY='{}'` to leave out the other rules.

**Docker** (from the repository root):

```bash
umask 077
cat > pin-webhook.env <<EOF
TOKEN=$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)
POLICY={}
PIN={"url":"https://<gateway>/m/{workspace}/{server}/mcp","quarantine":"tool"}
PIN_HEADERS={"x-portkey-api-key":"<gateway API key with mcp.invoke>"}
EOF
docker volume create mcp-pins
docker run -d --name mcp-pin-webhook --restart unless-stopped -p 8080:8080 --env-file pin-webhook.env \
  -v "$PWD/webhook:/app:ro" -v mcp-pins:/data python:3.12-slim python -u /app/server.py
```

Add `AIRS` and `AIRS_API_KEY` to the same env file to scan as well. `pinctl` runs in the container: `docker exec mcp-pin-webhook python /app/pinctl.py list`.

**Kubernetes:**

```bash
PIN='{"url":"https://<gateway>/m/{workspace}/{server}/mcp"}' \
PIN_HEADERS='{"x-portkey-api-key":"<gateway API key with mcp.invoke>"}' \
PIN_PVC=<existing PersistentVolumeClaim> bash k8s/webhook.sh deploy
bash k8s/webhook.sh pinctl list
```

Without `PIN_PVC`, the state is on an emptyDir and is lost whenever the pod is replaced (including `policy`, `down` and redeploys). Every server is then trusted on first use again, so use a PVC beyond a quick test.

**With the gateway in Docker** ([`airs-ai-gateway-docker`](https://github.com/PaloAltoNetworks/airs-ai-gateway-docker)), run the webhook on the installer's Compose network (`--network airs-ai-gateway-docker_default` on the `docker run` above, `-p` isn't needed) and point `PIN` at the gateway container's MCP listener. That's port 8788 (`MCP_PORT`), not the inference port 8787, and plain HTTP inside the network:

```
PIN={"url":"http://airs-gw-gateway:8788/m/{workspace}/{server}/mcp","quarantine":"tool"}
```

The gateway refuses private upstreams, so two hosts go in its `TRUSTED_CUSTOM_HOSTS` (comma-separated): the webhook (`mcp-pin-webhook`) and each MCP server's host. The installer rewrites `.env.runtime` and doesn't copy extra keys from `values.yaml`, so set it in a `docker-compose.override.yml` next to the generated compose file, which survives re-runs, and recreate the gateway (`docker compose up -d airs-gw-gateway`):

```yaml
services:
  airs-gw-gateway:
    environment:
      TRUSTED_CUSTOM_HOSTS: mcp-pin-webhook,byo-probe-mcp.default.svc.cluster.local
```

Without the MCP server's host, the first `initialize` through the gateway fails with HTTP 500 "Failed to restore session", and the reason is only in the gateway log (`SSRF block: DNS resolution rejected`).

## 2. Create the guardrail

Create and map the guardrail as in [`aigw-mcp-airs-webhook`](../aigw-mcp-airs-webhook/README.md) step 3, with these points:

- `failOnError: true`, so a webhook that's down blocks calls.
- A check `timeout` above 3 × `timeout_ms`, plus the AIRS timeout if AIRS is on (10000 ms covers the defaults without AIRS; use 15000 with it).
- Input only is enough for pinning (the decision is made before the tool runs). Map output too if AIRS scans results.
- An empty `mcp_integration_capability_ids` (all tools), so tools the server adds later still reach the webhook. With an explicit list, a new tool bypasses the guardrail entirely.
- Or make it the workspace's default MCP input guardrail, which covers every server in the workspace. With `airs-cli` that's one command and needs no SCM token for the mapping call: `airs-cli aigateway workspaces update <workspace slug> --defaults '{"mcp_input_guardrails":["<guardrail id>"]}'`. Check the workspace's current `defaults` first (`airs-cli aigateway workspaces get <workspace slug>`): the test ran on a workspace with none, so whether the update merges with or replaces existing keys wasn't tested.

To register the probe server as the MCP integration with `airs-cli`: `airs-cli aigateway mcp integrations create --name <name> --slug <slug> --organisation-id <tsg> --auth-type none --transport http --url <url> --configurations '{}' --secret-mappings '[]'`, then `airs-cli aigateway mcp integrations workspaces set <integration id> --workspace-binding <workspace id>=true --force`. The URL must have a dotted host that isn't `.local`: `http://byo-probe-mcp:8080/...` is refused with "Invalid value" and `http://x.mcp.local:8080/...` with "Invalid or unsafe custom host". The `<name>.<namespace>.svc.cluster.local` form was accepted (on Docker, as a network alias on the container).

## 3. Onboard a server

Trust on first use pins whatever the server serves at its first call. To pin a reviewed version instead, seed the baseline when the server is approved, before any client calls it:

```bash
docker exec mcp-pin-webhook python /app/pinctl.py seed <workspace>/<server>
docker exec mcp-pin-webhook python /app/pinctl.py show <workspace>/<server>   # what was pinned
```

`<workspace>` and `<server>` are the values the gateway sends as `mcpWorkspaceId` and `mcpServerId` (the slugs in the `/m/<workspace>/<server>/mcp` URL); `pinctl list` shows the keys the webhook has seen. With `require_seed: true`, servers that were never seeded are denied, so a lost state file fails closed instead of silently re-pinning.

## 4. Adding a new tool to an existing server

This is the normal path when a publisher adds a tool, or legitimately changes one:

1. **The publisher ships the tool.** Nothing needs to happen in the gateway first.
2. **The webhook puts it in the penalty box.** At the next fetch (within `refresh_s` of the next call to any tool on that server), the tool goes into the penalty box as `new` (or `changed`), and the webhook logs one `pin_drift` line: `{"pin_drift": {"server": "<ws>/<server>", "tool": "<tool>", "kind": "new", "hash": "...", "pinned_hash": null, "again": false}}`. Alert on `pin_drift`. Calls to the tool are denied with `-32446`.
3. **Review it.** `pinctl show` fetches `tools/list` now and prints the served descriptor, as a diff against the pinned one for a changed tool, plus the command to approve exactly that version:
   ```bash
   docker exec mcp-pin-webhook python /app/pinctl.py show <ws>/<server> <tool>
   # == sync_notes: PENALTY new since 2026-10-16T12:52:44Z, hash b3ce6201be39
   # --- pinned
   # +++ served
   # +{ "description": "...", "inputSchema": {...}, "name": "sync_notes" }
   # approve: pinctl.py approve <ws>/<server> sync_notes --hash b3ce6201be39
   ```
   Check the description and every parameter description for instructions aimed at the model (do X first, read a file, send data somewhere, don't tell the user). With `airs` on, `show` also prints the AIRS verdict for that version (section 6).
4. **Approve it with the hash you reviewed:**
   ```bash
   docker exec mcp-pin-webhook python /app/pinctl.py approve <ws>/<server> <tool> --hash <hash from show>
   ```
   `approve` fetches `tools/list` again first. If the publisher changed the tool after you looked, the hash no longer matches and nothing is approved ("changed since you looked"); review again.
5. **It applies at the next call**, with no restart. The tool's new descriptor is now the pinned one, and any later change goes through the same steps.

Notes:

- **Don't use `seed --force` or `reset`** to let a new tool in. They accept every pending change on the server at once, including any you haven't reviewed.
- **A rejected change stays denied.** If the publisher reverts a bad change, the tool stays in the penalty box (sticky). Once `show` shows the served descriptor matches the pinned one (an empty diff), approve it to release it.
- If the tool allowlist (`POLICY` `tools`) is on, add the tool there too; the allowlist and pinning are separate checks.
- Approving, seeding and resetting change only the state file. Nothing changes in the gateway, so no gateway admin access is needed.

## 5. Test

[`local_e2e.py`](local_e2e.py) runs the whole flow locally with no gateway: the probe MCP server ([`mcp/server.py`](../mcp/server.py)) and the webhook as two processes, with the probe server restarted in its `TOOL_DESCRIPTIONS` (rug-pull) and `EXTRA_TOOL` (new tool) modes between calls.

```bash
python3 aigw-mcp-descriptor-pinning/local_e2e.py
```

| Step | Expected |
|---|---|
| First call | allowed; `pin_baseline` logged |
| `echo`'s description changed | `echo` denied (`changed`); other tools allowed |
| Description changed back | still denied |
| `sync_notes` added | denied (`new`); `pinctl show` prints its descriptor |
| `sync_notes` changed after review | `approve --hash <reviewed>` refused |
| Reviewed version served again, approved with `--hash` | allowed |
| `quarantine: server`, one tool changed | every tool on the server denied, until the tool is approved |
| Another server | its own baseline |
| MCP server down | denied (`fail: closed`) |

Through a hybrid gateway, run the probe server in the same cluster with [`k8s/mcp.sh`](../k8s/mcp.sh), register `http://byo-probe-mcp.<ns>.svc.cluster.local:8080/a/mcp` as an MCP integration (auth type none), and map the guardrail to it. Call a tool, change the server's descriptors, wait `refresh_s`, and call again:

```bash
bash k8s/mcp.sh deploy
bash k8s/mcp.sh env 'TOOL_DESCRIPTIONS={"echo":"..."}'   # rug pull
bash k8s/mcp.sh env TOOL_DESCRIPTIONS- EXTRA_TOOL=sync_notes   # revert it, add a tool
```

The call should fail with `-32446`, and the webhook log should show `pin_drift`.

With the gateway in Docker, [`docker/mcp.sh`](../docker/mcp.sh) does the same for the probe server (`deploy` recreates the container, so pass every mode you want each time), and [`probe.sh`](../aigw-byo-guardrail-mcp/probe.sh) can call through the gateway's published MCP port:

```bash
bash docker/mcp.sh deploy                                # register the printed URL as the MCP integration
bash docker/mcp.sh deploy 'TOOL_DESCRIPTIONS={"echo":"..."}'   # rug pull
bash docker/mcp.sh deploy EXTRA_TOOL=sync_notes          # revert it, add a tool
docker logs mcp-pin-webhook | grep -E 'pin_drift|"verdict": false'
```

The client only sees `-32446` with `default.webhook: Webhook request failed`; `pin_drift` (`changed`, `new`, `airs-blocked`) and the `penalty box` reason are in the webhook's log.

## 6. AIRS descriptor scans, learning mode and schema validation

All three are optional, and each is one more key in `PIN`.

### AIRS descriptor scans

```json
"airs": {"profile": "<AIRS security profile>", "fail": "closed", "timeout_ms": 5000}
```

The webhook sends every tool version it hasn't scanned yet to the AIRS sync scan API: new and changed tools, and the whole `tools/list` the first time it sees a server. It sends them as an MCP `tools/list` tool event, with the served descriptor as a one-element JSON array in `output`. AIRS checks it for context poisoning per tool. The key is env `AIRS_LIST_API_KEY`, a runtime API key of its own, so descriptor scans get their own app in AIRS, separate from the tool call scans' `AIRS_API_KEY`. `k8s/webhook.sh` reads it from the `<name>-airs` Secret. Results are kept per server and per tool version in the state file. A version is scanned once, and a failed scan is retried at the next fetch.

| AIRS verdict | Tool |
|---|---|
| block | Penalty box as `airs-blocked`, even at first sight or in learning mode. `approve` needs `--force` |
| allow | Unchanged rules: a new or changed tool still needs `approve` (unless the server is learning) |
| scan failed | Penalty box as `airs-error` with `fail: closed` (the default), retried at the next fetch. `fail: open` treats it as allow |

Other settings: `content` (`tool_event`, the default, or `prompt`, which sends the descriptor as plain text and is checked as a user prompt), `app_name` (default `aigw-mcp-descriptors`), `max_bytes` (default 100000; a larger descriptor is a scan error, since the JSON can't be cut), `base_url`.

At first sight and in learning mode, scans run on the call path, in parallel. Raise the guardrail check's `timeout` to cover them. On a locked server, a changed or new tool is already denied, so it's scanned in the background and `pinctl show` has the verdict when you review it. `pinctl rescan <ws>/<server> [tool...]` scans the served versions again, for example after a profile change. `pinctl list` shows a per-server summary, and every scan is logged as `airs_descriptor` with `detected` (for example `tool.injection`), `threats` (`context poisoning`) and `scan_id`.

The security profile: set `content-type-mode` to `per_content_type` and set prompt injection to block. We tested with it on in the `prompt` and `tool-response` sections, with malicious code detection and everything else off (see Findings). The CLI's flag options (`--prompt-injection block`) apply to every section, and AIRS refuses prompt injection in the `response` section, so create the profile from JSON (`airs-cli runtime profiles create --name <name> --config <file>`).

### Learning mode

```json
"learn": {"duration_s": 86400}
```

A server first seen by a call starts in learning mode: for `duration_s` (or until `pinctl lock` if it's not set), new and changed tools join the baseline instead of the penalty box, logged as `pin_learned`. With `airs` on, a tool joins only after a clean scan. Tools AIRS blocks or couldn't scan go to the penalty box as usual. When the period ends, the server locks itself (`pin_locked`). `pinctl learn <ws>/<server> --for 12h` puts a server back into learning, and `pinctl lock` ends it. `require_seed` wins over learning: an unseeded server is still denied.

### Schema validation

```json
"validate": {"input": "enforce", "output": "enforce", "unknown": "allow"}
```

Checks a pinned tool's live call against its **pinned** descriptor, never the served one, so a publisher can't loosen a schema to let calls through. `input` checks the `tools/call` arguments against `inputSchema` (map the guardrail on input). `output` checks the result's `structuredContent` against `outputSchema` (map it on output too): a result without `structuredContent` fails, and tool errors (`isError`) and tools without an `outputSchema` are skipped. Modes: `off` (default), `log` (a `pin_validation` line, verdict unchanged) or `enforce` (deny). In learning mode, `enforce` only logs. The validator ([`webhook/schema.py`](../webhook/schema.py), standard library only) supports `type`, `required`, `properties`, `additionalProperties`, `enum`, `const`, `items`, length, size and range limits, and `pattern`. Any other keyword (`anyOf`, `$ref` and so on) is skipped with `unknown: allow`, or fails the call with `unknown: deny`.

## Limitations

- **It can't hide a poisoned descriptor from the model.** The gateway doesn't run guardrails on `tools/list`, so the client still receives the changed description; only calls to the tool are blocked. A poisoned description can still steer the model's other actions, which is what `quarantine: server` is for. Filtering `tools/list` needs gateway support.
- **Detection isn't instant.** A change is seen at the first fetch after it, so up to `refresh_s` after the server changes. Calls in that window use the old verdict. (On a hybrid gateway 2.29.0, `tools/list` was passed through live, so the gateway added no delay of its own.)
- **Trust on first use pins whatever is there first.** If the server is already poisoned at its first call, that's the baseline. Use `pinctl seed` at onboarding and `require_seed: true`.
- **The state file is the trust anchor.** Losing it resets every server to first use (unless `require_seed`). Keep it on a persistent volume, back it up, and run one replica. It isn't shared between replicas.
- **Per-user servers.** The webhook lists tools with its own gateway key. Servers that authenticate per user (OAuth with user consent, forwarded user identity) may refuse that key or show it a different tool list than a user gets.
- **Extra load.** Each server's `tools/list` is fetched at most once per `refresh_s` (three HTTP requests), on the call path. A slow MCP server makes that call slower. With `airs`, a server's first call also waits for its descriptor scans.

## Findings

Tested 2026-10-16 on a hybrid gateway 2.29.0 (Helm chart 1.2.0, unified mode, EKS): the webhook (`k8s/webhook.sh`, emptyDir state, `refresh_s` 10, no AIRS) and the probe MCP server (`k8s/mcp.sh`) in the gateway's cluster, an MCP integration with auth type none, the guardrail mapped on input to all tools, and a client calling the public gateway URL with its own key. The webhook fetched `tools/list` through the gateway's in-cluster Service with a separate `mcp.invoke` key.

- Every step in the table above gave the expected verdict, with the client getting `-32446`: first call pinned (`pin_baseline`), a changed `echo` description denied on the first call after the change while other tools stayed allowed, still denied after the revert, a new tool denied, `approve --hash` refused after a further change and accepted for the reviewed version, `quarantine: server` denying every tool on the server.
- The gateway passed `tools/list` through live: clients and the webhook saw a changed descriptor at once, and the first call after the change (1 s later) was denied. The gateway added no detection delay.
- A tool the gateway hadn't listed before was still passed to the guardrail (with an empty `mcp_integration_capability_ids`), so new tools don't bypass the check.
- Fetching `tools/list` on the call path added about 200 ms to the first call after each `refresh_s` (`list_ms` about 130 ms in-cluster).
- A new guardrail mapping applied only after the integration was re-saved, about 45 s later, as described in [`aigw-byo-guardrail-mcp`](../aigw-byo-guardrail-mcp/README.md).
- Redeploying the webhook on an emptyDir lost the state, and the server was pinned again on first use, as expected.
- The control plane's `GET /ai_gw/v2/mcp-servers/{id}/capabilities` returned each tool's full descriptor (`title`, `description`, `input_schema`, `output_schema`, `annotations`) and showed a changed description within a second of a client's `tools/list`. That could be an alternative to the webhook's own `tools/list` (not built: it needs a management-API credential in the webhook, and it wasn't tested whether it updates when nobody lists the tools).

Also tested 2026-10-16, locally with no gateway: the webhook (`webhook/server.py` with `PIN`) against the probe MCP server over plain HTTP, Python 3.12, with [`local_e2e.py`](local_e2e.py). All steps in the table above gave the expected verdicts, and the unit tests ([`tests/test_pin.py`](../tests/test_pin.py)) cover the same logic plus the MCP client against an SSE server with sessions and pagination.

- The first run found that `pinctl approve` approved the descriptor the webhook had last seen, not the one served now. After a publisher reverted a poisoned description, approving the tool put the poisoned version in the baseline. The call was still denied (the reverted version then showed up as changed), but the baseline was wrong. `show` and `approve` now fetch `tools/list` before acting.
- The gateway side (MCP guardrails run only on `tools/call`, the webhook payload's `mcpServerId` / `mcpWorkspaceId` / `mcpToolName`, `-32446`, `failOnError`) is from the [`aigw-byo-guardrail-mcp`](../aigw-byo-guardrail-mcp/README.md) tests on hybrid 2.27.0.

AIRS descriptor scans, learning mode and schema validation were tested 2026-10-16 on the same hybrid gateway 2.29.0 (the webhook on `k8s/webhook.sh` with `learn` 1800 s and `validate` enforce on input and output, the probe server's `add` tool for validation), and the scan format on 2026-10-17 directly against the AIRS sync scan API:

- **Validation:** once the server was locked, `add` with a string argument and a missing one was denied on input (`$: missing required property 'b'`, `$.a: expected number, got string`), and a result with a string `sum` and an extra property was denied on output. While the server was learning, the same call was only logged (`mode: "log (learning)"`) and reached the tool.
- **Learning:** a benign changed description and a benign new tool joined the baseline after a clean scan (`pin_learned`). A new tool with an `<IMPORTANT>` override was blocked by AIRS and denied. After `pinctl lock`, a changed tool went to the penalty box, was scanned in the background, and was released with `approve --hash`. `pinctl rescan` rescanned every served tool.
- **Latency:** the first call for a server, with `tools/list` and six parallel scans, took 658 ms at the client, against about 300 ms for a later call.
- **Scan format:** for a `tools/list` tool event, AIRS parses `output` as a JSON array of tools. Plain text and `{"tools": [...]}` got HTTP 400 ("failed to parse tools list"). With the array, the response has a `tool_detected` entry per tool (`tool_invoked`, `detections.injection`, `threats: ["context poisoning"]`), and a whole `tools/list` can go in one scan with a verdict per tool. The same text sent as a `tools/call` output was accepted, but scored like `prompt`.
- **Detection:** with a profile that has only prompt injection on (in the `prompt` and `tool-response` sections), `tool_event` scans blocked the poisoned test descriptors (an `<IMPORTANT>` override and a parameter description telling the model to read a key file) at first sight and in learning mode, and they went to the penalty box as `airs-blocked`. Benign probe tools such as `echo`, `whoami` and `get_page` were allowed. Verdicts were the same across repeated scans. `tool_event` is the default because it's the native format and gave the cleanest results in our comparison with `prompt`.

Tested 2026-10-22 on a hybrid gateway 2.29.0 in Docker, installed with `airs-ai-gateway-docker` 0.2.0 (the webhook and the probe server as containers on the installer's network, the state on a named volume, AIRS on a flat profile with prompt injection and toxic content set to block, the guardrail as the workspace's default MCP input guardrail):

- **Pinning:** the first call fetched `tools/list` through the gateway's MCP listener (`http://<gateway service>:8788/m/...`) and pinned the baseline. A changed `echo` description was denied as `changed` about 35 s later (`refresh_s` 30) while `whoami` stayed allowed, `echo` stayed denied after the description was reverted, and a new `sync_notes` was denied as `new`. `pinctl approve` released `echo`; that run passed an empty `--hash`, so it doesn't show that the hash check is enforced (the local test above covers it).
- **AIRS on the flat profile:** the corrected `tool_event` descriptor scan blocked the probe's `danger` tool at first sight (`tool.injection`, `tool.toxic_content`, `context poisoning`), so it was never pinned and its calls were denied as `airs-blocked`. The five other descriptors were allowed. The `tool_event` scan of a call's arguments (`input`, no `tool-call` section in the profile) was accepted and allowed a benign `echo`, with no HTTP 400. Tool results (`output`) and an injection in the arguments weren't tested on this setup.
- **Default guardrail:** the first call after setting the workspace default was already guarded, with no integration re-save.
- **Set-up:** the gateway's SSRF policy and the control plane's URL validation each blocked the probe server until its host was trusted and had a dotted, non-`.local` name (see step 1 and 2). The state volume wasn't restarted.

Not tested: `require_seed` and a PVC on a live Kubernetes gateway, a restart of the Docker state volume, the webhook reaching the gateway's public URL from inside the cluster, SaaS, and servers with per-user authentication.

## License

MIT; see [LICENSE](../LICENSE).
