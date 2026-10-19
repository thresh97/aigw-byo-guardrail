# aigw-byo-guardrail-mcp

The [webhook guardrail](../README.md) used on MCP tool calls (`target: mcp_tools`) instead of LLM requests. On the SaaS gateway on 2026-10-13, MCP guardrails didn't run at all: not the webhook check, not a built-in check, whether mapped to an MCP server or set as the workspace's default MCP guardrail. On the hybrid gateway (2.27.0, unified mode) on 2026-10-13 and 2026-10-14 they did run, input and output, with a few parameters that don't behave as they do for LLM guardrails: `sequential` doesn't stop at the first failing check, and `soft_deny_200` changes nothing. A new or changed guardrail mapping doesn't reach the hybrid gateway until the MCP integration itself is updated; until then the gateway keeps the mappings it had (an earlier version of this page reported per-server `run_on` as ignored, which was this cache). A mapping covers less than it seems to (tested 2026-10-14 on 2.27.0, rechecked on 2.29.0 2026-10-15 and 2026-10-19). It covers only the mapped server in the guardrail's own workspace. If it carries an explicit tool list, it covers only those tools, so tools the upstream adds later run unguarded. A server with no mapping, including the one created when an integration is granted to another workspace, allows every tool. Organisation-level guardrails can't be mapped to MCP servers at all. This page also covers how SaaS serves MCP and three integration gotchas found on the way.

> **Disclaimer:** Personal test notes. Not an official Palo Alto Networks or Portkey statement, and no support. Behavior may change in later releases.

## How to recognize it

On SaaS:

- A tool call that the guardrail should block comes back 200 with the tool's result.
- The webhook is never called: its logs have no invocation for the call. Any webhook that logs requests shows this; [`webhook/handler.py`](../webhook/handler.py) logs every call.
- A built-in check (for example `default.contains` with a deny word) mapped the same way doesn't block either.
- The guardrail and its mappings look right in the control plane: the guardrail has `target: mcp_tools`, and the MCP server object lists it under `guardrail_mappings`.

On hybrid, after you map a guardrail to an MCP server or change a mapping (`run_on`, tools), calls keep behaving as before the change: a new mapping's webhook is never called, and a tool switched to output-only (`run_on: ["output"]`) still gets `beforeRequestHook`. The mapping reads back correctly, and waiting doesn't help.

Also on hybrid, a guarded server lets some calls through with no webhook call at all:

- A tool the upstream added after the mapping was made runs on every server, even where it should be denied. Its mapping lists capability IDs, which is what picking tools at mapping time produces.
- The same integration granted to a second workspace runs every tool there. That workspace has its own MCP server object with no mapping.
- A guardrail from another workspace was mapped to the server, and the API accepted the mapping. The guardrail still never runs there.

## Workaround

- **SaaS:** none known. Use a hybrid gateway if you need MCP guardrails.
- **Hybrid, mapping changes:** after `PUT .../mcp-servers`, update the MCP integration (re-saving its unchanged `configurations` is enough, for example `airs-cli aigateway mcp integrations update <id> --file <same config>`). The gateway then drops its cached server data and the new mappings apply at once. Editing the guardrail's checks or actions doesn't do this.
- **Hybrid, cover every tool:** map without `mcp_integration_capability_ids` (leave the field out). An explicit list, even one naming every tool there is today, exempts every tool added later. Mapping a server also needs its capabilities to exist, and they are only registered by a `tools/list` through the gateway, so list once before mapping a new server.
- **Hybrid, cover every server:** every workspace an integration is granted to gets its own MCP server object. Map each one, using a guardrail created in that same workspace. Treat an unmapped server as unguarded, and check for one whenever an integration is granted to a new workspace.
- **Hybrid, guardrail target:** create MCP guardrails with `target: mcp_tools`. The target can't be changed later (an update reports success and leaves it unset), and mappings are refused without it.
- **Defence in depth for output-only checks:** a webhook can also act on `eventType` (return `verdict: true` for `beforeRequestHook`), so a stale mapping can't block on input.
- **Hybrid, block reason:** a webhook `verdict: false` reaches the client only as "Webhook request failed". Log your reason in the webhook; the client can't see it.

## Setup used

- Probe MCP server: [`mcp/server.py`](../mcp/server.py) on a Lambda Function URL, deployed with `mcp_server = true` ([`infra/mcp.tf`](../infra/mcp.tf)). Every path's first segment is a separate server name (`/a/mcp`, `/b/mcp`, ...), so one function can be registered as several MCP integrations. It requires its token in `x-mcp-token`, and its `whoami` tool returns the headers it received.
- Webhook: the guide's Lambda with `log_payload = true` and a header rule `x-app` deny `blockme`.
- MCP guardrail: `target: mcp_tools`, one check `default.webhook` (`webhookURL`, `headers: {x-guardrail-token: ...}`, `forwardHeaders: [x-app]`, `failOnError: false`), `actions.deny: true`.
- Mappings set with `PUT /ai_gw/v2/guardrails/<id>/mcp-servers`, body `{"mcp_servers": {"<mcp server id>": {"run_on": ["input","output"]}}}`. Leaving out `mcp_integration_capability_ids` covers all tools, including later ones; an explicit list covers only the tools it names (see [what a mapping covers](#hybrid-what-a-mapping-covers)). This call replaces the whole set. The MCP server id is the workspace-level server object, not the integration id; tool ids come from `GET /ai_gw/v2/mcp-servers/<id>/capabilities`.
- Driver: [`probe.sh`](probe.sh) (`GW`, `KEY`, `A`, `B`), one fresh MCP session per case, with and without `x-app: blockme`.
- Hybrid: the same webhook, an existing MCP server on the hybrid gateway with the guardrail mapped to one tool, the guardrail edited between runs with `PUT /ai_gw/v2/guardrails/<id>` (body `{name, checks, actions}`, the call the CLI's update makes). A second check, `default.contains` with words `foo` and `bar`, was added for the multi-check cases.

## Findings

SaaS: tested 2026-10-13 on the SaaS gateway (no version exposed), with the probe server and webhook on Lambda Function URLs. Hybrid: tested 2026-10-13 and 2026-10-14 against gateway image 2.27.0 (chart airs-gw-1.2.0, `SERVER_MODE=unified`) with the same webhook. The mapping scope was rechecked on 2.29.0 on 2026-10-15, and organisation guardrails were tested on 2.29.0 on 2026-10-19.

### SaaS: MCP guardrails don't run

| Setup | Expected | Observed |
|---|---|---|
| Webhook guardrail mapped to a server, all tools, input and output, `x-app: blockme` | blocked | 200, webhook not called |
| Same, mapped to one tool on input only, call to that tool with `blockme` | blocked | 200, webhook not called |
| Mapping made before the server's first use | blocked | 200, webhook not called |
| Workspace default MCP guardrail (`defaults.mcp_input_guardrails` / `mcp_output_guardrails`) with a built-in `contains` deny word, set for weeks | blocked | 200 |
| Rechecked about 60 to 75 minutes after the last change | blocked | 200, webhook not called |

A direct call to the webhook in the same window was logged, so the zero count is real. Whether workspace-default MCP guardrails are meant to be supported isn't documented.

### Hybrid: MCP guardrails run

- Only `tools/call` of mapped tools reaches the guardrail: once before the call (`beforeRequestHook`) and once after (`afterRequestHook`). `tools/list` and unmapped tools don't.
- The MCP URL is `https://<gateway>/m/<workspace-slug>/<server-slug>/mcp`; the server slug is the integration's slug.
- The webhook payload has `requestType: "mcpToolCall"` and `provider: "mcp"`. `request.json` is `{name, arguments}`, `request.text` the arguments as JSON, and `response.json` the tool result (empty on before; `statusCode` 200 on after). `metadata` is the client's `x-portkey-metadata` plus `mcpServerId` (server slug), `mcpWorkspaceId` (workspace slug) and `mcpToolName`.
- Without `forwardHeaders` the webhook sees only the gateway's own headers and the check's static `headers`: `user-agent: node`, `x-forwarded-for` = the gateway's egress IP, no trace id.
- **Deny:** HTTP 200 with JSON-RPC error `-32446` "Request blocked by guardrail", `data: {guardrail_id, reason, check_id}`. For a webhook `verdict: false` the reason is "default.webhook: Webhook request failed", not the webhook's reason (same as on LLM requests). A deny on input stops the call, so there's no after hook.

### Hybrid: forwardHeaders

- The control plane refuses some names with error AB01 "header '<name>' cannot be forwarded": `authorization`, `x-portkey-api-key`, `x-portkey-metadata`, `x-portkey-config`, `x-api-key`, `cookie`. It accepts `x-portkey-trace-id`, `user-agent`, `x-forwarded-for`, `mcp-session-id` and custom names.
- Forwarded headers arrive on both hooks. Forwarding `x-forwarded-for` gives the webhook the client's address instead of the gateway's (behind a load balancer that sets it), and `user-agent` gives it the client's. So a client-IP rule from the [guide](../README.md) needs `x-forwarded-for` in `forwardHeaders` for MCP.
- `mcp-session-id` only arrives if the upstream server uses sessions.

### Hybrid: actions and check parameters

| Setting | LLM-guardrail meaning | Observed on MCP tool calls |
|---|---|---|
| mapping `run_on: ["output"]` | output only | Output only, **once the integration has been updated** (see below). Before that the old input+output mapping kept running: `beforeRequestHook` called and input denies blocking, for over 14 hours and several guardrail versions |
| `actions.sequential: true` | run checks one after another | **Doesn't stop at the first failing check**: with two failing checks, both run (the webhook is called even when the check before it failed), and the reason lists both, joined with "; ". From the client and the webhook it looks the same as `false` |
| `actions.sequential: false` | run in parallel | Both checks run; reason lists both in check order; `check_id` is the first check's |
| `actions.soft_deny_200: true` | deny with HTTP 200 | **No difference**: a deny is already HTTP 200 with the JSON-RPC error; response identical |
| `actions.async: true` | check without blocking | Nothing blocked; both hooks still called, even after a failing input check |
| `actions.deny: false` | report, don't block | Nothing blocked; both hooks called; no hook results in the client's response headers or body |
| `failOnError: false`, webhook down | fail open | Call goes through |
| `failOnError: true`, webhook down | fail closed | Blocked; the reason shows the real cause, e.g. "default.webhook: Webhook error: HTTP error! status: 429" |

### Hybrid: when changes take effect

- Check and action changes reached the hybrid gateway in about a minute; they change the guardrail's `version_id`.
- Mapping changes through `PUT .../mcp-servers` don't change `version_id` and **don't take effect** until the gateway's cached data for that MCP server is invalidated. An update to the MCP integration does that (the gateway logs "Invalidating capabilities cache for MCP server …"); guardrail check edits don't. A new guardrail mapped to a server that had already been used didn't run for over 7 minutes, then ran right after the integration was re-saved. A tool switched to `run_on: ["output"]` still got both hooks 75 seconds later, then only `afterRequestHook` after the re-save, and both again after switching back and re-saving.
- Not tested: whether the cache expires on its own after longer than 14 hours, or on a gateway restart.

### Hybrid: what a mapping covers

Tested 2026-10-14 on 2.27.0, with several MCP servers on one upstream, a webhook allowlist that never allows the extra tool, and two workspaces A and B. Rechecked on 2.29.0 on 2026-10-15. Each mapping change was followed by an integration re-save.

| Case | Expected | Observed |
|---|---|---|
| Server with no mapping | no guardrail | Every tool runs, no webhook call |
| Mapping with explicit capability IDs; the upstream then adds a tool | new tool guarded | New tool listed, enabled even though the server's capabilities had been narrowed to one tool, and run with no webhook call |
| Same, remapped without capability IDs | new tool guarded | Denied; a tool added after that (no SCM change, no re-save) was denied too |
| New mapping on a server, no integration re-save, 74 s and 150 s later | guarded | Not guarded; guarded within 45 s of the re-save |
| Integration granted to workspace B as well | B's server guarded like A's | B gets its own server object, unmapped: every tool runs |
| Guardrail from A mapped to B's server (API accepts it) + re-save | guarded | Not guarded about 3 minutes later; the same guardrail kept blocking in A |
| Guardrail created in B, mapped to B's server | guarded | Guarded |
| Guardrail created without `target`, then updated to `target: mcp_tools` | target set | Update reports success, target stays unset; mappings refused ("MCP server mappings can only be set on guardrails with target mcp_tools") |

- Workspace boundary: a user of A calling B's server, or a user of B calling A's, gets 403. An integration not granted to B gets 404 there.
- Narrowing the workspace server's capabilities works without a re-save; enabling a tool there that the integration disables has no effect (reports success).

### Hybrid: organisation guardrails and MCP

Tested 2026-10-19 on gateway 2.29.0.

- An organisation-level guardrail (`/ai_gw/admin/v2/guardrails`) can be created with `target: mcp_tools`. The create response shows `name` and `target` as null, but a read shows both set.
- It can't be mapped to MCP servers. The admin routes `PUT` / `GET /ai_gw/admin/v2/guardrails/<id>/mcp-servers` (and `.../mcp-servers/<server>`) are listed in the published API spec and the CLI, but they return 404 `Cannot PUT`, an HTTP framework error page. The workspace API doesn't know the guardrail (404 AB02).
- Unmapped, it doesn't run on MCP tool calls in any workspace: only the workspace guardrails' hooks were called, and a call that only the organisation guardrail would deny went through.
- The SCM UI offers organisation guardrails for LLM requests only, with per-workspace exclusions. For MCP, use workspace guardrails mapped per server, as above.

### SaaS: where MCP is served

- MCP is on `https://mcp-aigw.portkey.ai/<workspace-slug>/<server-slug>/mcp`; `/<server-slug>/mcp` works too, since the key selects the workspace. Authenticate with `x-portkey-api-key` (scope `mcp.invoke`).
- A key from another workspace gets 403 "You do not have access to this resource". An unknown server gets 404 "Server '<workspace>/<server>' not found". An upstream the SaaS gateway can't reach (for example a cluster-internal URL) gets 502.
- `aigw.portkey.ai/m/<server>/mcp`, the form in the general MCP gateway docs, returns 404 after the key check. `mcp.portkey.ai` doesn't accept AI Gateway keys.
- The workspace MCP server object is created automatically when the integration is granted to the workspace, with the integration's slug.
- Tools are discovered on first use: the server's capabilities list stays empty until the first `tools/list` through the gateway.

### SaaS: static upstream headers

- Put static headers in `configurations.headers` (`auth_type: headers`), as in the gateway's [custom auth docs](https://portkey.ai/docs/aigw/product/mcp-gateway/authentication/custom-auth). `configurations.custom_headers`, the field name in the published CreateMcpIntegration schema, is accepted, stored and read back, but **never sent upstream**.
- When the upstream rejects the missing header with 401, the client sees HTTP 500 with JSON-RPC error -32000 "Failed to restore session. Please reinitialize." That message doesn't point at upstream auth.
- **Fixing the header on an integration that the gateway has already used didn't take effect** for at least 100 minutes; the gateway kept calling without it. An integration changed in the same request but never used before picked up the fix at once. A new integration created with the right header works immediately, so recreate rather than edit.
- What the upstream receives: the static headers, `mcp-protocol-version`, `user-agent: node-fetch` and `x-forwarded-for` (the gateway's egress IP). No client headers, no `x-portkey-*` headers and no trace id are passed through.

## License

MIT; see [LICENSE](../LICENSE).
