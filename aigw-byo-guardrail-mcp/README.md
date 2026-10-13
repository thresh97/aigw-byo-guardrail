# aigw-byo-guardrail-mcp

The [webhook guardrail](../README.md) used on MCP tool calls (`target: mcp_tools`) instead of LLM requests. On the SaaS gateway on 2026-10-13, MCP guardrails didn't run at all: not the webhook check, not a built-in check, whether mapped to an MCP server or set as the workspace's default MCP guardrail. Hybrid hasn't been tested yet. This page also covers how SaaS serves MCP and three integration gotchas found on the way.

> **Disclaimer:** Personal test notes. Not an official Palo Alto Networks or Portkey statement, and no support. Behavior may change in later releases.

## How to recognize it

- A tool call that the guardrail should block comes back 200 with the tool's result.
- The webhook is never called: its logs have no invocation for the call. Any webhook that logs requests shows this; [`webhook/handler.py`](../webhook/handler.py) logs every call.
- A built-in check (for example `default.contains` with a deny word) mapped the same way doesn't block either.
- The guardrail and its mappings look right in the control plane: the guardrail has `target: mcp_tools`, and the MCP server object lists it under `guardrail_mappings`.

## Workaround

None known on SaaS. The hybrid gateway is the next test here.

## Setup used

- Probe MCP server: [`mcp/server.py`](../mcp/server.py) on a Lambda Function URL, deployed with `mcp_server = true` ([`infra/mcp.tf`](../infra/mcp.tf)). Every path's first segment is a separate server name (`/a/mcp`, `/b/mcp`, ...), so one function can be registered as several MCP integrations. It requires its token in `x-mcp-token`, and its `whoami` tool returns the headers it received.
- Webhook: the guide's Lambda with `log_payload = true` and a header rule `x-app` deny `blockme`.
- MCP guardrail: `target: mcp_tools`, one check `default.webhook` (`webhookURL`, `headers: {x-guardrail-token: ...}`, `forwardHeaders: [x-app]`, `failOnError: false`), `actions.deny: true`.
- Mappings set with `PUT /ai_gw/v2/guardrails/<id>/mcp-servers`, body `{"mcp_servers": {"<mcp server id>": {"run_on": ["input","output"], "mcp_integration_capability_ids": []}}}` (empty list = all tools). This call replaces the whole set. The MCP server id is the workspace-level server object, not the integration id; tool ids come from `GET /ai_gw/v2/mcp-servers/<id>/capabilities`.
- Driver: [`probe.sh`](probe.sh) (`GW`, `KEY`, `A`, `B`), one fresh MCP session per case, with and without `x-app: blockme`.

## Findings

Tested 2026-10-13 on the SaaS gateway (no version exposed), with the probe server and webhook on Lambda Function URLs.

### SaaS: MCP guardrails don't run

| Setup | Expected | Observed |
|---|---|---|
| Webhook guardrail mapped to a server, all tools, input and output, `x-app: blockme` | blocked | 200, webhook not called |
| Same, mapped to one tool on input only, call to that tool with `blockme` | blocked | 200, webhook not called |
| Mapping made before the server's first use | blocked | 200, webhook not called |
| Workspace default MCP guardrail (`defaults.mcp_input_guardrails` / `mcp_output_guardrails`) with a built-in `contains` deny word, set for weeks | blocked | 200 |
| Rechecked about 60 to 75 minutes after the last change | blocked | 200, webhook not called |

A direct call to the webhook in the same window was logged, so the zero count is real. Whether workspace-default MCP guardrails are meant to be supported isn't documented.

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
