# aigw-mcp-tiered-tool-access

The AIRS AI Gateway has no per-user tool permissions for MCP. A guardrail webhook gets no verified user identity (see `aigw-byo-guardrail-mcp`), so it can't decide per user. The workaround is to turn each access tier into its own MCP server, each pointing at the same upstream, with layered controls on each server:

- a JWT group gate decides who may reach the server (`aigw-mcp-jwt-validation`);
- the server's capabilities decide which tools exist there;
- the [webhook](../README.md)'s tool allowlist enforces the same list independently.

Tested on the hybrid gateway 2.27.0 (2026-10-14) and 2.29.0 (2026-10-15), unified mode, with Keycloak.

> **Disclaimer:** Personal test notes. Not an official Palo Alto Networks or Portkey statement, and no support. Behavior may change in later releases.

## How to recognize it

You need this when different groups of users should see different tools of one MCP backend through the gateway, for example read-only tools for everyone and write tools for one team, and:

- the gateway offers per-server access (workspace grants, per-server JWT validation) but nothing per tool and per user;
- a guardrail webhook on MCP tool calls gets the server, workspace and tool name, but no verified user claims, so a per-user rule there would trust client-controlled data.

## Workaround

### 1. One MCP server per tier

For each tier (say `eng-l1`, `eng-l2`), register an MCP integration with the same upstream URL, named for the tier (`<app>-eng-l1`). Grant it to the workspace. If the upstream needs to know the tier, give it a distinct path or static header per integration.

### 2. Gate each server on a group claim

In each integration's `configurations`, require the tier's group (details and caveats in `aigw-mcp-jwt-validation`):

```json
"jwt_validation": {
  "jwksUri": "<realm-url>/protocol/openid-connect/certs",
  "algorithms": ["RS256"],
  "headerKey": "x-portkey-api-key",
  "requiredClaims": ["sub"],
  "claimValues": {
    "iss": {"values": "<realm-url>", "matchType": "exact"},
    "groups": {"values": ["eng-l1"], "matchType": "contains"}
  }
}
```

`headerKey: x-portkey-api-key` makes the client's gateway credential (its IdP JWT) the token that is checked. A user outside the group gets 401 on `initialize`. `contains` is array membership, so `eng-l10` doesn't pass `eng-l1`.

### 3. Narrow the server's capabilities

Disable every tool the tier shouldn't have on the integration's capabilities (SCM, or the integration capabilities API). Disabled tools disappear from `tools/list`, and calling one returns JSON-RPC -32602 `Tool '<name>' is disabled` before any guardrail runs. Changes apply within about a minute, with no re-save. The workspace server's own capabilities can narrow further, but they can't re-enable a tool the integration disables.

### 4. Enforce the same list in the guardrail webhook

Capabilities alone don't cover tools the upstream adds later: a new tool showed up listed and enabled on every tier, although each tier's capabilities had been narrowed to its own tools. So enforce an allowlist in the webhook too. Create a workspace guardrail with `target: mcp_tools`, check `default.webhook` with `failOnError: true`, and the policy as a static check header:

```json
"headers": {
  "x-guardrail-token": "<webhook token>",
  "x-tool-policy": "{\"<app>-eng-l1\":[\"search\"],\"<app>-eng-l2\":[\"search\",\"update\"]}"
}
```

Keys are server slugs (or `<workspace slug>/<server slug>`). Any tool not listed, and any server missing from the policy, is denied: JSON-RPC -32446 `Request blocked by guardrail`. [`webhook/handler.py`](../webhook/handler.py) implements this; any webhook that reads `metadata.mcpServerId` and `mcpToolName` can. Never put `x-tool-policy` in `forwardHeaders`: a client could then send its own policy.

Map the guardrail to every tier's server, input and output, **without** `mcp_integration_capability_ids`, then re-save each integration (mapping rules in `aigw-byo-guardrail-mcp`).

### 5. Keep it closed

- Every server an integration has in any workspace needs a mapping from a guardrail of that workspace. An unmapped server, including the one created when an integration is granted to another workspace, allows every enabled tool.
- Policy edits are guardrail edits: they apply in about a minute, with no integration re-save.
- Keep the policy header under about 8 KB if the webhook is on an AWS Lambda Function URL. At 12 KB and above the Function URL rejects the request (HTTP 413) and `failOnError` turns that into deny for everything.
- With `failOnError: true`, a webhook outage denies every call on mapped servers, after about a minute (the time for the change to reach the gateway).

### Optional: let the upstream authorize per user

If the upstream can verify tokens, forward the user's JWT (`user_identity_forwarding.method: bearer`, to a header the upstream reads). The upstream then authorizes each tool on the user's own claims. Have it check the audience: give tokens an audience the upstream requires, and gate the server on `claimValues.aud` at the gateway. This puts per-user decisions in the upstream, which needs its own code. The gateway layers above still apply.

### Not a workaround: the JWT in a second header for the webhook

A client can send its JWT twice, once as `x-portkey-api-key` and once in a custom header that the guardrail forwards to the webhook. The webhook can then verify it and decide per user. Standard MCP clients can't do this: their token refresh updates only the auth header, so the second header, which is static configuration, goes stale at expiry and every call is denied. The webhook also can't check that both headers carry the same token, because the gateway refuses to forward `x-portkey-api-key`. This only fits bespoke clients that set both headers from one token source.

## Setup used

- Hybrid gateway, unified mode; gateway authentication by the organisation's JWKS, so clients use their Keycloak token as `x-portkey-api-key`.
- Keycloak 26.7.5: groups `eng-l1`, `eng-l2`, `hr-shared-l1`, `hr-l2`, `eng-l10`; client-credentials test users with a `groups` claim, one with no groups.
- Upstream: the [probe MCP server](../mcp/server.py) (tools `echo`, `get_canary`, `danger`, `whoami`), one path per tier, plus an extra tool switched on later through `mcp_env`.
- Five tier integrations: four with a policy entry, and one gated like `eng-l1` but missing from the policy. Then a second workspace with one of the integrations granted to it.
- Webhook: [`webhook/handler.py`](../webhook/handler.py) on a Lambda Function URL, policy `{"<eng-l1>":["echo"],"<eng-l2>":["get_canary"],"<hr-shared-l1>":["whoami"],"<hr-l2>":["danger"]}`.
- Driver: [`tierprobe.sh`](tierprobe.sh), one fresh MCP session per user × server × tool.

## Findings

Tested 2026-10-14 against hybrid gateway 2.27.0 (chart airs-gw-1.2.0, unified mode) and rerun 2026-10-15 against 2.29.0 with identical results, Keycloak 26.7.5. Not tested on SaaS. MCP guardrails didn't run on SaaS on 2026-10-13 (`aigw-byo-guardrail-mcp`).

| Layer | Observed |
|---|---|
| Group gate | `initialize` succeeds only for users in the tier's group. Others get 401 `Invalid claims: groups`, a token with no `groups` claim gets `Invalid claims: groups (missing)`, and `eng-l10` is rejected on `eng-l1` |
| Capabilities | Disabled tools are absent from `tools/list`; calling one gets -32602 with no webhook call. Effective in 50–67 s, no re-save. Enabling a tool on the workspace server that the integration disables reports success and has no effect |
| Webhook allowlist | Listed tool runs; any other enabled tool -32446, and the after hook isn't called. A mapped server missing from the policy: every tool -32446 |
| All together, on each tier | Allowlisted tool runs; capability-disabled tools -32602; an enabled tool missing from the allowlist (the extra tool) -32446 |
| Upstream per-user authz (`bearer`) | The upstream got the user's token, verified it and allowed or refused a tool by group. One token with two audiences passed both the gateway's `claimValues.aud` gate and the upstream's audience check |

Changes and failures:

- Policy edit: effective in 52–68 s. Invalid JSON as policy: every call denied within about 34 s.
- Policy size on a Lambda Function URL: 4 KB and 8 KB work; 12 KB and 16 KB deny everything. The webhook is never invoked; SCM and the gateway carried 16 KB.
- Webhook URL pointed at an unreachable host: calls still allowed for about 60 s, then denied. After restoring the URL, still denied for about 50 s.

Gaps, all closed by the mapping rules in step 4 and 5 (details in `aigw-byo-guardrail-mcp`):

- An unmapped tier server ran every enabled tool.
- A tool the upstream added later was listed and enabled on every tier. While the mappings carried explicit capability IDs, it also ran with no webhook call. Remapped with no capability IDs, the allowlist denied it, and denied a tool added after that too.
- In a second workspace, the granted integration's server ran every tool until a guardrail from that workspace was mapped. A guardrail from the first workspace mapped there was accepted but never ran.
- The workspace boundary held: users of one workspace got 403 on the other's servers.

## License

MIT; see [LICENSE](../LICENSE).
