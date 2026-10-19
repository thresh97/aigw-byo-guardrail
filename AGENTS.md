# AGENTS.md

Guidance for coding agents running or changing this repo. Read README.md first: it explains the webhook, the policy
format and the test flow. The two nested articles build on it: [`aigw-byo-guardrail-mcp/`](aigw-byo-guardrail-mcp/README.md)
(the webhook as an MCP guardrail, with the probe MCP server) and [`aigw-mcp-airs-webhook/`](aigw-mcp-airs-webhook/README.md)
(Prisma AIRS scans of MCP tool calls through the webhook).

## What running this touches

- **AWS** (`terraform -chdir=infra apply`): the webhook Lambda, its IAM role, CloudWatch log group and a public Function
  URL (`authorization_type = "NONE"`; the shared token is the only protection). With `mcp_server = true`, the same set
  again for the probe MCP server. Terraform state holds the webhook token, the MCP token and, with AIRS on, the AIRS API
  key. A plain `apply` without the variables used last time can destroy or change what's deployed: check
  `terraform plan` first.
- **Kubernetes** (`k8s/webhook.sh`): a Deployment, Service, Secrets (`$NAME`, `$NAME-airs`) and ConfigMaps
  (`$NAME-code`, `$NAME-policy`) in `$K8S_NAMESPACE`. `delete` removes exactly those. Check that `NAME` doesn't clash
  with something already in the namespace.
- **SCM tenant** (`tests/e2e.sh wire`): guardrails, configs and service keys named `$PREFIX-closed` / `$PREFIX-open`
  (default prefix `byo-probe`) in `$WS_ID`. Their ids and key secrets go to `$STATE` (default
  `~/.local/state/aigw-byo-guardrail`), which `teardown` reads; don't delete it before teardown. The MCP articles also
  create MCP integrations, guardrail mappings and keys by hand (see their READMEs); name them `*-probe-*` or `*-test-*`.
- **Gateway:** a webhook on a private host (k8s, Docker) only works once its host is in the hybrid gateway's
  `TRUSTED_CUSTOM_HOSTS`. Changing that redeploys a shared data plane: get the operator's go-ahead first and revert it
  afterwards. Mapping a guardrail to an MCP server, or setting a workspace default, changes behavior for everyone using
  that server or workspace; the same applies.
- **Prisma AIRS** (with `AIRS` set): one sync scan per hook, logged in the tenant under `app_name`.

## Rules

- **Secrets.**
  - Never print, log or commit the webhook token, MCP token, AIRS API key, SCM credentials, gateway keys or JWTs.
    `terraform output -raw webhook_token` and `k8s/webhook.sh token` go into a variable, not the terminal.
  - When inspecting JSON from a CLI or API that may carry secrets, select known-safe fields (`jq '{id, name}'`, or
    `jq 'keys'` first). Don't rely on deleting the field names you expect: the secret field may be named differently.
  - Pass the AIRS key as `TF_VAR_airs_api_key` or env, never in a tfvars file. `LOG_PAYLOAD` / `log_payload` logs
    prompts and tool content: testing only.
- **Tenant data stays out of git.** `infra/terraform.tfvars`, `infra/backend.tf`, `*.auto.tfvars`, state files and
  `CLAUDE.local.md` are gitignored; keep deployment facts there. Don't add tenant or TSG IDs, workspace or org UUIDs,
  account numbers, gateway or Function URLs, real IPs, profile names or customer names to tracked files. Use
  placeholders (`<gateway>`, `<workspace uuid>`, `<your profile>`).
- **Only touch what you created.** `e2e.sh teardown` deletes the objects recorded in `$STATE`. Never delete guardrails,
  integrations, keys or profiles you didn't create; other people's objects may be in the same workspace.
- **Hybrid MCP mapping cache.** After mapping or unmapping a guardrail on an MCP server, re-save the MCP integration or
  the old mapping keeps running (see `aigw-byo-guardrail-mcp`). Don't report a mapping change as tested until you've
  done that.
- **Report what you observe.** A result counts only if the webhook log or the gateway response shows it. If a claim
  comes from docs or code reading rather than a run, say so.

## Cleanup (always finish with this)

1. Remove MCP guardrail mappings or workspace defaults you set, and re-save the integration.
2. `bash tests/e2e.sh teardown` (same `PREFIX`, `STATE` and `MODES` as `wire`); delete any MCP integrations, guardrails
   and keys you created by hand.
3. Revert `TRUSTED_CUSTOM_HOSTS` if you changed it.
4. `bash k8s/webhook.sh delete` and/or `terraform -chdir=infra destroy`, unless the operator wants it kept.

## Changing the code

- `webhook/` and `mcp/` are stdlib-only Python; shell scripts are bash with `set -euo pipefail`. Keep it that way: no
  new dependencies, so the Lambda zip and the k8s ConfigMap stay plain source files.
- A new file under `webhook/` has to be added in three places: the `archive_file` sources in `infra/main.tf`, the code
  ConfigMap in `k8s/webhook.sh`, and the README's file table. Exception: `pinctl.py` isn't in the Lambda zip, and
  `PIN` has no Terraform variable, since descriptor pinning refuses to run on Lambda (no shared state file).
- Descriptor pinning keeps state in a file (`PIN` `store`, default `/data/pins.json`). Deleting it, or a pod losing its
  emptyDir, resets every server to trust on first use. Treat it like the other tenant data: never commit it.
- New webhook settings go in env, documented in the module docstring, `infra/variables.tf`, `k8s/webhook.sh` and the
  article that uses them.
- Run `python3 -m unittest discover -s tests` before committing; the AIRS tests use a fake poster and never call AIRS.
- If you rerun a test against a new gateway or AIRS version, add the version and date to that article's Findings,
  not over the old results.
