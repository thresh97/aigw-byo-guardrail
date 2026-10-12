# aigw-byo-guardrail

A bring-your-own guardrail for the Prisma AIRS / Portkey AI Gateway
([webhook guardrail docs](https://portkey.ai/docs/integrations/guardrails/bring-your-own-guardrails)).
It blocks LLM requests based on request metadata the built-in guardrails can't match: the client IP
(CIDR allow and deny lists) and arbitrary request headers (regex require or deny rules).

> **Disclaimer:** This is a simple, art-of-the-possible example of a bring-your-own guardrail. It is **not** an official
> Palo Alto Networks or Portkey project, it is **not** a recommended or supported production design, and it comes with
> **no support**. Use it at your own risk, under the [MIT License](LICENSE).

```
client ──► AI Gateway (SaaS) ──► LLM provider
               │ default.webhook (beforeRequestHook, forwardHeaders: cf-connecting-ip, x-app)
               ▼
         Lambda Function URL (aigw-byo-guardrail)  → {"verdict": true|false}
```

| Path | What |
|---|---|
| `webhook/handler.py` | The Lambda (Python stdlib only). It reads the policy from env `POLICY`, authenticates the gateway with a shared token in `x-guardrail-token`, and logs the headers it received (auth values redacted) to CloudWatch |
| `infra/` | Terraform for the Lambda, its Function URL, IAM, the log group and the token |
| `tests/` | `python3 -m unittest tests/test_handler.py`; `e2e.sh` (wire, ask, policy, down/up, logs, teardown through a real gateway) and `cases.sh` (the full case matrix behind the Findings). Every request carries a readable `x-portkey-trace-id` (`<run>-<case>`) and `x-portkey-metadata` (run, case, guardrail, what it expects), so the gateway's logs explain themselves |

Needs: Terraform ≥ 1.5, AWS credentials, [`airs-cli`](https://www.npmjs.com/package/@cdot65/prisma-airs-cli) with a
tenant selected (`airs-cli doctor` all green), `jq`, `curl`.

## 1. Deploy the webhook

```bash
cp infra/terraform.tfvars.example infra/terraform.tfvars   # set your allow_cidrs / header_rules
cp infra/backend.tf.example infra/backend.tf               # optional: remote state
terraform -chdir=infra init
terraform -chdir=infra apply
```

Both files are gitignored. To change the policy later, edit `terraform.tfvars` and run `apply` again. That updates the Lambda env; nothing changes on the gateway side.

Smoke test:

```bash
URL=$(terraform -chdir=infra output -raw webhook_url)
curl -s -X POST "$URL" -d '{}'                                  # {"error": "unauthorized"}  (401)
curl -s -X POST "$URL" -d '{}' -H 'cf-connecting-ip: 192.0.2.10' \
  -H @<(printf 'x-guardrail-token: %s\n' "$(terraform -chdir=infra output -raw webhook_token)")
# {"verdict": true, ...} if 192.0.2.10 is in allow_cidrs
```

## 2. Wire it into a gateway workspace (airs-cli)

```bash
TSG=<tsg-id>                    # airs-cli tenant list
WS=<workspace-slug>             # airs-cli aigateway workspaces list
WS_ID=$(airs-cli --quiet aigateway workspaces get "$WS" --output json | jq -r .id)

# Guardrail: webhook check. The token goes in the check's headers. failOnError makes it fail closed.
CHECKS=$(terraform -chdir=infra output -json | jq -c '[{id: "default.webhook", parameters: {
  webhookURL: .webhook_url.value, headers: {"x-guardrail-token": .webhook_token.value},
  forwardHeaders: ["cf-connecting-ip", "x-app"], timeout: 3000, failOnError: true}}]')
ACTIONS='{"deny":true,"async":false,
  "on_success":{"feedback":{"value":1,"weight":1,"metadata":""}},
  "on_fail":{"feedback":{"value":-1,"weight":1,"metadata":""}}}'
GR=$(airs-cli --quiet aigateway guardrails create --workspace "$WS_ID" --name byo-ip-guardrail \
  --checks "$CHECKS" --actions "$ACTIONS" --output json)
GR_ID=$(jq -r .id <<<"$GR"); GR_SLUG=$(jq -r .slug <<<"$GR")

# Config: Anthropic passthrough. The client's own Authorization bearer (e.g. a Claude OAuth token from
# `claude setup-token`) is forwarded; there is no stored provider key. input_guardrails runs the webhook before each request.
CONFIG=$(jq -cn --arg g "$GR_SLUG" '{provider: "anthropic", retry: {attempts: 1},
  forward_headers: ["authorization", "anthropic-beta"], input_guardrails: [$g]}')
CFG_ID=$(airs-cli --quiet aigateway configs create --workspace "$WS_ID" --name byo-ip-config \
  --set "config=$CONFIG" --output json | jq -r .id)

# Service key whose default config is the one above. The secret is written once to gateway-key.json (gitignored),
# which holds {id, key}.
(umask 077; airs-cli --quiet aigateway api-keys service create --type workspace --workspace "$WS_ID" \
  --organisation-id "$TSG" --name byo-ip-key --scopes completions.write,logs.write \
  --set "defaults={\"config_id\":\"$CFG_ID\"}" --secret-output gateway-key.json --output json >/dev/null)
KEY_ID=$(jq -r .id gateway-key.json)
```

Two gotchas: `airs-cli` rejects `actions` unless every `feedback` object has a `metadata` field. And any header you want to
match has to be listed in `forwardHeaders`. The default payload has no client headers.

## 3. Test (curl)

```bash
GATEWAY=https://aigw.portkey.ai      # SaaS runtime
ask() {  # ask [extra curl args...] -> HTTP status + start of body
  curl -s -m 60 -w '\nHTTP %{http_code}\n' "$GATEWAY/v1/messages" \
    -H 'content-type: application/json' -H 'anthropic-version: 2023-06-01' -H 'anthropic-beta: oauth-2025-04-20' \
    -H @<(printf 'x-portkey-api-key: %s\nauthorization: Bearer %s\n' "$(jq -r .key gateway-key.json)" "$CLAUDE_CODE_OAUTH_TOKEN") \
    "$@" -d '{"model":"claude-haiku-4-5","max_tokens":10,"messages":[{"role":"user","content":"Reply with one word: ok"}]}' \
    | cut -c1-200
}
ask                                                    # 200 from an allowed egress IP
ask -H 'x-app: probe-blockme'                          # 446 (header deny rule)
ask -H 'x-forwarded-for: 192.0.2.10'                   # no effect on SaaS: the webhook only trusts cf-connecting-ip (hybrid: see Findings)
ask -H 'cf-connecting-ip: 192.0.2.10'                  # 403 "error code: 1000": the edge rejects it
```

A 446 response carries the reason from the webhook:

```bash
ask -H 'x-app: probe-blockme' >/dev/null   # or capture the full body and:
# jq '.hook_results.before_request_hooks[0].checks[0].data.responseData'   ->  {"reason": "x-app matches deny 'blockme'"}
```

To prove IP enforcement from an allowed network, add your own egress range to `deny_cidrs`, `apply`, and re-run `ask`.
Every request gets a 446 with `cf-connecting-ip=<your ip> in deny_cidrs`. Remove the range and `apply` again.

The webhook's CloudWatch log group (`terraform -chdir=infra output -raw log_group`) records every verdict and the header names
it received. That's the quickest way to see what the gateway actually forwards.

## 4. Teardown

```bash
airs-cli --quiet aigateway api-keys service delete "$KEY_ID" --force
airs-cli --quiet aigateway configs delete "$CFG_ID" --force
airs-cli --quiet aigateway guardrails delete "$GR_ID" --force
rm -f gateway-key.json
terraform -chdir=infra destroy
```

## Findings

Tested 2026-09-30 and again 2026-10-09 on the SaaS gateway (no version exposed), and on 2026-10-12 on a hybrid gateway
(image 2.27.0, chart airs-gw-1.2.0, EKS behind an AWS ALB), with the webhook on a Lambda Function URL as deployed by `infra/`.
`tests/e2e.sh` runs the same cases against either.

### Both gateways

- Allow and deny CIDR rules and header rules behave as described: 200 when allowed, 446 when blocked.
- On a block, the gateway's `explanation` says "Webhook request failed" even though the webhook returned 200 with `verdict:false`.
  The real reason is in `responseData`.
- **`failOnError: true` fails closed**: when the webhook errors (tested with HTTP 429), the request gets a 446. With
  `failOnError: false` it goes through and **no rule runs at all, header rules included**. A webhook *timeout*, as opposed to
  an error, hasn't been tested.
- The default payload has `requestType` (`messages`), `provider` (`anthropic`), `metadata` (from `x-portkey-metadata`) and the
  request body. It has no client IP unless you list the header in `forwardHeaders`.
- An egress IP can rotate within a NAT pool from one request to the next. Allowlist the whole range.

### SaaS gateway

What the webhook receives when the client sends each header (from the webhook's CloudWatch logs):

| Client sends | Reaches webhook as | Trust |
|---|---|---|
| nothing | `cf-connecting-ip` = client egress IP, set by the Cloudflare edge (the gateway runs as a Worker; there's a `cf-worker` header). `x-forwarded-for` = the same IP | ✅ (`cf-connecting-ip`) |
| spoofed `cf-connecting-ip` | request rejected at the edge: HTTP 403 `error code: 1000` | ✅ unforgeable |
| spoofed `x-forwarded-for` | the client's value **replaces** the edge's, it isn't appended to | ❌ client-controlled |
| spoofed `true-client-ip` | forwarded unchanged | ❌ client-controlled |
| `x-real-ip` | not forwarded (dropped) | n/a |
| custom header (`x-app`) | forwarded unchanged | client-controlled; fine for deny rules on cooperative clients |

Use `ip_headers = ["cf-connecting-ip"]` on SaaS.

### Hybrid gateway behind an ALB

What the webhook receives (the ALB in its default `append` XFF mode, the webhook on a Lambda Function URL):

| Client sends | Reaches webhook as | Trust |
|---|---|---|
| nothing | `x-forwarded-for` = client IP (set by the ALB) | ✅ only while the client sends none |
| spoofed `x-forwarded-for` | **only the client's value**: the ALB appends the real IP, but the Function URL keeps just the leftmost entry | ❌ client-controlled |
| spoofed `cf-connecting-ip` / `true-client-ip` / `x-real-ip` | forwarded unchanged | ❌ client-controlled |

- The Lambda Function URL itself keeps only the leftmost `x-forwarded-for` entry: a direct request with
  `x-forwarded-for: 192.0.2.10, 198.51.100.7` reaches the handler as `192.0.2.10`. So no handler logic can recover the
  load balancer's entry.
- In practice, with `ip_headers = ["x-forwarded-for"]`, a client **bypasses a deny rule** and **passes an allowlist** by sending
  `x-forwarded-for: <an allowed IP>`.
- **IP rules in this example aren't safe on a hybrid gateway as deployed.** Options:
  - Enforce client IPs at your own load balancer instead (ALB security group or listener rules, WAF); the gateway sits behind it anyway.
  - Overwrite the client IP header in a proxy you run in front of the gateway (set it to the peer address, drop the
    client's value), so whatever reaches the webhook was set by you. An ALB alone can't: its XFF modes are append,
    preserve and remove, and with `remove` the Function URL fills in the gateway's own egress IP. Not tested here.
  - Put the webhook behind a front end that keeps the full XFF chain (API Gateway, an ALB, a container) and read the entry
    your trusted hop added (counting from the right). Not tested here.
- Header rules are unaffected by this and work as on SaaS.

## License

[MIT](LICENSE). Provided as-is, with no support and no warranty. This is an example, not an official or recommended product.
