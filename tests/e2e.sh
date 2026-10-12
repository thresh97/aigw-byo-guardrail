#!/usr/bin/env bash
# e2e.sh: end-to-end test of the webhook guardrail through a real gateway (run from the repo root, after `terraform apply`).
#
#   bash tests/e2e.sh wire                       # create <PREFIX>-closed/-open guardrails, configs and service keys
#   bash tests/e2e.sh ask <label> [curl args]    # one /v1/messages request; prints label, HTTP code, verdicts, reason
#   bash tests/e2e.sh policy <file.tfvars>       # apply a test policy (copied to infra/probe.auto.tfvars, gitignored)
#   bash tests/e2e.sh policy reset               # remove the test policy and apply again
#   bash tests/e2e.sh down | up                  # webhook unreachable (Lambda reserved concurrency 0) | reachable again
#   bash tests/e2e.sh logs <since>               # webhook (and mock) CloudWatch lines since e.g. 30m, secrets redacted
#   bash tests/e2e.sh teardown                   # delete what `wire` created
#
# Env: GW_URL (gateway base URL, e.g. https://aigw.portkey.ai), WS_ID (workspace UUID), TSG (tenant TSG ID),
# KEY=closed|open (which guardrail `ask` goes through, default closed), OUT (dir for full response bodies, optional),
# FORWARD_HEADERS (comma list, default: the IP headers worth inspecting plus x-app),
# UPSTREAM_HOST (optional: an Anthropic-compatible mock as custom_host; otherwise Anthropic itself, with the client's bearer),
# BEARER (client bearer for the provider; default a dummy, fine with a mock), MOCK_LOG_GROUP (optional, for `logs`),
# FUNCTION_NAME (for down/up, default aigw-byo-guardrail),
# MODES (default "closed open"), STATE (where ids and key secrets go, default ~/.local/state/aigw-byo-guardrail; never commit or copy it).
set -euo pipefail
PREFIX=${PREFIX:-byo-probe}
STATE=${STATE:-$HOME/.local/state/aigw-byo-guardrail}
FORWARD_HEADERS=${FORWARD_HEADERS:-cf-connecting-ip,x-forwarded-for,x-real-ip,true-client-ip,forwarded,x-envoy-external-address,x-app}
TF=(terraform -chdir=infra)
GW=(airs-cli --quiet aigateway)
mkdir -p "$STATE" && chmod 700 "$STATE"

redact() {  # replace every secret this run knows about with <redacted>
  local s args=()
  for s in "$("${TF[@]}" output -raw webhook_token 2>/dev/null)" "${UPSTREAM_HOST:-}" "${BEARER:-}" \
           $(cat "$STATE"/*.key 2>/dev/null | jq -r '.key // empty' 2>/dev/null); do
    [ -n "$s" ] && [ ${#s} -ge 8 ] && args+=(-e "s|$(printf '%s' "$s" | sed 's/[][\.*^$|/]/\\&/g')|<redacted>|g")
  done
  if [ ${#args[@]} -gt 0 ]; then sed "${args[@]}"; else cat; fi
}

case ${1:-} in
  wire)
    : "${WS_ID:?set WS_ID}"; : "${TSG:?set TSG}"
    URL=$("${TF[@]}" output -raw webhook_url)
    ACTIONS='{"deny":true,"async":false,"on_success":{"feedback":{"value":1,"weight":1,"metadata":""}},
      "on_fail":{"feedback":{"value":-1,"weight":1,"metadata":""}}}'
    for mode in ${MODES:-closed open}; do
      fail=$([ $mode = closed ] && echo true || echo false)
      CHECKS=$(jq -cn --arg u "$URL" --arg t "$("${TF[@]}" output -raw webhook_token)" --arg f "$FORWARD_HEADERS" --argjson e "$fail" \
        '[{id: "default.webhook", parameters: {webhookURL: $u, headers: {"x-guardrail-token": $t},
           forwardHeaders: ($f | split(",")), timeout: 3000, failOnError: $e}}]')
      GR=$("${GW[@]}" guardrails create --workspace "$WS_ID" --name "$PREFIX-$mode" --checks "$CHECKS" --actions "$ACTIONS" --output json)
      CONFIG=$(jq -cn --arg g "$(jq -r .slug <<<"$GR")" --arg h "${UPSTREAM_HOST:-}" \
        '{provider: "anthropic", retry: {attempts: 1}, forward_headers: ["authorization", "anthropic-beta"], input_guardrails: [$g]}
         + (if $h == "" then {} else {custom_host: $h} end)')
      CFG=$("${GW[@]}" configs create --workspace "$WS_ID" --name "$PREFIX-$mode" --set "config=$CONFIG" --output json)
      (umask 077; "${GW[@]}" api-keys service create --type workspace --workspace "$WS_ID" --organisation-id "$TSG" \
        --name "$PREFIX-$mode" --scopes completions.write,logs.write --set "defaults={\"config_id\":\"$(jq -r .id <<<"$CFG")\"}" \
        --secret-output "$STATE/$mode.key" --output json >/dev/null)
      jq -n --arg gr "$(jq -r .id <<<"$GR")" --arg cfg "$(jq -r .id <<<"$CFG")" --arg key "$(jq -r .id "$STATE/$mode.key")" \
        '{guardrail: $gr, config: $cfg, key: $key}' > "$STATE/$mode.ids"
      printf 'wired\t%s\tfailOnError=%s\n' "$PREFIX-$mode" "$fail"
    done ;;
  ask)
    : "${GW_URL:?set GW_URL}"; label=${2:?label}; shift 2
    keyfile=$STATE/${KEY:-closed}.key; [ -f "$keyfile" ] || { echo "no $keyfile; run wire first" >&2; exit 1; }
    body=$(mktemp); trap 'rm -f "$body"' EXIT
    code=$(curl -s -m 60 -o "$body" -w '%{http_code}' "$GW_URL/v1/messages" \
      -H 'content-type: application/json' -H 'anthropic-version: 2023-06-01' \
      -H @<(printf 'x-portkey-api-key: %s\nauthorization: Bearer %s\n' "$(jq -r .key "$keyfile")" "${BEARER:-dummy-client-bearer}") \
      "$@" -d '{"model":"claude-haiku-4-5","max_tokens":10,"messages":[{"role":"user","content":"Reply with one word: ok"}]}') || code=000
    if [ -n "${OUT:-}" ]; then mkdir -p "$OUT"; redact < "$body" > "$OUT/$label.json"; fi
    summary=$(jq -r '[(.hook_results.before_request_hooks // [] | map(.verdict | tostring) | join(",")),
        ((.hook_results.before_request_hooks // [])[0].checks[0] | (.data.responseData.reason? // .data.explanation? // .error.message? // ""))] | @tsv' \
      "$body" 2>/dev/null || printf '\t%s' "$(head -c 160 "$body" | tr -d '\n')")
    printf '%s\t%s\t%s\t%s\n' "$label" "${KEY:-closed}" "$code" "$summary" | redact ;;
  policy)
    case ${2:?file or reset} in
      reset) rm -f infra/probe.auto.tfvars ;;
      *) cp "$2" infra/probe.auto.tfvars ;;
    esac
    "${TF[@]}" apply -input=false -auto-approve -no-color | grep -E '^Apply complete|Error' ;;
  down) aws lambda put-function-concurrency --function-name "${FUNCTION_NAME:-aigw-byo-guardrail}" \
          --reserved-concurrent-executions 0 --output text ;;
  up)   aws lambda delete-function-concurrency --function-name "${FUNCTION_NAME:-aigw-byo-guardrail}" && echo up ;;
  logs)
    since=${2:-30m}
    aws logs tail "$("${TF[@]}" output -raw log_group)" --since "$since" --format short | redact
    [ -n "${MOCK_LOG_GROUP:-}" ] && { echo "--- mock"; aws logs tail "$MOCK_LOG_GROUP" --since "$since" --format short | redact; } || true ;;
  teardown)
    for mode in ${MODES:-closed open}; do
      f=$STATE/$mode.ids; [ -f "$f" ] || continue
      "${GW[@]}" api-keys service delete "$(jq -r .key "$f")" --force >/dev/null && echo "deleted key $PREFIX-$mode"
      "${GW[@]}" configs delete "$(jq -r .config "$f")" --force >/dev/null && echo "deleted config $PREFIX-$mode"
      "${GW[@]}" guardrails delete "$(jq -r .guardrail "$f")" --force >/dev/null && echo "deleted guardrail $PREFIX-$mode"
      shred -u "$STATE/$mode.key" 2>/dev/null || rm -f "$STATE/$mode.key"; rm -f "$f"
    done ;;
  *) sed -n '2,19p' "$0"; exit 1 ;;
esac
