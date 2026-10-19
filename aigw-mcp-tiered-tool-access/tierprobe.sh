#!/usr/bin/env bash
# Tiered MCP tool access matrix: for every user x server (x tool), a fresh MCP session (initialize,
# notifications/initialized), then one operation.
#
# Usage: GW=https://<gateway>/m/<workspace-slug> TOKEN_URL=<IdP token endpoint> USERS="eng1 hr" SERVERS="<slug> ..." \
#        [OP=init|list|call] [TOOLS="echo whoami"] [ARGS='<json>'] [SCOPE="<extra scopes>"] [EXTRA='<header>'] \
#        [OUT=<dir>] bash tierprobe.sh
#   Each user is a client-credentials client: CLIENT_<USER>=<id> SECRET_<USER>=<secret> in the environment
#   (user name upper-cased, '-' -> '_'). The token is sent as x-portkey-api-key (gateway auth by the org JWKS,
#   and the servers' jwt_validation with headerKey x-portkey-api-key).
# Results: OUT/results.tsv (user, server, tool, init http, call http, result). Tokens are never written out.
set -euo pipefail

GW=${GW:?MCP base URL, see usage}; TOKEN_URL=${TOKEN_URL:?}
USERS=${USERS:?}; SERVERS=${SERVERS:?}; OP=${OP:-call}; TOOLS=${TOOLS:-echo}
OUT=${OUT:-/tmp/mcp-tiers-out}
umask 077; mkdir -p "$OUT"

mint() { # <user> -> access token
  local v; v=$(tr 'a-z-' 'A-Z_' <<<"$1"); local id="CLIENT_$v" sec="SECRET_$v"
  curl -s "$TOKEN_URL" -d grant_type=client_credentials --data-urlencode "client_id=${!id:?no client for $1}" \
    --data-urlencode "client_secret=${!sec:?no secret for $1}" ${SCOPE:+--data-urlencode "scope=$SCOPE"} | jq -r .access_token
}
post() { # <tag> <session> <body>; uses $TOKEN and $server
  local tag=$1 sid=$2 body=$3
  local args=(-s -o "$OUT/$tag.body" -D "$OUT/$tag.headers" -w '%{http_code}' -X POST "$GW/$server/mcp"
    -H 'content-type: application/json' -H 'accept: application/json, text/event-stream'
    -H "x-portkey-api-key: $TOKEN")
  [[ -n "$sid" ]] && args+=(-H "mcp-session-id: $sid")
  [[ -n "${EXTRA:-}" ]] && args+=(-H "$EXTRA")
  curl "${args[@]}" -d "$body"
}
rpc() { sed -n 's/^data: //p; /^{/p' "$1" | tail -1; }

printf 'user\tserver\ttool\tinit\tcall\tresult\n' > "$OUT/results.tsv"
for user in $USERS; do
  TOKEN=$(mint "$user"); [[ "$TOKEN" == ey* ]] || { echo "could not mint a token for $user" >&2; exit 1; }
  for server in $SERVERS; do
    for tool in $TOOLS; do
      [[ "$OP" == call ]] || tool=-
      tag="$user-$server-$tool"
      init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"tierprobe","version":"0"}}}'
      ic=$(post "$tag-init" "" "$init"); cc=-
      sid=$(grep -i '^mcp-session-id:' "$OUT/$tag-init.headers" | awk '{print $2}' | tr -d '\r' || true)
      if [[ "$ic" == 200 && "$OP" != init ]]; then
        post "$tag-notif" "$sid" '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null
        if [[ "$OP" == list ]]; then call='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
        else call=$(jq -cn --arg t "$tool" --argjson a "${ARGS:-{\"text\":\"hi\"\}}" '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:$t,arguments:$a}}'); fi
        cc=$(post "$tag-call" "$sid" "$call")
        res=$(rpc "$OUT/$tag-call.body" | jq -c 'if .error then {error: .error.code, msg: (.error.message | .[0:160])}
          elif .result.tools then {tools: [.result.tools[].name]}
          else {isError: .result.isError, text: (.result.content[0].text | .[0:200])} end' 2>/dev/null || head -c 200 "$OUT/$tag-call.body")
      elif [[ "$ic" == 200 ]]; then res=ok
      else res=$(head -c 200 "$OUT/$tag-init.body" | tr '\n' ' '); fi
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$user" "$server" "$tool" "$ic" "$cc" "$res" | tee -a "$OUT/results.tsv"
    done
  done
done
