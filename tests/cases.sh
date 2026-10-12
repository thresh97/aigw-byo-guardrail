#!/usr/bin/env bash
# cases.sh: the full case matrix through tests/e2e.sh (run from the repo root, after `terraform apply` and `e2e.sh wire`).
#
#   bash tests/cases.sh [base|deny|notallowed|down|all]   # default all; writes $OUT/cases-<step>.tsv and per-case files
#
# Env: everything e2e.sh needs (GW_URL, OUT, ...), plus
# CLIENT_IP (this client's egress IP as the gateway sees it), IP_HEADER (the one header the policy reads:
# cf-connecting-ip on SaaS, x-forwarded-for behind a load balancer), SPOOF_IP (default 192.0.2.10),
# RUN (readable run name for the trace ids, default <PREFIX>-<UTC time>),
# CTL_SSH (optional ssh host: run policy/down/up there, in ~/aigw-byo-guardrail, when terraform and the webhook's
# AWS access live on another host than the gateway client; the policy file goes over stdin).
# Each step writes a test policy (allow CLIENT_IP, or variants) to $OUT/policy-<step>.tfvars and applies it;
# `down` restores the base policy, and the caller runs `e2e.sh policy reset` at the end.
set -uo pipefail
: "${CLIENT_IP:?set CLIENT_IP}" "${IP_HEADER:?set IP_HEADER}" "${OUT:?set OUT}"
SPOOF_IP=${SPOOF_IP:-192.0.2.10}
export RUN=${RUN:-${PREFIX:-byo-probe}-$(date -u +%Y%m%dT%H%M%SZ)}
E=(bash tests/e2e.sh)
ctl() {  # ctl <e2e.sh args>: locally, or on $CTL_SSH; stdin is passed through
  if [ -n "${CTL_SSH:-}" ]; then ssh "$CTL_SSH" "bash -l -c 'cd ~/aigw-byo-guardrail && $*'"; else bash -c "$*"; fi
}
mkdir -p "$OUT"; [ -f "$OUT/started" ] || date -u +%FT%TZ > "$OUT/started"

policy() {  # policy <step> <allow list> <deny list>: write and apply a test policy
  cat > "$OUT/policy-$1.tfvars" <<EOF
# cases.sh $1 ($RUN)
policy = {
  ip_headers   = ["$IP_HEADER"]
  allow_cidrs  = [$2]
  deny_cidrs   = [$3]
  header_rules = [{ header = "x-app", deny = "blockme" }]
}
EOF
  ctl 'f=$(mktemp) && cat > $f && bash tests/e2e.sh policy $f; rm -f $f' < "$OUT/policy-$1.tfvars" >&2; sleep 5
}
ask() {  # ask <closed|open> <label> <note> [curl args]
  local key=$1 label=$2 note=$3; shift 3
  KEY=$key NOTE="$note" "${E[@]}" ask "$label" "$@"
}

base() {
  policy base "\"$CLIENT_IP/32\"" ""
  ask closed allowed "client IP allowed; expect 200"
  ask closed header-deny "x-app deny rule; expect 446" -H 'x-app: probe-blockme'
  ask closed header-other "other x-app value; expect 200" -H 'x-app: probe-ok'
  for h in x-forwarded-for true-client-ip x-real-ip cf-connecting-ip; do
    ask closed "spoof-$h" "spoofed $h $SPOOF_IP; policy reads $IP_HEADER" -H "$h: $SPOOF_IP"
  done
  ask closed spoof-allowed "spoofed $IP_HEADER = the allowed IP; expect 200" -H "$IP_HEADER: $CLIENT_IP"
  ask open open-allowed "failOnError false, allowed; expect 200"
  ask open open-header-deny "failOnError false, x-app deny rule; expect 446" -H 'x-app: probe-blockme'
}
deny() {
  policy deny "\"$CLIENT_IP/32\", \"${SPOOF_IP%.*}.0/24\"" "\"$CLIENT_IP/32\""
  ask closed deny "client IP in deny_cidrs; expect 446"
  ask open open-deny "failOnError false, client IP in deny_cidrs; expect 446"
  ask closed deny-spoof "client IP denied, spoofed $IP_HEADER $SPOOF_IP (allowed); 200 = bypass" -H "$IP_HEADER: $SPOOF_IP"
}
notallowed() {
  policy notallowed "\"${SPOOF_IP%.*}.0/24\"" ""
  ask closed notallowed "client IP not in allow_cidrs; expect 446"
  ask closed notallowed-spoof "spoofed $IP_HEADER $SPOOF_IP (allowed); 200 = allowlist passed" -H "$IP_HEADER: $SPOOF_IP"
}
down() {
  policy base "\"$CLIENT_IP/32\"" ""
  ctl bash tests/e2e.sh down >&2; sleep 5
  ask closed down "webhook down (429), failOnError true; expect 446"
  ask open open-down "webhook down (429), failOnError false; expect 200"
  ask open open-down-header-deny "webhook down, failOnError false, x-app deny value; 200 = no rule ran" -H 'x-app: probe-blockme'
  ctl bash tests/e2e.sh up >&2; sleep 10
  ask closed after-up "webhook up again; expect 200"
}

steps=${1:-all}; [ "$steps" = all ] && steps="base deny notallowed down"
for s in $steps; do
  echo "=== $s $(date -u +%T) run=$RUN" >&2
  "$s" | tee "$OUT/cases-$s.tsv"
done
