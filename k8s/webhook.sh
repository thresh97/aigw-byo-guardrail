#!/usr/bin/env bash
# k8s/webhook.sh: the same webhook as a Kubernetes Deployment + Service (webhook/server.py on a stock python image,
# code from a ConfigMap, no image build). Run from the repo root with kubectl pointed at the cluster.
#
#   bash k8s/webhook.sh deploy [policy.tfvars]   # create or update; policy defaults to infra/terraform.tfvars, else allow-all
#   bash k8s/webhook.sh policy <file.tfvars>|reset
#   bash k8s/webhook.sh url | token              # what the guardrail needs (token goes to stdout: capture it, don't print it)
#   bash k8s/webhook.sh down | up                # scale to 0 (connection refused) | back to 1
#   bash k8s/webhook.sh logs                     # every webhook line since `deploy` (pods replaced by policy/down are archived)
#   bash k8s/webhook.sh delete
#
# Env: NAME (default aigw-byo-guardrail), K8S_NAMESPACE (default default), KUBE_CONTEXT (optional),
# IMAGE (default public.ecr.aws/docker/library/python:3.12-slim),
# LOG_ARCHIVE (default ~/.local/state/aigw-byo-guardrail/k8s-<NAME>.log: logs of replaced pods; tokens are never logged).
# Put it where the gateway may call it: on a hybrid gateway that's a host TRUSTED_CUSTOM_HOSTS allows. `url` prints
# <name>.<ns>.svc: the gateway refuses *.svc.cluster.local webhook URLs even when trusted (see README Findings).
# Policy files use the infra/ tfvars format; terraform (no providers, no state kept) converts them to JSON.
set -euo pipefail
NAME=${NAME:-aigw-byo-guardrail}
NS=${K8S_NAMESPACE:-default}
IMAGE=${IMAGE:-public.ecr.aws/docker/library/python:3.12-slim}
K=(kubectl -n "$NS" ${KUBE_CONTEXT:+--context "$KUBE_CONTEXT"})
LOG_ARCHIVE=${LOG_ARCHIVE:-$HOME/.local/state/aigw-byo-guardrail/k8s-$NAME.log}
mkdir -p "$(dirname "$LOG_ARCHIVE")"

archive() { "${K[@]}" logs -l app="$NAME" --tail=-1 >> "$LOG_ARCHIVE" 2>/dev/null || true; }  # before replacing pods

policy_json() {  # policy_json [file.tfvars]: the POLICY env value, with infra/variables.tf defaults applied
  local f=${1:-} d
  [ -z "$f" ] && [ -f infra/terraform.tfvars ] && f=infra/terraform.tfvars
  [ -z "$f" ] && { echo '{}'; return; }
  d=$(mktemp -d); cp infra/variables.tf "$d/"
  echo 'output "policy" { value = jsonencode(var.policy) }' > "$d/out.tf"
  terraform -chdir="$d" init -input=false -no-color >/dev/null
  terraform -chdir="$d" apply -input=false -auto-approve -no-color -var-file="$(realpath "$f")" >/dev/null
  terraform -chdir="$d" output -raw policy; rm -rf "$d"
}
set_policy() {
  "${K[@]}" create configmap "$NAME-policy" --from-literal=POLICY="$1" --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null
  archive; "${K[@]}" rollout restart deploy/"$NAME" >/dev/null
  "${K[@]}" rollout status deploy/"$NAME" --timeout=120s >/dev/null && echo "policy applied: $1"
}

case ${1:-} in
  deploy)
    "${K[@]}" get secret "$NAME" >/dev/null 2>&1 || \
      "${K[@]}" create secret generic "$NAME" --from-literal=TOKEN="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)" >/dev/null
    "${K[@]}" create configmap "$NAME-code" --from-file=webhook/handler.py --from-file=webhook/server.py \
      --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null
    "${K[@]}" create configmap "$NAME-policy" --from-literal=POLICY="$(policy_json "${2:-}")" \
      --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null
    "${K[@]}" apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: {name: $NAME, labels: {app: $NAME}}
spec:
  replicas: 1
  selector: {matchLabels: {app: $NAME}}
  template:
    metadata: {labels: {app: $NAME}}
    spec:
      automountServiceAccountToken: false
      securityContext: {runAsNonRoot: true, runAsUser: 65534, runAsGroup: 65534, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: webhook
          image: $IMAGE
          command: [python, -u, /app/server.py]
          env:
            - {name: PYTHONDONTWRITEBYTECODE, value: "1"}
            - {name: TOKEN, valueFrom: {secretKeyRef: {name: $NAME, key: TOKEN}}}
            - {name: POLICY, valueFrom: {configMapKeyRef: {name: $NAME-policy, key: POLICY}}}
          ports: [{containerPort: 8080}]
          readinessProbe: {httpGet: {path: /healthz, port: 8080}, periodSeconds: 5}
          resources: {requests: {cpu: 10m, memory: 32Mi}, limits: {memory: 128Mi}}
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
          volumeMounts: [{name: code, mountPath: /app, readOnly: true}]
      volumes: [{name: code, configMap: {name: $NAME-code}}]
---
apiVersion: v1
kind: Service
metadata: {name: $NAME, labels: {app: $NAME}}
spec:
  selector: {app: $NAME}
  ports: [{port: 80, targetPort: 8080}]
EOF
    : > "$LOG_ARCHIVE"
    "${K[@]}" rollout restart deploy/"$NAME" >/dev/null   # pick up code or policy changes
    "${K[@]}" rollout status deploy/"$NAME" --timeout=180s ;;
  policy)
    case ${2:?file or reset} in
      reset) set_policy "$(policy_json)" ;;
      *) set_policy "$(policy_json "$2")" ;;
    esac ;;
  url) echo "http://$NAME.$NS.svc/" ;;
  token) "${K[@]}" get secret "$NAME" -o jsonpath='{.data.TOKEN}' | base64 -d ;;
  down) archive; "${K[@]}" scale deploy/"$NAME" --replicas=0 >/dev/null && "${K[@]}" wait --for=delete pod -l app="$NAME" --timeout=60s >/dev/null 2>&1; echo down ;;
  up) "${K[@]}" scale deploy/"$NAME" --replicas=1 >/dev/null && "${K[@]}" rollout status deploy/"$NAME" --timeout=120s >/dev/null && echo up ;;
  logs) cat "$LOG_ARCHIVE" 2>/dev/null; "${K[@]}" logs -l app="$NAME" --tail=-1 ;;
  delete) "${K[@]}" delete deploy/"$NAME" svc/"$NAME" secret/"$NAME" cm/"$NAME-code" cm/"$NAME-policy" --ignore-not-found; rm -f "$LOG_ARCHIVE" ;;
  *) sed -n '2,19p' "$0"; exit 1 ;;
esac
