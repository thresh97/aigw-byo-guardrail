#!/usr/bin/env bash
# k8s/mcp.sh: the probe MCP server (mcp/server.py) as a Kubernetes Deployment + Service, on a stock python image with
# the code from a ConfigMap (no image build). For MCP guardrail tests on a hybrid gateway in the same cluster.
# Run from the repo root with kubectl pointed at the cluster.
#
#   bash k8s/mcp.sh deploy                   # create or update; MCP URL: http://<name>.<ns>.svc.cluster.local:8080/<server>/mcp
#   bash k8s/mcp.sh env KEY=value ... | KEY-  # set or unset server modes (EXTRA_TOOL, TOOL_DESCRIPTIONS, ...; see mcp/server.py)
#   bash k8s/mcp.sh url | logs | delete
#
# No TOKEN by default (the integration then uses auth type none); set TOKEN=... with `env` to require x-mcp-token.
# Env: NAME (default byo-probe-mcp), K8S_NAMESPACE (default default), KUBE_CONTEXT (optional),
# IMAGE (default public.ecr.aws/docker/library/python:3.12-slim).
set -euo pipefail
NAME=${NAME:-byo-probe-mcp}
NS=${K8S_NAMESPACE:-default}
IMAGE=${IMAGE:-public.ecr.aws/docker/library/python:3.12-slim}
K=(kubectl -n "$NS" ${KUBE_CONTEXT:+--context "$KUBE_CONTEXT"})

# HTTP front end: hands each POST to the Lambda-style handler in server.py
RUN_PY='
import sys
sys.path.insert(0, "/app")
import server
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
    def handle_one(self, method):
        body = self.rfile.read(int(self.headers.get("content-length") or 0)).decode()
        r = server.handler({"headers": dict(self.headers.items()), "body": body, "rawPath": self.path,
                            "requestContext": {"http": {"method": method, "path": self.path}}}, None)
        b = (r.get("body") or "").encode()
        self.send_response(r["statusCode"])
        for k, v in (r.get("headers") or {}).items():
            self.send_header(k, v)
        self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_POST(self): self.handle_one("POST")
    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200); self.send_header("content-length", "0"); self.end_headers(); return
        self.handle_one("GET")
    def log_message(self, *a): pass
ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
'

case ${1:-} in
  deploy)
    "${K[@]}" create configmap "$NAME-code" --from-file=mcp/server.py --from-literal=run.py="$RUN_PY" \
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
        - name: mcp
          image: $IMAGE
          command: [python, -u, /app/run.py]
          env: [{name: PYTHONDONTWRITEBYTECODE, value: "1"}]
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
  ports: [{port: 8080, targetPort: 8080}]
EOF
    "${K[@]}" rollout restart deploy/"$NAME" >/dev/null   # pick up code changes
    "${K[@]}" rollout status deploy/"$NAME" --timeout=180s ;;
  env) shift; "${K[@]}" set env deploy/"$NAME" -c mcp "$@" >/dev/null
    "${K[@]}" rollout status deploy/"$NAME" --timeout=180s >/dev/null
    "${K[@]}" get deploy/"$NAME" -o jsonpath='{range .spec.template.spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}' \
      | grep -v '^TOKEN=' ;;
  url) echo "http://$NAME.$NS.svc.cluster.local:8080/<server>/mcp" ;;
  logs) "${K[@]}" logs -l app="$NAME" --tail=-1 ;;
  delete) "${K[@]}" delete deploy/"$NAME" svc/"$NAME" cm/"$NAME-code" --ignore-not-found ;;
  *) sed -n '2,12p' "$0"; exit 1 ;;
esac
