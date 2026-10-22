#!/usr/bin/env bash
# docker/mcp.sh: the probe MCP server (mcp/server.py) as a Docker container on a stock python image (no image build), for
# MCP guardrail tests on a hybrid gateway running in Docker (for example with the airs-ai-gateway-docker installer).
# Run from the repo root.
#
#   bash docker/mcp.sh deploy [KEY=value ...]   # (re)create; no arguments = the plain server. Modes: EXTRA_TOOL, TOOL_DESCRIPTIONS, ... (see mcp/server.py)
#   bash docker/mcp.sh url | logs | delete
#
# A container can't change its environment in place, so `deploy` recreates it: pass every mode you want each time.
# Env: NAME (default byo-probe-mcp), DOCKER_NETWORK (default airs-ai-gateway-docker_default, the installer's network; it must be
# the gateway's), MCP_HOST (default $NAME.default.svc.cluster.local, an alias on that network), IMAGE (default python:3.12-slim).
#
# Why MCP_HOST has a dot-separated name: the control plane rejects a one-word host ("Invalid value") and a `.local` host
# ("Invalid or unsafe custom host") when you register the MCP integration. The gateway then resolves the alias to a private
# address, so put MCP_HOST in the gateway's TRUSTED_CUSTOM_HOSTS too, or its SSRF policy refuses the upstream.
set -euo pipefail
NAME=${NAME:-byo-probe-mcp}
NET=${DOCKER_NETWORK:-airs-ai-gateway-docker_default}
MCP_HOST=${MCP_HOST:-$NAME.default.svc.cluster.local}
IMAGE=${IMAGE:-python:3.12-slim}

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
  deploy) shift
    envargs=(); for kv in "$@"; do envargs+=(-e "$kv"); done
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" --restart unless-stopped --network "$NET" \
      --network-alias "$NAME" --network-alias "$MCP_HOST" \
      -v "$PWD/mcp:/app:ro" -e PYTHONDONTWRITEBYTECODE=1 ${envargs[@]+"${envargs[@]}"} \
      "$IMAGE" python -u -c "$RUN_PY" >/dev/null
    for _ in $(seq 20); do
      docker exec "$NAME" python -c 'import urllib.request as u; u.urlopen("http://localhost:8080/healthz", timeout=2)' \
        >/dev/null 2>&1 && break; sleep 0.5
    done
    echo "MCP URL for the integration: http://$MCP_HOST:8080/<server>/mcp   (modes: ${*:-none})" ;;
  url) echo "http://$MCP_HOST:8080/<server>/mcp" ;;
  logs) docker logs "$NAME" ;;
  delete) docker rm -f "$NAME" ;;
  *) sed -n '2,9p' "$0"; exit 1 ;;
esac
