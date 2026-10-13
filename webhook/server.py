"""Plain HTTP host for handler.py (Kubernetes, docker, a VM): POST any path -> handler, GET /healthz -> 200.

Unlike a Lambda Function URL it passes every request header through unchanged, so a full x-forwarded-for chain
reaches the handler (see trusted_hops there). Env: PORT (default 8080), plus TOKEN and POLICY as for the Lambda.
Python stdlib only. No TLS: run it behind something that terminates TLS, or on a cluster-internal address.
"""

import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
import handler  # noqa: E402  (after logging is configured)


class Server(BaseHTTPRequestHandler):
    def do_GET(self):
        self._send(200 if self.path == "/healthz" else 404, {"ok": self.path == "/healthz"})

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length") or 0)).decode()
        r = handler.handler({"headers": dict(self.headers.items()), "body": body}, None)
        self._send(r["statusCode"], json.loads(r["body"]))

    def _send(self, status, obj):
        b = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, fmt, *args):  # handler.py already logs each call
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("", int(os.environ.get("PORT", "8080"))), Server).serve_forever()
