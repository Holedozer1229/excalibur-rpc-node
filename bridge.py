"""bridge.py — authenticated HTTP bridge exposing the Excalibur node RPC.

The node's own RPC (node_rpc.py) binds 127.0.0.1 with no auth — it must
never face the internet. This bridge binds 0.0.0.0 behind a bearer token
and proxies JSON-RPC to the local node.

Endpoints:
  POST /rpc/<network>   {"method":..., "params":[...], "id":...}
      network: "fork" (127.0.0.1:9432) | "mainnet" (127.0.0.1:9332)
  GET  /health           {"ok": true}  (no auth; for uptime checks)

Auth:  Authorization: Bearer <token>
Token: ~/workspace/.bridge_token (mode 600). Generated on first run,
       printed once to the log. Lux pastes it into the wallet UI.

Security posture: the bridge never holds private keys. Spending works by
the UI building + signing transactions client-side and submitting raw hex
via sendrawtransaction. The worst a token holder can do is read chain
state and relay transactions — same as any public node RPC.
"""

import hmac
import json
import os
import secrets
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOME = os.path.expanduser("~")
WORKSPACE = os.path.join(HOME, "workspace")
TOKEN_PATH = os.path.join(WORKSPACE, ".bridge_token")
PORT = 9443

UPSTREAM = {
    "fork": "http://127.0.0.1:9432/",
    "mainnet": "http://127.0.0.1:9332/",
}


def get_token():
    if os.path.exists(TOKEN_PATH):
        with open(TOKEN_PATH) as f:
            return f.read().strip()
    tok = secrets.token_hex(32)
    fd = os.open(TOKEN_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(tok + "\n")
    print(f"[bridge] NEW TOKEN (save this, shown once): {tok}", flush=True)
    return tok


TOKEN = get_token()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers",
                         "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def _reply(self, code, obj):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self._cors()
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            return self._reply(200, {"ok": True})
        return self._reply(404, {"error": "not found"})

    def _authed(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        return hmac.compare_digest(auth[7:].strip(), TOKEN)

    def do_POST(self):
        parts = self.path.strip("/").split("/")
        if len(parts) != 2 or parts[0] != "rpc" or parts[1] not in UPSTREAM:
            return self._reply(404, {"error": "use POST /rpc/fork or /rpc/mainnet"})
        if not self._authed():
            return self._reply(401, {"error": "unauthorized"})
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n)
            req = json.loads(body or b"{}")
            if not isinstance(req.get("method"), str):
                return self._reply(400, {"error": "bad request"})
        except Exception:
            return self._reply(400, {"error": "bad request"})
        try:
            up = urllib.request.Request(
                UPSTREAM[parts[1]], data=json.dumps(req).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(up, timeout=30) as r:
                payload = r.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self._cors()
            self.end_headers()
            self.wfile.write(payload)
        except Exception as e:
            self._reply(502, {"result": None, "error": f"upstream: {e}",
                              "id": req.get("id")})


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[bridge] listening on 0.0.0.0:{PORT} "
          f"(fork->9432, mainnet->9332)", flush=True)
    srv.serve_forever()
