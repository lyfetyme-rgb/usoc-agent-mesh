"""Local-only, read-only dashboard proxy; does not expose the health token."""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
TOKEN_FILE = Path(os.environ.get("AGENT_HEALTH_TOKEN_FILE", "secrets/health_token.txt"))
ASSETS = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8")}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        port = self.server.server_address[1]
        if self.headers.get("Host", "").lower() not in (f"127.0.0.1:{port}", f"localhost:{port}"):
            self.send_error(400)
            return
        if self.path == "/api/public-data":
            try:
                from agents.public_data import run
                data = run(100)
                data.pop("records", None)
                self.respond(200, json.dumps(data).encode(), "application/json")
            except (OSError, ValueError):
                self.respond(503, b'{"error":"Public dataset unavailable"}', "application/json")
            return
        if self.path == "/api/status":
            try:
                token = TOKEN_FILE.read_text(encoding="utf-8").strip()
                results = {}
                for endpoint in ("health", "ready"):
                    request = Request(f"http://127.0.0.1:8080/{endpoint}",
                                      headers={"Authorization": f"Bearer {token}"})
                    try:
                        with urlopen(request, timeout=3) as response:
                            results[endpoint] = json.load(response)
                    except HTTPError as exc:
                        if exc.code == 503 and endpoint == "ready":
                            results[endpoint] = json.load(exc)
                        else:
                            raise
                self.respond(200, json.dumps(results).encode(), "application/json")
            except (OSError, URLError, ValueError):
                self.respond(503, b'{"error":"Mesh status unavailable"}', "application/json")
            return
        asset = ASSETS.get(self.path)
        if not asset:
            self.send_error(404)
            return
        self.respond(200, (ROOT / asset[0]).read_bytes(), asset[1])

    def respond(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("USOC_DASHBOARD_PORT", "8090"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"USOC dashboard: http://127.0.0.1:{port}", flush=True)
    server.serve_forever()
