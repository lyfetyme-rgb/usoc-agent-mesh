"""Local-only, read-only dashboard proxy; does not expose the health token."""
from __future__ import annotations

import json
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
ASSETS = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8")}

# The browser aborts after 10s, so the proxy must fail first and report why.
STATUS_TIMEOUT_S = 8.0
MAX_REQUEST_WORKERS = 8
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def dashboard_host() -> str:
    """Bind address. Loopback-only unless a cluster deployment opts in."""
    return config_value("USOC_DASHBOARD_HOST", "127.0.0.1") or "127.0.0.1"


def allowed_dashboard_hosts() -> frozenset[str]:
    """Host header names accepted when the proxy is reachable off-loopback."""
    raw = config_value("USOC_DASHBOARD_ALLOWED_HOSTS", "") or ""
    return frozenset(part.strip().lower() for part in raw.split(",") if part.strip())


def bind_address() -> str:
    """Fail closed if a non-loopback bind has no Host allowlist.

    A proxy reachable through a Service must know which names it serves;
    otherwise a DNS-rebinding attack could make a browser use it as a confused
    deputy. Local development keeps the historical loopback default.
    """
    host = dashboard_host()
    if host not in LOOPBACK_HOSTS and not allowed_dashboard_hosts():
        raise RuntimeError(
            "USOC_DASHBOARD_ALLOWED_HOSTS must name the proxy's Service/Ingress "
            "hosts when USOC_DASHBOARD_HOST is not a loopback address"
        )
    return host


def config_value(name: str, default: str | None = None) -> str | None:
    """Read a setting from the environment, then .env, then use the default.

    ``Settings`` reads .env itself, but it does not export those values back to
    ``os.environ``. Without this lookup a dashboard started beside a .env-only
    mesh would send no token and report a permanent OFFLINE state.
    """
    value = os.environ.get(name)
    if value is not None:
        return value
    candidates = (Path.cwd() / ".env", ROOT.parent / ".env")
    for env_file in candidates:
        try:
            lines = env_file.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, raw = stripped.split("=", 1)
            if key.strip() != name:
                continue
            return raw.strip().strip("'\"")
    return default


def token_path() -> Path:
    return Path(config_value("AGENT_HEALTH_TOKEN_FILE", "secrets/health_token.txt") or "")


def health_token() -> str | None:
    """Accept an inline token or a mounted token file, just like the mesh."""
    inline = config_value("AGENT_HEALTH_TOKEN")
    if inline:
        return inline
    try:
        return token_path().read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def health_base_url() -> str:
    host = config_value("AGENT_HEALTH_HOST", "127.0.0.1") or "127.0.0.1"
    port = config_value("AGENT_HEALTH_PORT", "8080") or "8080"
    return f"http://{host}:{port}"


def fetch_status_endpoint(endpoint: str, token: str | None) -> tuple[dict | None, str | None]:
    """Fetch one probe. Return a reason code instead of discarding the other."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    request = Request(f"{health_base_url()}/{endpoint}", headers=headers)
    try:
        with urlopen(request, timeout=STATUS_TIMEOUT_S) as response:
            return json.load(response), None
    except HTTPError as exc:
        if endpoint == "ready" and exc.code == 503:
            try:
                return json.load(exc), None
            except (OSError, TypeError, ValueError):
                pass
        if exc.code in (401, 403):
            return None, "auth"
        return None, f"http_{exc.code}"
    except TimeoutError:
        return None, "timeout"
    except URLError as exc:
        reason = str(getattr(exc, "reason", exc)).lower()
        if "timed out" in reason or "timeout" in reason:
            return None, "timeout"
        return None, "transport"
    except (OSError, TypeError, ValueError):
        return None, "invalid_response"


def status_payload() -> dict:
    token = health_token()
    payload: dict = {"health": None, "ready": None, "errors": {}, "degraded": False}
    for endpoint in ("health", "ready"):
        result, reason = fetch_status_endpoint(endpoint, token)
        payload[endpoint] = result
        if reason:
            payload["errors"][endpoint] = reason
    payload["degraded"] = bool(payload["errors"]) or any(
        (payload.get(name) or {}).get("degraded") for name in ("health", "ready")
    )
    return payload


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not self._host_allowed():
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
            # Always 200: the client needs the reason codes to distinguish an
            # auth failure, a timeout and a stale/unknown mesh state.
            self.respond(200, json.dumps(status_payload()).encode(), "application/json")
            return
        asset = ASSETS.get(self.path)
        if not asset:
            self.send_error(404)
            return
        self.respond(200, (ROOT / asset[0]).read_bytes(), asset[1])

    def _host_allowed(self) -> bool:
        port = self.server.server_address[1]
        raw = self.headers.get("Host", "")
        try:
            host = urlsplit(f"//{raw}").hostname
        except ValueError:
            return False
        if not host:
            return False
        # A cluster Service name is only accepted when it was explicitly
        # configured, and only with that exact name (optionally with a port).
        declared = raw.lower()
        for name in allowed_dashboard_hosts():
            if declared == name or declared.startswith(f"{name}:"):
                return True
        if host in LOOPBACK_HOSTS:
            declared_host = raw.rsplit(":", 1)[0] if ":" in raw else raw
            return not declared_host or declared_host in ("127.0.0.1", "localhost", "[::1]")
        return host == "127.0.0.1" and raw.endswith(f":{port}")

    def respond(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class DashboardHTTPServer(ThreadingHTTPServer):
    """Loopback server with a bounded number of active request threads."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args, max_workers: int = MAX_REQUEST_WORKERS, **kwargs):
        self._slots = threading.BoundedSemaphore(max(1, max_workers))
        self._pool = ThreadPoolExecutor(max_workers=max(1, max_workers), thread_name_prefix="dashboard")
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.close_request(request)
            return
        self._pool.submit(self._serve_one, request, client_address)

    def _serve_one(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        finally:
            self.close_request(request)
            self._slots.release()

    def server_close(self):
        self._pool.shutdown(wait=True)
        super().server_close()


if __name__ == "__main__":
    port = int(os.environ.get("USOC_DASHBOARD_PORT", "8090"))
    host = bind_address()  # non-loopback binds require an explicit Host allowlist
    server = DashboardHTTPServer((host, port), Handler)
    print(f"USOC dashboard: http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
