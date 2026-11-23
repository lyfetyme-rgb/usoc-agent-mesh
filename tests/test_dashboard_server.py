"""Regression tests for the local dashboard proxy and its browser contract."""

from __future__ import annotations

import importlib.util
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "dashboard"


def _load_dashboard_server():
    spec = importlib.util.spec_from_file_location(
        "usoc_dashboard_server", DASHBOARD / "server.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


server_module = _load_dashboard_server()


def test_health_target_and_inline_token_are_read_per_request(monkeypatch):
    monkeypatch.setenv("AGENT_HEALTH_HOST", "127.0.0.1")
    monkeypatch.setenv("AGENT_HEALTH_PORT", "9091")
    monkeypatch.setenv("AGENT_HEALTH_TOKEN", "inline-secret")
    assert server_module.health_base_url() == "http://127.0.0.1:9091"
    assert server_module.health_token() == "inline-secret"


def test_health_target_is_read_from_dotenv(monkeypatch, tmp_path):
    for name in ("AGENT_HEALTH_HOST", "AGENT_HEALTH_PORT", "AGENT_HEALTH_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / ".env").write_text(
        "AGENT_HEALTH_PORT=9092\nAGENT_HEALTH_TOKEN=dotenv-secret\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    assert server_module.health_base_url() == "http://127.0.0.1:9092"
    assert server_module.health_token() == "dotenv-secret"


def test_status_payload_keeps_the_successful_half_and_reports_reason(monkeypatch):
    calls = []

    def fake_fetch(endpoint, token):
        calls.append((endpoint, token))
        if endpoint == "health":
            return {"status": "ok", "agents_running": 9, "agents_expected": 9}, None
        return None, "auth"

    monkeypatch.setenv("AGENT_HEALTH_TOKEN", "token")
    monkeypatch.setattr(server_module, "fetch_status_endpoint", fake_fetch)
    payload = server_module.status_payload()
    assert payload["health"]["status"] == "ok"
    assert payload["ready"] is None
    assert payload["errors"] == {"ready": "auth"}
    assert payload["degraded"] is True
    assert calls == [("health", "token"), ("ready", "token")]


def test_http_surface_is_loopback_only_and_sends_hardening_headers(monkeypatch):
    monkeypatch.setattr(
        server_module,
        "status_payload",
        lambda: {"health": {"status": "ok"}, "ready": {"ready": True}, "errors": {}, "degraded": False},
    )
    srv = server_module.DashboardHTTPServer(("127.0.0.1", 0), server_module.Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        with urllib.request.urlopen(f"{base}/api/status", timeout=5) as response:
            body = json.load(response)
            assert body["ready"]["ready"] is True
            assert response.headers["Cache-Control"] == "no-store"
            assert "default-src 'self'" in response.headers["Content-Security-Policy"]
            assert response.headers["X-Frame-Options"] == "DENY"
        request = urllib.request.Request(f"{base}/api/status", headers={"Host": "evil.example"})
        try:
            urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as exc:
            assert exc.code == 400
        else:
            raise AssertionError("non-loopback Host header was accepted")
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


def test_browser_contract_avoids_false_timeouts_stale_states_and_overflow():
    app = (DASHBOARD / "app.js").read_text(encoding="utf-8")
    html = (DASHBOARD / "index.html").read_text(encoding="utf-8")
    style = (DASHBOARD / "style.css").read_text(encoding="utf-8")

    assert "const FETCH_TIMEOUT_MS = 10000;" in app
    assert "STATUS_TIMEOUT_S = 8.0" in (DASHBOARD / "server.py").read_text(encoding="utf-8")
    assert 'aria-live="polite"' in html
    assert 'id="sync-dot" aria-hidden="true"' in html
    for marker in ("UNKNOWN", "STALE", "PARTIAL", "TIMED OUT", "AUTH REQUIRED"):
        assert marker in app
    assert "failures = 0; refresh()" not in app
    assert "repeat(3,minmax(0,1fr))" in style
    assert "overflow-wrap:anywhere" in style
    assert ".dot.warn" in style
    assert "--muted:#637c84" not in style


def test_dashboard_applies_ops_console_ux_controls():
    """UI/UX Pro Max direction: keyboard/touch, busy feedback, reduced motion."""
    app = (DASHBOARD / "app.js").read_text(encoding="utf-8")
    html = (DASHBOARD / "index.html").read_text(encoding="utf-8")
    style = (DASHBOARD / "style.css").read_text(encoding="utf-8")

    # Explicit pause/resume and manual refresh keep background work controllable.
    assert 'id="live-toggle"' in html
    assert 'aria-pressed="false"' in html
    assert 'id="refresh-now"' in html
    assert "let paused = false;" in app
    assert 'setAttribute("aria-pressed", String(paused))' in app

    # Loading feedback is announced and the panel is marked busy during fetch.
    assert 'id="public-panel" aria-busy="false"' in html
    assert 'setAttribute("aria-busy", "true")' in app
    assert 'setAttribute("aria-busy", "false")' in app

    # SVG icons instead of glyph icons; no external font request under the CSP.
    assert "<svg" in html
    assert "◐" not in html and "⌁" not in html
    assert "@import" not in style
    assert "fonts.googleapis" not in style

    # Accessibility and dense-console tokens from the verified design direction.
    assert ":focus-visible" in style
    assert "min-height:44px" in style
    assert "prefers-reduced-motion" in style
    assert "--ok:#22c55e" in style
    assert "--warn:#fbbf24" in style
    assert "--bad:#ef4444" in style
