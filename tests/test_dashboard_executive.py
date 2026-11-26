"""REQ-008: browser-safe executive KPI surface."""

from __future__ import annotations

import importlib.util
import json
import threading
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "dashboard"


def _load_server():
    spec = importlib.util.spec_from_file_location(
        "usoc_dashboard_executive_server", DASHBOARD / "server.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


server_module = _load_server()


def test_executive_kpis_are_counts_only_and_drop_unknown_fields(monkeypatch, tmp_path: Path):
    evidence = tmp_path / "kpis.json"
    evidence.write_text(
        json.dumps(
            {
                "requirements": 15,
                "tests": 490,
                "deploy_approvals": 0,
                "operational_validations": 0,
                "raw_payload": "do-not-expose",
                "secret": "do-not-expose",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("USOC_KPI_EVIDENCE_FILE", str(evidence))
    monkeypatch.setattr(
        server_module,
        "status_payload",
        lambda: {
            "health": {"status": "ok"},
            "ready": {"ready": True},
            "errors": {},
            "degraded": False,
        },
    )

    body = server_module.executive_kpis()
    assert body["health"] == "ok"
    assert body["ready"] == "ok"
    assert body["requirements"] == 15
    assert body["tests"] == 490
    assert set(body) == {
        "health",
        "ready",
        "degraded",
        "error_count",
        "requirements",
        "tests",
        "deploy_approvals",
        "operational_validations",
    }
    assert "do-not-expose" not in json.dumps(body)


def test_missing_kpi_evidence_reports_unknown_not_zero(monkeypatch):
    monkeypatch.delenv("USOC_KPI_EVIDENCE_FILE", raising=False)
    monkeypatch.setattr(
        server_module,
        "status_payload",
        lambda: {
            "health": {"status": "ok"},
            "ready": {"ready": True},
            "errors": {},
            "degraded": False,
        },
    )
    body = server_module.executive_kpis()
    for key in (
        "requirements",
        "tests",
        "deploy_approvals",
        "operational_validations",
    ):
        assert body[key] == "UNKNOWN"


def test_executive_kpis_route_is_browser_safe(monkeypatch):
    monkeypatch.setattr(
        server_module,
        "executive_kpis",
        lambda: {
            "health": "ok",
            "ready": "ok",
            "degraded": False,
            "error_count": 0,
            "requirements": 15,
            "tests": 490,
            "deploy_approvals": 0,
            "operational_validations": 0,
        },
    )
    srv = server_module.DashboardHTTPServer(("127.0.0.1", 0), server_module.Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        with urllib.request.urlopen(f"{base}/api/executive-kpis", timeout=5) as response:
            payload = json.load(response)
            assert payload["requirements"] == 15
            assert response.headers["Cache-Control"] == "no-store"
            assert response.headers["Content-Security-Policy"].startswith("default-src 'self'")
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


def test_executive_view_has_no_token_or_local_storage_path():
    app = (DASHBOARD / "app.js").read_text(encoding="utf-8")
    html = (DASHBOARD / "index.html").read_text(encoding="utf-8")
    assert "executive-kpis" in app
    assert 'id="executive-kpis"' in html
    assert "AGENT_HEALTH_TOKEN" not in app
    assert "localStorage" not in app


def test_executive_kpis_refresh_with_the_main_status_poll():
    app = (DASHBOARD / "app.js").read_text(encoding="utf-8")
    start = app.index("async function refresh()")
    end = app.index("function scheduleNext()", start)
    body = app[start:end]
    assert "refreshExecutive()" in body
