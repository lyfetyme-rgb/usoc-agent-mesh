"""Guardrails for the load-test artifacts.

The production HTTP surface is read-only. These tests stop a future edit from
reintroducing a synthetic task-dispatch API or sending the admin token to k6.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOADTEST = ROOT / "tests" / "loadtest"


def test_k6_probe_targets_only_the_read_only_health_surface():
    script = (LOADTEST / "k6-health-probe.js").read_text(encoding="utf-8")

    assert "/health" in script
    assert "/ready" in script
    assert "${BASE_URL}/diagnostics" not in script
    assert "/v1/tasks/dispatch" not in script
    assert "__ENV.AGENT_HEALTH_TOKEN" in script
    assert "Authorization" in script


def test_nonce_harness_drives_the_real_postgres_approval_path():
    harness = (LOADTEST / "nonce_contention.py").read_text(encoding="utf-8")

    assert "PostgresApprovalStore" in harness
    assert "consume(" in harness
    assert "/v1/tasks/dispatch" not in harness
    assert "role_pack" not in harness


def test_loadtest_readme_documents_the_real_contract():
    readme = (LOADTEST / "README.md").read_text(encoding="utf-8")

    assert "/health" in readme
    assert "/ready" in readme
    assert "diagnostics" in readme
    assert "do not\ninvent a `/v1/tasks/dispatch`" in readme
    assert "PostgresApprovalStore" in readme
