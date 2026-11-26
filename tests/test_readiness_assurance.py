"""REQ-010: security and production-readiness assurance artifacts."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "toolbox" / "scripts" / "readiness_check.py"
DOCS = ROOT / "docs" / "readiness"


def test_committed_readiness_artifacts_pass_the_validator():
    from importlib.util import module_from_spec, spec_from_file_location

    spec = spec_from_file_location("readiness_check", CHECKER)
    assert spec and spec.loader
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.validate_readiness(ROOT) == []


def test_readiness_validator_cli_succeeds():
    result = subprocess.run(
        [sys.executable, str(CHECKER)], cwd=ROOT, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert "readiness assurance ok" in result.stdout


def test_assurance_matrix_maps_every_section_six_invariant_to_a_test():
    matrix = (DOCS / "assurance-matrix.md").read_text(encoding="utf-8")
    invariants = (
        "non-root",
        "read-only rootfs",
        "zero browser token exposure",
        "strict egress",
        "Ed25519 signatures",
        "single-use nonce atomicity",
        "OIDC/detached credential checks",
        "shadow fail-closed",
        "immutable OEKP evidence",
        "no raw payloads in ledger/evidence/health",
    )
    for label in invariants:
        assert label in matrix
    for test in (
        "tests/test_kubernetes_manifests.py",
        "tests/test_dashboard_server.py",
        "tests/test_security.py",
        "tests/test_production_trust.py",
        "tests/test_production_signing.py",
        "tests/test_shadow_mode.py",
        "tests/test_observability_hardening.py",
    ):
        assert test in matrix
        assert (ROOT / test).exists()


def test_assurance_records_do_not_claim_results_that_were_not_performed():
    penetration = (DOCS / "penetration-test.md").read_text(encoding="utf-8").lower()
    recovery = (DOCS / "recovery-drill.md").read_text(encoding="utf-8").lower()
    assert "procedure" in penetration
    assert "no unmitigated high-severity finding" not in penetration
    assert "procedure" in recovery
    assert "observed rto" not in recovery or "not yet performed" in recovery


def test_recovery_drill_is_explicitly_offline_and_bounded():
    drill = (DOCS / "recovery-drill.md").read_text(encoding="utf-8")
    assert "offline simulation" in drill.lower()
    assert "no live production" in drill.lower()
    assert "RTO" in drill and "RPO" in drill
    assert "raw payload" not in drill.lower()
