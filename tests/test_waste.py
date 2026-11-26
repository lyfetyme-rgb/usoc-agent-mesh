"""REQ-004: HITL-gated waste optimization with measured savings."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from agents.contracts import ActionClass, RiskLevel
from agents.governance import ApprovalStatus
from agents.waste import ResourceObservation, WasteOptimizer


def _observations(
    value: float, *, resource_id: str = "vm-17", count: int = 4
) -> list[ResourceObservation]:
    return [
        ResourceObservation(
            tenant_id="tenant-a",
            resource_id=resource_id,
            metric="cpu_utilization_pct",
            value=value,
            window_hours=24,
            observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        for _ in range(count)
    ]


def test_waste_analyzer_identifies_idle_resources_with_bounded_savings():
    optimizer = WasteOptimizer(idle_cpu_pct=5.0, usd_per_resource_hour=0.08)
    candidates = optimizer.analyze(_observations(2.0))

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.category == "idle"
    assert 0.0 < float(candidate.estimated_monthly_saving_usd) < 730.0
    assert 0.0 <= candidate.confidence <= 1.0
    assert len(candidate.evidence_fingerprint) == 64


def test_waste_proposal_is_a_pending_namespaced_hitl_request():
    optimizer = WasteOptimizer()
    candidate = optimizer.analyze(_observations(2.0))[0]
    request = optimizer.build_approval_request(candidate, requested_by="waste-agent")

    assert request.status is ApprovalStatus.PENDING
    assert request.action_class is ActionClass.EXECUTE
    assert request.risk is RiskLevel.HIGH
    assert request.target == "sandbox/waste/tenant-a/vm-17"
    assert request.signature is None
    assert request.quorum >= 1
    assert "2.0" not in request.justification


def test_waste_savings_validation_refuses_missing_after_data():
    optimizer = WasteOptimizer()
    observations = _observations(2.0)
    candidate = optimizer.analyze(observations)[0]

    try:
        optimizer.validate_savings(candidate, observations, [])
    except ValueError as exc:
        assert "after" in str(exc)
    else:
        raise AssertionError("missing after-window observations were accepted")

    after = _observations(0.0)  # resource reclaimed after HITL approval
    report = optimizer.validate_savings(candidate, observations, after)
    assert report.validated is True
    assert report.realized_ratio >= 1.0

    worse = optimizer.validate_savings(candidate, observations, _observations(9.0))
    assert worse.validated is False


def test_waste_analysis_suppresses_mission_protected_capacity():
    optimizer = WasteOptimizer()
    observations = [
        item.model_copy(
            update={"mission_id": "mission-critical", "mission_protected": True}
        )
        for item in _observations(2.0)
    ]
    candidate = optimizer.analyze(observations)[0]
    assert candidate.suppressed is True
    assert "mission" in (candidate.suppression_reason or "")
    with pytest.raises(ValueError, match="mission"):
        optimizer.build_approval_request(candidate, requested_by="waste-agent")


def test_waste_module_has_no_autonomous_apply_path():
    source = open(__import__("agents.waste").__file__, encoding="utf-8").read()
    assert "def apply(" not in source
    assert "requests.post" not in source
    assert "urlopen" not in source
