"""REQ-003: deterministic, advisory-only AICEE control-plane analytics."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agents.aicee import AiceeEngine, Signal
from agents.contracts import ActionClass, RiskLevel


def _signals(*values: float, key: str = "latency_ms") -> list[Signal]:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return [
        Signal(
            tenant_id="tenant-a",
            source="telemetry",
            key=key,
            value=value,
            observed_at=start + timedelta(minutes=index),
        )
        for index, value in enumerate(values)
    ]


def test_aicee_detects_an_anomaly_and_keeps_recommendations_advisory():
    engine = AiceeEngine(anomaly_z=1.4, min_samples=4)
    report = engine.analyze(_signals(10, 11, 10, 11, 90))

    assert report.tenant_id == "tenant-a"
    anomaly = next(item for item in report.anomalies if item.key == "latency_ms")
    assert anomaly.direction == "high"
    assert anomaly.score > 0
    assert report.recommendations

    for recommendation in report.recommendations:
        assert recommendation.action_class is ActionClass.RECOMMEND
        assert recommendation.risk is RiskLevel.LOW
        assert "target" not in recommendation.model_dump()


def test_aicee_forecast_is_deterministic_bounded_and_redacted():
    engine = AiceeEngine(horizon=3)
    signals = _signals(10, 12, 14, 16, 18)

    first = engine.analyze(signals)
    second = engine.analyze(signals)
    assert first == second

    assert len(first.forecasts) == 3
    for point in first.forecasts:
        assert point.lower <= point.expected <= point.upper
    assert len(first.evidence_fingerprints) == len(set(first.evidence_fingerprints))
    assert all(
        len(item) == 64 and set(item) <= set("0123456789abcdef")
        for item in first.evidence_fingerprints
    )


def test_aicee_rejects_non_finite_values_and_mixed_tenants():
    engine = AiceeEngine()
    with pytest.raises(ValueError, match="finite"):
        engine.analyze(_signals(float("nan")))

    signals = _signals(1, 2, 3)
    signals[0] = signals[0].model_copy(update={"tenant_id": "tenant-b"})
    with pytest.raises(ValueError, match="single tenant"):
        engine.analyze(signals)
