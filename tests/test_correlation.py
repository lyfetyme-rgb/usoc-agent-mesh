"""Deterministic correlation tests: alias merge, dedupe, windows and scoring."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from agents.connectors import EntityType, Provenance, Severity, Signal, SourceType
from agents.correlation import CorrelationConfig, CorrelationEngine
from agents.contracts import RiskLevel

BASE = datetime(2026, 11, 14, 11, 0, tzinfo=timezone.utc)


def signal(
    source: str,
    source_type: SourceType,
    entity: str,
    severity: Severity = Severity.HIGH,
    *,
    offset_s: int = 0,
    aliases: list[str] | None = None,
    category: str = "event",
    external_id: str | None = None,
    attributes: dict | None = None,
) -> Signal:
    observed = BASE + timedelta(seconds=offset_s)
    return Signal(
        source=source,
        source_type=source_type,
        entity=entity,
        entity_type=EntityType.HOST,
        severity=severity,
        category=category,
        title=f"{source} event on {entity}",
        observed_at=observed,
        aliases=aliases or [],
        external_id=external_id,
        attributes=attributes or {},
        provenance=Provenance(
            connector=source,
            location="test",
            fetched_at=observed,
        ),
    )


def engine(**overrides) -> CorrelationEngine:
    params = dict(window_s=900, min_sources=2, min_score=0)
    params.update(overrides)
    return CorrelationEngine(CorrelationConfig(**params))


def test_aliases_merge_into_one_incident() -> None:
    signals = [
        signal(
            "obs",
            SourceType.OBSERVABILITY,
            "edge-02",
            aliases=["i-0abc123", "svc-edge-02"],
            category="resource_saturation",
        ),
        signal(
            "vuln",
            SourceType.VULNERABILITY,
            "i-0abc123",
            Severity.CRITICAL,
            offset_s=60,
            category="vulnerability",
        ),
        signal(
            "soc",
            SourceType.SOC,
            "edge-02",
            Severity.CRITICAL,
            offset_s=120,
            category="c2_beacon",
        ),
    ]
    result = engine().correlate(signals)
    assert len(result.incidents) == 1
    incident = result.incidents[0]
    assert incident.entity == "edge-02"
    assert set(incident.aliases) >= {"i-0abc123", "svc-edge-02"}
    assert len(incident.source_types) == 3
    assert incident.risk is RiskLevel.CRITICAL
    assert len(incident.signal_ids) == 3


def test_duplicate_redelivery_is_deduplicated() -> None:
    first = signal(
        "obs", SourceType.OBSERVABILITY, "edge-02", external_id="evt-1", offset_s=0
    )
    newer = signal(
        "obs", SourceType.OBSERVABILITY, "edge-02", external_id="evt-1", offset_s=30
    )
    result = engine(min_sources=1).correlate([first, newer])
    assert result.signals_total == 2
    assert result.signals_considered == 1
    assert result.duplicates == 1
    assert result.incidents[0].signals[0].observed_at == newer.observed_at


def test_min_sources_filters_single_tool_noise() -> None:
    signals = [
        signal("obs", SourceType.OBSERVABILITY, "edge-09", category="cpu"),
        signal(
            "obs", SourceType.OBSERVABILITY, "edge-09", offset_s=10, category="memory"
        ),
    ]
    assert engine(min_sources=2).correlate(signals).incidents == []
    assert len(engine(min_sources=1).correlate(signals).incidents) == 1


def test_window_splits_one_entity_into_separate_incidents() -> None:
    signals = [
        signal("obs", SourceType.OBSERVABILITY, "edge-02", offset_s=0),
        signal("soc", SourceType.SOC, "edge-02", offset_s=60),
        signal("obs", SourceType.OBSERVABILITY, "edge-02", offset_s=3_600),
        signal("soc", SourceType.SOC, "edge-02", offset_s=3_660),
    ]
    result = engine(window_s=900).correlate(signals)
    assert len(result.incidents) == 2
    starts = sorted(incident.window_start for incident in result.incidents)
    assert starts[0] < starts[1]


def test_attack_chain_pattern_raises_the_score() -> None:
    ordinary = [
        signal("obs", SourceType.OBSERVABILITY, "edge-02", category="cpu"),
        signal(
            "cloud",
            SourceType.CLOUD_COST,
            "edge-02",
            offset_s=60,
            category="cost",
        ),
    ]
    chain = [
        signal("identity", SourceType.IDENTITY, "edge-02", category="auth"),
        signal("network", SourceType.NETWORK, "edge-02", offset_s=30, category="egress"),
        signal("soc", SourceType.SOC, "edge-02", offset_s=60, category="c2"),
    ]
    low = engine(min_sources=2).correlate(ordinary).incidents[0]
    high = engine(min_sources=2).correlate(chain).incidents[0]
    assert high.score > low.score
    assert any("attack chain" in reason for reason in high.reasons)
    assert high.risk is RiskLevel.HIGH


def test_correlation_is_deterministic() -> None:
    signals = [
        signal("obs", SourceType.OBSERVABILITY, "edge-02", aliases=["i-0abc123"]),
        signal("soc", SourceType.SOC, "i-0abc123", offset_s=30),
        signal("identity", SourceType.IDENTITY, "edge-02", offset_s=60),
    ]
    first = engine().correlate(signals)
    second = engine().correlate(list(reversed(signals)))
    assert [i.id for i in first.incidents] == [i.id for i in second.incidents]
    assert [i.score for i in first.incidents] == [i.score for i in second.incidents]


def test_min_score_and_truncation() -> None:
    signals = [
        signal("obs", SourceType.OBSERVABILITY, "edge-02", offset_s=i)
        for i in range(5)
    ]
    signals.append(signal("soc", SourceType.SOC, "edge-02", offset_s=10))
    filtered = engine(min_sources=2, min_score=100).correlate(signals)
    assert filtered.incidents == []

    result = engine(min_sources=2, min_score=0, max_signals_per_incident=3).correlate(
        signals
    )
    assert result.incidents[0].truncated is True
    assert len(result.incidents[0].signals) == 3


def test_severity_and_source_diversity_drive_risk() -> None:
    signals = [
        signal("soc", SourceType.SOC, "edge-02", Severity.CRITICAL),
        signal("vuln", SourceType.VULNERABILITY, "edge-02", Severity.CRITICAL, offset_s=30),
    ]
    incident = engine(min_sources=2).correlate(signals).incidents[0]
    assert incident.score >= 60
    assert incident.risk is RiskLevel.HIGH
    assert "highest severity: critical" in incident.reasons
