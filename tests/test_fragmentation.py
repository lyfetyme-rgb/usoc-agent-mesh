"""Fragmentation service tests: ingest, correlate, govern and audit."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from agents.bus import InMemoryBus
from agents.config import Settings
from agents.connectors import (
    EntityType,
    Provenance,
    Severity,
    Signal,
    SourceType,
    build_fixture_connectors,
)
from agents.contracts import ActionClass, RiskLevel, TaskSpec, TaskResult
from agents.correlation import CorrelationConfig, CorrelationEngine
from agents.evidence import EvidenceChain
from agents.fragmentation import FragmentationService
from agents.governance import (
    DecisionType,
    InMemoryApprovalStore,
    PolicyConfig,
    PolicyEngine,
)
from agents.llm import EchoLLM
from agents.observability import Metrics
from agents.security import Signer
from agents.shell import Shell
from agents.store import InMemoryStore
from agents.usoc_agents import AiceeAgent

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "fragmentation"
SECRET = "test-secret-that-is-long-enough-for-hmac-0123456789"


def settings(tmp_path: Path) -> Settings:
    return Settings(
        bus="memory",
        workspace=tmp_path / "workspace",
        log_level="CRITICAL",
        correlation_window_s=900,
        correlation_min_sources=2,
        correlation_min_score=40,
        connector_max_records=1_000,
    )


def build_service(tmp_path: Path, *, governed: bool = True):
    config = settings(tmp_path)
    connectors = build_fixture_connectors(config, FIXTURES)
    signer = Signer(SECRET)
    store = InMemoryApprovalStore(signer=signer, ttl_s=3_600)
    policy = (
        PolicyEngine(
            PolicyConfig(allowed_targets=["sandbox/*"], approval_ttl_s=3_600), store
        )
        if governed
        else None
    )
    evidence = EvidenceChain(tmp_path / "evidence.jsonl", signer=signer)
    service = FragmentationService(
        connectors,
        policy,
        evidence,
        config,
        requested_by="fragmentation",
    )
    return service, store, evidence


def signal(
    source: str,
    source_type: SourceType,
    entity: str,
    *,
    attributes: dict | None = None,
    offset_s: int = 0,
) -> Signal:
    observed = datetime(2026, 11, 14, 11, 0, tzinfo=timezone.utc)
    from datetime import timedelta

    observed = observed + timedelta(seconds=offset_s)
    return Signal(
        source=source,
        source_type=source_type,
        entity=entity,
        entity_type=EntityType.HOST,
        severity=Severity.HIGH,
        category="event",
        title=f"{source} on {entity}",
        observed_at=observed,
        attributes=attributes or {},
        provenance=Provenance(connector=source, location="test", fetched_at=observed),
    )


def test_run_holds_for_human_approval_and_records_evidence(tmp_path: Path) -> None:
    service, store, evidence = build_service(tmp_path)

    async def run():
        report = await service.run(mission_id="mission-1")
        await service.close()
        return report

    report = asyncio.run(run())
    assert report.correlation.incidents, "fixtures should produce a correlated incident"
    assert report.correlation.incidents[0].risk is RiskLevel.CRITICAL
    assert report.action is not None
    assert report.action.action_class is ActionClass.CONTAIN
    assert report.action.target == "sandbox/edge-02"
    assert report.decision is not None
    assert report.decision.decision is DecisionType.HOLD
    assert report.approval_ref == report.decision.approval_ref
    assert report.evidence_refs
    assert asyncio.run(store.pending())
    ok, message = evidence.verify()
    assert ok, message


def test_approved_approval_is_rechecked_on_redispatch(tmp_path: Path) -> None:
    service, store, _ = build_service(tmp_path)

    async def run():
        first = await service.run(mission_id="mission-1")
        await store.decide(first.approval_ref, approved=True, approver="operator")
        second = await service.run(
            mission_id="mission-1", approval_ref=first.approval_ref
        )
        await service.close()
        return first, second

    first, second = asyncio.run(run())
    assert first.decision.decision is DecisionType.HOLD
    assert second.decision is not None
    assert second.decision.decision is DecisionType.ALLOW
    assert second.authorization_ref is not None


def test_approval_does_not_cross_missions(tmp_path: Path) -> None:
    service, store, _ = build_service(tmp_path)

    async def run():
        first = await service.run(mission_id="mission-1")
        await store.decide(first.approval_ref, approved=True, approver="operator")
        other = await service.run(mission_id="mission-2", approval_ref=first.approval_ref)
        await service.close()
        return other

    other = asyncio.run(run())
    assert other.decision.decision is DecisionType.DENY
    assert any("scoped to mission" in reason for reason in other.decision.reasons)


def test_missing_policy_fails_closed(tmp_path: Path) -> None:
    service, _, _ = build_service(tmp_path, governed=False)

    async def run():
        report = await service.run(mission_id="mission-1")
        await service.close()
        return report

    report = asyncio.run(run())
    assert report.decision is not None
    assert report.decision.decision is DecisionType.DENY
    assert any("policy engine is not configured" in r for r in report.decision.reasons)


def test_unsafe_vendor_target_falls_back_to_sandbox(tmp_path: Path) -> None:
    service, _, _ = build_service(tmp_path)
    service.engine = CorrelationEngine(
        CorrelationConfig(window_s=900, min_sources=1, min_score=0)
    )
    unsafe = signal(
        "soc",
        SourceType.SOC,
        "edge-02",
        attributes={"containment_target": "../../etc/passwd"},
    )
    incident = service.engine.correlate([unsafe]).incidents[0]
    action = service.propose(incident)
    assert action.target == "sandbox/edge-02"

    safe = signal(
        "soc",
        SourceType.SOC,
        "edge-02",
        attributes={"containment_target": "sandbox/edge-02"},
        offset_s=30,
    )
    incident = service.engine.correlate([safe]).incidents[0]
    assert service.propose(incident).target == "sandbox/edge-02"


def test_shell_reports_fragmentation_status(
    tmp_path: Path, settings, registry, tools
) -> None:
    service, _, _ = build_service(tmp_path)
    agents = {
        spec.id: SimpleNamespace(id=spec.id, uptime_s=1.0, _tasks=set())
        for spec in registry.subsystems
    }
    shell = Shell(
        registry,
        agents,
        InMemoryBus(),
        Metrics(),
        None,
        fragmentation=service,
    )

    async def check():
        health = await shell.health()
        issues = await shell.diagnostics()
        await service.close()
        return health, issues

    health, issues = asyncio.run(check())
    assert health["fragmentation"]["configured"] is True
    assert health["fragmentation"]["connectors"] == 11
    assert issues == []


def test_shell_reports_a_broken_connector_configuration(registry) -> None:
    shell = Shell(
        registry,
        {},
        InMemoryBus(),
        Metrics(),
        None,
        fragmentation=None,
        fragmentation_error="ConnectorConfigError: bad yaml",
    )
    issues = asyncio.run(shell.diagnostics())
    assert any("fragmentation disabled" in issue for issue in issues)


def test_aicee_summarizes_correlated_incidents_without_a_model(
    settings, registry, tools
) -> None:
    spec = registry.by_id["aicee"]
    agent = AiceeAgent(
        spec,
        InMemoryBus(),
        llm=EchoLLM(),
        tools=tools,
        settings=settings,
        store=InMemoryStore(),
        metrics=Metrics(),
    )
    task = TaskSpec(
        objective="Summarize the correlated incidents",
        inputs={
            "correlated_incidents": [
                {
                    "id": "inc-123",
                    "entity": "edge-02",
                    "risk": "critical",
                    "score": 100.0,
                    "sources": ["soc", "identity", "network"],
                }
            ]
        },
    )
    result = asyncio.run(agent.handle_task(task, None))
    assert isinstance(result, TaskResult)
    assert result.ok
    assert "inc-123" in result.output
    assert "critical" in result.output
    assert result.data["count"] == 1


def test_aicee_rejects_a_non_list_payload(settings, registry, tools) -> None:
    spec = registry.by_id["aicee"]
    agent = AiceeAgent(
        spec,
        InMemoryBus(),
        llm=EchoLLM(),
        tools=tools,
        settings=settings,
        store=InMemoryStore(),
        metrics=Metrics(),
    )
    task = TaskSpec(
        objective="Summarize",
        inputs={"correlated_incidents": {"not": "a list"}},
    )
    result = asyncio.run(agent.handle_task(task, None))
    assert result.code == "bad_request"
