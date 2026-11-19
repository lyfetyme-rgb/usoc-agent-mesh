"""Shadow-mode safety tests.

Shadow mode must be indistinguishable from live operation at the policy/HITL/
evidence layer, while being *strictly* weaker at the execution layer: no handler
runs, no mutating tool writes, no egress leaves the process, no Atlassian state
is touched, and every record is marked so BENGAL will never treat it as
execution proof. These are negative guarantees — a regression here is a safety
incident, so each is asserted explicitly.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

import agents.__main__ as cli
from agents.atlassian_bridge import AtlassianBridge, build_bridge
from agents.bus import InMemoryBus
from agents.config import Settings
from agents.contracts import (
    ActionClass,
    Classification,
    Message,
    RiskLevel,
    TaskResult,
    TaskSpec,
)
from agents.egress import EgressError, EgressGuard
from agents.evidence import EvidenceChain, render_export
from agents.fragmentation import FragmentationService
from agents.governance import (
    ApprovalRequest,
    ApprovalStatus,
    ApprovalVerification,
    GovernanceDecision,
    DecisionType,
)
from agents.observability import Metrics
from agents.registry import SubsystemSpec
from agents.runtime import SubsystemAgent
from agents.security import SecurityError, Signer
from agents.store import InMemoryStore
from agents.tools import ToolError, build_default_tools
from agents.usoc_agents import BengalAgent, OekpAgent

EGRESS_TARGET = "atlassian:https://example.atlassian.net"
PAYLOAD_DIGEST = "a" * 64


# -- configuration -----------------------------------------------------------

def test_shadow_flag_defaults_off():
    assert Settings().shadow_mode is False


def test_shadow_flag_reads_env(monkeypatch):
    monkeypatch.setenv("AGENT_SHADOW_MODE", "true")
    assert Settings().shadow_mode is True
    monkeypatch.setenv("AGENT_SHADOW_MODE", "false")
    assert Settings().shadow_mode is False


def test_shadow_cli_forces_isolated_workspace_and_no_bridge(tmp_path):
    base = tmp_path / "live"
    args = argparse.Namespace(
        command="shadow",
        shadow=True,
        workspace=base,
        registry=None,
        connectors=None,
        json_logs=False,
        profile=None,
    )
    settings = cli._settings(args)
    assert settings.shadow_mode is True
    assert settings.workspace == base / "shadow"
    assert settings.atlassian_bridge_enabled is False
    assert settings.atlassian_jsm_enabled is False


# -- no execution ------------------------------------------------------------

class ShadowSpyAgent(SubsystemAgent):
    """Force a policy ALLOW and count handler invocations."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handled = 0

    async def _authorize(self, msg, spec):
        return GovernanceDecision(
            decision=DecisionType.ALLOW,
            policy_ref="pol-shadow-test",
            authorization_ref="auth-shadow-test",
            reasons=["test-sanctioned action"],
        )

    async def handle_task(self, spec, msg):
        self.handled += 1
        return TaskResult(ok=True, output="EXECUTED")


def shadow_spec() -> SubsystemSpec:
    return SubsystemSpec(
        id="seraphim",
        name="Seraphim",
        description="shadow-test subsystem.",
        capabilities=["containment"],
    )


async def test_shadow_blocks_execution_of_allowed_action(settings, tmp_path):
    shadow_settings = settings.model_copy(update={"shadow_mode": True})
    bus = InMemoryBus(insecure_dev_mode=True)
    evidence = EvidenceChain(tmp_path / "chain.jsonl")
    agent = ShadowSpyAgent(
        shadow_spec(),
        bus,
        llm=None,
        tools=None,
        settings=shadow_settings,
        store=InMemoryStore(),
        metrics=Metrics(),
        known_agents={"seraphim"},
        policy=None,
        evidence=evidence,
        approvals=None,
    )
    await bus.subscribe("client", [])
    await agent.start()
    try:
        await bus.publish(
            Message.task(
                sender="client",
                recipient="seraphim",
                objective="evaluate containment action",
                action_class=ActionClass.EXECUTE,
                target="sandbox/node-1",
                risk=RiskLevel.MEDIUM,
            )
        )
        reply = await bus.receive("client", timeout=2)
        assert reply is not None
        assert reply.kind == "result"
        assert agent.handled == 0, "shadow mode must never invoke the handler"
        assert reply.payload.data["shadow"] is True
        assert reply.payload.data["would_have"] == "ALLOW"
        assert reply.payload.authorization_ref == "auth-shadow-test"

        records = evidence.records()
        kinds = [r.kind for r in records]
        assert "shadow.task" in kinds
        assert "shadow.decision" in kinds
        assert all(r.shadow for r in records)
        ok, detail = evidence.verify()
        assert ok, detail
    finally:
        await agent.stop()


async def test_live_mode_executes_allowed_action(settings, tmp_path):
    """Control: the same ALLOW really executes when shadow is off."""
    bus = InMemoryBus(insecure_dev_mode=True)
    evidence = EvidenceChain(tmp_path / "chain.jsonl")
    agent = ShadowSpyAgent(
        shadow_spec(),
        bus,
        llm=None,
        tools=None,
        settings=settings,
        store=InMemoryStore(),
        metrics=Metrics(),
        known_agents={"seraphim"},
        policy=None,
        evidence=evidence,
        approvals=None,
    )
    await bus.subscribe("client", [])
    await agent.start()
    try:
        await bus.publish(
            Message.task(
                sender="client",
                recipient="seraphim",
                objective="evaluate containment action",
                action_class=ActionClass.EXECUTE,
                target="sandbox/node-1",
                risk=RiskLevel.MEDIUM,
            )
        )
        reply = await bus.receive("client", timeout=2)
        assert reply is not None
        assert agent.handled == 1
        assert reply.payload.output == "EXECUTED"
    finally:
        await agent.stop()


# -- external writes ---------------------------------------------------------

def test_bridge_refuses_in_shadow_even_when_fully_configured(tmp_path):
    signer = Signer("test-secret-that-is-long-enough-32")
    shadow_settings = Settings(
        shadow_mode=True,
        atlassian_bridge_enabled=True,
        atlassian_base_url="https://example.atlassian.net",
        atlassian_api_key="key",
        atlassian_confluence_space_key="SD",
    )
    assert build_bridge(shadow_settings, signer) is None
    with pytest.raises(SecurityError, match="shadow"):
        AtlassianBridge(shadow_settings, signer)


def _perfect_signoff() -> ApprovalRequest:
    return ApprovalRequest(
        action_class=ActionClass.EXECUTE,
        target="sandbox/target",
        risk=RiskLevel.HIGH,
        requested_by="planner",
        status=ApprovalStatus.APPROVED,
        decided_by="alice",
        egress_target=EGRESS_TARGET,
        egress_payload_digest=PAYLOAD_DIGEST,
        verification=ApprovalVerification(
            verified=True, method="detached", approver_id="alice"  # type: ignore[arg-type]
        ),
    )


def test_shadow_egress_denies_even_with_perfect_signoff():
    guard = EgressGuard(block_tainted=True, shadow=True)
    with pytest.raises(EgressError, match="shadow mode"):
        guard.assert_allowed(
            target=EGRESS_TARGET,
            tainted=True,
            signoffs=[_perfect_signoff()],
            payload_digest=PAYLOAD_DIGEST,
        )
    # Unconditional: even clean, unrestricted data may not leave in shadow.
    with pytest.raises(EgressError, match="shadow mode"):
        guard.assert_allowed(target=EGRESS_TARGET)


def test_live_egress_allows_perfect_signoff():
    """Control: the guard still works normally outside shadow."""
    guard = EgressGuard(block_tainted=True, shadow=False)
    guard.assert_allowed(
        target=EGRESS_TARGET,
        tainted=True,
        signoffs=[_perfect_signoff()],
        payload_digest=PAYLOAD_DIGEST,
    )


# -- mutating tools ----------------------------------------------------------

async def test_mutating_tools_fail_closed_but_stay_registered(settings, tmp_path):
    ws = tmp_path / "workspace"
    evidence = EvidenceChain(ws / "evidence" / "chain.jsonl")
    registry = build_default_tools(ws, evidence, allow_write=False, allow_delete=True)

    # Registry validation requires these tools to remain declared.
    for name in ("workspace.write", "workspace.delete", "evidence.append"):
        assert name in registry.tools

    with pytest.raises(ToolError, match="shadow mode"):
        await registry.call("workspace.write", {"path": "x", "content": "y"})
    with pytest.raises(ToolError, match="shadow mode"):
        await registry.call("workspace.delete", {"path": "x"})
    with pytest.raises(ToolError, match="shadow mode"):
        await registry.call("evidence.append", {"kind": "x", "actor": "y"})

    # Read-only tools remain usable so shadow can observe real inputs.
    assert await registry.call("workspace.list", {"subdir": "."}) is not None


# -- evidence and BENGAL -----------------------------------------------------

async def test_oekp_direct_append_is_shadow_marked(settings, tmp_path):
    """OEKP's own handler must mark records when settings enable shadow mode."""
    shadow_settings = settings.model_copy(update={"shadow_mode": True})
    chain = EvidenceChain(tmp_path / "oekp.jsonl")
    agent = OekpAgent(
        SubsystemSpec(
            id="oekp",
            name="OEKP",
            description="shadow-test evidence writer.",
            capabilities=["evidence"],
        ),
        InMemoryBus(insecure_dev_mode=True),
        llm=None,
        tools=None,
        settings=shadow_settings,
        store=InMemoryStore(),
        metrics=Metrics(),
        known_agents=set(),
        policy=None,
        evidence=chain,
        approvals=None,
    )
    result = await agent.handle_task(
        TaskSpec(objective="record an observation", inputs={"kind": "test.event"}),
        Message.task(sender="client", recipient="oekp", objective="record an observation"),
    )
    assert result.ok, result.error
    records = chain.records()
    assert len(records) == 1
    assert records[0].shadow is True, "direct OEKP append lost its shadow marking"
    ok, detail = chain.verify()
    assert ok, detail


async def test_fragmentation_direct_append_is_shadow_marked(settings, tmp_path):
    """Fragmentation's own audit path must mark records in shadow mode."""
    shadow_settings = settings.model_copy(update={"shadow_mode": True})
    chain = EvidenceChain(tmp_path / "fragmentation.jsonl")
    service = FragmentationService([], evidence=chain, settings=shadow_settings)
    await service._audit("test.event", {"objective": "observe"})
    records = chain.records()
    assert len(records) == 1
    assert records[0].shadow is True, "direct fragmentation append lost its shadow marking"
    ok, detail = chain.verify()
    assert ok, detail


def test_shadow_evidence_exports_and_is_not_execution_proof(tmp_path):
    chain = EvidenceChain(tmp_path / "chain.jsonl")

    async def seed():
        await chain.append(
            kind="shadow.decision",
            actor="seraphim",
            data={"shadow": True, "would_have": "ALLOW"},
            shadow=True,
        )

    import asyncio

    asyncio.run(seed())
    ok, detail = chain.verify()
    assert ok, detail
    records = chain.records()
    assert len(records) == 1
    assert records[0].shadow is True

    oekp = json.loads(render_export(records, "oekp", verified=ok, detail=detail))
    assert oekp["records"][0]["shadow"] is True

    bengal = json.loads(render_export(records, "bengal", verified=ok, detail=detail))
    assert bengal["totals"]["shadow_only"] == 1

    bus = InMemoryBus(insecure_dev_mode=True)
    agent = BengalAgent(
        SubsystemSpec(
            id="bengal",
            name="Bengal",
            description="shadow-test verifier.",
            capabilities=["verify"],
        ),
        bus,
        llm=None,
        tools=None,
        settings=Settings(),
        store=InMemoryStore(),
        metrics=Metrics(),
        evidence=chain,
    )
    result = asyncio.run(agent.handle_task(None, Message.task(sender="x", recipient="bengal", objective="verify")))
    assert result.data["shadow_only_count"] == 1
    assert result.data["trusted_for_execution"] is False
