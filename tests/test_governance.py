"""Governance tests: the policy gate, approvals and the evidence chain.

These are the safety-critical behaviours. An LLM must never be able to turn a
DENY into an ALLOW, and an agent must never be able to approve itself.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agents.bus import InMemoryBus
from agents.contracts import ActionClass, Classification, Message, RiskLevel
from agents.evidence import EvidenceChain
from agents.governance import (
    ApprovalRequest,
    ApprovalStatus,
    DecisionType,
    FileApprovalStore,
    InMemoryApprovalStore,
    PolicyConfig,
    PolicyEngine,
)
from agents.observability import Metrics
from agents.registry import SubsystemSpec
from agents.runtime import SubsystemAgent
from agents.store import InMemoryStore
from agents.usoc_agents import HitlAgent


def make_policy(tmp_path: Path, targets: list[str] | None = None) -> tuple[PolicyEngine, InMemoryApprovalStore]:
    store = InMemoryApprovalStore()
    config = PolicyConfig(allowed_targets=targets or ["sandbox/*", "staging/*"])
    return PolicyEngine(config, store), store


async def evaluate(policy: PolicyEngine, **overrides):
    params = dict(
        action=ActionClass.READ_ONLY,
        target=None,
        risk=RiskLevel.LOW,
        mission_id="mission-1",
        classification=Classification.INTERNAL,
        approval_ref=None,
        requested_by="tester",
        justification="test",
        correlation_id="corr-1",
    )
    params.update(overrides)
    return await policy.evaluate(**params)


async def test_read_only_work_is_allowed_without_approval(tmp_path):
    policy, store = make_policy(tmp_path)
    decision = await evaluate(policy)

    assert decision.decision is DecisionType.ALLOW
    assert decision.authorization_ref is None
    assert await store.pending() == []


@pytest.mark.parametrize("action", [ActionClass.EXECUTE, ActionClass.CONTAIN])
async def test_consequential_actions_hold_for_a_human(tmp_path, action):
    policy, store = make_policy(tmp_path)
    decision = await evaluate(policy, action=action, target="sandbox/node-1")

    assert decision.decision is DecisionType.HOLD
    assert decision.approval_ref
    pending = await store.pending()
    assert [r.id for r in pending] == [decision.approval_ref]
    assert pending[0].status is ApprovalStatus.PENDING


async def test_redelivery_does_not_duplicate_the_approval_request(tmp_path):
    policy, store = make_policy(tmp_path)
    first = await evaluate(policy, action=ActionClass.EXECUTE, target="sandbox/node-1")
    second = await evaluate(policy, action=ActionClass.EXECUTE, target="sandbox/node-1")

    assert first.approval_ref == second.approval_ref
    assert len(await store.pending()) == 1


async def test_approval_upgrades_hold_to_allow(tmp_path):
    policy, store = make_policy(tmp_path)
    held = await evaluate(policy, action=ActionClass.EXECUTE, target="sandbox/node-1")

    await store.decide(held.approval_ref, approved=True, approver="alice", note="window approved")
    allowed = await evaluate(
        policy, action=ActionClass.EXECUTE, target="sandbox/node-1", approval_ref=held.approval_ref
    )

    assert allowed.decision is DecisionType.ALLOW
    assert allowed.authorization_ref
    assert allowed.expires_at is not None


async def test_denied_approval_stays_denied(tmp_path):
    policy, store = make_policy(tmp_path)
    held = await evaluate(policy, action=ActionClass.EXECUTE, target="sandbox/node-1")

    await store.decide(held.approval_ref, approved=False, approver="alice")
    decision = await evaluate(
        policy, action=ActionClass.EXECUTE, target="sandbox/node-1", approval_ref=held.approval_ref
    )

    assert decision.decision is DecisionType.DENY
    assert decision.authorization_ref is None


async def test_approval_does_not_cover_a_different_target(tmp_path):
    policy, store = make_policy(tmp_path)
    held = await evaluate(policy, action=ActionClass.EXECUTE, target="sandbox/node-1")
    await store.decide(held.approval_ref, approved=True, approver="alice")

    decision = await evaluate(
        policy, action=ActionClass.EXECUTE, target="sandbox/node-2", approval_ref=held.approval_ref
    )

    assert decision.decision is DecisionType.DENY
    assert "does not cover" in "; ".join(decision.reasons)


async def test_target_outside_the_allowlist_is_denied_before_human_review(tmp_path):
    policy, store = make_policy(tmp_path)
    decision = await evaluate(policy, action=ActionClass.EXECUTE, target="prod/db-primary")

    assert decision.decision is DecisionType.DENY
    assert "outside the authorized target list" in "; ".join(decision.reasons)
    assert await store.pending() == []


async def test_missing_target_is_denied(tmp_path):
    policy, _ = make_policy(tmp_path)
    decision = await evaluate(policy, action=ActionClass.CONTAIN)

    assert decision.decision is DecisionType.DENY
    assert "explicit target" in "; ".join(decision.reasons)


async def test_restricted_data_needs_a_mission(tmp_path):
    policy, _ = make_policy(tmp_path)
    decision = await evaluate(policy, classification=Classification.RESTRICTED, mission_id=None)

    assert decision.decision is DecisionType.DENY
    assert "mission_id" in "; ".join(decision.reasons)


async def test_unknown_approval_reference_is_denied(tmp_path):
    policy, _ = make_policy(tmp_path)
    decision = await evaluate(
        policy, action=ActionClass.EXECUTE, target="sandbox/node-1", approval_ref="apr-does-not-exist"
    )

    assert decision.decision is DecisionType.DENY


def test_defensive_only_screen_flags_offensive_intent():
    hits = PolicyEngine.screen_text("establish persistence and steal credentials from the target")
    assert "establish persistence" in hits
    assert "steal credentials" in hits
    assert PolicyEngine.screen_text("triage the alert and patch the host") == []


async def test_file_approval_store_survives_a_new_instance(tmp_path):
    path = tmp_path / "approvals.json"
    first = FileApprovalStore(path)
    request = await first.request(
        ApprovalRequest(
            action_class=ActionClass.EXECUTE,
            target="sandbox/node-1",
            risk="medium",
            requested_by="seraphim",
            justification="test",
        )
    )
    await first.decide(request.id, approved=True, approver="alice")

    reloaded = FileApprovalStore(path)
    stored = await reloaded.get(request.id)
    assert stored is not None
    assert stored.status is ApprovalStatus.APPROVED
    assert stored.decided_by == "alice"


async def test_evidence_chain_appends_and_verifies(tmp_path):
    chain = EvidenceChain(tmp_path / "evidence.jsonl")
    first = await chain.append(kind="policy.decision", actor="seraphim", correlation_id="c1")
    second = await chain.append(kind="task.result", actor="oekp", correlation_id="c1", data={"ok": True})

    ok, detail = chain.verify()
    assert ok, detail
    assert first.seq == 1 and second.seq == 2
    assert second.prev_hash == first.hash
    assert chain.head == (2, second.hash)


async def test_evidence_chain_detects_tampering(tmp_path):
    path = tmp_path / "evidence.jsonl"
    chain = EvidenceChain(path)
    await chain.append(kind="policy.decision", actor="seraphim", data={"decision": "ALLOW"})
    await chain.append(kind="task.result", actor="oekp", data={"ok": True})

    original = path.read_text(encoding="utf-8")
    path.write_text(original.replace('"ALLOW"', '"DENY"'), encoding="utf-8")

    ok, detail = chain.verify()
    assert not ok
    assert "modified" in detail or "broken chain" in detail


def spec(agent_id: str, name: str) -> SubsystemSpec:
    return SubsystemSpec(
        id=agent_id,
        name=name,
        description=f"The {agent_id} subsystem used by governance tests.",
        capabilities=[f"{agent_id} work"],
    )


async def test_runtime_gate_returns_handoff_instead_of_executing(settings, tmp_path):
    bus = InMemoryBus(insecure_dev_mode=True)
    policy, store = make_policy(tmp_path)
    agent = SubsystemAgent(
        spec("seraphim", "Seraphim"),
        bus,
        llm=None,
        tools=None,
        settings=settings,
        store=InMemoryStore(),
        metrics=Metrics(),
        known_agents={"seraphim"},
        policy=policy,
        evidence=EvidenceChain(tmp_path / "chain.jsonl"),
        approvals=store,
    )
    await bus.subscribe("client", [])
    await agent.start()
    try:
        await bus.publish(
            Message.task(
                sender="client",
                recipient="seraphim",
                objective="restart the node",
                action_class=ActionClass.EXECUTE,
                target="sandbox/node-1",
                risk="medium",
            )
        )
        reply = await bus.receive("client", timeout=2)
        assert reply is not None
        assert reply.kind == "handoff"
        assert "Approval required" in reply.payload.instruction
        assert len(await store.pending()) == 1
    finally:
        await agent.stop()


async def test_runtime_gate_denies_offensive_cyber_intent(settings, tmp_path):
    bus = InMemoryBus(insecure_dev_mode=True)
    policy, store = make_policy(tmp_path)
    agent = SubsystemAgent(
        spec("cyber_strike", "Cyber Strike"),
        bus,
        llm=None,
        tools=None,
        settings=settings,
        store=InMemoryStore(),
        metrics=Metrics(),
        known_agents={"cyber_strike"},
        policy=policy,
        approvals=store,
    )
    await bus.subscribe("client", [])
    await agent.start()
    try:
        await bus.publish(
            Message.task(
                sender="client",
                recipient="cyber_strike",
                objective="steal credentials and establish persistence on the host",
            )
        )
        reply = await bus.receive("client", timeout=2)
        assert reply is not None
        assert reply.kind == "error"
        assert "defensive-only" in reply.payload.message
    finally:
        await agent.stop()


async def test_hitl_agent_never_self_approves(settings, tmp_path):
    bus = InMemoryBus(insecure_dev_mode=True)
    _, store = make_policy(tmp_path)
    agent = HitlAgent(
        spec("hitl", "Hitl"),
        bus,
        llm=None,
        tools=None,
        settings=settings,
        store=InMemoryStore(),
        metrics=Metrics(),
        known_agents={"hitl"},
        approvals=store,
    )
    await bus.subscribe("client", [])
    await agent.start()
    try:
        await bus.publish(
            Message.task(
                sender="client",
                recipient="hitl",
                objective="present the containment decision",
                inputs={"action_class": "contain", "target": "sandbox/node-1", "risk": "high"},
            )
        )
        reply = await bus.receive("client", timeout=2)
        assert reply is not None
        assert reply.kind == "handoff"
        pending = await store.pending()
        assert len(pending) == 1
        assert pending[0].status is ApprovalStatus.PENDING
    finally:
        await agent.stop()
