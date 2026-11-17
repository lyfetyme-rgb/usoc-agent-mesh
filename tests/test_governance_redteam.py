"""Adversarial governance tests.

Four attacks that matter in multi-worker production:

1. Approval replay / scope creep - a signed approval must be single-use and
   bound to action, target, mission, risk, taint disclosure and TTL.
2. Taint laundering - a tainted "read-only" step must not slip past HITL and
   seed a later mutating step.
3. Sandbox spoofing - CSSSF rehearsal output must not become execution proof.
4. Cross-worker impersonation - a sibling worker must not emit SERAPHIM policy
   verdicts or HITL approval grants, even through a different transport.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from agents.bus import (
    InMemoryBus,
    TopicRule,
    topic_rules_from_authority,
)
from agents.contracts import (
    ActionClass,
    Classification,
    Failure,
    Message,
    RiskLevel,
    TaskResult,
)
from agents.evidence import EvidenceChain, sandbox_origin
from agents.governance import (
    ApprovalRequest,
    ApprovalStatus,
    DecisionType,
    InMemoryApprovalStore,
    PolicyConfig,
    PolicyEngine,
    taint_disclosure_hash,
)
from agents.llm import EchoLLM
from agents.observability import Metrics
from agents.registry import SubsystemSpec
from agents.runtime import SubsystemAgent
from agents.store import InMemoryStore
from agents.usoc_agents import BengalAgent, OekpAgent

SECRET = "red-team-secret-that-is-long-enough-32"
TARGET = "sandbox/node-1"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def make_store() -> InMemoryApprovalStore:
    return InMemoryApprovalStore(
        approvers={"alice", "bob"}, require_allowlist=True
    )


async def decided_approval(
    store: InMemoryApprovalStore,
    *,
    action: ActionClass = ActionClass.EXECUTE,
    target: str = TARGET,
    risk: RiskLevel = RiskLevel.HIGH,
    mission_id: str | None = None,
    provenance: list[str] | None = None,
    tainted: bool = False,
) -> ApprovalRequest:
    prov = provenance or []
    req = await store.request(
        ApprovalRequest(
            action_class=action,
            target=target,
            risk=risk,
            mission_id=mission_id,
            requested_by="seraphim",
            justification="controlled red-team action",
            provenance=prov,
            tainted=tainted,
            taint_hash=taint_disclosure_hash(prov, tainted),
        )
    )
    return await store.decide(req.id, approved=True, approver="alice")


def make_policy(
    store: InMemoryApprovalStore,
    *,
    consumption_audit=None,
    approval_ttl_s: int = 86_400,
) -> PolicyEngine:
    return PolicyEngine(
        PolicyConfig(allowed_targets=["sandbox/*"], approval_ttl_s=approval_ttl_s),
        store,
        consumption_audit=consumption_audit,
    )


def evaluate(policy: PolicyEngine, **overrides):
    params = dict(
        action=ActionClass.EXECUTE,
        target=TARGET,
        risk=RiskLevel.HIGH,
        mission_id=None,
        classification=Classification.INTERNAL,
        approval_ref=None,
        requested_by="seraphim",
        justification="red-team",
        correlation_id="corr-redteam",
    )
    params.update(overrides)
    return policy.evaluate(**params)


class KidSigner:
    """Test signer that stamps a caller-chosen key id, like the real keyring."""

    def __init__(self, kids: dict[str, str]) -> None:
        self.kids = kids

    def sign_message(self, msg: Message) -> Message:
        kid = self.kids.get(msg.sender)
        return msg.model_copy(
            update={
                "signing_kid": kid,
                "signature_alg": "ed25519" if kid else None,
                "signature": "sig" if kid else None,
            }
        )

    def verify_message(self, msg: Message) -> tuple[bool, str]:
        return True, "test-verified"


def authority_with_kids() -> SimpleNamespace:
    return SimpleNamespace(
        public={
            "seraphim": {"seraphim-1": "key"},
            "hitl": {"hitl-1": "key"},
        }
    )


def worker_spec() -> SubsystemSpec:
    return SubsystemSpec(
        id="worker",
        name="Worker",
        description="red-team worker.",
        capabilities=["work"],
        tools=[],
    )


# ---------------------------------------------------------------------------
# 1. approval replay / scope creep
# ---------------------------------------------------------------------------
async def test_approval_nonce_is_single_use():
    store = make_store()
    ap = await decided_approval(store)
    policy = make_policy(store)
    kwargs = dict(approval_ref=ap.id)

    first = await evaluate(policy, **kwargs)
    assert first.decision is DecisionType.ALLOW

    replay = await evaluate(policy, **kwargs)
    assert replay.decision is DecisionType.DENY
    assert "already consumed" in "; ".join(replay.reasons)


async def test_approval_is_bound_to_target_and_mission():
    store = make_store()
    ap = await decided_approval(store, mission_id="mission-a")
    policy = make_policy(store)

    wrong_target = await evaluate(
        policy, approval_ref=ap.id, target=TARGET + "-other"
    )
    assert wrong_target.decision is DecisionType.DENY
    assert "does not cover this action and target" in "; ".join(wrong_target.reasons)

    wrong_mission = await evaluate(policy, approval_ref=ap.id, mission_id="mission-b")
    assert wrong_mission.decision is DecisionType.DENY
    assert "scoped to mission" in "; ".join(wrong_mission.reasons)

    # The failed attempts must not have spent the nonce: the correct scope works.
    correct = await evaluate(policy, approval_ref=ap.id, mission_id="mission-a")
    assert correct.decision is DecisionType.ALLOW


async def test_approval_risk_is_a_ceiling_not_an_escalation_path():
    store = make_store()
    low = await decided_approval(store, risk=RiskLevel.LOW)
    high = await decided_approval(store, risk=RiskLevel.HIGH)
    policy = make_policy(store)

    escalate = await evaluate(policy, approval_ref=low.id, risk=RiskLevel.CRITICAL)
    assert escalate.decision is DecisionType.DENY
    assert "at most low risk" in "; ".join(escalate.reasons)

    # A HIGH approval covers a LOW action of the same scope.
    covered = await evaluate(
        policy, approval_ref=high.id, risk=RiskLevel.LOW, correlation_id="covered"
    )
    assert covered.decision is DecisionType.ALLOW


async def test_approval_is_bound_to_taint_disclosure():
    store = make_store()
    ap = await decided_approval(
        store, tainted=True, provenance=["connector://vendor-api"]
    )
    policy = make_policy(store)

    laundered = await evaluate(
        policy,
        approval_ref=ap.id,
        tainted=True,
        provenance=["connector://trusted-internal"],
    )
    assert laundered.decision is DecisionType.DENY
    assert "fresh approval" in "; ".join(laundered.reasons)

    undisclosed = await evaluate(
        policy, approval_ref=ap.id, tainted=False, provenance=[]
    )
    assert undisclosed.decision is DecisionType.DENY

    correct = await evaluate(
        policy,
        approval_ref=ap.id,
        tainted=True,
        provenance=["connector://vendor-api"],
    )
    assert correct.decision is DecisionType.ALLOW


async def test_approved_approval_expires_from_decision_time():
    store = make_store()
    ap = await decided_approval(store)
    stale = (await store.get(ap.id)).model_copy(
        update={"decided_at": datetime.now(timezone.utc) - timedelta(days=2)}
    )
    store._items[ap.id] = stale  # simulate an old signed decision in the store
    policy = make_policy(store, approval_ttl_s=60)

    decision = await evaluate(policy, approval_ref=ap.id)
    assert decision.decision is DecisionType.DENY
    assert "expired" in "; ".join(decision.reasons)


async def test_consumed_nonce_is_recorded_in_evidence(tmp_path: Path):
    from agents.security import Signer

    store = make_store()
    ap = await decided_approval(store)
    chain = EvidenceChain(tmp_path / "evidence.jsonl", signer=Signer(SECRET))
    audited = []

    async def audit(request: ApprovalRequest, **context) -> None:
        await chain.append(
            kind="approval.consumed",
            actor="oekp",
            subsystem="oekp",
            correlation_id=str(context.get("correlation_id") or ""),
            data={"approval_id": request.id, "nonce": request.nonce},
        )
        audited.append(request.nonce)

    policy = make_policy(store, consumption_audit=audit)
    decision = await evaluate(policy, approval_ref=ap.id)
    assert decision.decision is DecisionType.ALLOW

    assert audited == [ap.nonce]
    records = chain.records()
    assert len(records) == 1
    assert records[0].kind == "approval.consumed"
    assert records[0].data["nonce"] == ap.nonce
    ok, _ = chain.verify()
    assert ok


# ---------------------------------------------------------------------------
# 2. taint laundering
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "action",
    [ActionClass.READ_ONLY, ActionClass.RECOMMEND, ActionClass.SIMULATE],
)
async def test_tainted_nongoverned_action_requires_hitl(action: ActionClass):
    store = make_store()
    policy = make_policy(store)

    decision = await evaluate(
        policy,
        action=action,
        target=None,
        risk=RiskLevel.LOW,
        approval_ref=None,
        provenance=["connector://vendor-api"],
        tainted=True,
    )
    assert decision.decision is DecisionType.HOLD
    assert decision.approval_ref is not None
    assert "tainted output is not a harmless read" in "; ".join(decision.reasons)

    pending = await store.pending()
    assert len(pending) == 1
    assert pending[0].tainted is True
    assert pending[0].taint_hash == taint_disclosure_hash(
        ["connector://vendor-api"], True
    )


async def test_runtime_fails_closed_for_tainted_work_without_policy(settings, tools):
    bus = InMemoryBus(insecure_dev_mode=True)
    await bus.subscribe("client", [])
    agent = SubsystemAgent(
        worker_spec(),
        bus,
        llm=EchoLLM(),
        tools=tools,
        settings=settings,
        store=InMemoryStore(),
        metrics=Metrics(),
        known_agents={"worker"},
        policy=None,
    )
    await agent.start()
    try:
        await bus.publish(
            Message.task(
                sender="client",
                recipient="worker",
                objective="summarize vendor payload",
                provenance=["connector://vendor-api"],
                tainted=True,
            )
        )
        reply = await bus.receive("client", timeout=1)
        assert reply is not None and reply.kind == "error"
        assert reply.payload.code == "policy_denied"
    finally:
        await agent.stop()


async def test_taint_survives_task_result(settings, tools):
    bus = InMemoryBus(insecure_dev_mode=True)
    await bus.subscribe("client", [])
    agent = SubsystemAgent(
        worker_spec(),
        bus,
        llm=EchoLLM(),
        tools=tools,
        settings=settings,
        store=InMemoryStore(),
        metrics=Metrics(),
        known_agents={"worker"},
    )
    await agent.start()
    original = agent.handle_task

    async def tainted_handler(spec, msg):
        result = await original(spec, msg)
        return result.model_copy(update={"tainted": True})

    agent.handle_task = tainted_handler
    try:
        await bus.publish(
            Message.task(
                sender="client",
                recipient="worker",
                objective="summarize the latest telemetry",
                provenance=["connector://vendor-api"],
            )
        )
        reply = await bus.receive("client", timeout=1)
        assert reply is not None and isinstance(reply.payload, TaskResult)
        assert reply.payload.tainted is True
        assert "connector://vendor-api" in reply.payload.provenance
    finally:
        await agent.stop()


# ---------------------------------------------------------------------------
# 3. sandbox spoofing
# ---------------------------------------------------------------------------
def oekp_stub(chain: EvidenceChain):
    return SimpleNamespace(id="oekp", evidence=chain, metrics=Metrics())


def bengal_stub(chain: EvidenceChain):
    return SimpleNamespace(id="bengal", evidence=chain, metrics=Metrics())


def oekp_task(**inputs):
    return Message.task(
        sender="seraphim",
        recipient="oekp",
        objective="record the result",
        inputs=inputs,
        action_class=ActionClass.READ_ONLY,
    )


async def test_csssf_provenance_is_rejected_without_rehearsal_flag(tmp_path: Path):
    chain = EvidenceChain(tmp_path / "evidence.jsonl")
    msg = oekp_task(provenance=["csssf:sandbox/run-42"])
    result = await OekpAgent.handle_task(oekp_stub(chain), msg.payload, msg)
    assert isinstance(result, Failure)
    assert result.code == "rehearsal_only"
    assert chain.records() == []


async def test_csssf_provenance_rehearsal_flag_is_recorded_and_bengal_reports_it(
    tmp_path: Path,
):
    chain = EvidenceChain(tmp_path / "evidence.jsonl")
    msg = oekp_task(
        provenance=["csssf:sandbox/run-42"],
        rehearsal_only=True,
    )
    spec = msg.payload
    result = await OekpAgent.handle_task(oekp_stub(chain), spec, msg)
    assert result is not None and result.ok is True  # type: ignore[union-attr]

    records = chain.records()
    assert len(records) == 1
    assert records[0].rehearsal_only is True
    assert records[0].origin == "seraphim"
    assert sandbox_origin(
        origin=records[0].origin, provenance=records[0].provenance
    )

    verification = await BengalAgent.handle_task(bengal_stub(chain), spec, msg)
    assert verification is not None
    assert verification.data["verified"] is True
    assert verification.data["rehearsal_only_count"] == 1
    assert verification.data["trusted_for_execution"] is False
    assert "not execution proof" in verification.output


async def test_sandbox_origin_cannot_be_spoofed_from_payload(tmp_path: Path):
    chain = EvidenceChain(tmp_path / "evidence.jsonl")
    # Attacker claims "production" in inputs but the authenticated sender is
    # csssf and there is no rehearsal flag: still rejected.
    msg = Message.task(
        sender="csssf",
        recipient="oekp",
        objective="record",
        inputs={"origin": "production", "provenance": ["cleared"]},
        action_class=ActionClass.SIMULATE,
    )
    result = await OekpAgent.handle_task(oekp_stub(chain), msg.payload, msg)
    assert isinstance(result, Failure)
    assert result.code == "rehearsal_only"


# ---------------------------------------------------------------------------
# 4. cross-worker impersonation
# ---------------------------------------------------------------------------
def verdict_event(sender: str) -> Message:
    return Message.event(
        sender=sender, name="policy.verdict", topic="policy.verdict", data={}
    )


def test_topic_rules_pin_senders_and_kids():
    rules = topic_rules_from_authority(authority_with_kids())
    assert rules["policy.verdict"] == TopicRule(
        "policy.verdict", frozenset({"seraphim"}), frozenset({"seraphim-1"})
    )
    assert rules["approval.granted"].senders == frozenset({"hitl"})


async def test_memory_bus_denies_impersonated_policy_verdict():
    rules = topic_rules_from_authority(authority_with_kids())
    bus = InMemoryBus(
        insecure_dev_mode=True,
        signer=KidSigner({"seraphim": "seraphim-1", "bengal": "bengal-1"}),
        topic_rules=rules,
    )

    await bus.publish(verdict_event("seraphim"))
    with pytest.raises(PermissionError, match="may not publish"):
        await bus.publish(verdict_event("bengal"))


async def test_memory_bus_denies_wrong_signing_kid():
    rules = topic_rules_from_authority(authority_with_kids())
    bus = InMemoryBus(
        insecure_dev_mode=True,
        signer=KidSigner({"seraphim": "stolen-kid"}),
        topic_rules=rules,
    )
    with pytest.raises(PermissionError, match="not trusted"):
        await bus.publish(verdict_event("seraphim"))


async def test_receive_side_quarantines_spoofed_topic_message():
    rules = topic_rules_from_authority(authority_with_kids())
    bus = InMemoryBus(
        signer=KidSigner({"seraphim": "seraphim-1"}),
        publish_acl={},
        subscribe_acl={"oekp": ["policy.verdict"]},
        topic_rules=rules,
    )
    await bus.subscribe("oekp", ["policy.verdict"])
    # Simulate a sibling worker writing a forged message straight to the queue.
    forged = verdict_event("bengal")
    bus._queues["oekp"].put_nowait(forged)

    assert await bus.receive("oekp", timeout=0.2) is None
    assert bus.dlq == [forged]
    assert bus.stats["rejected"] == 1


async def test_redis_bus_denies_impersonated_grant(monkeypatch):
    redis_asyncio = pytest.importorskip("redis.asyncio")
    monkeypatch.setattr(redis_asyncio, "from_url", lambda *a, **k: SimpleNamespace())
    from agents.bus import RedisBus

    rules = topic_rules_from_authority(authority_with_kids())
    bus = RedisBus(
        "redis://unused",
        signer=KidSigner({"bengal": "bengal-1", "hitl": "hitl-1"}),
        publish_acl={"bengal": ["approval.granted"], "hitl": ["approval.granted"]},
        topic_rules=rules,
    )
    grant = Message.event(
        sender="bengal", name="approval.granted", topic="approval.granted", data={}
    )
    with pytest.raises(PermissionError, match="may not publish"):
        await bus.publish(grant)


async def test_runtime_publish_guard_rejects_foreign_sender(settings, tools):
    bus = InMemoryBus(
        insecure_dev_mode=True,
        signer=KidSigner({}),
        topic_rules=topic_rules_from_authority(authority_with_kids()),
    )
    agent = SubsystemAgent(
        worker_spec(),
        bus,
        llm=EchoLLM(),
        tools=tools,
        settings=settings,
        store=InMemoryStore(),
        metrics=Metrics(),
    )
    with pytest.raises(PermissionError, match="may not publish"):
        await agent._publish(verdict_event("bengal"))
