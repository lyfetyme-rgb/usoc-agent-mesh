"""Security tests: authentication, approval integrity and secret handling.

These cover the controls that make the mesh safe to expose beyond a laptop:

* message authentication and tamper quarantine
* approval identity, four-eyes, TTL, mission scope and signatures
* keyed evidence MACs
* redaction of secrets in logs
* the read-only health endpoint
* destructive tools disabled by default
"""

from __future__ import annotations

import asyncio
import json
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agents.bus import InMemoryBus
from agents.config import Settings
from agents.contracts import ActionClass, Classification, Message, RiskLevel
from agents.evidence import EvidenceChain, EvidenceRecord
from agents.governance import (
    ApprovalRequest,
    ApprovalStatus,
    DecisionType,
    FileApprovalStore,
    InMemoryApprovalStore,
    PolicyConfig,
    PolicyEngine,
)
from agents.llm import OpenAICompatibleLLM
from agents.security import (
    SecurityError,
    Signer,
    build_signer,
    configured_approvers,
    redact_fields,
    redact_text,
    redact_url,
)
from agents.service import HealthServer
from agents.tools import build_default_tools

SECRET = "test-secret-that-is-long-enough-for-hmac-0123456789"


def signer() -> Signer:
    return Signer(SECRET)


def approval(**overrides) -> ApprovalRequest:
    params = dict(
        action_class=ActionClass.EXECUTE,
        target="sandbox/node-1",
        risk=RiskLevel.MEDIUM,
        mission_id="mission-1",
        requested_by="seraphim",
        justification="test",
        correlation_id="corr-1",
    )
    params.update(overrides)
    return ApprovalRequest(**params)


async def evaluate(policy: PolicyEngine, **overrides):
    params = dict(
        action=ActionClass.EXECUTE,
        target="sandbox/node-1",
        risk=RiskLevel.MEDIUM,
        mission_id="mission-1",
        classification=Classification.INTERNAL,
        approval_ref=None,
        requested_by="seraphim",
        justification="test",
        correlation_id="corr-1",
    )
    params.update(overrides)
    return await policy.evaluate(**params)


# -- message authentication -------------------------------------------------
async def test_memory_bus_signs_and_verifies_messages():
    bus = InMemoryBus(signer=signer())
    await bus.subscribe("a", [])
    await bus.publish(Message.task(sender="orchestrator", recipient="a", objective="work"))

    received = await bus.receive("a", timeout=0.5)
    assert received is not None
    assert received.signature
    ok, detail = bus.signer.verify_message(received)
    assert ok, detail


async def test_tampered_message_is_quarantined_not_delivered():
    bus = InMemoryBus(signer=signer())
    await bus.subscribe("a", [])
    original = signer().sign_message(
        Message.task(sender="orchestrator", recipient="a", objective="work")
    )
    tampered = original.model_copy(update={"sender": "attacker"})
    await bus._queues["a"].put(tampered)

    assert await bus.receive("a", timeout=0.05) is None
    assert len(bus.dlq) == 1
    assert bus.stats["rejected"] == 1


async def test_signature_is_bound_to_the_sender():
    signed = signer().sign_message(
        Message.task(sender="orchestrator", recipient="a", objective="work")
    )
    impersonation = signed.model_copy(update={"sender": "seraphim"})
    ok, detail = signer().verify_message(impersonation)
    assert not ok
    assert "signature" in detail


def test_signature_survives_a_json_roundtrip():
    signed = signer().sign_message(
        Message.task(sender="orchestrator", recipient="a", objective="work")
    )
    again = Message.model_validate_json(signed.model_dump_json())
    ok, detail = signer().verify_message(again)
    assert ok, detail


def test_message_freshness_can_be_enforced():
    s = Signer(SECRET, max_age_s=30)
    old = Message.task(sender="a", recipient="b", objective="work").model_copy(
        update={"created_at": datetime.now(timezone.utc) - timedelta(minutes=5)}
    )
    ok, detail = s.verify_message(s.sign_message(old))
    assert not ok
    assert "too old" in detail


def test_redis_bus_requires_an_explicit_secret():
    with pytest.raises(SecurityError):
        build_signer(Settings(bus="redis", shared_secret=None, shared_secret_file=None))


def test_memory_bus_gets_an_ephemeral_secret():
    s = build_signer(Settings(bus="memory", shared_secret=None))
    assert s is not None


def test_authentication_can_be_explicitly_disabled():
    assert build_signer(Settings(message_auth=False)) is None


def test_secret_can_be_mounted_from_a_file(tmp_path: Path):
    path = tmp_path / "secret"
    path.write_text(SECRET + "\n", encoding="utf-8")
    s = build_signer(
        Settings(bus="redis", shared_secret=None, shared_secret_file=path)
    )
    assert s is not None
    ok, _ = s.verify_record("probe", {"x": 1}, s.sign_record("probe", {"x": 1}))
    assert ok


def test_short_secrets_are_rejected():
    with pytest.raises(SecurityError):
        Signer("too-short")


async def test_remote_plaintext_model_endpoint_is_rejected():
    with pytest.raises(SecurityError, match="https"):
        OpenAICompatibleLLM("http://api.example.test/v1", "sk-test")

    # Loopback is allowed for local models such as Ollama.
    client = OpenAICompatibleLLM("http://127.0.0.1:11434/v1", "sk-test")
    await client.close()

    client = OpenAICompatibleLLM("https://api.example.test/v1", "sk-test")
    await client.close()


def test_settings_repr_hides_secrets():
    settings = Settings(
        shared_secret=SECRET, llm_api_key="sk-live-secret", health_token="health-secret"
    )
    text = repr(settings)
    assert SECRET not in text
    assert "sk-live-secret" not in text
    assert "health-secret" not in text


def test_approver_allowlist_parsing():
    settings = Settings(approvers="alice, bob ,, carol")
    assert configured_approvers(settings) == {"alice", "bob", "carol"}


# -- approvals --------------------------------------------------------------
async def test_approver_must_be_on_the_allowlist():
    store = InMemoryApprovalStore(
        signer=signer(), approvers={"alice"}, require_allowlist=True
    )
    request = await store.request(approval())

    with pytest.raises(ValueError, match="allowlist"):
        await store.decide(request.id, approved=True, approver="mallory")

    updated = await store.decide(request.id, approved=True, approver="alice")
    assert updated.status is ApprovalStatus.APPROVED
    assert updated.signature


async def test_empty_allowlist_fails_closed_when_required():
    store = InMemoryApprovalStore(require_allowlist=True)
    request = await store.request(approval())
    with pytest.raises(ValueError, match="not configured"):
        await store.decide(request.id, approved=True, approver="alice")


async def test_requester_cannot_approve_their_own_request():
    store = InMemoryApprovalStore(
        signer=signer(), approvers={"alice", "bob"}, require_allowlist=True
    )
    request = await store.request(approval(requested_by="alice"))

    with pytest.raises(ValueError, match="cannot approve their own"):
        await store.decide(request.id, approved=True, approver="alice")

    updated = await store.decide(request.id, approved=True, approver="bob")
    assert updated.decided_by == "bob"


async def test_pending_approval_expires():
    store = InMemoryApprovalStore(signer=signer(), ttl_s=1)
    old = approval(created_at=datetime.now(timezone.utc) - timedelta(minutes=5))
    request = await store.request(old)

    with pytest.raises(ValueError, match="expired"):
        await store.decide(request.id, approved=True, approver="alice")


async def test_policy_denies_an_expired_pending_approval():
    store = InMemoryApprovalStore(signer=signer())
    old = approval(created_at=datetime.now(timezone.utc) - timedelta(minutes=5))
    request = await store.request(old)
    policy = PolicyEngine(
        PolicyConfig(allowed_targets=["sandbox/*"], approval_ttl_s=60), store
    )

    decision = await evaluate(policy, approval_ref=request.id)
    assert decision.decision is DecisionType.DENY
    assert "expired" in "; ".join(decision.reasons)


async def test_approval_is_scoped_to_its_mission():
    store = InMemoryApprovalStore(signer=signer())
    request = await store.request(approval(mission_id="mission-a"))
    await store.decide(request.id, approved=True, approver="alice")
    policy = PolicyEngine(PolicyConfig(allowed_targets=["sandbox/*"]), store)

    decision = await evaluate(policy, mission_id="mission-b", approval_ref=request.id)
    assert decision.decision is DecisionType.DENY
    assert "scoped to mission" in "; ".join(decision.reasons)


async def test_request_cannot_inject_a_preapproved_record():
    store = InMemoryApprovalStore(signer=signer())
    forged = approval(
        status=ApprovalStatus.APPROVED,
        decided_by="alice",
        decided_at=datetime.now(timezone.utc),
    )
    stored = await store.request(forged)

    assert stored.status is ApprovalStatus.PENDING
    assert stored.decided_by is None
    assert stored.decided_at is None

    policy = PolicyEngine(PolicyConfig(allowed_targets=["sandbox/*"]), store)
    decision = await evaluate(policy, approval_ref=stored.id)
    assert decision.decision is DecisionType.HOLD


async def test_duplicate_approval_id_is_rejected():
    store = InMemoryApprovalStore(signer=signer())
    request = await store.request(approval())
    with pytest.raises(ValueError, match="already exists"):
        await store.request(request.model_copy())


async def test_approved_approval_expires():
    store = InMemoryApprovalStore(signer=signer())
    request = await store.request(approval())
    approved = await store.decide(request.id, approved=True, approver="alice")
    stale = approved.model_copy(
        update={"decided_at": datetime.now(timezone.utc) - timedelta(minutes=5)}
    )
    store._items[request.id] = store._sign(stale)

    policy = PolicyEngine(
        PolicyConfig(allowed_targets=["sandbox/*"], approval_ttl_s=60), store
    )
    decision = await evaluate(policy, approval_ref=request.id)
    assert decision.decision is DecisionType.DENY
    assert "expired" in "; ".join(decision.reasons)


async def test_wildcard_approval_does_not_cover_a_concrete_target():
    store = InMemoryApprovalStore(signer=signer())
    request = await store.request(approval(target="sandbox/*"))
    await store.decide(request.id, approved=True, approver="alice")
    policy = PolicyEngine(PolicyConfig(allowed_targets=["sandbox/*"]), store)

    decision = await evaluate(policy, target="sandbox/node-1", approval_ref=request.id)
    assert decision.decision is DecisionType.DENY
    assert "does not cover" in "; ".join(decision.reasons)


async def test_file_store_rejects_a_tampered_approval(tmp_path: Path):
    path = tmp_path / "approvals.json"
    store = FileApprovalStore(path, signer=signer())
    request = await store.request(approval())

    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["approvals"][0]["target"] = "prod/db-primary"
    path.write_text(json.dumps(raw), encoding="utf-8")

    reloaded = FileApprovalStore(path, signer=signer())
    assert await reloaded.get(request.id) is None
    assert reloaded.rejected >= 1


async def test_file_store_rejects_unsigned_records_when_signing(tmp_path: Path):
    path = tmp_path / "approvals.json"
    unsigned = approval()
    path.write_text(
        json.dumps({"approvals": [unsigned.model_dump(mode="json")]}), encoding="utf-8"
    )

    store = FileApprovalStore(path, signer=signer())
    assert await store.get(unsigned.id) is None
    assert store.rejected == 1


async def test_file_store_sees_an_approval_from_another_process(tmp_path: Path):
    path = tmp_path / "approvals.json"
    writer = FileApprovalStore(path, signer=signer(), approvers={"alice"})
    reader = FileApprovalStore(path, signer=signer(), approvers={"alice"})

    request = await writer.request(approval())
    assert (await reader.get(request.id)).status is ApprovalStatus.PENDING

    await reader.decide(request.id, approved=True, approver="alice")
    refreshed = await writer.get(request.id)
    assert refreshed is not None
    assert refreshed.status is ApprovalStatus.APPROVED


# -- evidence ---------------------------------------------------------------
async def test_evidence_mac_detects_a_recomputed_hash(tmp_path: Path):
    path = tmp_path / "chain.jsonl"
    chain = EvidenceChain(path, signer=signer())
    await chain.append(kind="policy.decision", actor="seraphim", data={"decision": "ALLOW"})
    ok, detail = chain.verify()
    assert ok, detail

    record = EvidenceRecord.model_validate_json(path.read_text(encoding="utf-8").strip())
    tampered = record.model_copy(update={"data": {"decision": "DENY"}})
    tampered.hash = tampered.compute_hash()
    path.write_text(tampered.model_dump_json() + "\n", encoding="utf-8")

    ok, detail = chain.verify()
    assert not ok
    assert "MAC" in detail


async def test_evidence_chain_still_verifies_without_a_signer(tmp_path: Path):
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    await chain.append(kind="task.result", actor="oekp", data={"ok": True})
    ok, detail = chain.verify()
    assert ok, detail


# -- redaction --------------------------------------------------------------
def test_redaction_removes_bearer_tokens_and_url_credentials():
    assert redact_text("Authorization: Bearer abc.def-123") == "Authorization: Bearer ***"
    assert redact_text("Authorization: Basic YWxpY2U6c2VjcmV0") == "Authorization: Basic ***"
    assert redact_url("redis://user:s3cret@redis:6379/0") == "redis://user:***@redis:6379/0"
    assert (
        redact_text("https://example.test/cb?token=abc123&ok=1")
        == "https://example.test/cb?token=***&ok=1"
    )


def test_redaction_masks_sensitive_fields():
    out = redact_fields(
        {
            "api_key": "sk-live",
            "nested": {"password": "hunter2", "safe": "visible"},
            "headers": ["Bearer xyz"],
            "header_list": [{"authorization": "Bearer z"}],
            "access_token": "abc",
            "tokens": 42,
            "tokens_used": 1200,
            "max_tokens": 8000,
        }
    )
    assert out["api_key"] == "***"
    assert out["nested"]["password"] == "***"
    assert out["nested"]["safe"] == "visible"
    assert out["headers"] == ["Bearer ***"]
    assert out["header_list"][0]["authorization"] == "***"
    assert out["access_token"] == "***"
    # Counters must stay visible or the logs become useless.
    assert out["tokens"] == 42
    assert out["tokens_used"] == 1200
    assert out["max_tokens"] == 8000


# -- service ----------------------------------------------------------------
async def _http(port: int, path: str, token: str | None = None) -> tuple[int, dict]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    lines = [f"GET {path} HTTP/1.1", "Host: localhost", "Connection: close"]
    if token:
        lines.append(f"Authorization: Bearer {token}")
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
    await writer.drain()
    raw = await reader.read()
    writer.close()
    with suppress(ConnectionError, OSError):
        await writer.wait_closed()
    head, _, body = raw.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1])
    return status, json.loads(body or b"{}")


async def test_health_server_requires_its_token():
    async def provider(path: str) -> tuple[int, dict]:
        return 200, {"path": path}

    server = HealthServer("127.0.0.1", 0, provider, token="health-token")
    await server.start()
    try:
        assert (await _http(server.port, "/health"))[0] == 401
        status, body = await _http(server.port, "/health", token="health-token")
        assert status == 200 and body["path"] == "/health"
        status, body = await _http(server.port, "/ready", token="health-token")
        assert status == 200 and body["path"] == "/ready"
        assert (await _http(server.port, "/submit", token="health-token"))[0] == 404
    finally:
        await server.stop()


# -- tools ------------------------------------------------------------------
def test_destructive_workspace_delete_is_off_by_default(tmp_path: Path):
    assert "workspace.delete" not in build_default_tools(tmp_path / "ws").tools
    assert "workspace.delete" in build_default_tools(tmp_path / "ws", allow_delete=True).tools
