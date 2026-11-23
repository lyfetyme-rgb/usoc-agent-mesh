"""Strict edge ingress: quarantine malformed work before it burns tokens."""

from __future__ import annotations

import json

from agents.contracts import ActionClass, Message
from agents.ingress import IngressGate, IngressQuarantine


def _raw(**overrides):
    message = Message.task(
        sender="client",
        recipient="oekp",
        objective="Summarize the sandbox alert for a human analyst.",
        action_class=ActionClass.EXECUTE,
        target="sandbox/alerts/1",
        tenant_id="tenant-a",
        correlation_id="trace-123",
    )
    payload = message.model_dump(mode="json")
    payload.update(overrides)
    return payload


def test_valid_task_is_accepted_with_a_deterministic_idempotency_key():
    gate = IngressGate(secret="cluster-secret")
    result = gate.accept(_raw())

    assert result.quarantined is False
    assert result.accepted is not None
    key = result.accepted.payload.idempotency_key
    assert key is not None and len(key) == 64
    assert key == gate.accept(_raw()).accepted.payload.idempotency_key
    assert result.fingerprint is None


def test_caller_supplied_idempotency_key_is_preserved():
    raw = _raw()
    raw["payload"]["idempotency_key"] = "client-supplied-token-123"
    result = IngressGate().accept(raw)
    assert result.accepted is not None
    assert result.accepted.payload.idempotency_key == "client-supplied-token-123"


def test_unknown_fields_are_quarantined_without_retaining_the_value():
    quarantine = IngressQuarantine(capacity=4)
    gate = IngressGate(quarantine=quarantine)
    result = gate.accept(_raw(unexpected_field="api_key=sk-super-secret"))

    assert result.quarantined is True
    assert result.accepted is None
    assert result.code == "schema_invalid"
    blob = json.dumps(quarantine.snapshot())
    assert "sk-super-secret" not in blob
    assert "unexpected_field" not in blob
    assert quarantine.snapshot()["quarantined"] == 1


def test_missing_tenant_is_quarantined_when_required():
    raw = _raw()
    del raw["tenant_id"]
    del raw["payload"]["tenant_id"]
    result = IngressGate(require_tenant=True).accept(raw)
    assert result.quarantined is True
    assert result.code == "tenant_required"


def test_malformed_payload_is_quarantined():
    raw = _raw()
    raw["payload"]["kind"] = "unknown-kind"
    result = IngressGate().accept(raw)
    assert result.quarantined is True
    assert result.code == "schema_invalid"
    assert result.fingerprint is not None and len(result.fingerprint) == 16


def test_quarantine_is_bounded_and_reports_counts_only_to_public_probes():
    quarantine = IngressQuarantine(capacity=2)
    gate = IngressGate(quarantine=quarantine)
    for index in range(5):
        gate.accept(_raw(unexpected_field=f"secret-{index}"))

    snapshot = quarantine.snapshot()
    assert snapshot["quarantined"] == 5
    assert snapshot["retained"] == 2
    assert snapshot["dropped"] == 3
    assert len(snapshot["recent"]) == 2
    assert all("recent" not in item for item in snapshot["recent"])


def test_governed_action_without_tenant_is_accepted_in_dev_mode():
    raw = _raw()
    del raw["tenant_id"]
    del raw["payload"]["tenant_id"]
    result = IngressGate().accept(raw)
    assert result.quarantined is False
    assert result.tenant_id == "default"
