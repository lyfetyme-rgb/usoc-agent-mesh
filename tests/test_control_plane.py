"""REQ-003: authenticated, bounded, signed control-plane gateway adapter."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from agents.asymmetric import Ed25519Signer, Ed25519Verifier, generate_keypair
from agents.contracts import ActionClass, RiskLevel
from agents.control_plane import ControlPlaneGateway, GatewayEvent

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
TOKEN = "a" * 32  # deliberately low-entropy test material, not a credential


def _keys():
    private, public = generate_keypair()
    return Ed25519Signer(private, key_id="test"), Ed25519Verifier(public, key_id="test")


def _payload(**overrides: object) -> dict:
    body: dict = {
        "tenant_id": "tenant-a",
        "source": "aicee",
        "event_type": "control_event",
        "action_class": ActionClass.EXECUTE.value,
        "target": "sandbox/tenant-a/job-1",
        "risk": RiskLevel.HIGH.value,
        "correlation_id": "corr-1",
        "idempotency_key": "idem-1",
        "deadline": (NOW + timedelta(seconds=30)).isoformat(),
        "payload_digest": "a" * 64,
        "provenance": ["aicee", "telemetry"],
        "tainted": True,
    }
    body.update(overrides)
    return body


def _body(payload: dict, signer: Ed25519Signer | None = None) -> bytes:
    signer = signer or _keys()[0]
    event = GatewayEvent.model_validate(payload)
    data = event.model_dump(mode="json")
    signature = signer.sign_record(
        "control-plane-envelope", data, event.source
    )
    return json.dumps(
        {"event": data, "signature": signature}, separators=(",", ":")
    ).encode("utf-8")


def _gateway(submit_result: dict | None = None):
    signer, verifier = _keys()
    seen: list[object] = []
    result = submit_result or {"decision": "HOLD", "authorization_ref": None}

    def submit(request: object) -> dict:
        seen.append(request)
        return result

    return (
        ControlPlaneGateway(
            token=TOKEN,
            signature_verifier=verifier,
            submit=submit,
            now=NOW,
        ),
        seen,
        signer,
    )


def _headers(token: str | None = TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token else {}


def test_gateway_rejects_missing_or_wrong_bearer_token_without_delegation():
    gateway, seen, signer = _gateway()
    body = _body(_payload(), signer)

    for token in (None, "wrong-secret"):
        status, response = gateway.handle("POST", "/v1/events", _headers(token), body)
        assert status == 401
        assert response["reason"] == "unauthenticated"
        assert TOKEN not in json.dumps(response)
    assert seen == []


def test_gateway_rejects_unsigned_or_tampered_envelope():
    gateway, seen, signer = _gateway()
    payload = _payload()
    event = GatewayEvent.model_validate(payload)
    unsigned = json.dumps({"event": event.model_dump(mode="json"), "signature": ""}).encode()
    status, response = gateway.handle("POST", "/v1/events", _headers(), unsigned)
    assert status == 401
    assert response["reason"] == "invalid_signature"

    valid = _body(payload, signer)
    tampered = valid.replace(b'"source":"aicee"', b'"source":"attacker"')
    status, response = gateway.handle("POST", "/v1/events", _headers(), tampered)
    assert status == 401
    assert response["reason"] in {"invalid_signature", "invalid_request"}
    assert seen == []


def test_gateway_delegates_a_valid_request_and_turns_hold_into_a_handoff():
    gateway, seen, signer = _gateway()
    status, response = gateway.handle(
        "POST", "/v1/events", _headers(), _body(_payload(), signer)
    )

    assert status == 202
    assert response["status"] == "handoff"
    assert response["handoff"] is True
    assert response["decision"] == "HOLD"
    assert len(response["evidence_fingerprint"]) == 64
    assert len(seen) == 1
    assert getattr(seen[0], "tainted", False) is True


def test_gateway_rejects_expired_deadline_before_delegation():
    gateway, seen, signer = _gateway()
    body = _body(_payload(deadline=(NOW - timedelta(seconds=1)).isoformat()), signer)
    status, response = gateway.handle("POST", "/v1/goals", _headers(), body)
    assert status == 408
    assert response["reason"] == "deadline_expired"
    assert seen == []


def test_gateway_rejects_oversized_payload_and_unknown_routes():
    gateway, seen, signer = _gateway()
    big = _body(_payload(), signer) + b"x" * 300_000
    status, response = gateway.handle("POST", "/v1/events", _headers(), big)
    assert status == 413
    assert response["reason"] == "payload_too_large"

    status, response = gateway.handle(
        "POST", "/v1/tasks/dispatch", _headers(), _body(_payload(), signer)
    )
    assert status == 404
    assert response["reason"] == "unknown_route"
    assert seen == []


def test_gateway_enforces_idempotency_server_side_and_ignores_cached_flag():
    gateway, seen, signer = _gateway({"decision": "ALLOW", "authorization_ref": "auth-1", "cached": True})
    body = _body(_payload(), signer)
    first_status, first = gateway.handle("POST", "/v1/events", _headers(), body)
    second_status, second = gateway.handle("POST", "/v1/events", _headers(), body)

    assert first_status == 202
    assert first["status"] == "accepted"
    assert second_status == 200
    assert second["status"] == "replayed"
    assert second["evidence_fingerprint"] == first["evidence_fingerprint"]
    assert second["authorization_ref"] == "auth-1"
    assert len(seen) == 1


def test_gateway_rejects_idempotency_key_reuse_with_a_different_envelope():
    gateway, seen, signer = _gateway()
    gateway.handle("POST", "/v1/events", _headers(), _body(_payload(), signer))
    changed = _payload(payload_digest="b" * 64)
    status, response = gateway.handle("POST", "/v1/events", _headers(), _body(changed, signer))
    assert status == 409
    assert response["reason"] == "idempotency_conflict"
    assert len(seen) == 1


def test_gateway_rejects_unknown_fields_without_delegation():
    gateway, seen, signer = _gateway()
    clean = GatewayEvent.model_validate(_payload()).model_dump(mode="json")
    signature = signer.sign_record("control-plane-envelope", clean, clean["source"])
    body = json.dumps(
        {"event": {**clean, "raw_payload": "do-not-expose"}, "signature": signature},
        separators=(",", ":"),
    ).encode("utf-8")
    status, response = gateway.handle("POST", "/v1/events", _headers(), body)
    assert status == 400
    assert response["reason"] == "invalid_request"
    assert "do-not-expose" not in json.dumps(response)
    assert seen == []
