"""Private, authenticated control-plane gateway adapter.

This is a library boundary, not a new public HTTP authority. It enforces the
Section 6 envelope (tenant, correlation id, stable idempotency key, deadline,
provenance, taint and payload limit), verifies an Ed25519/HMAC sender binding,
and applies server-side idempotency before delegating to an injected governed
runner. It never owns a model, a bus client, a token store or an execution path.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from collections import OrderedDict
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .contracts import ActionClass, RiskLevel
from .security import canonical

MAX_PAYLOAD_BYTES = 262_144  # Section 6: reject oversized envelopes before the broker
MAX_IDEMPOTENCY_ENTRIES = 4_096
ROUTES = frozenset({"/v1/events", "/v1/goals"})
SIGNATURE_SCOPE = "control-plane-envelope"


class GatewayEvent(BaseModel):
    """Canonical control-plane envelope. Raw payload bodies are never accepted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=200)
    source: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=128)
    action_class: ActionClass
    target: str = Field(min_length=1, max_length=300)
    risk: RiskLevel
    correlation_id: str = Field(min_length=1, max_length=200)
    idempotency_key: str = Field(min_length=1, max_length=200)
    deadline: datetime
    payload_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    provenance: list[str] = Field(default_factory=list, max_length=32)
    tainted: bool = False

    @field_validator("deadline")
    @classmethod
    def _has_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("deadline must carry a timezone")
        return value


class GatewayEnvelope(BaseModel):
    """A signed event. The signature never becomes part of evidence output."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event: GatewayEvent
    signature: str = Field(default="", max_length=512)


class SignatureVerifier(Protocol):
    """HMAC or Ed25519 verifier supplied by the trust subsystem."""

    def verify_record(
        self,
        scope: str,
        body: dict[str, Any],
        signature: str | None,
        identity: str = "",
    ) -> tuple[bool, str]: ...


class _IdempotencyCache:
    """Bounded, atomic replay protection for this gateway process.

    A multi-replica deployment must inject a shared transactional store through
    ``submit``; this cache still prevents a single process from delegating the
    same envelope twice.
    """

    def __init__(self, limit: int = MAX_IDEMPOTENCY_ENTRIES) -> None:
        self._limit = limit
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, tuple[str, int, dict[str, Any]]] = OrderedDict()

    def replay_or_run(
        self,
        key: str,
        fingerprint: str,
        produce: Callable[[], tuple[int, dict[str, Any]]],
    ) -> tuple[bool, int, dict[str, Any]]:
        with self._lock:
            existing = self._entries.get(key)
            if existing is not None:
                seen_fingerprint, status, response = existing
                if not hmac.compare_digest(seen_fingerprint, fingerprint):
                    return True, 409, {"reason": "idempotency_conflict"}
                return True, 200, {**response, "status": "replayed"}
            status, response = produce()
            self._entries[key] = (fingerprint, status, response)
            self._entries.move_to_end(key)
            while len(self._entries) > self._limit:
                self._entries.popitem(last=False)
            return False, status, response


class ControlPlaneGateway:
    """Validate, authenticate and delegate without executing work itself."""

    def __init__(
        self,
        *,
        token: str,
        signature_verifier: SignatureVerifier,
        submit: Callable[[GatewayEvent], dict[str, Any]],
        now: datetime | None = None,
    ) -> None:
        if not token or len(token) < 16:
            raise ValueError("control-plane gateway token must be at least 16 characters")
        if not hasattr(signature_verifier, "verify_record"):
            raise ValueError("signature_verifier must provide verify_record")
        if not callable(submit):
            raise ValueError("submit must be a callable")
        self._token = token
        self._verifier = signature_verifier
        self._submit = submit
        self._now = now
        self._idempotency = _IdempotencyCache()

    def handle(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | str,
    ) -> tuple[int, dict[str, Any]]:
        if method.upper() != "POST" or path not in ROUTES:
            return 404, {"reason": "unknown_route"}
        authorization = str(headers.get("Authorization") or "")
        prefix = "Bearer "
        presented = authorization[len(prefix):] if authorization.startswith(prefix) else ""
        if not hmac.compare_digest(presented, self._token):
            return 401, {"reason": "unauthenticated"}

        raw = body.encode("utf-8") if isinstance(body, str) else body
        if len(raw) > MAX_PAYLOAD_BYTES:
            return 413, {"reason": "payload_too_large"}
        try:
            envelope = GatewayEnvelope.model_validate(json.loads(raw))
        except (TypeError, ValueError, json.JSONDecodeError):
            return 400, {"reason": "invalid_request"}

        event_body = envelope.event.model_dump(mode="json")
        valid, _detail = self._verifier.verify_record(
            SIGNATURE_SCOPE, event_body, envelope.signature, envelope.event.source
        )
        if not valid:
            return 401, {"reason": "invalid_signature"}

        now = self._now or datetime.now(timezone.utc)
        if envelope.event.deadline <= now:
            return 408, {"reason": "deadline_expired"}

        fingerprint = hashlib.sha256(canonical(event_body)).hexdigest()

        def produce() -> tuple[int, dict[str, Any]]:
            result = self._submit(envelope.event)
            decision = str(result.get("decision") or "DENY").upper()
            status: Literal[200, 202] = 202
            return status, {
                "status": "handoff" if decision == "HOLD" else "accepted",
                "decision": decision,
                "handoff": decision == "HOLD",
                "authorization_ref": result.get("authorization_ref"),
                "payload_digest": envelope.event.payload_digest,
                "evidence_fingerprint": fingerprint,
            }

        replayed, status, response = self._idempotency.replay_or_run(
            envelope.event.idempotency_key, fingerprint, produce
        )
        if replayed and status == 409:
            return 409, response
        return status, response
