"""Strict edge ingress and bounded quarantine.

Malformed or unauthorised input is rejected here, before the orchestrator, a
coordinator or a model ever sees it. The quarantine stores only a code and a
16-hex fingerprint of the validation error -- never the offending value, which
may contain secrets or PHI. Every accepted task receives a deterministic
idempotency key so a network retry maps to one logical unit of work.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable

from .config import Settings
from .contracts import Message, TaskSpec
from .resilience import deterministic_idempotency_key
from .task_ledger import reason_fingerprint


class IngressQuarantine:
    """Bounded, redacted record of rejected edge input."""

    def __init__(self, *, capacity: int = 256, clock: Callable[[], float] = time.monotonic) -> None:
        if capacity < 1:
            raise ValueError("capacity must be positive")
        self.capacity = capacity
        self._clock = clock
        self._records: deque[dict[str, Any]] = deque()
        self._total = 0

    def add(self, *, code: str, error: BaseException | str, tenant_id: str) -> None:
        self._total += 1
        record = {
            "code": code,
            "fingerprint": reason_fingerprint(error),
            "tenant_id": tenant_id[:64] or "default",
            "ts": self._clock(),
        }
        if len(self._records) >= self.capacity:
            self._records.popleft()
        self._records.append(record)

    def snapshot(self) -> dict[str, Any]:
        return {
            "quarantined": self._total,
            "retained": len(self._records),
            "dropped": self._total - len(self._records),
            "capacity": self.capacity,
            "recent": [dict(record) for record in self._records],
        }


@dataclass(frozen=True)
class IngestResult:
    accepted: Message | None
    quarantined: bool
    tenant_id: str
    code: str | None = None
    fingerprint: str | None = None


@dataclass(frozen=True)
class GoalIngestResult:
    """Normalised goal request carrying its deterministic execution token."""

    goal: str
    tenant_id: str
    idempotency_key: str
    digest: str
    quarantined: bool = False
    code: str | None = None
    fingerprint: str | None = None


def _goal_digest(tenant_id: str, goal: str) -> str:
    canonical = json.dumps([tenant_id, goal], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _payload_digest(payload: TaskSpec) -> str:
    canonical = json.dumps(
        payload.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class IngressGate:
    """Validate and normalise raw input into a governed ``Message``."""

    MAX_GOAL_CHARS = 8_192

    def __init__(
        self,
        *,
        quarantine: IngressQuarantine | None = None,
        require_tenant: bool = False,
        secret: str = "",
        max_goal_chars: int = MAX_GOAL_CHARS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.quarantine = quarantine or IngressQuarantine(clock=clock)
        self.require_tenant = require_tenant
        self.secret = secret
        self.max_goal_chars = max_goal_chars
        self.clock = clock

    def _reject(self, raw: Any, *, code: str, error: BaseException | str, tenant_id: str) -> IngestResult:
        self.quarantine.add(code=code, error=error, tenant_id=tenant_id)
        return IngestResult(
            accepted=None,
            quarantined=True,
            tenant_id=tenant_id or "default",
            code=code,
            fingerprint=reason_fingerprint(error),
        )

    def accept(self, raw: dict[str, Any]) -> IngestResult:
        tenant = str(raw.get("tenant_id") or "default")[:64]
        try:
            message = Message.model_validate(raw)
        except Exception as exc:
            return self._reject(raw, code="schema_invalid", error=exc, tenant_id=tenant)

        tenant = message.tenant_id or "default"
        if self.require_tenant and not message.tenant_id:
            return self._reject(
                raw, code="tenant_required", error="tenant_id is required", tenant_id=tenant
            )

        if isinstance(message.payload, TaskSpec) and not message.payload.idempotency_key:
            key = deterministic_idempotency_key(
                tenant_id=tenant,
                correlation_id=message.correlation_id,
                agent_id=message.recipient or "mesh",
                action=message.payload.action_class.value,
                payload_digest=_payload_digest(message.payload),
                secret=self.secret,
            )
            payload = message.payload.model_copy(update={"idempotency_key": key})
            message = message.model_copy(update={"payload": payload})

        return IngestResult(accepted=message, quarantined=False, tenant_id=tenant)

    def accept_goal(
        self,
        goal: str,
        *,
        tenant_id: str = "default",
        idempotency_key: str | None = None,
    ) -> GoalIngestResult:
        """Validate a mesh goal and bind it to one tenant-scoped work token.

        Raw goal text is never stored in the quarantine or the ledger. Only the
        deterministic HMAC token and a digest of ``(tenant, goal)`` leave this
        method, so a replay is provably the same logical request.
        """
        tenant = str(tenant_id or "default")[:64] or "default"

        def reject(error: str | BaseException, code: str = "schema_invalid") -> GoalIngestResult:
            self.quarantine.add(code=code, error=error, tenant_id=tenant)
            return GoalIngestResult(
                goal="",
                tenant_id=tenant,
                idempotency_key="",
                digest="",
                quarantined=True,
                code=code,
                fingerprint=reason_fingerprint(error),
            )

        if not isinstance(goal, str):
            return reject("goal must be a string")
        cleaned = goal.strip()
        if not cleaned or len(cleaned) > self.max_goal_chars:
            return reject(f"goal must be 1-{self.max_goal_chars} characters")
        if self.require_tenant and not tenant_id:
            return reject("tenant_id is required", code="tenant_required")

        digest = _goal_digest(tenant, cleaned)
        if idempotency_key:
            key = str(idempotency_key)[:200]
        else:
            key = deterministic_idempotency_key(
                tenant_id=tenant,
                correlation_id="",
                agent_id="mesh",
                action="goal",
                payload_digest=digest,
                secret=self.secret,
            )
        return GoalIngestResult(
            goal=cleaned, tenant_id=tenant, idempotency_key=key, digest=digest
        )


def gate_from_settings(settings: Settings, **overrides: Any) -> IngressGate:
    """Build a gate from deployment settings; explicit overrides win."""
    options: dict[str, Any] = {
        "require_tenant": settings.ingress_require_tenant,
        "secret": settings.shared_secret or "",
        "quarantine": IngressQuarantine(capacity=settings.ingress_quarantine_max),
    }
    options.update(overrides)
    return IngressGate(**options)
