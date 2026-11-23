"""Task-aware runtime state: a bounded, redacted lifecycle ledger.

Counters answer "how many"; traces answer "where did this one go". The ledger
answers the operational middle question: "which tasks are still unresolved, at
which hop, after how many attempts". It is observation-only -- it has no handle
on policy, approvals, the bus or the evidence chain, so it cannot change an
execution decision or authorize a live nonce.

Privacy is structural rather than conventional:

* no goal, objective, output or error text is accepted (``extra="forbid"``);
* failure reasons are reduced to 16-hex digests of redacted text;
* only opaque trace/step/agent identifiers are retained;
* entries are evicted by count and by TTL, and eviction counters are exported.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections import Counter, deque
from typing import Any, Callable, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .security import redact_text

TaskState = Literal[
    "received",
    "retried",
    "completed",
    "idempotent_hit",
    "shadow_blocked",
    "timed_out",
    "failed",
    "denied",
    "held",
    "handed_off",
    "deduplicated",
    "deadline",
    "sender_denied",
    "goal_accepted",
    "goal_planned",
    "goal_completed",
    "goal_failed",
]

Resolved: dict[str, bool | None] = {
    "completed": True,
    "idempotent_hit": True,
    "shadow_blocked": True,
    "goal_completed": True,
    "failed": False,
    "timed_out": False,
    "denied": False,
    "held": False,
    "handed_off": False,
    "deduplicated": False,
    "deadline": False,
    "sender_denied": False,
    "goal_failed": False,
    "received": None,
    "retried": None,
    "goal_accepted": None,
    "goal_planned": None,
}

Successful: dict[str, bool | None] = {
    "completed": True,
    "idempotent_hit": True,
    "shadow_blocked": True,
    "goal_completed": True,
    "failed": False,
    "timed_out": False,
    "denied": False,
    "held": False,
    "handed_off": False,
    "deduplicated": False,
    "deadline": False,
    "sender_denied": False,
    "goal_failed": False,
    "received": None,
    "retried": None,
    "goal_accepted": None,
    "goal_planned": None,
}


def reason_fingerprint(value: Any) -> str:
    """Stable 16-hex group key for a failure reason, with redaction first."""
    text = value if isinstance(value, str) else repr(value)
    return hashlib.sha256(redact_text(text).encode("utf-8")).hexdigest()[:16]


class TaskEvent(BaseModel):
    """One redacted lifecycle transition. Extra fields are refused outright."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str
    trace_id: str
    agent_id: str
    step_id: str | None = None
    state: TaskState
    attempt: int = Field(default=0, ge=0)
    ok: bool | None = None
    resolved: bool | None = None
    latency_ms: int | None = Field(default=None, ge=0)
    tokens: int = Field(default=0, ge=0)
    reason_fingerprint: str | None = None
    ts: float

    @field_validator("trace_id", "agent_id")
    @classmethod
    def _bounded_id(cls, value: str) -> str:
        if not value or len(value) > 64:
            raise ValueError("identifiers must be 1-64 characters")
        return value

    @field_validator("step_id")
    @classmethod
    def _bounded_step(cls, value: str | None) -> str | None:
        if value is not None and len(value) > 64:
            raise ValueError("step_id must be at most 64 characters")
        return value

    @field_validator("reason_fingerprint")
    @classmethod
    def _opaque_fingerprint(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[0-9a-f]{16}", value):
            raise ValueError("reason_fingerprint must be a 16-character hex digest")
        return value


class TaskLedger:
    """Bounded, TTL-swept, observation-only lifecycle ledger."""

    def __init__(
        self,
        *,
        max_events: int = 2048,
        ttl_s: float = 3600.0,
        recent_limit: int = 20,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_events < 1:
            raise ValueError("max_events must be positive")
        if ttl_s <= 0:
            raise ValueError("ttl_s must be positive")
        if recent_limit < 0:
            raise ValueError("recent_limit must be non-negative")
        self.max_events = max_events
        self.ttl_s = ttl_s
        self.recent_limit = recent_limit
        self._clock = clock
        self._events: deque[TaskEvent] = deque()
        self._seq = 0
        self._dropped = 0
        self._expired = 0
        self._started = clock()

    def record(
        self,
        *,
        agent_id: str,
        state: str,
        correlation_id: str = "",
        step_id: str | None = None,
        attempt: int = 0,
        ok: bool | None = None,
        resolved: bool | None = None,
        latency_ms: int | None = None,
        tokens: int = 0,
        reason: str | BaseException | None = None,
    ) -> TaskEvent:
        """Append one transition. Raw reason text is hashed, never retained."""
        if state not in get_args(TaskState):
            raise ValueError(f"unsupported task state: {state!r}")
        self._sweep()
        trace = correlation_id.split(":", 1)[0] if correlation_id else "-"
        step = step_id or (correlation_id.split(":", 1)[1] if ":" in correlation_id else None)
        fingerprint = None
        if reason is not None:
            fingerprint = (
                reason_fingerprint(reason)
                if isinstance(reason, str)
                else reason_fingerprint(f"{type(reason).__name__}:{reason}")
            )
        self._seq += 1
        event = TaskEvent(
            event_id=f"evt-{self._seq}",
            trace_id=trace[:64] or "-",
            agent_id=agent_id[:64] or "-",
            step_id=step[:64] if step else None,
            state=state,  # type: ignore[arg-type]
            attempt=max(0, int(attempt)),
            ok=Successful.get(state) if ok is None else ok,
            resolved=Resolved.get(state) if resolved is None else resolved,
            latency_ms=max(0, int(latency_ms)) if latency_ms is not None else None,
            tokens=max(0, int(tokens)),
            reason_fingerprint=fingerprint,
            ts=self._clock(),
        )
        if len(self._events) >= self.max_events:
            self._events.popleft()
            self._dropped += 1
        self._events.append(event)
        return event

    def _sweep(self) -> None:
        cutoff = self._clock() - self.ttl_s
        before = len(self._events)
        while self._events and self._events[0].ts < cutoff:
            self._events.popleft()
        self._expired += before - len(self._events)

    def counts(self) -> dict[str, int]:
        """Counts only: safe for public liveness/readiness payloads."""
        self._sweep()
        terminal = [event for event in self._events if event.resolved is not None]
        return {
            "tasks_tracked": len(self._events),
            "tasks_resolved": sum(1 for event in terminal if event.resolved),
            "tasks_unresolved": sum(1 for event in terminal if not event.resolved),
        }

    def snapshot(self) -> dict[str, Any]:
        """Full redacted view for admin diagnostics and CLI inspection."""
        counts = self.counts()
        events = list(self._events)
        return {
            "uptime_s": round(self._clock() - self._started, 1),
            "capacity": self.max_events,
            "ttl_s": self.ttl_s,
            "retained": len(events),
            "dropped": self._dropped,
            "expired": self._expired,
            "states": dict(sorted(Counter(event.state for event in events).items())),
            "by_agent": dict(sorted(Counter(event.agent_id for event in events).items())),
            **counts,
            "resolved": counts["tasks_resolved"],
            "unresolved": counts["tasks_unresolved"],
            "resolution_rate": (
                round(counts["tasks_resolved"] / (counts["tasks_resolved"] + counts["tasks_unresolved"]), 4)
                if counts["tasks_resolved"] + counts["tasks_unresolved"]
                else 0.0
            ),
            "recent": [event.model_dump() for event in events[-self.recent_limit :]],
        }
