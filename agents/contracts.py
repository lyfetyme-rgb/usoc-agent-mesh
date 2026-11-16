"""Wire contracts for the mesh.

Everything an agent sends or receives is a ``Message``. The payload is a
discriminated union, so a message is validated end to end the moment it is
deserialised - there is no "dict with a kind field" escaping into agent code.

Invariants enforced here:
  * ``kind`` is derived from the payload, never stored twice
  * every message belongs to a ``correlation_id`` (one goal = one correlation)
  * ``hop`` counts agent-to-agent delegations and is capped to stop A->B->A loops
  * payloads are capped so a runaway prompt cannot wedge the broker
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Literal, Union
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA_VERSION = "1.0"
MAX_HOPS = 8
MAX_PAYLOAD_BYTES = 256 * 1024


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return uuid4().hex


class Strict(BaseModel):
    """Reject unknown fields: contracts fail loudly instead of silently degrading."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ActionClass(str, Enum):
    """How consequential a task is. Drives the governance gate."""

    READ_ONLY = "read_only"
    RECOMMEND = "recommend"
    SIMULATE = "simulate"
    EXECUTE = "execute"
    CONTAIN = "contain"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Classification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


GOVERNED_ACTIONS = frozenset({ActionClass.EXECUTE, ActionClass.CONTAIN})


class TaskSpec(Strict):
    """Do this work. ``inputs`` is intentionally open; typed payloads go in ``data``."""

    kind: Literal["task"] = "task"
    objective: str = Field(min_length=1, max_length=20_000)
    inputs: dict[str, Any] = Field(default_factory=dict)
    expected: str | None = Field(default=None, max_length=4_000)
    budget_tokens: int | None = Field(default=None, ge=1_000)
    idempotency_key: str | None = Field(default=None, max_length=200)
    action_class: ActionClass = ActionClass.READ_ONLY
    target: str | None = Field(default=None, max_length=300)
    risk: RiskLevel = RiskLevel.LOW
    approval_ref: str | None = Field(default=None, max_length=100)
    justification: str | None = Field(default=None, max_length=2_000)
    mission_id: str | None = Field(default=None, max_length=100)
    tenant_id: str | None = Field(default=None, max_length=100)
    # Provenance/taint tracking: which upstream subsystems contributed data and
    # whether any of it came from an untrusted source (telemetry, vendor payloads).
    provenance: list[str] = Field(default_factory=list, max_length=32)
    tainted: bool = False


class Artifact(Strict):
    name: str
    kind: Literal["text", "json", "file", "url"] = "text"
    value: str


class TaskResult(Strict):
    kind: Literal["result"] = "result"
    ok: bool
    output: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    artifacts: list[Artifact] = Field(default_factory=list)
    tokens_used: int = 0
    error: str | None = None
    policy_decision_ref: str | None = None
    authorization_ref: str | None = None
    evidence_ref: str | None = None
    # Provenance flows with the result so downstream steps inherit taint.
    provenance: list[str] = Field(default_factory=list)
    tainted: bool = False


class Query(Strict):
    """A cheap side question; expects a ``QueryReply`` on the same correlation."""

    kind: Literal["query"] = "query"
    question: str = Field(min_length=1, max_length=8_000)
    context: dict[str, Any] = Field(default_factory=dict)


class QueryReply(Strict):
    kind: Literal["reply"] = "reply"
    answer: str
    data: dict[str, Any] = Field(default_factory=dict)


class Event(Strict):
    """Fire and forget. Nothing awaits an event."""

    kind: Literal["event"] = "event"
    name: str = Field(min_length=1, max_length=200)
    data: dict[str, Any] = Field(default_factory=dict)


class Failure(Strict):
    kind: Literal["error"] = "error"
    code: str
    message: str
    retryable: bool = False


class Handoff(Strict):
    """The agent cannot proceed without a human."""

    kind: Literal["handoff"] = "handoff"
    instruction: str
    reason: Literal["auth", "approval", "judgement", "missing_info"] = "judgement"


Payload = Annotated[
    Union[TaskSpec, TaskResult, Query, QueryReply, Event, Failure, Handoff],
    Field(discriminator="kind"),
]

PayloadKind = Literal["task", "result", "query", "reply", "event", "error", "handoff"]


class Message(Strict):
    id: str = Field(default_factory=_uuid)
    correlation_id: str = Field(default_factory=_uuid)
    causation_id: str | None = None
    sender: str = Field(max_length=128)
    recipient: str | None = Field(default=None, max_length=128)
    topic: str = Field(max_length=256)
    payload: Payload
    schema_version: str = SCHEMA_VERSION
    hop: int = Field(default=0, ge=0)
    attempt: int = Field(default=0, ge=0)
    deadline: datetime | None = None
    created_at: datetime = Field(default_factory=_now)
    # USOC governance envelope fields (section 15 of the master prompt)
    mission_id: str | None = Field(default=None, max_length=100)
    tenant_id: str | None = Field(default=None, max_length=100)
    classification: Classification = Classification.INTERNAL
    policy_decision_ref: str | None = Field(default=None, max_length=100)
    authorization_ref: str | None = Field(default=None, max_length=100)
    evidence_ref: str | None = Field(default=None, max_length=100)
    # HMAC-SHA256 over the canonical message, keyed by sender. Set by the bus.
    signature: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def _enforce_limits(self) -> "Message":
        if self.hop > MAX_HOPS:
            raise ValueError(f"hop limit exceeded ({self.hop} > {MAX_HOPS})")
        size = len(json.dumps(self.payload.model_dump(mode="json")).encode("utf-8"))
        if size > MAX_PAYLOAD_BYTES:
            raise ValueError(f"payload too large ({size} > {MAX_PAYLOAD_BYTES} bytes)")
        return self

    # -- derived views ------------------------------------------------------
    @property
    def kind(self) -> str:
        return self.payload.kind

    def expired(self, now: datetime | None = None) -> bool:
        return self.deadline is not None and (now or _now()) >= self.deadline

    def summary(self, limit: int = 90) -> str:
        p = self.payload
        if isinstance(p, TaskSpec):
            text = p.objective
        elif isinstance(p, TaskResult):
            text = p.error or p.output
        elif isinstance(p, Query):
            text = p.question
        elif isinstance(p, QueryReply):
            text = p.answer
        elif isinstance(p, Event):
            text = p.name
        elif isinstance(p, Failure):
            text = f"{p.code}: {p.message}"
        else:
            text = p.instruction
        text = " ".join(text.split())
        return text if len(text) <= limit else text[: limit - 3] + "..."

    # -- constructors -------------------------------------------------------
    @classmethod
    def task(
        cls,
        *,
        sender: str,
        recipient: str,
        objective: str,
        inputs: dict[str, Any] | None = None,
        expected: str | None = None,
        budget_tokens: int | None = None,
        correlation_id: str | None = None,
        deadline: datetime | None = None,
        idempotency_key: str | None = None,
        action_class: ActionClass = ActionClass.READ_ONLY,
        target: str | None = None,
        risk: RiskLevel = RiskLevel.LOW,
        approval_ref: str | None = None,
        justification: str | None = None,
        mission_id: str | None = None,
        tenant_id: str | None = None,
        classification: Classification = Classification.INTERNAL,
        provenance: list[str] | None = None,
        tainted: bool = False,
    ) -> "Message":
        return cls(
            correlation_id=correlation_id or _uuid(),
            sender=sender,
            recipient=recipient,
            topic=f"inbox.{recipient}",
            deadline=deadline,
            mission_id=mission_id,
            tenant_id=tenant_id,
            classification=classification,
            payload=TaskSpec(
                objective=objective,
                inputs=inputs or {},
                expected=expected,
                budget_tokens=budget_tokens,
                idempotency_key=idempotency_key,
                action_class=action_class,
                target=target,
                risk=risk,
                approval_ref=approval_ref,
                justification=justification,
                mission_id=mission_id,
                tenant_id=tenant_id,
                provenance=provenance or [],
                tainted=tainted,
            ),
        )

    @classmethod
    def event(cls, *, sender: str, name: str, data: dict[str, Any] | None = None, topic: str | None = None, correlation_id: str | None = None) -> "Message":
        topic = topic or f"topic.{name.split('.')[0]}"
        return cls(
            correlation_id=correlation_id or _uuid(),
            sender=sender,
            topic=topic,
            payload=Event(name=name, data=data or {}),
        )

    def reply_with(self, payload: Payload, *, topic: str | None = None, hop: int | None = None) -> "Message":
        """Address a payload back to this message's sender on the same correlation."""
        return Message(
            correlation_id=self.correlation_id,
            causation_id=self.id,
            sender=self.recipient or self.sender,
            recipient=self.sender,
            topic=topic or f"inbox.{self.sender}",
            hop=self.hop if hop is None else hop,
            deadline=self.deadline,
            mission_id=self.mission_id,
            tenant_id=self.tenant_id,
            classification=self.classification,
            policy_decision_ref=self.policy_decision_ref,
            authorization_ref=self.authorization_ref,
            evidence_ref=self.evidence_ref,
            payload=payload,
        )

    def child(self, *, sender: str, recipient: str, payload: Payload, topic: str | None = None) -> "Message":
        """Delegate onward. Increments the hop counter so loops cannot nest forever."""
        return Message(
            correlation_id=self.correlation_id,
            causation_id=self.id,
            sender=sender,
            recipient=recipient,
            topic=topic or f"inbox.{recipient}",
            hop=self.hop + 1,
            deadline=self.deadline,
            mission_id=self.mission_id,
            tenant_id=self.tenant_id,
            classification=self.classification,
            policy_decision_ref=self.policy_decision_ref,
            authorization_ref=self.authorization_ref,
            evidence_ref=self.evidence_ref,
            payload=payload,
        )


class Step(BaseModel):
    """One unit of delegated work inside a plan."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9_]{1,40}$")
    agent: str
    objective: str = Field(min_length=1, max_length=8_000)
    depends_on: list[str] = Field(default_factory=list)
    expected: str | None = None
    action_class: ActionClass = ActionClass.READ_ONLY
    target: str | None = None
    risk: RiskLevel = RiskLevel.LOW
    provenance: list[str] = Field(default_factory=list)
    tainted: bool = False


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    goal: str
    steps: list[Step] = Field(min_length=1, max_length=12)


class GoalResult(BaseModel):
    goal: str
    ok: bool
    answer: str
    correlation_id: str
    steps: list[dict[str, Any]] = Field(default_factory=list)
    tokens_used: int = 0
    elapsed_ms: int = 0


class ErrorCode(str, Enum):
    TIMEOUT = "timeout"
    DEADLINE = "deadline"
    HOP_LIMIT = "hop_limit"
    NO_AGENT = "no_agent"
    BAD_PLAN = "bad_plan"
    BUDGET = "budget"
    HANDLER = "handler"
