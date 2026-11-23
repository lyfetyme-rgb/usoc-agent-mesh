"""Agent runtime.

One ``BaseAgent`` per subsystem. The runtime owns everything that is the same
for all nine, so a subsystem author only writes domain logic:

    mailbox loop -> validate -> enforce deadline/hop/budget -> handle -> reply
    retries with backoff, dead lettering, idempotency, concurrency limits

Agents collaborate through two primitives that keep the topology flat:

``delegate(recipient, ...)``  send a TaskSpec and await its TaskResult
``ask(recipient, ...)``       send a Query and await its QueryReply

Both are request/response over the bus, keyed by correlation id. No agent ever
holds a reference to another agent, so any of the nine can be restarted,
scaled or replaced without touching the others.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .bus import Bus
from .config import Settings
from .contracts import (
    GOVERNED_ACTIONS,
    ActionClass,
    Artifact,
    Classification,
    ErrorCode,
    Failure,
    Handoff,
    Message,
    Query,
    QueryReply,
    RiskLevel,
    TaskResult,
    TaskSpec,
)
from .evidence import EvidenceChain
from .governance import DecisionType, GovernanceDecision, PolicyEngine
from .llm import LLM
from .observability import Metrics, bound, log, trace
from .registry import SubsystemSpec
from .store import StateStore
from .task_ledger import TaskLedger
from .tools import ToolRegistry, ToolError


NO_LLM_CODE = "deterministic_no_llm"


class AgentError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class RetryableError(RuntimeError):
    """Raised when the work may succeed on a later attempt."""


class Outcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str
    data: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    artifacts: list[Artifact] = Field(default_factory=list)
    needs: list[str] = Field(default_factory=list, description="other subsystem ids needed to finish")


TASK_SYSTEM = """You are the {name} subsystem, one agent in a mesh of {count} cooperating agents.
Your job: {description}
Your capabilities: {capabilities}
Tools you may call: {tools}

Rules:
1. Do only your subsystem's job, at the depth the objective requires.
2. Use supplied inputs and tool results. Never invent facts, files or numbers.
3. If finishing requires another subsystem, list its id in "needs".
4. Be concise. The requester sees your summary, not your reasoning.
5. Reply with one JSON object:
   {{"summary": "...", "data": {{}}, "confidence": 0.0-1.0,
     "artifacts": [{{"name": "...", "kind": "text|json|file|url", "value": "..."}}],
     "needs": []}}
"""

QUERY_SYSTEM = """You are the {name} subsystem. Answer the question from the supplied context only.
If the context is insufficient, say what is missing. Two or three sentences.
"""


@dataclass
class Pending:
    """Correlation id -> future, for request/response over a fire-and-forget bus."""

    futures: dict[str, asyncio.Future] = field(default_factory=dict)

    def expect(self, correlation_id: str) -> asyncio.Future:
        if correlation_id in self.futures:
            raise AgentError(ErrorCode.BAD_PLAN.value, f"duplicate correlation {correlation_id}")
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self.futures[correlation_id] = future
        return future

    def resolve(self, correlation_id: str, payload: Any) -> None:
        future = self.futures.pop(correlation_id, None)
        if future is not None and not future.done():
            future.set_result(payload)
        elif future is None:
            log("agent.orphan_reply", correlation=correlation_id)

    def discard(self, correlation_id: str) -> None:
        self.futures.pop(correlation_id, None)

    def fail_all(self, exc: BaseException) -> None:
        for future in self.futures.values():
            if not future.done():
                future.set_exception(exc)
        self.futures.clear()


class BaseAgent:
    """Mailbox + policy. Subclasses override ``handle_task``/``handle_query``."""

    max_tool_rounds = 2
    # Subclasses with only deterministic handlers set this True. The card's
    # model_tier must agree; Mesh validates the pair at startup.
    deterministic = False

    def __init__(
        self,
        spec: SubsystemSpec,
        bus: Bus,
        *,
        llm: LLM,
        tools: ToolRegistry,
        settings: Settings,
        store: StateStore,
        metrics: Metrics,
        known_agents: set[str] | None = None,
        policy: PolicyEngine | None = None,
        evidence: EvidenceChain | None = None,
        approvals: Any | None = None,
        ledger: TaskLedger | None = None,
    ) -> None:
        self.spec = spec
        self.id = spec.id
        self.bus = bus
        self.llm = llm
        self.tools = tools
        self.settings = settings
        self.store = store
        self.metrics = metrics
        self.known_agents = known_agents or set()
        self.policy = policy
        self.evidence = evidence
        self.approvals = approvals
        self.ledger = ledger
        self.pending = Pending()
        self._in_flight: set[str] = set()
        self._sem = asyncio.Semaphore(settings.max_concurrency)
        self._tasks: set[asyncio.Task] = set()
        self._loop_task: asyncio.Task | None = None
        self._stopping = asyncio.Event()
        self._started_at = 0.0

    @property
    def no_llm(self) -> bool:
        """The capability card is authoritative: deterministic never calls a model."""
        return self.spec.model_tier == "deterministic"

    def _no_llm_failure(self) -> Failure:
        self.metrics.inc("llm.blocked")
        return Failure(
            code=NO_LLM_CODE,
            message=f"{self.id} is deterministic (no LLM); use its deterministic handler",
        )

    def _ledger(
        self,
        msg: Message,
        state: str,
        *,
        ok: bool | None = None,
        resolved: bool | None = None,
        latency_ms: int | None = None,
        tokens: int = 0,
        reason: str | BaseException | None = None,
    ) -> None:
        """Record one redacted lifecycle transition; telemetry never breaks work."""
        if self.ledger is None:
            return
        try:
            self.ledger.record(
                agent_id=self.id,
                state=state,
                correlation_id=msg.correlation_id,
                attempt=msg.attempt,
                ok=ok,
                resolved=resolved,
                latency_ms=latency_ms,
                tokens=tokens,
                reason=reason,
            )
        except Exception:  # pragma: no cover - observation must not change control flow
            log("ledger.record_failed", state=state)

    # -- lifecycle ----------------------------------------------------------
    async def start(self) -> None:
        await self.bus.subscribe(self.id, list(self.spec.subscribes))
        self._started_at = time.monotonic()
        self._loop_task = asyncio.create_task(self._run(), name=f"agent:{self.id}")
        log("agent.started", agent=self.id, subscribes=self.spec.subscribes)

    async def stop(self, *, grace_s: float = 5.0) -> None:
        self._stopping.set()
        if self._loop_task:
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass
        if self._tasks:
            _, pending = await asyncio.wait(self._tasks, timeout=grace_s)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
        self.pending.fail_all(AgentError(ErrorCode.HANDLER.value, "agent stopping"))
        log("agent.stopped", agent=self.id)

    @property
    def uptime_s(self) -> float:
        return round(time.monotonic() - self._started_at, 1) if self._started_at else 0.0

    async def _run(self) -> None:
        with bound(agent=self.id):
            while not self._stopping.is_set():
                try:
                    msg = await self.bus.receive(self.id, timeout=1.0)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    log("agent.receive_failed", error=str(exc))
                    await asyncio.sleep(0.2)
                    continue
                if msg is None:
                    continue
                await self._sem.acquire()
                task = asyncio.create_task(self._process(msg), name=f"{self.id}:{msg.id[:8]}")
                self._tasks.add(task)
                task.add_done_callback(self._on_done)

    def _on_done(self, task: asyncio.Task) -> None:
        self._tasks.discard(task)
        self._sem.release()
        if task.cancelled():
            return
        exc = task.exception()
        if exc:
            log("agent.task_crashed", error=repr(exc))

    # -- dispatch -----------------------------------------------------------
    async def _process(self, msg: Message) -> None:
        # Orchestrator steps carry "<trace>:<step>" correlations. Bind the trace
        # here so agent-side failures, HOLDs and tool calls are greppable by the
        # same goal id as the orchestrator's events.
        task_trace = msg.correlation_id.split(":", 1)[0] if msg.correlation_id else "-"
        with bound(agent=self.id), trace(task_trace):
            try:
                # Deadlines govern new work, not replies to work already done.
                if msg.kind in ("task", "query") and msg.expired():
                    self._ledger(msg, "deadline", ok=False, resolved=False, reason="message expired before processing")
                    await self._reject(msg, ErrorCode.DEADLINE, "message expired before processing")
                    return
                if isinstance(msg.payload, TaskSpec):
                    await self._on_task(msg, msg.payload)
                elif isinstance(msg.payload, Query):
                    await self._on_query(msg, msg.payload)
                elif isinstance(msg.payload, (TaskResult, QueryReply, Failure, Handoff)):
                    self.pending.resolve(msg.correlation_id, msg.payload)
                    await self.bus.ack(self.id, msg)
                else:
                    await self.bus.ack(self.id, msg)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # never lose a message to an unhandled error
                log("agent.dispatch_failed", error=repr(exc), kind=msg.kind)
                await self._reject(msg, ErrorCode.HANDLER, repr(exc))

    async def _on_task(self, msg: Message, spec: TaskSpec) -> None:
        # -- replay guard: drop a task already being processed in this agent --
        if msg.correlation_id in self._in_flight:
            self.metrics.inc("task.duplicate_inflight")
            self._ledger(msg, "deduplicated", ok=False, resolved=False, reason="duplicate in flight")
            await self._reject(msg, "duplicate_inflight", "task is already being processed")
            return
        self._in_flight.add(msg.correlation_id)
        try:
            await self._on_task_body(msg, spec)
        finally:
            self._in_flight.discard(msg.correlation_id)

    async def _on_task_body(self, msg: Message, spec: TaskSpec) -> None:
        # -- least-privilege: only configured senders may task this agent --
        if self.spec.allowed_senders is not None and msg.sender not in self.spec.allowed_senders and "*" not in self.spec.allowed_senders:
            self.metrics.inc("task.sender_denied")
            self._ledger(msg, "sender_denied", ok=False, resolved=False, reason="sender not permitted")
            await self._reject(msg, "sender_not_permitted", f"sender {msg.sender!r} is not permitted to task {self.id}")
            return
        # -- replay guard: a redelivery that already completed must not spend
        # the approval nonce a second time. The cache only holds results whose
        # first delivery passed the governance gate below.
        key = self._idempotency_key(msg, spec)
        if key:
            cached = await self.store.get(key)
            if cached is not None:
                self.metrics.inc("task.idempotent_hit")
                self._ledger(msg, "idempotent_hit", ok=True, resolved=True)
                await self._publish(msg.reply_with(TaskResult.model_validate(cached)))
                await self.bus.ack(self.id, msg)
                return

        # Shadow runs still leave a signed, verifiable observation of every input
        # so operators can compare mesh behaviour with the incumbent process.
        if self.settings.shadow_mode:
            await self._audit(
                "shadow.task",
                msg,
                {
                    "objective": spec.objective,
                    "action_class": spec.action_class.value,
                    "target": spec.target,
                    "shadow": True,
                },
                spec,
            )

        # -- governance gate: no consequential action without a policy ALLOW --
        decision: GovernanceDecision | None = None
        try:
            decision = await self._authorize(msg, spec)
        except Exception as exc:
            log("policy.error", error=repr(exc))
            self._ledger(msg, "failed", ok=False, resolved=False, reason=exc)
            await self._reject(msg, "policy_error", f"policy evaluation failed: {exc}")
            return
        if decision is not None:
            await self._audit(
                "policy.decision", msg, decision.model_dump(mode="json"), spec
            )
            if decision.decision is DecisionType.HOLD:
                self.metrics.inc("policy.hold")
                self._ledger(msg, "held", ok=False, resolved=False, reason="approval required")
                await self._publish(
                    msg.reply_with(
                        Handoff(
                            instruction=(
                                f"Approval required: {decision.approval_ref}. "
                                f"Approve with: python -m agents approve {decision.approval_ref}"
                            ),
                            reason="approval",
                            approval_ref=decision.approval_ref,
                        )
                    )
                )
                await self.bus.ack(self.id, msg)
                log("policy.hold", approval=decision.approval_ref, target=spec.target)
                return
            if decision.decision is DecisionType.DENY:
                self.metrics.inc("policy.denied")
                self._ledger(msg, "denied", ok=False, resolved=False, reason="; ".join(decision.reasons))
                await self._reject(msg, "policy_denied", "; ".join(decision.reasons))
                return
            # Shadow mode: keep the real policy outcome, but stop before the
            # handler. No tool, target or external sink is touched.
            if self.settings.shadow_mode and decision.allowed:
                self.metrics.inc("policy.shadow_blocked")
                self._ledger(msg, "shadow_blocked", ok=True, resolved=True)
                shadow_data = decision.model_dump(mode="json")
                shadow_data.update(
                    {
                        "shadow": True,
                        "would_have": decision.decision.value,
                        "objective": spec.objective,
                        "target": spec.target,
                    }
                )
                evidence_ref = await self._audit(
                    "shadow.decision", msg, shadow_data, spec
                )
                await self._publish(
                    msg.reply_with(
                        TaskResult(
                            ok=True,
                            output=(
                                f"shadow: would have executed {spec.action_class.value} "
                                f"on {spec.target}"
                            ),
                            data={
                                "shadow": True,
                                "would_have": decision.decision.value,
                                "action_class": spec.action_class.value,
                                "target": spec.target,
                            },
                            policy_decision_ref=decision.policy_ref,
                            authorization_ref=decision.authorization_ref,
                            evidence_ref=evidence_ref,
                        )
                    )
                )
                await self.bus.ack(self.id, msg)
                return

        started = time.perf_counter()
        self.metrics.inc("task.received")
        self._ledger(msg, "received")
        log("task.start", actor=msg.sender, objective=spec.objective, attempt=msg.attempt)
        try:
            result = await asyncio.wait_for(
                self.handle_task(spec, msg), timeout=self.settings.task_timeout_s
            )
        except (asyncio.TimeoutError, TimeoutError) as exc:
            self.metrics.inc("task.timeout")
            self._ledger(
                msg, "timed_out", ok=False, resolved=False,
                latency_ms=int((time.perf_counter() - started) * 1000), reason=exc,
            )
            await self._reject(msg, ErrorCode.TIMEOUT, f"exceeded {self.settings.task_timeout_s}s")
            return
        except RetryableError as exc:
            if msg.attempt + 1 < self.settings.max_attempts:
                # Bounded exponential backoff. Without it a broken provider turns
                # the retry budget into a tight loop against the broker.
                delay = min(
                    self.settings.retry_backoff_base_s * (2**msg.attempt),
                    self.settings.retry_backoff_max_s,
                )
                if delay > 0:
                    await asyncio.sleep(delay)
                self.metrics.inc("task.retried")
                self._ledger(msg, "retried", reason=exc)
                log("task.retry", reason=str(exc), attempt=msg.attempt + 1, backoff_s=delay)
                await self.bus.nack(self.id, msg, requeue=True)
            else:
                self.metrics.inc("task.failed")
                self._ledger(msg, "failed", ok=False, resolved=False, reason=exc)
                await self._reject(msg, ErrorCode.HANDLER, f"gave up after {msg.attempt + 1} attempts: {exc}")
            return
        except Exception as exc:
            self.metrics.inc("task.failed")
            self._ledger(msg, "failed", ok=False, resolved=False, reason=exc)
            log("task.error", error=repr(exc))
            await self._reject(msg, ErrorCode.HANDLER, f"{type(exc).__name__}: {exc}")
            return

        if not isinstance(result, TaskResult):
            # A subsystem may answer with Handoff (needs a human) or Failure.
            is_handoff = isinstance(result, Handoff)
            self.metrics.inc("task.handoff" if is_handoff else "task.failed")
            self._ledger(
                msg, "handed_off" if is_handoff else "failed",
                ok=False, resolved=False, reason="human handoff" if is_handoff else "handler failure",
            )
            await self._publish(msg.reply_with(result))
            await self.bus.ack(self.id, msg)
            return

        # Carry provenance through the mesh: this result names its producer and
        # inherits the caller's taint. Downstream steps cannot launder poisoned
        # telemetry by re-delegating under a different agent identity.
        merged = list(dict.fromkeys([*result.provenance, *spec.provenance, self.id]))
        result = result.model_copy(
            update={"provenance": merged, "tainted": result.tainted or spec.tainted}
        )

        if decision is not None and decision.authorization_ref:
            evidence_ref = await self._audit(
                "task.result",
                msg,
                {
                    "objective": spec.objective,
                    "target": spec.target,
                    "ok": result.ok,
                    "output": result.output[:2_000],
                    "policy_ref": decision.policy_ref,
                    "authorization_ref": decision.authorization_ref,
                    "provenance": decision.provenance,
                    "tainted": decision.tainted,
                },
                spec,
            )
            result = result.model_copy(
                update={
                    "policy_decision_ref": decision.policy_ref,
                    "authorization_ref": decision.authorization_ref,
                    "evidence_ref": evidence_ref,
                }
            )
        if key:
            await self.store.set(key, result.model_dump(mode="json"), ttl_s=3600)
        self.metrics.inc("task.completed")
        self._ledger(
            msg, "completed",
            ok=result.ok,
            resolved=result.ok,
            latency_ms=int((time.perf_counter() - started) * 1000),
            tokens=result.tokens_used,
            reason=None if result.ok else (result.error or "handler returned ok=False"),
        )
        log(
            "task.done",
            actor=msg.sender,
            ok=result.ok,
            ms=int((time.perf_counter() - started) * 1000),
            tokens=result.tokens_used,
        )
        await self._publish(msg.reply_with(result))
        # ACK last: on Redis a failed publish/evidence write must leave the
        # message pending for redelivery. Idempotency keys make that safe.
        await self.bus.ack(self.id, msg)

    async def _publish(self, msg: Message) -> None:
        """Runtime-side topic ACL check before the transport sees a message.

        The bus repeats this check *after* signing so it can bind the trusted
        ``signing_kid``. Here we fail early on a foreign sender if a restricted
        topic rule is configured; a worker cannot escape it by calling the bus
        directly because the bus enforces the same map on publish and receive.
        """
        rules = getattr(self.bus, "topic_rules", None)
        if rules:
            from .bus import topic_rule_denial

            detail = topic_rule_denial(msg, rules, check_kid=False)
            if detail:
                self.metrics.inc("topic.acl_denied")
                log("topic.acl_denied", sender=msg.sender, topic=msg.topic, reason=detail)
                raise PermissionError(detail)
        await self.bus.publish(msg)

    async def _authorize(self, msg: Message, spec: TaskSpec) -> GovernanceDecision | None:
        """Return a decision for consequential work, None for ordinary work."""
        # -- least-privilege: per-agent action class / target scoping --
        if self.spec.allowed_action_classes is not None and spec.action_class not in self.spec.allowed_action_classes:
            self.metrics.inc("policy.denied")
            return GovernanceDecision(
                decision=DecisionType.DENY,
                policy_ref="pol-scope",
                reasons=[f"action class {spec.action_class.value} not permitted for {self.id}"],
            )
        if self.spec.allowed_targets is not None and spec.target is not None:
            import fnmatch

            if not any(fnmatch.fnmatchcase(spec.target, p) for p in self.spec.allowed_targets):
                self.metrics.inc("policy.denied")
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref="pol-scope",
                    reasons=[f"target {spec.target!r} not permitted for {self.id}"],
                )
        # Tainted work is consequential even when its action class is not:
        # poisoned connector telemetry can seed a later mutating step.
        requires_policy = spec.action_class in GOVERNED_ACTIONS or spec.tainted
        if self.policy is None:
            # Fail closed: a missing policy engine must never let governed or
            # tainted work through. Only clean non-governed work is unaffected.
            if requires_policy:
                self.metrics.inc("policy.denied")
                return GovernanceDecision(
                    decision=DecisionType.DENY,
                    policy_ref="pol-unavailable",
                    reasons=[
                        "policy engine is not configured; governed and tainted actions are refused"
                    ],
                )
            return None
        violations = self.policy.screen_text(
            f"{spec.objective} {spec.target or ''} {spec.justification or ''}"
        )
        if violations:
            self.metrics.inc("policy.denied")
            return GovernanceDecision(
                decision=DecisionType.DENY,
                policy_ref=self.policy.policy_ref(spec.action_class, spec.target, spec.risk),
                reasons=[f"defensive-only boundary: prohibited intent ({', '.join(violations)})"],
            )
        if not requires_policy:
            return None
        try:
            return await asyncio.wait_for(
                self.policy.evaluate(
            action=spec.action_class,
            target=spec.target,
            risk=spec.risk,
            mission_id=spec.mission_id or msg.mission_id,
            classification=msg.classification,
            approval_ref=spec.approval_ref,
            requested_by=msg.sender,
            justification=spec.justification or spec.objective,
            correlation_id=msg.correlation_id,
            provenance=spec.provenance,
            tainted=spec.tainted,
            amount=spec.amount,
            currency=spec.currency,
        ),
        timeout=5.0,
    )
        except asyncio.TimeoutError:
            self.metrics.inc("policy.denied")
            return GovernanceDecision(
                decision=DecisionType.DENY,
                policy_ref=self.policy.policy_ref(spec.action_class, spec.target, spec.risk),
                reasons=["policy evaluation timed out"],
            )

    async def _audit(
        self,
        kind: str,
        msg: Message,
        data: dict[str, Any],
        spec: TaskSpec | None = None,
    ) -> str | None:
        if self.evidence is None:
            return None
        provenance = list(spec.provenance) if spec is not None else []
        # CSSSF only ever writes under sandbox/. Its results are rehearsals,
        # never production execution proof, even when the action was governed.
        rehearsal = self.id == "csssf" or (
            spec is not None and spec.action_class is ActionClass.SIMULATE
        )
        record = await self.evidence.append(
            kind=kind,
            actor=self.id,
            subsystem=self.id,
            correlation_id=msg.correlation_id,
            mission_id=msg.mission_id,
            classification=msg.classification.value,
            provenance=provenance,
            tainted=bool(spec.tainted) if spec is not None else False,
            rehearsal_only=rehearsal,
            shadow=bool(self.settings.shadow_mode),
            origin=self.id,
            data=data,
        )
        return record.id

    async def _on_query(self, msg: Message, query: Query) -> None:
        try:
            reply = await asyncio.wait_for(self.handle_query(query, msg), timeout=self.settings.task_timeout_s)
        except Exception as exc:
            await self._reject(msg, ErrorCode.HANDLER, f"query failed: {exc}")
            return
        await self._publish(msg.reply_with(reply))
        await self.bus.ack(self.id, msg)

    async def _reject(self, msg: Message, code: ErrorCode | str, detail: str) -> None:
        payload = Failure(
            code=str(code.value if isinstance(code, ErrorCode) else code),
            message=detail,
            retryable=False,
        )
        # Only work requests get a failure reply; never bounce errors off replies.
        if msg.kind in ("task", "query"):
            await self._publish(msg.reply_with(payload))
        await self.bus.ack(self.id, msg)
        log("task.rejected", code=payload.code, detail=detail)

    def _idempotency_key(self, msg: Message, spec: TaskSpec) -> str | None:
        idempotency_key = spec.idempotency_key
        # Governed actions must be idempotent: derive a stable key from the
        # message so redeliveries collapse instead of re-executing.
        if not idempotency_key and spec.action_class in GOVERNED_ACTIONS:
            idempotency_key = f"gov:{msg.correlation_id}:{spec.action_class.value}:{spec.target or ''}"
        if not idempotency_key:
            return None
        # Scope the cache to the agent, sender, tenant and mission. A shared
        # store must never let one agent or tenant replay another's result.
        material = "|".join(
            [
                self.id,
                msg.sender,
                idempotency_key,
                spec.objective,
                spec.tenant_id or msg.tenant_id or "",
                spec.mission_id or msg.mission_id or "",
                # A clean cached result must never be replayed for a tainted
                # re-dispatch of the same objective and target.
                "1" if spec.tainted else "0",
                "|".join(sorted(set(spec.provenance))),
            ]
        )
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]
        return f"task:{digest}"

    # -- domain hooks -------------------------------------------------------
    async def handle_task(self, spec: TaskSpec, msg: Message) -> TaskResult | Handoff | Failure:
        """Default implementation: one bounded LLM call with optional tool rounds."""
        if self.no_llm:
            return self._no_llm_failure()
        system = TASK_SYSTEM.format(
            name=self.spec.name,
            count=len(self.known_agents) or 9,
            description=self.spec.description,
            capabilities="; ".join(self.spec.capabilities),
            tools=json.dumps(self.tools.describe(self.spec.tools)) if self.spec.tools else "none",
        )
        tool_results: list[dict[str, Any]] = []
        tokens = 0
        budget = spec.budget_tokens or self.settings.max_tokens_per_step
        expected = Outcome.model_json_schema()

        for round_no in range(self.max_tool_rounds + 1):
            final_round = round_no == self.max_tool_rounds
            user = json.dumps(
                {
                    "objective": spec.objective,
                    "inputs": spec.inputs,
                    "expected": spec.expected,
                    "tool_results": tool_results,
                    **({"instruction": "Final answer required. Return the JSON outcome now."} if final_round else {}),
                },
                default=str,
            )
            try:
                resp = await self.llm.complete(
                    system=system,
                    messages=[{"role": "user", "content": user}],
                    json_schema=expected if final_round else None,
                    model=self.settings.model_fast if self.spec.model_tier == "fast" else self.settings.model,
                    max_tokens=min(4_000, max(512, budget - tokens)),
                )
            except Exception as exc:
                raise RetryableError(f"model call failed: {exc}") from exc

            tokens += resp.tokens
            data = resp.data or {}
            if not final_round and data.get("tool_name"):
                tool_results.append(await self._run_tool(data))
                continue
            if not final_round and not data:
                continue
            return self._to_result(resp.text, data, tokens, budget)

        return TaskResult(ok=False, error="no outcome produced", tokens_used=tokens)

    async def _run_tool(self, call: dict[str, Any]) -> dict[str, Any]:
        if self.no_llm:
            return {"tool": str(call.get("tool_name")), "error": "deterministic agents cannot call tools"}
        name = str(call.get("tool_name"))
        if name not in self.spec.tools:
            return {"tool": name, "error": "not permitted for this subsystem"}
        if self.settings.shadow_mode and name in {
            "workspace.write",
            "workspace.delete",
            "evidence.append",
        }:
            self.metrics.inc("tool.shadow_blocked")
            return {"tool": name, "error": "shadow mode: mutating tools are disabled"}
        self.metrics.inc("tool.called")
        log("tool.call", tool=name)
        try:
            value = await self.tools.call(name, call.get("arguments") or {})
            return {"tool": name, "result": value}
        except ToolError as exc:
            return {"tool": name, "error": str(exc)}

    def _to_result(self, text: str, data: dict[str, Any], tokens: int, budget: int) -> TaskResult:
        outcome: Outcome | None = None
        try:
            outcome = Outcome.model_validate(data)
        except ValidationError:
            outcome = None
        if outcome is None:
            return TaskResult(ok=True, output=text.strip()[:8_000], tokens_used=tokens)
        result = TaskResult(
            ok=True,
            output=outcome.summary[:8_000],
            data={**outcome.data, "confidence": outcome.confidence, "needs": outcome.needs},
            artifacts=outcome.artifacts,
            tokens_used=tokens,
        )
        if tokens > budget:
            result.data["budget_exceeded"] = True
            self.metrics.inc("task.budget_exceeded")
        return result

    async def handle_query(self, query: Query, msg: Message) -> QueryReply:
        if self.no_llm:
            refusal = self._no_llm_failure()
            return QueryReply(answer=refusal.message, data={"code": refusal.code})
        system = QUERY_SYSTEM.format(name=self.spec.name)
        user = json.dumps({"question": query.question, "context": query.context}, default=str)
        try:
            resp = await self.llm.complete(
                system=system,
                messages=[{"role": "user", "content": user}],
                model=self.settings.model_fast,
                max_tokens=600,
            )
        except Exception as exc:
            raise RetryableError(f"model call failed: {exc}") from exc
        return QueryReply(answer=resp.text.strip()[:4_000])

    # -- collaboration helpers ---------------------------------------------
    async def delegate(
        self,
        recipient: str,
        objective: str,
        *,
        inputs: dict[str, Any] | None = None,
        expected: str | None = None,
        timeout_s: float | None = None,
        idempotency_key: str | None = None,
        action_class: ActionClass = ActionClass.READ_ONLY,
        target: str | None = None,
        risk: RiskLevel = RiskLevel.LOW,
        approval_ref: str | None = None,
        justification: str | None = None,
        mission_id: str | None = None,
        provenance: list[str] | None = None,
        tainted: bool = False,
    ) -> TaskResult:
        self._require_known(recipient)
        self._require_delegation_allowed(recipient, action_class, target)
        msg = Message.task(
            sender=self.id,
            recipient=recipient,
            objective=objective,
            inputs=inputs,
            expected=expected,
            budget_tokens=self.settings.max_tokens_per_step,
            idempotency_key=idempotency_key,
            action_class=action_class,
            target=target,
            risk=risk,
            approval_ref=approval_ref,
            justification=justification,
            mission_id=mission_id,
            provenance=provenance,
            tainted=tainted,
        )
        payload = await self._request(msg, timeout_s)
        if isinstance(payload, Failure):
            raise AgentError(payload.code, payload.message)
        if isinstance(payload, Handoff):
            raise AgentError("handoff", payload.instruction)
        return payload

    async def ask(self, recipient: str, question: str, *, context: dict[str, Any] | None = None, timeout_s: float | None = None) -> QueryReply:
        self._require_known(recipient)
        self._require_recipient_allowed(recipient)
        msg = Message(
            sender=self.id,
            recipient=recipient,
            topic=f"inbox.{recipient}",
            payload=Query(question=question, context=context or {}),
        )
        payload = await self._request(msg, timeout_s)
        if isinstance(payload, Failure):
            raise AgentError(payload.code, payload.message)
        return payload

    async def _request(self, msg: Message, timeout_s: float | None) -> Any:
        future = self.pending.expect(msg.correlation_id)
        await self._publish(msg)
        limit = timeout_s or self.settings.task_timeout_s
        try:
            return await asyncio.wait_for(future, timeout=limit)
        except (asyncio.TimeoutError, TimeoutError) as exc:
            self.pending.discard(msg.correlation_id)
            self.metrics.inc("request.timeout")
            raise AgentError(ErrorCode.TIMEOUT.value, f"{msg.recipient} did not answer within {limit}s") from exc

    def _require_known(self, recipient: str) -> None:
        if recipient == self.id:
            raise AgentError(ErrorCode.BAD_PLAN.value, "agent cannot delegate to itself")
        if self.known_agents and recipient not in self.known_agents:
            raise AgentError(ErrorCode.NO_AGENT.value, f"unknown agent: {recipient}")

    def _require_recipient_allowed(self, recipient: str) -> None:
        if self.spec.allowed_recipients is None:
            return
        if recipient in self.spec.allowed_recipients or "*" in self.spec.allowed_recipients:
            return
        raise AgentError(
            ErrorCode.BAD_PLAN.value,
            f"recipient {recipient!r} not permitted for {self.id}",
        )

    def _require_delegation_allowed(self, recipient: str, action_class: ActionClass, target: str | None) -> None:
        self._require_recipient_allowed(recipient)
        if self.spec.allowed_action_classes is not None and action_class not in self.spec.allowed_action_classes:
            raise AgentError(
                ErrorCode.BAD_PLAN.value,
                f"action class {action_class.value} not permitted for {self.id}",
            )
        if self.spec.allowed_targets is not None and target is not None:
            import fnmatch

            if not any(fnmatch.fnmatchcase(target, p) for p in self.spec.allowed_targets):
                raise AgentError(
                    ErrorCode.BAD_PLAN.value,
                    f"target {target!r} not permitted for {self.id}",
                )

    async def emit(self, name: str, data: dict[str, Any] | None = None) -> None:
        await self._publish(Message.event(sender=self.id, name=name, data=data))


class SubsystemAgent(BaseAgent):
    """Default agent. Override methods to add deterministic domain logic."""
