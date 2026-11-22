"""Goal planning and execution.

The orchestrator is not an agent: it owns no domain work. It turns a goal into a
small DAG of steps, assigns each step to the subsystem whose capability card
fits, runs independent steps concurrently, feeds results forward, and returns
one answer.

Two planners:
  * ``LLMPlanner`` asks the model to produce the DAG, with the nine cards as
    the only allowed owners.
  * ``RouterPlanner`` is deterministic and offline: it splits the goal into
    clauses, scores each against capability cards, and chains the winners.

Both produce the same ``Plan`` and pass the same validator, so a bad model
output can never produce an invalid or cyclic DAG.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from pydantic import ValidationError

from .bus import Bus
from .config import Settings
from .contracts import (
    GOVERNED_ACTIONS,
    Compensation,
    ErrorCode,
    Failure,
    GoalResult,
    Handoff,
    Message,
    Plan,
    Step,
    TaskResult,
)
from .llm import EchoLLM, LLM, extract_json
from .observability import Metrics, log, new_trace, trace
from .registry import Registry, RegistryError, tokens

PLANNER_SYSTEM = """You plan work for a mesh of {count} subsystem agents.
Each step is executed by exactly one agent and its result is passed to the steps that depend on it.

Available agents (id: capabilities):
{menu}

Return one JSON object:
{{"goal": "...", "steps": [{{"id": "s1", "agent": "<id>", "objective": "...",
  "depends_on": [], "expected": "..."}}]}}

Rules:
- Use 1 to 9 steps. Only the agent ids above are allowed.
- Step ids are s1, s2, ... in execution order.
- depends_on may only reference earlier step ids. Steps with no shared dependency run in parallel.
- Each objective must be self-contained: name the exact work and what it consumes.
- Do not add steps that do not contribute to the goal. Do not plan your own summarisation step.
- action_class is one of: read_only, recommend, simulate, execute, contain.
  Use read_only for analysis and evidence. Use execute or contain only for a change to a real target,
  and then a concrete target string is mandatory. A policy gate decides whether it runs.
- A step with action_class execute or contain must include "compensate": an object with
  agent, objective, action_class, target and risk that reverses the change. Use null only
  when there is no honest undo; the goal result then reports the step as uncompensated.
  The orchestrator never invents a compensation from model prose.
- A governed step may also include "approval_ref" with the id of a human decision.
  Without one it will HOLD and the goal will fail; never invent an approval id.
- At most one governed step (execute/contain) may be ready in any wave. Add a
  dependency between governed steps so they serialize; two mutating steps may
  never run in parallel just because they look independent.
"""


class PlanError(ValueError):
    pass


class Planner(Protocol):
    async def plan(self, goal: str) -> Plan: ...


def validate_plan(plan: Plan, registry: Registry) -> Plan:
    known = registry.by_id
    seen: set[str] = set()
    # A wave is the set of steps whose dependencies are already satisfied. Track
    # the static topological layer so a plan cannot put two world-changing steps
    # in one asyncio.gather: a failure after one committed would leave split
    # state even if the other step was "probably independent".
    layer: dict[str, int] = {}
    governed_by_layer: dict[int, list[str]] = {}
    for step in plan.steps:
        if step.agent not in known:
            raise PlanError(f"step {step.id}: unknown agent {step.agent!r}")
        if step.id in seen:
            raise PlanError(f"duplicate step id {step.id}")
        unknown_deps = [d for d in step.depends_on if d not in seen]
        if unknown_deps:
            raise PlanError(f"step {step.id}: dependencies must be earlier steps, got {unknown_deps}")
        if step.action_class in GOVERNED_ACTIONS and not step.target:
            raise PlanError(f"step {step.id}: {step.action_class.value} requires an explicit target")
        level = max((layer[dep] + 1 for dep in step.depends_on), default=0)
        layer[step.id] = level
        if step.action_class in GOVERNED_ACTIONS:
            governed_by_layer.setdefault(level, []).append(step.id)
        seen.add(step.id)
    if not plan.steps:
        raise PlanError("plan has no steps")
    for level, ids in governed_by_layer.items():
        if len(ids) > 1:
            raise PlanError(
                f"wave {level} has multiple mutating steps {ids}; "
                "governed steps must be serialized with an explicit dependency"
            )
    return plan


class LLMPlanner:
    def __init__(self, llm: LLM, registry: Registry, settings: Settings) -> None:
        self.llm = llm
        self.registry = registry
        self.settings = settings

    async def plan(self, goal: str) -> Plan:
        system = PLANNER_SYSTEM.format(count=len(self.registry), menu=self.registry.menu())
        resp = await self.llm.complete(
            system=system,
            messages=[{"role": "user", "content": json.dumps({"goal": goal})}],
            json_schema=Plan.model_json_schema(),
            model=self.settings.model,
            max_tokens=2_000,
        )
        raw = resp.data or extract_json(resp.text)
        if not raw:
            raise PlanError("planner returned no JSON")
        try:
            plan = Plan.model_validate(raw)
        except ValidationError as exc:
            raise PlanError(f"planner JSON invalid: {exc}") from exc
        return validate_plan(plan, self.registry)


class RouterPlanner:
    """Deterministic fallback: clause-split, score, chain."""

    SPLIT = re.compile(r"[,;\n]+|\s+then\s+|\s+and\s+", re.IGNORECASE)

    def __init__(self, registry: Registry) -> None:
        self.registry = registry

    async def plan(self, goal: str) -> Plan:
        raw = [c.strip(" .") for c in self.SPLIT.split(goal) if c.strip(" .")]
        # "correlation between A and B" must not become two steps: fold
        # fragments with no real content back into the clause before them.
        clauses: list[str] = []
        for clause in raw:
            if clauses and len(tokens(clause)) < 2:
                clauses[-1] = f"{clauses[-1]} and {clause}"
            else:
                clauses.append(clause)
        steps: list[Step] = []
        previous: str | None = None
        for clause in clauses[:6]:
            owner = self.registry.best(clause)
            if owner is None:
                continue
            if steps and steps[-1].agent == owner.id:
                steps[-1] = steps[-1].model_copy(update={"objective": f"{steps[-1].objective}; {clause}"})
                continue
            step_id = f"s{len(steps) + 1}"
            steps.append(
                Step(
                    id=step_id,
                    agent=owner.id,
                    objective=clause,
                    depends_on=[previous] if previous else [],
                )
            )
            previous = step_id

        if not steps:
            owner = self.registry.best(goal)
            if owner is None:
                raise PlanError("no subsystem's capabilities match this goal")
            steps = [Step(id="s1", agent=owner.id, objective=goal)]

        return validate_plan(Plan(goal=goal, steps=steps), self.registry)


class Orchestrator:
    def __init__(
        self,
        bus: Bus,
        registry: Registry,
        planner: Planner,
        settings: Settings,
        metrics: Metrics,
        mission_id: str | None = None,
    ) -> None:
        self.bus = bus
        self.registry = registry
        self.planner = planner
        self.settings = settings
        self.metrics = metrics
        self.mission_id = mission_id
        self.id = "orchestrator"
        self._pending: dict[str, asyncio.Future] = {}
        self._pump_task: asyncio.Task | None = None
        self._stopping = asyncio.Event()

    async def start(self) -> None:
        await self.bus.subscribe(self.id, [])
        self._pump_task = asyncio.create_task(self._pump(), name="orchestrator:pump")

    async def stop(self) -> None:
        self._stopping.set()
        if self._pump_task:
            self._pump_task.cancel()
            try:
                await self._pump_task
            except asyncio.CancelledError:
                pass
        for future in self._pending.values():
            if not future.done():
                future.set_exception(RuntimeError("orchestrator stopping"))
        self._pending.clear()

    async def _pump(self) -> None:
        while not self._stopping.is_set():
            msg = await self.bus.receive(self.id, timeout=1.0)
            if msg is None:
                continue
            future = self._pending.pop(msg.correlation_id, None)
            if future is not None and not future.done():
                future.set_result(msg.payload)
            await self.bus.ack(self.id, msg)

    async def run(self, goal: str) -> GoalResult:
        trace_id = new_trace()
        started = time.perf_counter()
        with trace(trace_id):
            log("goal.start", goal=goal)
            try:
                plan = await asyncio.wait_for(self.planner.plan(goal), timeout=self.settings.plan_timeout_s)
            except Exception as exc:
                log("goal.plan_failed", error=str(exc))
                return GoalResult(
                    goal=goal,
                    ok=False,
                    answer=f"Could not plan this goal: {exc}",
                    correlation_id=trace_id,
                    elapsed_ms=int((time.perf_counter() - started) * 1000),
                )

            await self.bus.publish(
                Message.event(sender=self.id, name="plan.created", correlation_id=trace_id, data={"steps": len(plan.steps)})
            )
            log("goal.planned", steps=len(plan.steps), plan=[(s.id, s.agent) for s in plan.steps])
            return await self._execute(plan, trace_id, started)

    async def _execute(self, plan: Plan, trace_id: str, started: float) -> GoalResult:
        # Planners validate, but a caller can inject a Plan directly. Re-check here
        # so an untrusted or buggy planner cannot put two mutating steps in one wave.
        try:
            validate_plan(plan, self.registry)
        except PlanError as exc:
            return await self._fail(plan, trace_id, started, {}, f"invalid plan: {exc}")

        deadline = datetime.now(timezone.utc) + timedelta(
            seconds=self.settings.plan_timeout_s + len(plan.steps) * self.settings.task_timeout_s
        )
        results: dict[str, TaskResult] = {}
        records: dict[str, dict[str, Any]] = {}
        done: set[str] = set()

        while len(done) < len(plan.steps):
            ready = [s for s in plan.steps if s.id not in done and set(s.depends_on) <= done]
            if not ready:
                return await self._fail(plan, trace_id, started, results, "plan contains a dependency cycle")
            mutating = [s.id for s in ready if s.action_class in GOVERNED_ACTIONS]
            if len(mutating) > 1:
                # Defence in depth: validation above already rejects this, but a
                # plan can be mutated after planning. Refuse before any side effect.
                return await self._fail(
                    plan,
                    trace_id,
                    started,
                    results,
                    f"refusing wave with multiple mutating steps {mutating}",
                )

            outcomes = await asyncio.gather(
                *(self._run_step(step, plan, results, trace_id, deadline) for step in ready),
                return_exceptions=True,
            )
            # Record the whole wave before failing. A wave runs to completion, so
            # siblings of a failed step really did execute; hiding them would make
            # the failure report and the compensation pass both incomplete.
            for step, outcome in zip(ready, outcomes):
                done.add(step.id)
                if isinstance(outcome, BaseException):
                    log("step.crashed", step=step.id, error=repr(outcome))
                    provenance, tainted = self._taint_context(step, results)
                    results[step.id] = self._failed_result(repr(outcome), provenance, tainted)
                    record = {
                        "id": step.id,
                        "agent": step.agent,
                        "ok": False,
                        "output": "",
                        "ms": 0,
                        "tokens": 0,
                        "action_class": step.action_class.value,
                        "target": step.target,
                        "provenance": provenance,
                        "tainted": tainted,
                        "error": repr(outcome),
                    }
                    records[step.id] = record
                    continue
                result, ms = outcome
                results[step.id] = result
                records[step.id] = {
                    "id": step.id,
                    "agent": step.agent,
                    "ok": result.ok,
                    "output": result.output,
                    "ms": ms,
                    "tokens": result.tokens_used,
                    "action_class": step.action_class.value,
                    "target": step.target,
                    "approval_ref": step.approval_ref,
                    "provenance": result.provenance,
                    "tainted": result.tainted,
                    "policy_decision_ref": result.policy_decision_ref,
                    "authorization_ref": result.authorization_ref,
                    "evidence_ref": result.evidence_ref,
                    "error": result.error,
                }
            for step in ready:
                record = records[step.id]
                if not record["ok"]:
                    return await self._fail(
                        plan, trace_id, started, results,
                        f"step {step.id} failed: {record['error']}"
                    )

        answer = await self._synthesize(plan, results)
        total_tokens = sum(r.tokens_used for r in results.values())
        elapsed = int((time.perf_counter() - started) * 1000)
        self.metrics.inc("goal.completed")
        self.metrics.observe("goal.duration_ms", elapsed)
        log("goal.done", steps=len(results), tokens=total_tokens, ms=elapsed)
        await self.bus.publish(
            Message.event(
                sender=self.id,
                name="goal.completed",
                correlation_id=trace_id,
                data={"ok": True, "tokens": total_tokens, "ms": elapsed},
            )
        )
        return GoalResult(
            goal=plan.goal,
            ok=True,
            answer=answer,
            correlation_id=trace_id,
            steps=[records[s.id] for s in plan.steps if s.id in records],
            tokens_used=total_tokens,
            elapsed_ms=elapsed,
        )

    @staticmethod
    def _taint_context(
        step: Step, results: dict[str, TaskResult]
    ) -> tuple[list[str], bool]:
        """Aggregate declared and inherited taint for one step.

        Every hop keeps the full chain, so a governed step cannot launder poisoned
        telemetry by depending on a clean-looking intermediary.
        """
        provenance = list(step.provenance)
        tainted = step.tainted
        for dep in step.depends_on:
            result = results.get(dep)
            if result is None:
                continue
            provenance.extend(result.provenance)
            tainted = tainted or result.tainted
        return list(dict.fromkeys(provenance)), tainted

    @staticmethod
    def _failed_result(error: str, provenance: list[str], tainted: bool) -> TaskResult:
        """A failed hop still carries the taint of the chain that reached it."""
        return TaskResult(
            ok=False,
            error=error,
            provenance=list(provenance),
            tainted=tainted,
        )

    async def _run_step(
        self, step: Step, plan: Plan, results: dict[str, TaskResult], trace_id: str, deadline: datetime
    ) -> tuple[TaskResult, int]:
        prior = {
            dep: {"output": results[dep].output, "data": results[dep].data}
            for dep in step.depends_on
            if dep in results
        }
        provenance, tainted = self._taint_context(step, results)
        inputs = {
            "goal": plan.goal,
            "step_id": step.id,
            "step": f"{step.id} of {len(plan.steps)}",
            "prior_results": prior,
        }
        key = hashlib.sha256(f"{trace_id}|{plan.goal}|{step.id}|{step.objective}".encode()).hexdigest()[:32]
        msg = Message.task(
            sender=self.id,
            recipient=step.agent,
            objective=step.objective,
            inputs=inputs,
            expected=step.expected,
            budget_tokens=self.settings.max_tokens_per_step,
            correlation_id=f"{trace_id}:{step.id}",
            deadline=deadline,
            idempotency_key=key,
            action_class=step.action_class,
            target=step.target,
            risk=step.risk,
            approval_ref=step.approval_ref,
            mission_id=self.mission_id,
            provenance=list(dict.fromkeys(provenance)),
            tainted=tainted,
        )
        started = time.perf_counter()
        log("step.start", step=step.id, agent=step.agent)
        payload = await self._request(msg)
        ms = int((time.perf_counter() - started) * 1000)
        if isinstance(payload, Failure):
            return self._failed_result(f"{payload.code}: {payload.message}", provenance, tainted), ms
        if isinstance(payload, Handoff):
            return self._failed_result(f"handoff required: {payload.instruction}", provenance, tainted), ms
        if not isinstance(payload, TaskResult):
            return self._failed_result(f"unexpected reply {type(payload).__name__}", provenance, tainted), ms
        log("step.done", step=step.id, ok=payload.ok, ms=ms)
        return payload, ms

    async def _request(self, msg: Message) -> Any:
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[msg.correlation_id] = future
        await self.bus.publish(msg)
        try:
            return await asyncio.wait_for(future, timeout=self.settings.task_timeout_s + 5)
        except (asyncio.TimeoutError, TimeoutError):
            self._pending.pop(msg.correlation_id, None)
            self.metrics.inc("step.timeout")
            return Failure(code=ErrorCode.TIMEOUT.value, message=f"{msg.recipient} did not answer")

    async def _synthesize(self, plan: Plan, results: dict[str, TaskResult]) -> str:
        ordered = [results[s.id] for s in plan.steps if s.id in results]
        if len(ordered) == 1:
            return ordered[0].output
        if isinstance(self.planner, RouterPlanner) or not ordered:
            return "\n\n".join(f"### {step.agent}\n{result.output}" for step, result in zip(plan.steps, ordered))
        digest = json.dumps(
            [{"step": s.id, "agent": s.agent, "output": results[s.id].output} for s in plan.steps if s.id in results],
            indent=2,
        )
        llm = getattr(self.planner, "llm", None)
        if llm is None:
            return "\n\n".join(f"### {step.agent}\n{result.output}" for step, result in zip(plan.steps, ordered))
        try:
            resp = await llm.complete(
                system="Combine these subsystem results into one direct answer for the requester. "
                "Keep concrete facts, numbers and file names. Do not invent anything.",
                messages=[{"role": "user", "content": digest}],
                model=self.settings.model,
                max_tokens=1_500,
            )
            return resp.text.strip()
        except Exception as exc:
            log("goal.synthesis_failed", error=repr(exc))
            return "\n\n".join(f"### {step.agent}\n{result.output}" for step, result in zip(plan.steps, ordered))

    async def _fail(
        self,
        plan: Plan,
        trace_id: str,
        started: float,
        results: dict[str, TaskResult],
        reason: str,
    ) -> GoalResult:
        self.metrics.inc("goal.failed")
        self.metrics.observe("goal.duration_ms", int((time.perf_counter() - started) * 1000))
        log("goal.failed", reason=reason)
        owners = {step.id: step.agent for step in plan.steps}
        kinds = {
            step.id: (step.action_class.value, step.target, step.approval_ref)
            for step in plan.steps
        }
        completed = []
        for sid, result in results.items():
            action_class, target, approval_ref = kinds.get(sid, ("?", None, None))
            completed.append(
                {
                    "id": sid,
                    "agent": owners.get(sid, "?"),
                    "ok": result.ok,
                    "output": result.output,
                    "tokens": result.tokens_used,
                    "action_class": action_class,
                    "target": target,
                    "approval_ref": approval_ref,
                    "provenance": result.provenance,
                    "tainted": result.tainted,
                    "policy_decision_ref": result.policy_decision_ref,
                    "authorization_ref": result.authorization_ref,
                    "evidence_ref": result.evidence_ref,
                    "error": result.error,
                }
            )
        compensations, uncompensated = await self._compensate(plan, trace_id, results)
        await self.bus.publish(
            Message.event(
                sender=self.id,
                name="goal.failed",
                correlation_id=trace_id,
                data={
                    "reason": reason,
                    "steps": len(completed),
                    "compensations": len(compensations),
                    "uncompensated": uncompensated,
                },
            )
        )
        if compensations:
            await self.bus.publish(
                Message.event(
                    sender=self.id,
                    name="goal.compensated",
                    correlation_id=trace_id,
                    data={"records": compensations},
                )
            )
        return GoalResult(
            goal=plan.goal,
            ok=False,
            answer=reason,
            correlation_id=trace_id,
            steps=completed,
            compensations=compensations,
            uncompensated=uncompensated,
            tokens_used=sum(r.tokens_used for r in results.values()),
            elapsed_ms=int((time.perf_counter() - started) * 1000),
        )

    async def _compensate(
        self, plan: Plan, trace_id: str, results: dict[str, TaskResult]
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Undo successfully completed governed steps, newest first.

        Only steps that actually changed the world are candidates, and only if
        they declared an undo. Compensation is dispatched as an ordinary task so
        the runtime policy gate, human approvals and evidence chain all apply.
        """
        records: list[dict[str, Any]] = []
        uncompensated: list[str] = []
        for step in reversed(plan.steps):
            result = results.get(step.id)
            if result is None or not result.ok or step.action_class not in GOVERNED_ACTIONS:
                continue
            if step.compensate is None:
                uncompensated.append(step.id)
                continue
            records.append(await self._run_compensation(step, step.compensate, result, trace_id))
        return records, uncompensated

    async def _run_compensation(
        self,
        step: Step,
        comp: Compensation,
        source: TaskResult,
        trace_id: str,
    ) -> dict[str, Any]:
        key = hashlib.sha256(
            f"{trace_id}|{step.id}|compensate|{comp.objective}".encode()
        ).hexdigest()[:32]
        msg = Message.task(
            sender=self.id,
            recipient=comp.agent,
            objective=comp.objective,
            inputs={
                "goal": "compensate a failed goal",
                "step_id": step.id,
                "compensating_for": step.objective,
                "prior_output": source.output[:2_000],
            },
            expected="Reverse the original action and report exactly what was undone.",
            budget_tokens=self.settings.max_tokens_per_step,
            correlation_id=f"{trace_id}:comp:{step.id}",
            deadline=datetime.now(timezone.utc)
            + timedelta(seconds=self.settings.task_timeout_s),
            idempotency_key=key,
            action_class=comp.action_class,
            target=comp.target,
            risk=comp.risk,
            approval_ref=comp.approval_ref,
            mission_id=self.mission_id,
            provenance=list(source.provenance),
            tainted=source.tainted,
            justification=f"Compensation for failed goal after step {step.id}",
        )
        base: dict[str, Any] = {
            "step": step.id,
            "agent": comp.agent,
            "action_class": comp.action_class.value,
            "target": comp.target,
            "approval_ref": comp.approval_ref,
        }
        log("compensation.start", step=step.id, agent=comp.agent)
        try:
            payload = await self._request(msg)
        except Exception as exc:  # a failed undo must be reported, not raised out of _fail
            payload = Failure(code=ErrorCode.HANDLER.value, message=repr(exc))

        if isinstance(payload, Handoff):
            base.update(
                status="hold",
                approval_ref=payload.approval_ref or comp.approval_ref,
                detail=payload.instruction,
            )
        elif isinstance(payload, Failure):
            denied = {
                "policy_denied",
                "policy_error",
                "sender_not_permitted",
                ErrorCode.DEADLINE.value,
            }
            base.update(
                status="denied" if payload.code in denied else "failed",
                detail=f"{payload.code}: {payload.message}",
            )
        elif isinstance(payload, TaskResult):
            if payload.ok:
                base.update(
                    status="done",
                    detail=payload.output,
                    policy_decision_ref=payload.policy_decision_ref,
                    authorization_ref=payload.authorization_ref,
                    evidence_ref=payload.evidence_ref,
                )
            else:
                base.update(status="failed", detail=payload.error or payload.output)
        else:
            base.update(status="failed", detail=f"unexpected reply {type(payload).__name__}")
        self.metrics.inc(f"compensation.{base['status']}")
        log("compensation.result", step=step.id, status=base["status"])
        return base
