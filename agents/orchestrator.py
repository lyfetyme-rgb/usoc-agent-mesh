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
"""


class PlanError(ValueError):
    pass


class Planner(Protocol):
    async def plan(self, goal: str) -> Plan: ...


def validate_plan(plan: Plan, registry: Registry) -> Plan:
    known = registry.by_id
    seen: set[str] = set()
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
        seen.add(step.id)
    if not plan.steps:
        raise PlanError("plan has no steps")
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
        deadline = datetime.now(timezone.utc) + timedelta(
            seconds=self.settings.plan_timeout_s + len(plan.steps) * self.settings.task_timeout_s
        )
        results: dict[str, TaskResult] = {}
        records: dict[str, dict[str, Any]] = {}
        done: set[str] = set()

        while len(done) < len(plan.steps):
            ready = [s for s in plan.steps if s.id not in done and set(s.depends_on) <= done]
            if not ready:
                return self._fail(plan, trace_id, started, results, "plan contains a dependency cycle")

            outcomes = await asyncio.gather(
                *(self._run_step(step, plan, results, trace_id, deadline) for step in ready),
                return_exceptions=True,
            )
            for step, outcome in zip(ready, outcomes):
                done.add(step.id)
                if isinstance(outcome, BaseException):
                    log("step.crashed", step=step.id, error=repr(outcome))
                    return self._fail(plan, trace_id, started, results, f"step {step.id} crashed: {outcome}")
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
                    "policy_decision_ref": result.policy_decision_ref,
                    "authorization_ref": result.authorization_ref,
                    "evidence_ref": result.evidence_ref,
                }
                if not result.ok:
                    return self._fail(plan, trace_id, started, results, f"step {step.id} failed: {result.error}")

        answer = await self._synthesize(plan, results)
        total_tokens = sum(r.tokens_used for r in results.values())
        elapsed = int((time.perf_counter() - started) * 1000)
        self.metrics.inc("goal.completed")
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

    async def _run_step(
        self, step: Step, plan: Plan, results: dict[str, TaskResult], trace_id: str, deadline: datetime
    ) -> tuple[TaskResult, int]:
        prior = {
            dep: {"output": results[dep].output, "data": results[dep].data}
            for dep in step.depends_on
            if dep in results
        }
        # Aggregate taint from every upstream step this one depends on. A plan
        # built from advisory output (AICEE/COHESION) keeps the provenance of the
        # telemetry that fed it, so SERAPHIM sees the real chain, not just the
        # identity of the agent that forwarded it.
        provenance = list(step.provenance)
        tainted = step.tainted
        for dep in step.depends_on:
            if dep in results:
                provenance.extend(results[dep].provenance)
                tainted = tainted or results[dep].tainted
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
            mission_id=self.mission_id,
            provenance=list(dict.fromkeys(provenance)),
            tainted=tainted,
        )
        started = time.perf_counter()
        log("step.start", step=step.id, agent=step.agent)
        payload = await self._request(msg)
        ms = int((time.perf_counter() - started) * 1000)
        if isinstance(payload, Failure):
            return TaskResult(ok=False, error=f"{payload.code}: {payload.message}"), ms
        if isinstance(payload, Handoff):
            return TaskResult(ok=False, error=f"handoff required: {payload.instruction}"), ms
        if not isinstance(payload, TaskResult):
            return TaskResult(ok=False, error=f"unexpected reply {type(payload).__name__}"), ms
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

    def _fail(
        self,
        plan: Plan,
        trace_id: str,
        started: float,
        results: dict[str, TaskResult],
        reason: str,
    ) -> GoalResult:
        self.metrics.inc("goal.failed")
        log("goal.failed", reason=reason)
        owners = {step.id: step.agent for step in plan.steps}
        completed = [
            {"id": sid, "agent": owners.get(sid, "?"), "output": result.output}
            for sid, result in results.items()
        ]
        return GoalResult(
            goal=plan.goal,
            ok=False,
            answer=reason,
            correlation_id=trace_id,
            steps=completed,
            tokens_used=sum(r.tokens_used for r in results.values()),
            elapsed_ms=int((time.perf_counter() - started) * 1000),
        )
