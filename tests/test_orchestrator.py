from __future__ import annotations

import asyncio
import json
import time

import pytest

from agents.contracts import Plan, Step
from agents.llm import EchoLLM, LLMResponse
from agents.mesh import Mesh
from agents.orchestrator import LLMPlanner, PlanError, RouterPlanner, validate_plan

GOAL = (
    "Collect edge telemetry from the cluster, analyse anomalies in the workload data, "
    "evaluate the policy for a containment action, then record the evidence."
)


class FakeLLM:
    """Returns a canned JSON body as if the model had answered."""

    model = "fake"
    is_offline = False

    def __init__(self, body: dict) -> None:
        self.body = body
        self.calls = 0

    async def complete(self, *, system, messages, json_schema=None, model=None, max_tokens=None):
        self.calls += 1
        return LLMResponse(text=json.dumps(self.body), data=self.body, tokens=3, model="fake")

    async def close(self) -> None:
        return None


class SlowLLM:
    """Echo model with latency, to prove independent steps run in parallel."""

    model = "slow"

    def __init__(self, delay: float = 0.25) -> None:
        self.delay = delay
        self.inner = EchoLLM()

    async def complete(self, **kwargs):
        await asyncio.sleep(self.delay)
        return await self.inner.complete(**kwargs)

    async def close(self) -> None:
        return None


class StaticPlanner:
    def __init__(self, plan: Plan) -> None:
        self.plan_ = plan

    async def plan(self, goal: str) -> Plan:
        return self.plan_


async def test_router_plan_chains_the_right_owners(registry):
    plan = await RouterPlanner(registry).plan(GOAL)
    assert [step.agent for step in plan.steps] == ["acie", "aicee", "seraphim", "oekp"]
    assert plan.steps[0].depends_on == []
    assert plan.steps[-1].depends_on == [plan.steps[-2].id]
    assert len({step.id for step in plan.steps}) == len(plan.steps)


async def test_router_splits_and_clauses_across_agents(registry):
    plan = await RouterPlanner(registry).plan("record the evidence and route the approval to a human reviewer")
    assert [step.agent for step in plan.steps] == ["oekp", "hitl"]
    assert plan.steps[1].depends_on == ["s1"]


async def test_router_does_not_split_short_conjunctions(registry):
    plan = await RouterPlanner(registry).plan("analyse the correlation between cpu pressure and latency")
    assert len(plan.steps) == 1
    assert plan.steps[0].agent == "aicee"


async def test_router_plan_fails_cleanly_when_nothing_matches(registry):
    with pytest.raises(PlanError):
        await RouterPlanner(registry).plan("xyzzy plugh")


async def test_llm_planner_accepts_a_valid_plan(registry, settings):
    body = {
        "goal": "g",
        "steps": [
            {"id": "s1", "agent": "aicee", "objective": "analyse", "depends_on": []},
            {"id": "s2", "agent": "oekp", "objective": "record", "depends_on": ["s1"]},
        ],
    }
    plan = await LLMPlanner(FakeLLM(body), registry, settings).plan("g")
    assert [s.agent for s in plan.steps] == ["aicee", "oekp"]


@pytest.mark.parametrize(
    "steps",
    [
        [{"id": "s1", "agent": "ghost", "objective": "x", "depends_on": []}],
        [{"id": "s1", "agent": "aicee", "objective": "x", "depends_on": ["s9"]}],
        [{"id": "s1", "agent": "aicee", "objective": "x", "depends_on": []}] * 2,
    ],
)
async def test_bad_plans_are_rejected(registry, steps):
    with pytest.raises(PlanError):
        validate_plan(Plan(goal="g", steps=[Step.model_validate(s) for s in steps]), registry)


async def test_mesh_runs_a_multi_step_goal_end_to_end(settings):
    async with Mesh(settings) as mesh:
        result = await mesh.run(GOAL)
        metrics = mesh.metrics.snapshot()["counters"]
        kinds = {msg.kind for msg in mesh.trace()}

    assert result.ok, result.answer
    assert [step["agent"] for step in result.steps] == ["acie", "aicee", "seraphim", "oekp"]
    assert all(step["ok"] for step in result.steps)
    assert result.answer
    assert metrics["goal.completed"] == 1
    assert metrics["task.completed"] == 4
    assert {"task", "result", "event"} <= kinds


async def test_mesh_reports_unplannable_goals(settings):
    async with Mesh(settings) as mesh:
        result = await mesh.run("xyzzy plugh")
    assert not result.ok
    assert "Could not plan" in result.answer


async def test_independent_steps_run_concurrently(settings):
    plan = Plan(
        goal="two independent jobs",
        steps=[
            Step(id="s1", agent="acie", objective="collect edge telemetry"),
            Step(id="s2", agent="aicee", objective="analyse the telemetry"),
        ],
    )
    async with Mesh(settings, llm=SlowLLM(0.3), planner=StaticPlanner(plan)) as mesh:
        started = time.perf_counter()
        result = await mesh.run("two independent jobs")
        elapsed = time.perf_counter() - started

    assert result.ok
    assert elapsed < 0.55, f"steps serialised: {elapsed:.2f}s"
    assert mesh.metrics.counters["task.completed"] == 2


async def test_dependent_steps_receive_prior_results(settings):
    plan = Plan(
        goal="chain",
        steps=[
            Step(id="s1", agent="acie", objective="collect edge telemetry"),
            Step(id="s2", agent="oekp", objective="record the evidence", depends_on=["s1"]),
        ],
    )
    async with Mesh(settings, planner=StaticPlanner(plan)) as mesh:
        result = await mesh.run("chain")
        tasks = [m for m in mesh.trace() if m.kind == "task" and m.recipient == "oekp"]

    assert result.ok
    assert tasks and "s1" in json.dumps(tasks[0].payload.inputs)
