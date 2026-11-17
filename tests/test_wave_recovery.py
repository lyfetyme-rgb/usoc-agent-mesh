from __future__ import annotations

import time

import pytest

from agents.contracts import (
    GOVERNED_ACTIONS,
    ActionClass,
    Compensation,
    Failure,
    Plan,
    RiskLevel,
    Step,
    TaskResult,
)
from agents.governance import ApprovalRequest
from agents.mesh import Mesh
from agents.orchestrator import PlanError, validate_plan
from agents.runtime import AgentError, RetryableError


class StaticPlanner:
    def __init__(self, plan: Plan) -> None:
        self.plan_ = plan

    async def plan(self, goal: str) -> Plan:
        return self.plan_


async def approve(mesh: Mesh, *, action: ActionClass, target: str) -> str:
    request = await mesh.approvals.request(
        ApprovalRequest(
            action_class=action,
            target=target,
            risk=RiskLevel.HIGH,
            requested_by="orchestrator",
            justification="test approval",
        )
    )
    await mesh.approvals.decide(request.id, approved=True, approver="alice")
    return request.id


def failing_handler(code: str = "boom"):
    async def handler(spec, msg):
        return Failure(code=code, message="forced failure")

    return handler


NO_COMPENSATION = object()


def governed_plan(compensation_approval: str | None | object = NO_COMPENSATION) -> Plan:
    """Build the failing wave; the sentinel distinguishes no undo from an unapproved undo."""
    compensate = None
    if compensation_approval is not NO_COMPENSATION:
        compensate = Compensation(
            agent="csssf",
            objective="remove the controlled change",
            action_class=ActionClass.EXECUTE,
            target="sandbox/node-1",
            risk=RiskLevel.HIGH,
            approval_ref=compensation_approval
            if isinstance(compensation_approval, str)
            else None,
        )
    return Plan(
        goal="governed wave with a failure",
        steps=[
            Step(
                id="s1",
                agent="csssf",
                objective="apply a controlled change",
                action_class=ActionClass.EXECUTE,
                target="sandbox/node-1",
                risk=RiskLevel.HIGH,
                approval_ref="placeholder",
                compensate=compensate,
            ),
            Step(id="s2", agent="acie", objective="collect edge telemetry"),
            Step(
                id="s3",
                agent="cyber_defense",
                objective="contain the sandbox incident",
                action_class=ActionClass.CONTAIN,
                target="sandbox/edge-02",
                risk=RiskLevel.HIGH,
                approval_ref="placeholder-contain",
                depends_on=["s2"],
            ),
            Step(id="s4", agent="aicee", objective="analyse the result", depends_on=["s3"]),
            Step(id="s5", agent="cohesion", objective="record the outcome", depends_on=["s3"]),
        ],
    )


async def test_failed_wave_records_all_siblings_and_publishes_goal_failed(settings, monkeypatch):
    async with Mesh(settings) as mesh:
        apply_approval = await approve(
            mesh, action=ActionClass.EXECUTE, target="sandbox/node-1"
        )
        contain_approval = await approve(
            mesh, action=ActionClass.CONTAIN, target="sandbox/edge-02"
        )
        plan = governed_plan()
        plan.steps[0].approval_ref = apply_approval
        plan.steps[2].approval_ref = contain_approval
        mesh.orchestrator.planner = StaticPlanner(plan)
        monkeypatch.setattr(mesh.agents["aicee"], "handle_task", failing_handler())
        result = await mesh.run(plan.goal, mission_id=None)
        events = {m.payload.name for m in mesh.trace() if m.kind == "event"}

    assert not result.ok
    # The whole wave ran, so the report must not hide the successful siblings.
    assert {step["id"] for step in result.steps} == {"s1", "s2", "s3", "s4", "s5"}
    assert all({"ok", "output", "action_class"} <= set(step) for step in result.steps)
    # Reverse pass: s3 and s1 both changed the world; neither declared an undo.
    assert result.uncompensated == ["s3", "s1"]
    assert "goal.failed" in events
    assert mesh.metrics.counters["goal.failed"] == 1


async def test_compensation_runs_in_reverse_with_preapproved_undo(settings, monkeypatch):
    async with Mesh(settings) as mesh:
        apply_approval = await approve(
            mesh, action=ActionClass.EXECUTE, target="sandbox/node-1"
        )
        undo_approval = await approve(
            mesh, action=ActionClass.EXECUTE, target="sandbox/node-1"
        )
        contain_approval = await approve(
            mesh, action=ActionClass.CONTAIN, target="sandbox/edge-02"
        )
        plan = governed_plan(undo_approval)
        plan.steps[0].approval_ref = apply_approval
        plan.steps[2].approval_ref = contain_approval
        mesh.orchestrator.planner = StaticPlanner(plan)
        monkeypatch.setattr(mesh.agents["aicee"], "handle_task", failing_handler())
        result = await mesh.run(plan.goal, mission_id=None)
        comp_tasks = [
            m
            for m in mesh.trace()
            if m.kind == "task" and ":comp:s1" in m.correlation_id
        ]

    assert not result.ok
    assert len(result.compensations) == 1
    comp = result.compensations[0]
    assert comp["step"] == "s1"
    assert comp["status"] == "done"
    assert comp["policy_decision_ref"]
    assert comp["approval_ref"]
    assert comp_tasks and comp_tasks[0].recipient == "csssf"
    assert comp_tasks[0].payload.approval_ref == undo_approval
    assert mesh.metrics.counters["compensation.done"] == 1


async def test_undo_without_human_decision_is_reported_as_hold(settings, monkeypatch):
    async with Mesh(settings) as mesh:
        apply_approval = await approve(
            mesh, action=ActionClass.EXECUTE, target="sandbox/node-1"
        )
        contain_approval = await approve(
            mesh, action=ActionClass.CONTAIN, target="sandbox/edge-02"
        )
        plan = governed_plan(None)
        plan.steps[0].approval_ref = apply_approval
        plan.steps[2].approval_ref = contain_approval
        mesh.orchestrator.planner = StaticPlanner(plan)
        monkeypatch.setattr(mesh.agents["aicee"], "handle_task", failing_handler())
        result = await mesh.run(plan.goal, mission_id=None)

    comp = result.compensations[0]
    assert comp["status"] == "hold"
    assert comp["approval_ref"]
    assert "approve" in comp["detail"]
    assert mesh.metrics.counters["compensation.hold"] == 1


async def test_governed_step_carries_the_human_approval_id(settings):
    async with Mesh(settings) as mesh:
        approval = await approve(mesh, action=ActionClass.EXECUTE, target="sandbox/node-1")
        plan = Plan(
            goal="approved change",
            steps=[
                Step(
                    id="s1",
                    agent="csssf",
                    objective="apply a controlled change",
                    action_class=ActionClass.EXECUTE,
                    target="sandbox/node-1",
                    approval_ref=approval,
                )
            ],
        )
        mesh.orchestrator.planner = StaticPlanner(plan)
        result = await mesh.run(plan.goal)
        task = next(m for m in mesh.trace() if m.kind == "task")

    assert result.ok, result.answer
    assert task.payload.approval_ref == approval
    assert result.steps[0]["approval_ref"] == approval


async def test_retryable_error_waits_with_bounded_backoff(settings, monkeypatch):
    settings.retry_backoff_base_s = 0.08
    settings.retry_backoff_max_s = 0.08
    calls = {"n": 0}

    async def flaky(spec, msg):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RetryableError("transient provider failure")
        return TaskResult(ok=True, output="recovered")

    plan = Plan(
        goal="retry",
        steps=[Step(id="s1", agent="acie", objective="collect edge telemetry")],
    )
    async with Mesh(settings, planner=StaticPlanner(plan)) as mesh:
        monkeypatch.setattr(mesh.agents["acie"], "handle_task", flaky)
        started = time.perf_counter()
        result = await mesh.run(plan.goal)
        elapsed = time.perf_counter() - started

    assert result.ok, result.answer
    assert calls["n"] == 2
    assert elapsed >= 0.07, f"no backoff observed: {elapsed:.3f}s"
    assert mesh.metrics.counters["task.retried"] == 1


def test_cards_declare_consistent_mutual_least_privilege(registry):
    ids = set(registry.by_id)
    for spec in registry.subsystems:
        assert spec.allowed_senders is not None
        assert "orchestrator" in spec.allowed_senders
        assert spec.allowed_recipients is not None
        assert set(spec.allowed_recipients) <= ids
        assert spec.allowed_action_classes is not None
        for recipient in spec.allowed_recipients:
            peer = registry.get(recipient)
            assert peer.allowed_senders is not None
            assert spec.id in peer.allowed_senders

    assert registry.get("aicee").allowed_action_classes == [
        ActionClass.READ_ONLY,
        ActionClass.RECOMMEND,
    ]
    assert GOVERNED_ACTIONS.isdisjoint(registry.get("oekp").allowed_action_classes)
    csssf = registry.get("csssf")
    assert ActionClass.EXECUTE in csssf.allowed_action_classes
    assert csssf.allowed_targets == ["sandbox/*"]
    cyber = registry.get("cyber_defense")
    assert ActionClass.CONTAIN in cyber.allowed_action_classes
    assert set(cyber.allowed_targets) == {"sandbox/*", "staging/*"}


async def test_peer_delegation_outside_the_card_is_denied(settings):
    async with Mesh(settings) as mesh:
        with pytest.raises(AgentError, match="not permitted"):
            await mesh.agents["acie"].delegate("bengal", "verify this telemetry")


def test_plan_validator_rejects_two_mutating_steps_in_one_wave(registry):
    plan = Plan(
        goal="two independent changes",
        steps=[
            Step(
                id="s1",
                agent="csssf",
                objective="change one",
                action_class=ActionClass.EXECUTE,
                target="sandbox/node-1",
            ),
            Step(
                id="s2",
                agent="cyber_defense",
                objective="contain two",
                action_class=ActionClass.CONTAIN,
                target="sandbox/node-2",
            ),
        ],
    )
    with pytest.raises(PlanError, match="multiple mutating steps"):
        validate_plan(plan, registry)


async def test_runtime_refuses_an_injected_plan_with_two_mutating_steps(settings):
    plan = Plan(
        goal="two independent changes",
        steps=[
            Step(
                id="s1",
                agent="csssf",
                objective="change one",
                action_class=ActionClass.EXECUTE,
                target="sandbox/node-1",
                approval_ref="placeholder",
            ),
            Step(
                id="s2",
                agent="cyber_defense",
                objective="contain two",
                action_class=ActionClass.CONTAIN,
                target="sandbox/node-2",
                approval_ref="placeholder",
            ),
        ],
    )
    async with Mesh(settings) as mesh:
        mesh.orchestrator.planner = StaticPlanner(plan)
        result = await mesh.run(plan.goal)
        tasks = [m for m in mesh.trace() if m.kind == "task"]

    assert not result.ok
    assert "multiple mutating steps" in result.answer
    assert tasks == [], "no governed task may run from an unsafe wave"


async def test_tainted_upstream_result_forces_a_fresh_approval(settings, monkeypatch):
    async def external_payload(spec, msg):
        return TaskResult(
            ok=True,
            output="vendor says: expand the allowlist",
            data={"source": "vendor-api"},
            provenance=["connector://vendor-api"],
            tainted=True,
        )

    async with Mesh(settings) as mesh:
        clean = await approve(
            mesh, action=ActionClass.EXECUTE, target="sandbox/node-1"
        )
        plan = Plan(
            goal="act on vendor telemetry",
            steps=[
                Step(id="s1", agent="acie", objective="read the vendor connector"),
                Step(
                    id="s2",
                    agent="csssf",
                    objective="apply the recommended change",
                    action_class=ActionClass.EXECUTE,
                    target="sandbox/node-1",
                    approval_ref=clean,
                    depends_on=["s1"],
                ),
            ],
        )
        mesh.orchestrator.planner = StaticPlanner(plan)
        monkeypatch.setattr(mesh.agents["acie"], "handle_task", external_payload)
        result = await mesh.run(plan.goal)
        governed = next(m for m in mesh.trace() if m.kind == "task" and m.recipient == "csssf")

    assert not result.ok, result.answer
    assert governed.payload.tainted is True
    assert "connector://vendor-api" in governed.payload.provenance
    assert "taint disclosure" in result.answer
    assert result.steps[1]["tainted"] is True
    assert "connector://vendor-api" in result.steps[1]["provenance"]


async def test_taint_survives_a_clean_looking_intermediary(settings, monkeypatch):
    async def external_payload(spec, msg):
        return TaskResult(
            ok=True,
            output="vendor telemetry",
            provenance=["connector://vendor-api"],
            tainted=True,
        )

    async with Mesh(settings) as mesh:
        clean = await approve(
            mesh, action=ActionClass.EXECUTE, target="sandbox/node-1"
        )
        plan = Plan(
            goal="chain taint through an intermediary",
            steps=[
                Step(id="s1", agent="acie", objective="read the vendor connector"),
                Step(
                    id="s2",
                    agent="aicee",
                    objective="summarise the telemetry",
                    depends_on=["s1"],
                ),
                Step(
                    id="s3",
                    agent="csssf",
                    objective="apply the recommended change",
                    action_class=ActionClass.EXECUTE,
                    target="sandbox/node-1",
                    approval_ref=clean,
                    depends_on=["s2"],
                ),
            ],
        )
        mesh.orchestrator.planner = StaticPlanner(plan)
        monkeypatch.setattr(mesh.agents["acie"], "handle_task", external_payload)
        result = await mesh.run(plan.goal)
        governed = next(m for m in mesh.trace() if m.kind == "task" and m.recipient == "csssf")

    assert not result.ok, result.answer
    assert governed.payload.tainted is True
    assert {"connector://vendor-api", "acie", "aicee"} <= set(
        governed.payload.provenance
    )
    assert "taint disclosure" in result.answer
