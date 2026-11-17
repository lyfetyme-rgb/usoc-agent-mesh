from __future__ import annotations

import asyncio

import pytest

from agents.bus import InMemoryBus
from agents.contracts import ActionClass, Message, TaskResult, TaskSpec
from agents.llm import EchoLLM
from agents.observability import Metrics
from agents.registry import SubsystemSpec
from agents.runtime import AgentError, SubsystemAgent
from agents.store import InMemoryStore


def spec(agent_id: str, capabilities: list[str] | None = None, tools: list[str] | None = None) -> SubsystemSpec:
    return SubsystemSpec(
        id=agent_id,
        name=agent_id.title(),
        description=f"The {agent_id} subsystem used by runtime tests.",
        capabilities=capabilities or [f"{agent_id} work"],
        tools=tools or [],
    )


async def make_agent(spec_, bus, settings, tools, llm, known):
    agent = SubsystemAgent(
        spec_,
        bus,
        llm=llm,
        tools=tools,
        settings=settings,
        store=InMemoryStore(),
        metrics=Metrics(),
        known_agents=known,
    )
    await agent.start()
    return agent


async def test_agent_delegates_and_awaits_result(settings, tools):
    bus = InMemoryBus(insecure_dev_mode=True)
    llm = EchoLLM()
    known = {"caller", "worker"}
    caller = await make_agent(spec("caller", ["coordinate"]), bus, settings, tools, llm, known)
    worker = await make_agent(spec("worker", ["worker work"]), bus, settings, tools, llm, known)
    try:
        result = await caller.delegate("worker", "do the worker work", inputs={"x": 1}, timeout_s=2)
        assert isinstance(result, TaskResult)
        assert result.ok
        assert "offline" in result.data
        assert llm.calls == 1
    finally:
        await caller.stop()
        await worker.stop()


async def test_unknown_recipient_fails_fast(settings, tools):
    bus = InMemoryBus(insecure_dev_mode=True)
    agent = await make_agent(spec("caller"), bus, settings, tools, EchoLLM(), {"caller"})
    try:
        with pytest.raises(AgentError) as info:
            await agent.delegate("nobody", "hello")
        assert info.value.code == "no_agent"
        assert bus.history == []
    finally:
        await agent.stop()


async def test_dead_recipient_times_out(settings, tools):
    bus = InMemoryBus(insecure_dev_mode=True)
    known = {"caller", "ghost"}
    agent = await make_agent(spec("caller"), bus, settings, tools, EchoLLM(), known)
    try:
        with pytest.raises(AgentError) as info:
            await agent.delegate("ghost", "are you there", timeout_s=0.2)
        assert info.value.code == "timeout"
    finally:
        await agent.stop()


async def test_idempotency_key_deduplicates_side_effects(settings, tools):
    bus = InMemoryBus(insecure_dev_mode=True)
    llm = EchoLLM()
    await bus.subscribe("client", [])
    worker = await make_agent(spec("worker"), bus, settings, tools, llm, {"worker"})
    try:
        first = Message.task(sender="client", recipient="worker", objective="charge the card", idempotency_key="order-1")
        second = Message.task(sender="client", recipient="worker", objective="charge the card", idempotency_key="order-1")
        await bus.publish(first)
        await bus.publish(second)

        replies = [await bus.receive("client", timeout=1) for _ in range(2)]
        assert all(r is not None and isinstance(r.payload, TaskResult) for r in replies)
        assert replies[0].payload.output == replies[1].payload.output
        assert llm.calls == 1
    finally:
        await worker.stop()


async def test_expired_task_is_rejected_without_calling_the_model(settings, tools):
    from datetime import datetime, timedelta, timezone

    bus = InMemoryBus(insecure_dev_mode=True)
    llm = EchoLLM()
    await bus.subscribe("client", [])
    worker = await make_agent(spec("worker"), bus, settings, tools, llm, {"worker"})
    try:
        msg = Message.task(
            sender="client",
            recipient="worker",
            objective="too late",
            deadline=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        await bus.publish(msg)
        reply = await bus.receive("client", timeout=1)
        assert reply is not None and reply.kind == "error"
        assert reply.payload.code == "deadline"
        assert llm.calls == 0
    finally:
        await worker.stop()


async def test_tool_calls_are_limited_to_the_card(settings, tools):
    bus = InMemoryBus(insecure_dev_mode=True)
    worker = await make_agent(spec("worker", tools=[]), bus, settings, tools, EchoLLM(), {"worker"})
    try:
        result = await worker._run_tool({"tool_name": "workspace.write", "arguments": {"path": "x", "content": "y"}})
        assert "not permitted" in result["error"]
    finally:
        await worker.stop()


async def test_governed_task_without_a_policy_fails_closed(settings, tools):
    bus = InMemoryBus(insecure_dev_mode=True)
    await bus.subscribe("client", [])
    worker = await make_agent(spec("worker"), bus, settings, tools, EchoLLM(), {"worker"})
    try:
        await bus.publish(
            Message.task(
                sender="client",
                recipient="worker",
                objective="do the thing",
                action_class=ActionClass.EXECUTE,
                target="sandbox/node-1",
            )
        )
        reply = await bus.receive("client", timeout=1)
        assert reply is not None and reply.kind == "error"
        assert reply.payload.code == "policy_denied"
    finally:
        await worker.stop()


async def test_result_carries_provenance_and_taint(settings, tools):
    bus = InMemoryBus(insecure_dev_mode=True)
    await bus.subscribe("client", [])
    worker = await make_agent(spec("worker"), bus, settings, tools, EchoLLM(), {"worker"})
    try:
        await bus.publish(
            Message.task(
                sender="client",
                recipient="worker",
                objective="summarize the latest telemetry",
                provenance=["acie"],
                tainted=True,
            )
        )
        reply = await bus.receive("client", timeout=1)
        assert reply is not None and isinstance(reply.payload, TaskResult)
        assert reply.payload.tainted is True
        assert "acie" in reply.payload.provenance
        assert "worker" in reply.payload.provenance
    finally:
        await worker.stop()


def test_idempotency_keys_are_scoped_by_agent_and_tenant():
    from types import SimpleNamespace

    task = TaskSpec(objective="charge the card", idempotency_key="order-1")
    tenant_a = Message.task(
        sender="client", recipient="worker", objective="charge the card", tenant_id="tenant-a"
    )
    tenant_b = Message.task(
        sender="client", recipient="worker", objective="charge the card", tenant_id="tenant-b"
    )
    worker_a = SimpleNamespace(id="worker-a")
    worker_b = SimpleNamespace(id="worker-b")

    key_a = SubsystemAgent._idempotency_key(worker_a, tenant_a, task)
    assert key_a
    assert key_a != SubsystemAgent._idempotency_key(worker_b, tenant_a, task)
    assert key_a != SubsystemAgent._idempotency_key(worker_a, tenant_b, task)

    tainted = TaskSpec(
        objective="charge the card",
        idempotency_key="order-1",
        provenance=["connector://vendor-api"],
        tainted=True,
    )
    assert key_a != SubsystemAgent._idempotency_key(worker_a, tenant_a, tainted)
