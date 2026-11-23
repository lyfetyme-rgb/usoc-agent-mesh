"""Task-aware runtime state: bounded, redacted, lifecycle-aware ledger.

Regression target: an operator must be able to answer "what is still unresolved,
where did it stall, and how many attempts did it take" without exposing goals,
error text or approval details on a public probe.
"""

from __future__ import annotations

import json
import re

import pytest
from pydantic import ValidationError

from agents.bus import InMemoryBus
from agents.llm import EchoLLM
from agents.observability import Metrics
from agents.store import InMemoryStore
from agents.task_ledger import TaskEvent, TaskLedger, reason_fingerprint
from agents.tools import ToolRegistry


def test_ledger_records_lifecycle_and_resolution_state():
    ledger = TaskLedger(max_events=16)
    ledger.record(
        agent_id="oekp", state="received", correlation_id="trace1:s1", step_id="s1", attempt=0
    )
    event = ledger.record(
        agent_id="oekp",
        state="completed",
        correlation_id="trace1:s1",
        step_id="s1",
        attempt=1,
        ok=True,
        resolved=True,
        latency_ms=42,
        tokens=9,
    )
    snapshot = ledger.snapshot()

    assert snapshot["states"]["received"] == 1
    assert snapshot["states"]["completed"] == 1
    assert snapshot["by_agent"]["oekp"] == 2
    assert snapshot["resolved"] == 1
    assert snapshot["unresolved"] == 0
    assert snapshot["retained"] == 2
    assert snapshot["recent"][-1]["trace_id"] == "trace1"
    assert snapshot["recent"][-1]["step_id"] == "s1"
    assert snapshot["recent"][-1]["attempt"] == 1
    assert event.latency_ms == 42


def test_unresolved_terminal_states_are_counted():
    ledger = TaskLedger()
    ledger.record(agent_id="a", state="received", correlation_id="t:s1")
    ledger.record(agent_id="a", state="failed", correlation_id="t:s1", ok=False, resolved=False)
    ledger.record(agent_id="a", state="held", correlation_id="t:s2", ok=False, resolved=False)
    ledger.record(agent_id="a", state="shadow_blocked", correlation_id="t:s3", ok=True, resolved=True)

    snapshot = ledger.snapshot()
    assert snapshot["unresolved"] == 2
    assert snapshot["resolved"] == 1
    assert snapshot["resolution_rate"] == round(1 / 3, 4)


def test_ledger_is_bounded_and_reports_dropped_events():
    ledger = TaskLedger(max_events=3)
    for i in range(10):
        ledger.record(agent_id="a", state="received", correlation_id=f"t{i}:s1")

    snapshot = ledger.snapshot()
    assert snapshot["retained"] == 3
    assert snapshot["dropped"] == 7
    assert snapshot["capacity"] == 3


def test_ledger_expires_old_events_without_leaking_them():
    now = [1_000.0]
    ledger = TaskLedger(max_events=10, ttl_s=5.0, clock=lambda: now[0])
    ledger.record(agent_id="a", state="received", correlation_id="t:s1")
    now[0] += 6.0

    snapshot = ledger.snapshot()
    assert snapshot["retained"] == 0
    assert snapshot["expired"] == 1


def test_ledger_never_stores_raw_error_text_or_secrets():
    ledger = TaskLedger()
    ledger.record(
        agent_id="a",
        state="failed",
        correlation_id="t:s1",
        reason="api_key=sk-supersecret-value cannot be used",
    )
    payload = json.dumps(ledger.snapshot())

    assert "sk-supersecret-value" not in payload
    assert "cannot be used" not in payload
    fingerprint = ledger.snapshot()["recent"][-1]["reason_fingerprint"]
    assert re.fullmatch(r"[0-9a-f]{16}", fingerprint)


def test_task_event_forbids_extra_fields():
    with pytest.raises(ValidationError):
        TaskEvent(
            event_id="1",
            trace_id="t",
            agent_id="a",
            state="received",
            goal="charge the card",
        )


def test_reason_fingerprint_is_stable_and_opaque():
    first = reason_fingerprint("boom api_key=sk-supersecret-value")
    assert first == reason_fingerprint("boom api_key=sk-supersecret-value")
    assert first != reason_fingerprint("different failure")
    assert "boom" not in first
    assert "supersecret" not in first


async def test_runtime_writes_task_lifecycle_to_ledger(settings, tools: ToolRegistry):
    ledger = TaskLedger()
    bus = InMemoryBus(insecure_dev_mode=True)
    from agents.runtime import SubsystemAgent

    worker = SubsystemAgent(
        spec=_runtime_spec(),
        bus=bus,
        llm=EchoLLM(),
        tools=tools,
        settings=settings,
        store=InMemoryStore(),
        metrics=Metrics(),
        known_agents={"worker"},
        ledger=ledger,
    )
    await bus.subscribe("client", [])
    await worker.start()
    try:
        from agents.contracts import Message

        await bus.publish(
            Message.task(sender="client", recipient="worker", objective="summarize an alert")
        )
        reply = await bus.receive("client", timeout=2)
        assert reply is not None and reply.kind == "result"
    finally:
        await worker.stop()

    states = ledger.snapshot()["states"]
    assert states.get("received") == 1
    assert states.get("completed") == 1
    assert ledger.snapshot()["resolved"] == 1


async def test_shell_surfaces_task_counts_without_public_identifiers():
    from types import SimpleNamespace

    from agents.shell import Shell

    ledger = TaskLedger()
    ledger.record(agent_id="oekp", state="received", correlation_id="trace1:s1")
    ledger.record(
        agent_id="oekp", state="failed", correlation_id="trace1:s1",
        ok=False, resolved=False, reason="secret-bearing failure",
    )
    shell = Shell(
        registry=SimpleNamespace(subsystems=[], roles_total=0),
        agents={},
        bus=SimpleNamespace(stats={}, dlq=[], signer=None),
        metrics=Metrics(),
        ledger=ledger,
    )

    public = await shell.health(detailed=False)
    assert public["tasks"]["tasks_unresolved"] == 1
    assert "oekp" not in json.dumps(public)
    assert "secret-bearing" not in json.dumps(public)

    detailed = await shell.health(detailed=True)
    assert detailed["task_ledger"]["by_agent"] == {"oekp": 2}
    assert "1 unresolved tasks" in await shell.diagnostics()


def _runtime_spec():
    from agents.registry import SubsystemSpec

    return SubsystemSpec(
        id="worker",
        name="Worker",
        description="Ledger integration test worker.",
        capabilities=["ledger work"],
        tools=[],
    )
