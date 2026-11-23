"""Regression tests for the mesh-only system-engineering hardening pass."""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from agents import security
from agents.bus import InMemoryBus
from agents.connectors import ConnectorBatch, SourceType, ingest_connectors
from agents.contracts import ErrorCode, Message
from agents.evidence import EvidenceChain, EvidenceRecord
from agents.governance import ActionClass, ApprovalRequest, FileApprovalStore
from agents.llm import EchoLLM, OpenAICompatibleLLM
from agents.observability import (
    JsonFormatter,
    Metrics,
    TextFormatter,
    log,
    trace,
    trace_id,
)
from agents.orchestrator import Orchestrator
from agents.registry import SubsystemSpec
from agents.runtime import SubsystemAgent
from agents.security import SecurityError
from agents.service import HealthServer
from agents.shell import Shell
from agents.store import InMemoryStore


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self.status_code = 200
        self.request = None
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


class _QueueClient:
    def __init__(self, payloads: list[dict]) -> None:
        self.payloads = list(payloads)
        self.calls = 0

    async def post(self, *_args, **_kwargs) -> _FakeResponse:
        self.calls += 1
        return _FakeResponse(self.payloads.pop(0))

    async def aclose(self) -> None:
        return None


def test_log_supports_severity_and_stable_fingerprint(caplog):
    caplog.set_level(logging.DEBUG, logger="mesh")
    log(
        "task.error",
        level="ERROR",
        fingerprint="deadbeef",
        detail="notify jane.doe@example.com",
    )
    record = next(r for r in caplog.records if r.getMessage() == "task.error")
    assert record.levelname == "ERROR"
    assert record.fields["fingerprint"] == "deadbeef"
    rendered = JsonFormatter().format(record)
    assert "jane.doe@example.com" not in rendered


def test_formatters_redact_prepopulated_fields():
    fields = {"url": "https://user:secret@host.example.com", "email": "jane@example.com"}
    record = logging.LogRecord(
        "mesh", logging.INFO, __file__, 1, "event", None, None, None
    )
    record.fields = fields
    for formatter in (JsonFormatter(), TextFormatter()):
        rendered = formatter.format(record)
        assert "secret@" not in rendered
        assert "jane@example.com" not in rendered


def test_trace_context_is_restored_and_agent_logs_are_self_describing():
    previous = trace_id.get()
    with trace("trace-A"):
        assert trace_id.get() == "trace-A"
        log("inside.trace")
    assert trace_id.get() == previous
    record = logging.LogRecord("mesh", logging.INFO, __file__, 1, "x", None, None, None)
    rendered = json.loads(JsonFormatter().format(record))
    assert rendered["trace"] == previous
    assert rendered["agent"] == "-"


def test_metrics_snapshot_exposes_latency_summaries():
    metrics = Metrics()
    for value in (40, 750, 6_000):
        metrics.observe("goal.duration_ms", value)
    summary = metrics.snapshot()["latencies"]["goal.duration_ms"]
    assert summary["count"] == 3
    assert summary["sum_ms"] == 6_790
    assert summary["avg_ms"] == round(6_790 / 3)
    # Bucket estimates are upper bounds: 750ms lands in the le_1000 bucket.
    assert summary["p50_bucket_ms"] <= 1_000
    assert summary["p95_bucket_ms"] <= 5_000


@pytest.mark.asyncio
async def test_llm_retries_malformed_provider_responses():
    good = {
        "choices": [{"message": {"content": "ok"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }
    llm = OpenAICompatibleLLM("https://api.example.test/v1", "sk-test", max_retries=1)
    llm._client = _QueueClient([{"choices": [], "usage": {}}, good])
    response = await llm.complete(system="sys", messages=[{"role": "user", "content": "go"}])
    assert response.text == "ok"
    assert llm._client.calls == 2
    await llm.close()


@pytest.mark.asyncio
async def test_inmemory_store_sweeps_expired_entries_on_write():
    store = InMemoryStore()
    await store.set("old", "value", ttl_s=0.001)
    await asyncio.sleep(0.01)
    await store.set("new", "value", ttl_s=60)
    assert "old" not in store._data


@pytest.mark.asyncio
async def test_bus_history_and_dead_letters_are_bounded():
    bus = InMemoryBus(insecure_dev_mode=True, history_limit=3, dlq_limit=2, max_queue=1)
    await bus.subscribe("noisy", [])
    for i in range(8):
        await bus.publish(Message.event(sender="test", name="n", data={"i": i}))
    assert len(bus.history) <= 3
    assert len(bus.dlq) <= 2


@pytest.mark.asyncio
async def test_wildcard_publish_is_counted_and_logged(caplog):
    caplog.set_level(logging.INFO, logger="mesh")
    bus = InMemoryBus(insecure_dev_mode=True)
    with pytest.raises(PermissionError):
        await bus.publish(Message.event(sender="test", name="n", topic="inbox.*"))
    assert bus.stats["acl_denied"] == 1
    assert any(r.getMessage() == "bus.wildcard_rejected" for r in caplog.records)


@pytest.mark.asyncio
async def test_corrupt_approval_file_fails_closed_without_overwrite(tmp_path):
    path = tmp_path / "approvals.json"
    store = FileApprovalStore(path)
    await store.request(
        ApprovalRequest(
            action_class=ActionClass.EXECUTE,
            target="sandbox/node-1",
            risk="medium",
            requested_by="seraphim",
            justification="test",
        )
    )
    original = path.read_text(encoding="utf-8")
    path.write_text("{corrupt", encoding="utf-8")
    with pytest.raises(SecurityError):
        await store.pending()
    with pytest.raises(SecurityError):
        await store.request(
            ApprovalRequest(
                action_class=ActionClass.EXECUTE,
                target="sandbox/node-2",
                risk="medium",
                requested_by="seraphim",
                justification="test",
            )
        )
    assert path.read_text(encoding="utf-8") == "{corrupt"
    assert json.loads(original)["approvals"]


@pytest.mark.asyncio
async def test_public_health_resists_approval_faults_and_reports_degraded():
    class BrokenApprovals:
        async def pending(self):
            raise OSError("approval file unreadable")

    registry = SimpleNamespace(
        subsystems=[SimpleNamespace(id="aicee")], roles_total=1
    )
    bus = SimpleNamespace(stats={"unrouted": 2}, dlq=["x"], signer=None)
    shell = Shell(
        registry,
        {},
        bus,
        Metrics(),
        BrokenApprovals(),
        fragmentation_error="redis password=secret-value",
    )
    health = await shell.health(detailed=False)
    ok, ready = await shell.ready(detailed=False)
    assert health["degraded"] is True
    assert ready["degraded"] is True
    rendered = json.dumps({"health": health, "ready": ready})
    assert "aicee" not in rendered
    assert "secret-value" not in rendered
    assert ok is False


@pytest.mark.asyncio
async def test_orchestrator_pump_survives_a_transport_error(settings, registry):
    class FlakyBus:
        def __init__(self) -> None:
            self.calls = 0
            self.owner = None

        async def subscribe(self, *_args, **_kwargs) -> None:
            return None

        async def receive(self, *_args, **_kwargs):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("redis timeout")
            self.owner._stopping.set()
            return None

        async def ack(self, *_args, **_kwargs) -> None:
            return None

    bus = FlakyBus()
    orchestrator = Orchestrator(bus, registry, object(), settings, Metrics())
    bus.owner = orchestrator
    task = asyncio.create_task(orchestrator._pump())
    await asyncio.wait_for(task, timeout=2)
    assert task.exception() is None
    assert bus.calls >= 2


@pytest.mark.asyncio
async def test_connector_failures_emit_structured_events(caplog):
    caplog.set_level(logging.INFO, logger="mesh")

    class Broken:
        name = "broken"

        async def fetch(self) -> ConnectorBatch:
            raise RuntimeError("token abc123 for jane@example.com")

    result = await ingest_connectors([Broken()])
    assert result.errors
    records = [r for r in caplog.records if r.getMessage() == "connector.ingest"]
    assert records
    rendered = " ".join(JsonFormatter().format(r) for r in records)
    assert "jane@example.com" not in rendered


@pytest.mark.asyncio
async def test_runtime_acks_only_after_reply_is_published(settings, tools):
    class OrderBus:
        def __init__(self) -> None:
            self.calls: list[str] = []
            self.topic_rules = None

        async def publish(self, _msg: Message) -> None:
            self.calls.append("publish")

        async def ack(self, _agent: str, _msg: Message) -> None:
            self.calls.append("ack")

    bus = OrderBus()
    spec = SubsystemSpec(
        id="worker",
        name="Worker",
        description="ACK ordering test agent.",
        capabilities=["worker work"],
        tools=[],
    )
    agent = SubsystemAgent(
        spec,
        bus,
        llm=EchoLLM(),
        tools=tools,
        settings=settings,
        store=InMemoryStore(),
        metrics=Metrics(),
        known_agents={"worker"},
    )
    await agent._reject(
        Message.task(sender="client", recipient="worker", objective="test"),
        ErrorCode.HANDLER,
        "boom",
    )
    assert bus.calls == ["publish", "ack"]


@pytest.mark.asyncio
async def test_agent_logs_carry_the_orchestrator_trace(settings, tools, caplog):
    caplog.set_level(logging.INFO, logger="mesh")
    bus = InMemoryBus(insecure_dev_mode=True)
    await bus.subscribe("client", [])
    spec = SubsystemSpec(
        id="worker",
        name="Worker",
        description="Trace propagation test agent.",
        capabilities=["worker work"],
        tools=[],
    )
    agent = SubsystemAgent(
        spec,
        bus,
        llm=EchoLLM(),
        tools=tools,
        settings=settings,
        store=InMemoryStore(),
        metrics=Metrics(),
        known_agents={"client", "worker"},
    )
    await agent._process(
        Message.task(
            sender="client",
            recipient="worker",
            objective="do the worker work",
            correlation_id="traceA:step1",
        )
    )
    record = next(r for r in caplog.records if r.getMessage() == "task.start")
    assert record.fields["trace"] == "traceA"
    assert record.fields["agent"] == "worker"


@pytest.mark.asyncio
async def test_planner_failure_counts_as_a_goal_failure(settings, registry):
    class BrokenPlanner:
        async def plan(self, _goal: str):
            raise RuntimeError("planner offline")

    bus = InMemoryBus(insecure_dev_mode=True)
    metrics = Metrics()
    orchestrator = Orchestrator(bus, registry, BrokenPlanner(), settings, metrics)
    result = await orchestrator.run("inspect the alert")
    assert result.ok is False
    assert metrics.counters["goal.failed"] == 1
    assert metrics.counters["goal.duration_ms.count"] == 1
    assert any(
        getattr(msg.payload, "name", None) == "goal.failed"
        and msg.correlation_id == result.correlation_id
        for msg in bus.history
    )


@pytest.mark.asyncio
async def test_health_server_logs_internal_errors_without_leaking_secrets(caplog):
    caplog.set_level(logging.INFO, logger="mesh")

    async def provider(_path: str) -> tuple[int, dict]:
        raise RuntimeError("bearer abc123")

    server = HealthServer("127.0.0.1", 0, provider)
    await server.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        writer.write(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        assert b"HTTP/1.1 500 Internal Server Error" in response
        assert b"abc123" not in response
    finally:
        await server.stop()

    record = next(r for r in caplog.records if r.getMessage() == "health.server_error")
    rendered = JsonFormatter().format(record)
    assert "abc123" not in rendered
    assert "RuntimeError" in rendered


@pytest.mark.asyncio
async def test_evidence_tail_reads_one_record_not_whole_chain(tmp_path, monkeypatch):
    chain = EvidenceChain(tmp_path / "evidence.jsonl")
    for i in range(25):
        await chain.append(kind="test", actor="tester", data={"i": i})

    parsed = 0
    original = EvidenceRecord.model_validate_json

    def counting(line):
        nonlocal parsed
        parsed += 1
        return original(line)

    monkeypatch.setattr(EvidenceRecord, "model_validate_json", counting)
    seq, digest = chain._tail()
    assert seq == 25
    assert digest == chain._last_hash
    assert parsed == 1


@pytest.mark.asyncio
async def test_evidence_tail_handles_record_larger_than_scan_block(tmp_path):
    chain = EvidenceChain(tmp_path / "evidence.jsonl")
    record = await chain.append(
        kind="test.large", actor="tester", data={"blob": "x" * 12_000}
    )
    assert chain._tail() == (record.seq, record.hash)
    ok, _ = chain.verify()
    assert ok


@pytest.mark.asyncio
async def test_async_exclusive_lock_keeps_event_loop_responsive(tmp_path, monkeypatch):
    gate = threading.Event()

    @contextmanager
    def slow_lock(_path, timeout_s=10.0):
        gate.set()
        time.sleep(0.2)
        yield

    monkeypatch.setattr(security, "exclusive_lock", slow_lock)

    async def holder():
        async with security.async_exclusive_lock(tmp_path / "state.json"):
            await asyncio.sleep(0.01)

    task = asyncio.create_task(holder())
    await asyncio.to_thread(gate.wait, 2)
    loop = asyncio.get_running_loop()
    started = loop.time()
    await asyncio.sleep(0.01)
    assert loop.time() - started < 0.08
    await task


def test_file_approval_store_uses_non_blocking_locks():
    source = Path(__file__).resolve().parents[1] / "agents" / "governance.py"
    text = source.read_text(encoding="utf-8")
    assert text.count("async with async_exclusive_lock(self.path):") >= 3
    assert "with exclusive_lock(" not in text
