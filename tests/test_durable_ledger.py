"""Durable, tenant-partitioned task state with a signed cold archive.

The process-local ledger remains the fast path; these tests reproduce the
scaling requirements: events must be partitioned by tenant, hot state must be
written through with a TTL, cold lineage must be signed and tamper-evident, and
a dead Redis must degrade to local observation without changing execution.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from agents.durable import (
    InMemoryLedgerSink,
    LedgerSink,
    RedisLedgerSink,
    SignedArchiveSink,
)
from agents.task_ledger import TaskLedger


class FakeRedis:
    """Minimal async Redis double that records every write."""

    def __init__(self, *, fail: bool = False) -> None:
        self.commands: list[tuple[str, tuple]] = []
        self.fail = fail

    async def hset(self, key, mapping=None, **kwargs):
        self.commands.append(("hset", (key, dict(mapping or {}))))
        if self.fail:
            raise ConnectionError("redis unavailable")

    async def zadd(self, key, mapping=None, **kwargs):
        self.commands.append(("zadd", (key, dict(mapping or {}))))
        if self.fail:
            raise ConnectionError("redis unavailable")

    async def expire(self, key, ttl):
        self.commands.append(("expire", (key, ttl)))

    async def zrangebyscore(self, key, min, max, start=None, num=None):
        return []

    async def aclose(self):
        self.commands.append(("aclose", ()))


def test_task_ledger_writes_through_sink_with_tenant_partition():
    sink = InMemoryLedgerSink()
    ledger = TaskLedger(sink=sink, tenant_id="tenant-a")
    ledger.record(agent_id="oekp", state="received", correlation_id="trace1:s1")
    ledger.record(
        agent_id="oekp",
        state="failed",
        correlation_id="trace1:s1",
        ok=False,
        resolved=False,
        reason="secret-bearing failure",
    )

    assert sink.count == 2
    assert sink.events[0].tenant_id == "tenant-a"
    assert [event.state for event in sink.events] == ["received", "failed"]
    snapshot = ledger.snapshot()
    assert snapshot["storage"]["backend"] == "memory"
    assert snapshot["tenants"]["tenant-a"] == 2
    assert "secret-bearing" not in json.dumps(snapshot)


def test_sink_query_filters_by_tenant_trace_and_status():
    sink = InMemoryLedgerSink()
    ledger = TaskLedger(sink=sink)
    ledger.record(agent_id="oekp", state="received", correlation_id="trace1:s1", tenant_id="t1")
    ledger.record(agent_id="oekp", state="received", correlation_id="trace2:s1", tenant_id="t2")
    ledger.record(agent_id="oekp", state="completed", correlation_id="trace1:s1", tenant_id="t1")

    assert len(sink.query(tenant_id="t1")) == 2
    assert len(sink.query(trace_id="trace2")) == 1
    assert len(sink.query(status="completed")) == 1
    assert len(sink.query(tenant_id="t1", status="received")) == 1


async def test_signed_archive_is_tamper_evident_and_redacted(tmp_path: Path):
    path = tmp_path / "archive.jsonl"
    archive = SignedArchiveSink(path=path, secret="archive-key")
    ledger = TaskLedger(archive=archive, tenant_id="tenant-a")
    ledger.record(
        agent_id="oekp",
        state="failed",
        correlation_id="trace1:s1",
        ok=False,
        resolved=False,
        reason="api_key=sk-super-secret leaked here",
    )
    await ledger.flush()

    assert archive.verify() is True
    blob = path.read_text(encoding="utf-8")
    assert "sk-super-secret" not in blob
    assert "api_key" not in blob
    assert len(blob.strip().splitlines()) == 1

    payload = json.loads(blob.strip().splitlines()[0])
    payload["event"]["state"] = "completed"
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    assert archive.verify() is False


async def test_redis_sink_partitions_keys_and_expires_hot_state():
    client = FakeRedis()
    sink = RedisLedgerSink(client=client, hot_ttl_s=600)
    ledger = TaskLedger(sink=sink, tenant_id="tenant-a")
    ledger.record(agent_id="oekp", state="received", correlation_id="trace1:s1")
    ledger.record(agent_id="oekp", state="completed", correlation_id="trace1:s1")
    await ledger.flush()

    keys = [args[0] for name, args in client.commands if name in ("hset", "zadd")]
    assert any("tenant-a" in key and "trace1" in key for key in keys)
    assert any("received" in key for key in keys)
    assert any("completed" in key for key in keys)
    assert any(name == "expire" and args[1] == 600 for name, args in client.commands)
    assert sink.snapshot()["failed_writes"] == 0


async def test_dead_redis_degrades_to_local_observation_without_raising():
    client = FakeRedis(fail=True)
    sink = RedisLedgerSink(client=client)
    ledger = TaskLedger(sink=sink, tenant_id="tenant-a")

    event = ledger.record(agent_id="oekp", state="received", correlation_id="trace1:s1")
    await ledger.flush()

    assert event is not None
    assert ledger.counts()["tasks_tracked"] == 1
    assert sink.snapshot()["failed_writes"] > 0
    assert sink.snapshot()["backend"] == "redis"


async def test_ledger_and_sinks_are_safe_without_a_running_loop():
    sink = InMemoryLedgerSink()
    ledger = TaskLedger(sink=sink)
    # Called from synchronous code with no event loop: still recorded locally.
    ledger.record(agent_id="oekp", state="received", correlation_id="trace1:s1")
    await ledger.flush()
    assert sink.count == 1


def test_ledger_sink_protocol_is_minimal():
    assert {"emit", "snapshot"} <= set(dir(LedgerSink))
