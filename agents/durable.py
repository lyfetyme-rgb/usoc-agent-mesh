"""Durable, tenant-partitioned hot storage and signed cold lineage archive.

The process-local ``TaskLedger`` stays the authoritative fast path. This module
adds two observation-only sinks that can be composed at the mesh root:

* ``RedisLedgerSink`` — write-through hot state partitioned by tenant and trace,
  with a TTL on every key. A dead Redis only increments a counter; it can never
  change an execution decision or raise into a task handler.
* ``SignedArchiveSink`` — append-only HMAC hash chain of the *redacted* events,
  suitable for streaming to object storage for compliance.

No raw payload, goal, output or error text is ever accepted by either sink:
they only see ``TaskEvent`` objects whose reason is already a 16-hex digest.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .task_ledger import LedgerSink, TaskEvent


@runtime_checkable
class _Sink(Protocol):
    def emit(self, event: TaskEvent) -> None: ...


class InMemoryLedgerSink:
    """Deterministic sink for offline use and tests."""

    def __init__(self) -> None:
        self.events: list[TaskEvent] = []

    @property
    def count(self) -> int:
        return len(self.events)

    def emit(self, event: TaskEvent) -> None:
        self.events.append(event)

    def query(
        self,
        *,
        tenant_id: str | None = None,
        trace_id: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        matches = [
            event.model_dump()
            for event in self.events
            if (tenant_id is None or event.tenant_id == tenant_id)
            and (trace_id is None or event.trace_id == trace_id)
            and (status is None or event.state == status)
        ]
        return matches[-max(0, limit) :] if limit else matches

    def snapshot(self) -> dict[str, Any]:
        tenants: dict[str, int] = {}
        for event in self.events:
            tenants[event.tenant_id] = tenants.get(event.tenant_id, 0) + 1
        return {"backend": "memory", "events": len(self.events), "tenants": tenants}

    async def flush(self) -> None:
        return None

    async def close(self) -> None:
        return None


class RedisLedgerSink:
    """Hot-tier redis sink with tenant/trace partitioning and TTL expiry.

    Writes are scheduled from synchronous ledger hooks using the running loop.
    If no loop exists yet they are buffered until ``flush()``. Redis failures are
    counted and logged, never propagated: a telemetry outage must not turn into
    a failed or duplicated task.
    """

    def __init__(
        self,
        client: Any | None = None,
        *,
        url: str | None = None,
        socket_timeout_s: float = 5.0,
        hot_ttl_s: int = 86_400,
        prefix: str = "usoc:ledger",
    ) -> None:
        self._client = client
        self._url = url
        self._socket_timeout_s = socket_timeout_s
        self.hot_ttl_s = hot_ttl_s
        self.prefix = prefix
        self._queue: list[TaskEvent] = []
        self._tasks: set[asyncio.Task[Any]] = set()
        self.failed_writes = 0
        self.written = 0

    def _get_client(self) -> Any:
        if self._client is None:
            import redis.asyncio as aioredis

            self._client = aioredis.Redis.from_url(
                self._url or "redis://localhost:6379/0",
                socket_timeout=self._socket_timeout_s,
                decode_responses=True,
            )
        return self._client

    def emit(self, event: TaskEvent) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            self._queue.append(event)
            return
        task = loop.create_task(self._write(event))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _write(self, event: TaskEvent) -> None:
        try:
            client = self._get_client()
            record = event.model_dump(mode="json")
            event_key = f"{self.prefix}:events:{event.tenant_id}:{event.trace_id}"
            status_key = f"{self.prefix}:status:{event.tenant_id}:{event.state}"
            await client.hset(
                event_key, mapping={event.event_id: json.dumps(record, sort_keys=True)}
            )
            await client.expire(event_key, self.hot_ttl_s)
            await client.zadd(
                status_key, mapping={f"{event.trace_id}:{event.event_id}": float(event.ts)}
            )
            await client.expire(status_key, self.hot_ttl_s)
            self.written += 1
        except Exception:
            self.failed_writes += 1

    async def flush(self) -> None:
        queued, self._queue = self._queue, []
        for event in queued:
            await self._write(event)
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    async def query(
        self,
        *,
        tenant_id: str | None = None,
        trace_id: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if not tenant_id or not trace_id:
            return []
        key = f"{self.prefix}:events:{tenant_id}:{trace_id}"
        try:
            values = await self._get_client().hvals(key)
        except Exception:
            self.failed_writes += 1
            return []
        results = []
        for value in values[-max(0, limit) :]:
            try:
                record = json.loads(value)
            except (TypeError, ValueError):
                continue
            if status is None or record.get("state") == status:
                results.append(record)
        return results

    def snapshot(self) -> dict[str, Any]:
        return {
            "backend": "redis",
            "written": self.written,
            "failed_writes": self.failed_writes,
            "pending": len(self._queue) + len(self._tasks),
            "hot_ttl_s": self.hot_ttl_s,
        }

    async def close(self) -> None:
        await self.flush()
        if self._client is not None and hasattr(self._client, "aclose"):
            await self._client.aclose()


class FanoutLedgerSink:
    """Mirror ledger events to several sinks (e.g. Redis hot + Postgres cold).

    Each sink is independent: one failing sink cannot stop the others or affect
    execution. Queries and snapshots come from the first sink that supports the
    operation, preferring the durable (last) sink so unbounded history wins.
    """

    def __init__(self, *sinks: Any) -> None:
        self.sinks = list(sinks)

    def emit(self, event: TaskEvent) -> None:
        for sink in self.sinks:
            try:
                sink.emit(event)
            except Exception:
                pass

    async def flush(self) -> None:
        for sink in self.sinks:
            if hasattr(sink, "flush"):
                try:
                    await sink.flush()
                except Exception:
                    pass

    async def query(self, **kwargs: Any) -> list[dict[str, Any]]:
        for sink in reversed(self.sinks):
            if hasattr(sink, "query"):
                try:
                    return await sink.query(**kwargs)
                except Exception:
                    continue
        return []

    def snapshot(self) -> dict[str, Any]:
        snapshots = [
            sink.snapshot()
            for sink in self.sinks
            if hasattr(sink, "snapshot")
        ]
        return {"backend": "fanout", "tiers": snapshots}

    async def close(self) -> None:
        for sink in self.sinks:
            if hasattr(sink, "close"):
                try:
                    await sink.close()
                except Exception:
                    pass


class SignedArchiveSink:
    """Append-only HMAC hash chain over redacted task events.

    The chain is verified by recomputing it from genesis; a modified record or
    a removed entry fails verification. Each record contains only the opaque
    ``TaskEvent`` fields, so the archive is safe to stream to cold storage.
    """

    def __init__(self, *, path: str | Path, secret: str) -> None:
        self.path = Path(path)
        self.secret = secret
        self._records: list[dict[str, Any]] = []
        self._written = 0
        self._prev = "0" * 64

    def emit(self, event: TaskEvent) -> None:
        record = {"seq": len(self._records) + 1, "prev": self._prev, "event": event.model_dump()}
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = hmac.new(self.secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        self._records.append({**record, "hash": digest})
        self._prev = digest

    async def flush(self) -> None:
        if self._written >= len(self._records):
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        new = self._records[self._written :]
        with self.path.open("a", encoding="utf-8") as handle:
            for record in new:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
        self._written = len(self._records)

    def verify(self) -> bool:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return False
        prev = "0" * 64
        for expected_seq, line in enumerate(lines, 1):
            try:
                entry = json.loads(line)
            except ValueError:
                return False
            digest = entry.pop("hash", "")
            if entry.get("seq") != expected_seq or entry.get("prev") != prev:
                return False
            canonical = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
            actual = hmac.new(self.secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(actual, digest):
                return False
            prev = digest
        return True

    def snapshot(self) -> dict[str, Any]:
        return {"backend": "signed-jsonl", "records": len(self._records), "verified": self.verify()}


__all__ = [
    "LedgerSink",
    "InMemoryLedgerSink",
    "RedisLedgerSink",
    "FanoutLedgerSink",
    "SignedArchiveSink",
]
