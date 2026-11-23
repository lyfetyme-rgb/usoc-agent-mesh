"""Transactional approval backend tests (offline SQL/cache fakes)."""

from __future__ import annotations

import asyncio
import copy
import json

from agents.contracts import ActionClass, RiskLevel
from agents.governance import ApprovalRequest, ApprovalStatus
from agents.postgres import PostgresApprovalStore
from agents.security import Signer

SECRET = "test-shared-secret-with-at-least-32-characters"


class FakeBackend:
    """Minimal transactional-ish backend; row locking is simulated with a lock."""

    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], dict] = {}
        self.partitions: set[str] = set()
        self.lock = asyncio.Lock()
        self.lock_held_during_apply = False

    async def ensure_partition(self, tenant_id: str) -> None:
        self.partitions.add(tenant_id)

    async def fetch(self, tenant_id: str, record_id: str, *, for_update: bool) -> dict | None:
        row = self.rows.get((tenant_id, record_id))
        return copy.deepcopy(row)

    async def transact_record(self, tenant_id, record_id, apply) -> dict | None:
        async with self.lock:
            self.lock_held_during_apply = self.lock.locked()
            # Force a scheduling point while the lock is held: a read-then-write
            # implementation would let a second coroutine see stale state here.
            await asyncio.sleep(0)
            raw = copy.deepcopy(self.rows.get((tenant_id, record_id)))
            updated = await apply(raw)
            if updated is None:
                return None
            self.rows[(tenant_id, record_id)] = copy.deepcopy(updated)
            return updated

    async def insert(self, tenant_id: str, record: dict) -> bool:
        async with self.lock:
            key = (tenant_id, record["id"])
            if key in self.rows:
                return False
            self.rows[key] = copy.deepcopy(record)
            return True

    async def update(self, tenant_id: str, record: dict) -> None:
        async with self.lock:
            self.rows[(tenant_id, record["id"])] = copy.deepcopy(record)

    async def pending(self, tenant_id: str) -> list[dict]:
        return [
            copy.deepcopy(row)
            for (tenant, _), row in self.rows.items()
            if tenant == tenant_id and row["status"] == ApprovalStatus.PENDING.value
        ]

    async def append_events(self, tenant_id: str, events: list[dict]) -> None:
        raise AssertionError("not used by approval tests")

    async def events(self, tenant_id: str, trace_id: str, limit: int) -> list[dict]:
        raise AssertionError("not used by approval tests")

    async def close(self) -> None:
        return None


class FakeCache:
    def __init__(self) -> None:
        self.data: dict[str, str] = {}
        self.deletes: list[str] = []

    async def get(self, key: str) -> str | None:
        return self.data.get(key)

    async def setex(self, key: str, ttl: int, value: str) -> None:
        self.data[key] = value

    async def delete(self, key: str) -> None:
        self.deletes.append(key)
        self.data.pop(key, None)


def store(signer: Signer | None = None) -> tuple[PostgresApprovalStore, FakeBackend, FakeCache]:
    backend = FakeBackend()
    cache = FakeCache()
    return (
        PostgresApprovalStore(
            backend,
            cache=cache,
            signer=signer,
            approvers={"bob"},
            require_allowlist=True,
        ),
        backend,
        cache,
    )


def request(tenant: str = "tenant-a", approval_id: str = "apr-1") -> ApprovalRequest:
    return ApprovalRequest(
        id=approval_id,
        tenant_id=tenant,
        action_class=ActionClass.EXECUTE,
        target="sandbox/job",
        risk=RiskLevel.LOW,
        requested_by="alice",
    )


async def test_request_decide_consume_round_trip_and_single_use():
    approvals, backend, cache = store(Signer(SECRET))
    issued = await approvals.request(request())
    assert issued.status is ApprovalStatus.PENDING
    assert ("tenant-a", "apr-1") in backend.rows

    decided = await approvals.decide(
        "apr-1", tenant_id="tenant-a", approved=True, approver="bob"
    )
    assert decided.status is ApprovalStatus.APPROVED
    assert await approvals.get("apr-1", tenant_id="tenant-a") == decided

    spent = await approvals.consume(
        "apr-1", tenant_id="tenant-a", nonce=issued.nonce, correlation_id="trace-1"
    )
    assert spent is not None and spent.consumed_by == "trace-1"
    assert await approvals.consume(
        "apr-1", tenant_id="tenant-a", nonce=issued.nonce
    ) is None
    assert any("apr-1" in key for key in cache.deletes)  # hot cache invalidated


async def test_partitions_are_tenant_scoped_even_with_the_same_approval_id():
    approvals, backend, _ = store()
    a = await approvals.request(request("tenant-a"))
    b = await approvals.request(request("tenant-b"))
    assert a.nonce != b.nonce
    assert backend.partitions == {"tenant-a", "tenant-b"}

    assert await approvals.get("apr-1", tenant_id="tenant-c") is None
    decided_b = await approvals.decide(
        "apr-1", tenant_id="tenant-b", approved=True, approver="bob"
    )
    spent_wrong_tenant = await approvals.consume(
        "apr-1", tenant_id="tenant-a", nonce=b.nonce
    )
    assert spent_wrong_tenant is None
    assert await approvals.consume("apr-1", tenant_id="tenant-b", nonce=b.nonce) is not None
    still_pending_a = await approvals.get("apr-1", tenant_id="tenant-a")
    assert still_pending_a is not None and still_pending_a.status is ApprovalStatus.PENDING
    assert decided_b.status is ApprovalStatus.APPROVED


async def test_tampered_or_badly_signed_database_rows_are_rejected():
    approvals, backend, _ = store(Signer(SECRET))
    await approvals.request(request())
    row = backend.rows[("tenant-a", "apr-1")]
    row["target"] = "sandbox/other"
    # Drop the cached (still-valid) copy so the read exercises the tampered
    # database row; the signature check must reject it.
    approvals.cache.data.clear()
    assert await approvals.get("apr-1", tenant_id="tenant-a") is None
    assert approvals.rejected == 1
    assert await approvals.consume(
        "apr-1", tenant_id="tenant-a", nonce="anything"
    ) is None


async def test_concurrent_consumes_spend_the_nonce_once():
    approvals, backend, _ = store()
    issued = await approvals.request(request())
    await approvals.decide("apr-1", tenant_id="tenant-a", approved=True, approver="bob")
    results = await asyncio.gather(
        *(
            approvals.consume("apr-1", tenant_id="tenant-a", nonce=issued.nonce)
            for _ in range(8)
        )
    )
    assert backend.lock_held_during_apply
    assert len([r for r in results if r is not None]) == 1


async def test_pending_is_partition_scoped():
    approvals, _, _ = store()
    await approvals.request(request("tenant-a", "apr-a"))
    await approvals.request(request("tenant-b", "apr-b"))
    assert [r.id for r in await approvals.pending(tenant_id="tenant-a")] == ["apr-a"]
    assert [r.id for r in await approvals.pending(tenant_id="tenant-b")] == ["apr-b"]


async def test_invalid_tenant_fails_closed():
    approvals, _, _ = store()
    try:
        await approvals.get("apr-1", tenant_id="")
    except Exception as exc:
        assert "tenant_id" in str(exc)
    else:
        raise AssertionError("empty tenant was accepted")
