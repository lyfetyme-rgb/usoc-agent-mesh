"""Transactional, tenant-partitioned PostgreSQL governance storage.

Two backends live here:

* ``PostgresApprovalStore`` replaces ``FileApprovalStore``. Every state change
  is a row-locked transaction, so several control-plane replicas can safely
  decide and consume the same approval without OS file locks. Nonce atomicity
  comes from ``SELECT ... FOR UPDATE`` plus the signed ``consumed_at`` field;
  all identity, TTL, quorum and shadow checks are still performed by
  ``InMemoryApprovalStore`` methods on a per-transaction view.
* ``PostgresLedgerStore`` replaces the bounded in-process ``TaskLedger`` ring
  with an append-only, tenant-partitioned table. There is no 2,048-slot cap
  and no eviction: history is queried by ``(tenant_id, trace_id)``.

Neither module imports a database driver at import time. ``psycopg`` is loaded
only when the default adapter is constructed; callers may inject any object
implementing ``SqlBackend`` for offline tests. Redis is a *hot cache only*:
consume/decide always take the database lock and never trust cached state.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import uuid
from typing import Any, Awaitable, Callable, Protocol

from .evidence import EvidenceRecord
from .governance import (
    ApprovalCredential,
    ApprovalRequest,
    ApprovalStatus,
    InMemoryApprovalStore,
)
from .security import SecurityError, Signer
from .task_ledger import TaskEvent

DEFAULT_TENANT = "default"
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9_]+$")


# -- adapter -----------------------------------------------------------------
class SqlBackend(Protocol):
    """The narrow SQL surface the stores need (easy to fake in tests)."""

    async def ensure_partition(self, tenant_id: str) -> None: ...
    async def fetch(self, tenant_id: str, record_id: str, *, for_update: bool) -> dict | None: ...
    async def transact_record(
        self,
        tenant_id: str,
        record_id: str,
        apply: Callable[[dict | None], Awaitable[dict | None]],
    ) -> dict | None: ...
    async def insert(self, tenant_id: str, record: dict) -> bool: ...
    async def update(self, tenant_id: str, record: dict) -> None: ...
    async def pending(self, tenant_id: str) -> list[dict]: ...
    async def append_events(self, tenant_id: str, events: list[dict]) -> None: ...
    async def events(self, tenant_id: str, trace_id: str, limit: int) -> list[dict]: ...
    async def append_evidence(
        self,
        tenant_id: str,
        record: dict,
        finalize: Callable[[int, str], dict],
    ) -> dict: ...
    async def evidence_records(self, tenant_id: str) -> list[dict]: ...
    async def close(self) -> None: ...


class PsycopgBackend:
    """psycopg3 adapter. Requires ``pip install agent-mesh[postgres]``."""

    def __init__(self, dsn: str, *, approval_table: str = "governance_approvals",
                 ledger_table: str = "task_ledger_events",
                 evidence_table: str = "oekp_evidence",
                 evidence_head_table: str = "oekp_evidence_head",
                 connect: Any | None = None) -> None:
        if not dsn and connect is None:
            raise SecurityError("PostgreSQL DSN is required")
        names = (approval_table, ledger_table, evidence_table, evidence_head_table)
        for name in names:
            if not _SAFE_IDENTIFIER.fullmatch(name):
                raise SecurityError(f"unsafe SQL identifier: {name!r}")
        if len(set(names)) != len(names):
            raise SecurityError("PostgreSQL table names must be distinct")
        self.dsn = dsn
        self.approval_table = approval_table
        self.ledger_table = ledger_table
        self.evidence_table = evidence_table
        self.evidence_head_table = evidence_head_table
        self._connect = connect
        self._partitions: set[str] = set()
        self._schema_ready = False

    async def _connection(self):
        if self._connect is not None:
            return await self._connect()
        try:
            import psycopg  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - exercised by install docs
            raise SecurityError(
                "PostgreSQL backend requires agent-mesh[postgres] (psycopg3)"
            ) from exc
        return await psycopg.AsyncConnection.connect(self.dsn)

    @staticmethod
    def _partition_name(table: str, tenant_id: str) -> str:
        digest = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()[:16]
        return f"{table}_{digest}"

    async def _execute(self, sql: str, params: tuple = ()) -> Any:
        async with await self._connection() as conn:
            async with conn.transaction():
                async with conn.cursor() as cur:
                    await cur.execute(sql, params)
                    if cur.description:
                        return await cur.fetchall()
                    return cur.rowcount

    async def _one(self, sql: str, params: tuple) -> dict | None:
        async with await self._connection() as conn:
            async with conn.transaction():
                async with conn.cursor() as cur:
                    await cur.execute(sql, params)
                    row = await cur.fetchone()
                    return dict(row) if row else None

    async def _many(self, sql: str, params: tuple) -> list[dict]:
        rows = await self._execute(sql, params) or []
        return [dict(row) for row in rows]

    async def _schema(self) -> None:
        if self._schema_ready:
            return
        await self._execute(
            f"""CREATE TABLE IF NOT EXISTS {self.approval_table} (
                    tenant_id TEXT NOT NULL,
                    id TEXT NOT NULL,
                    record JSONB NOT NULL,
                    status TEXT NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    PRIMARY KEY (tenant_id, id)
                ) PARTITION BY LIST (tenant_id)"""
        )
        await self._execute(
            f"""CREATE TABLE IF NOT EXISTS {self.ledger_table} (
                    tenant_id TEXT NOT NULL,
                    trace_id TEXT NOT NULL,
                    seq BIGINT NOT NULL,
                    event JSONB NOT NULL,
                    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    PRIMARY KEY (tenant_id, trace_id, seq)
                ) PARTITION BY LIST (tenant_id)"""
        )
        await self._execute(
            f"""CREATE TABLE IF NOT EXISTS {self.evidence_table} (
                    tenant_id TEXT NOT NULL,
                    seq BIGINT NOT NULL,
                    record JSONB NOT NULL,
                    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    PRIMARY KEY (tenant_id, seq)
                )"""
        )
        await self._execute(
            f"""CREATE TABLE IF NOT EXISTS {self.evidence_head_table} (
                    tenant_id TEXT PRIMARY KEY,
                    seq BIGINT NOT NULL DEFAULT 0,
                    last_hash TEXT NOT NULL DEFAULT 'genesis'
                )"""
        )
        self._schema_ready = True

    async def ensure_partition(self, tenant_id: str) -> None:
        await self._schema()
        for table in (self.approval_table, self.ledger_table):
            name = self._partition_name(table, tenant_id)
            if name in self._partitions:
                continue
            await self._execute(
                f"CREATE TABLE IF NOT EXISTS {name} PARTITION OF {table} FOR VALUES IN (%s)",
                (tenant_id,),
            )
            self._partitions.add(name)

    async def fetch(self, tenant_id: str, record_id: str, *, for_update: bool) -> dict | None:
        suffix = " FOR UPDATE" if for_update else ""
        row = await self._one(
            f"SELECT record FROM {self.approval_table} "
            f"WHERE tenant_id=%s AND id=%s{suffix}",
            (tenant_id, record_id),
        )
        if not row:
            return None
        record = row["record"]
        return json.loads(record) if isinstance(record, str) else record

    async def transact_record(
        self,
        tenant_id: str,
        record_id: str,
        apply: Callable[[dict | None], Awaitable[dict | None]],
    ) -> dict | None:
        """Hold the row lock for the entire read-modify-write, not just the read.

        ``fetch(for_update=True)`` cannot keep ``FOR UPDATE`` past its own
        connection's transaction. Approval decisions and nonce spends therefore
        go through this callback: the row is locked, governance logic runs on
        that locked snapshot, and the update commits in the same transaction.
        Any exception rolls the whole operation back.
        """
        async with await self._connection() as conn:
            async with conn.transaction():
                async with conn.cursor() as cur:
                    await cur.execute(
                        f"SELECT record FROM {self.approval_table} "
                        "WHERE tenant_id=%s AND id=%s FOR UPDATE",
                        (tenant_id, record_id),
                    )
                    row = await cur.fetchone()
                    raw = None
                    if row is not None:
                        value = row["record"]
                        raw = json.loads(value) if isinstance(value, str) else value
                    updated = await apply(raw)
                    if updated is None:
                        return None
                    await cur.execute(
                        f"""UPDATE {self.approval_table}
                            SET record=%s, status=%s, updated_at=now()
                            WHERE tenant_id=%s AND id=%s""",
                        (
                            json.dumps(updated),
                            updated["status"],
                            tenant_id,
                            record_id,
                        ),
                    )
                    return updated

    async def insert(self, tenant_id: str, record: dict) -> bool:
        count = await self._execute(
            f"""INSERT INTO {self.approval_table} (tenant_id, id, record, status)
                VALUES (%s, %s, %s, %s) ON CONFLICT (tenant_id, id) DO NOTHING""",
            (tenant_id, record["id"], json.dumps(record), record["status"]),
        )
        return int(count or 0) > 0

    async def update(self, tenant_id: str, record: dict) -> None:
        await self._execute(
            f"""UPDATE {self.approval_table}
                SET record=%s, status=%s, updated_at=now()
                WHERE tenant_id=%s AND id=%s""",
            (json.dumps(record), record["status"], tenant_id, record["id"]),
        )

    async def pending(self, tenant_id: str) -> list[dict]:
        rows = await self._many(
            f"SELECT record FROM {self.approval_table} WHERE tenant_id=%s AND status=%s",
            (tenant_id, ApprovalStatus.PENDING.value),
        )
        return [json.loads(r["record"]) if isinstance(r["record"], str) else r["record"] for r in rows]

    async def append_events(self, tenant_id: str, events: list[dict]) -> None:
        await self.ensure_partition(tenant_id)
        if not events:
            return
        # Sequence numbers are assigned by the database, not by TaskEvent (which
        # deliberately has no seq field). A per-trace advisory lock makes
        # concurrent replicas assign gap-free sequences instead of racing MAX().
        async with await self._connection() as conn:
            async with conn.transaction():
                async with conn.cursor() as cur:
                    for event in events:
                        trace = event["trace_id"]
                        await cur.execute(
                            "SELECT pg_advisory_xact_lock(hashtext(%s))",
                            (f"{tenant_id}:{trace}",),
                        )
                        await cur.execute(
                            f"""INSERT INTO {self.ledger_table} (tenant_id, trace_id, seq, event)
                                SELECT %s, %s, COALESCE(MAX(seq), 0) + 1, %s::jsonb
                                FROM {self.ledger_table}
                                WHERE tenant_id=%s AND trace_id=%s""",
                            (tenant_id, trace, json.dumps(event), tenant_id, trace),
                        )

    async def events(self, tenant_id: str, trace_id: str, limit: int) -> list[dict]:
        rows = await self._many(
            f"""SELECT event FROM {self.ledger_table}
                WHERE tenant_id=%s AND trace_id=%s ORDER BY seq DESC LIMIT %s""",
            (tenant_id, trace_id, int(limit)),
        )
        return [json.loads(r["event"]) if isinstance(r["event"], str) else r["event"] for r in rows]

    async def append_evidence(
        self,
        tenant_id: str,
        record: dict,
        finalize: Callable[[int, str], dict],
    ) -> dict:
        """Atomically assign seq/prev under a row lock and insert the record.

        The whole head-update + append is one transaction, so two replicas can
        append concurrently without forking the OEKP chain.
        """
        await self._schema()
        async with await self._connection() as conn:
            async with conn.transaction():
                async with conn.cursor() as cur:
                    await cur.execute(
                        f"""INSERT INTO {self.evidence_head_table} (tenant_id, seq, last_hash)
                            VALUES (%s, 0, 'genesis') ON CONFLICT (tenant_id) DO NOTHING""",
                        (tenant_id,),
                    )
                    await cur.execute(
                        f"SELECT seq, last_hash FROM {self.evidence_head_table} "
                        "WHERE tenant_id=%s FOR UPDATE",
                        (tenant_id,),
                    )
                    head = await cur.fetchone()
                    seq = int(head[0]) + 1
                    prev = str(head[1])
                    completed = finalize(seq, prev)
                    await cur.execute(
                        f"""INSERT INTO {self.evidence_table} (tenant_id, seq, record)
                            VALUES (%s, %s, %s::jsonb)""",
                        (tenant_id, seq, json.dumps(completed)),
                    )
                    await cur.execute(
                        f"""UPDATE {self.evidence_head_table}
                            SET seq=%s, last_hash=%s WHERE tenant_id=%s""",
                        (seq, completed["hash"], tenant_id),
                    )
                    return completed

    async def evidence_records(self, tenant_id: str) -> list[dict]:
        await self._schema()
        rows = await self._many(
            f"SELECT record FROM {self.evidence_table} WHERE tenant_id=%s ORDER BY seq",
            (tenant_id,),
        )
        return [
            json.loads(r["record"]) if isinstance(r["record"], str) else r["record"]
            for r in rows
        ]

    async def close(self) -> None:
        self._schema_ready = False
        self._partitions.clear()


# -- approvals ---------------------------------------------------------------
class PostgresApprovalStore:
    """Drop-in ``ApprovalStore`` with row locks and a Redis read cache."""

    def __init__(
        self,
        backend: SqlBackend | None = None,
        *,
        dsn: str = "",
        cache: Any | None = None,
        cache_ttl_s: float = 2.0,
        namespace: str = "usoc",
        shadow: bool = False,
        signer: Signer | None = None,
        approvers: set[str] | None = None,
        require_allowlist: bool = False,
        ttl_s: int = 86_400,
        approver_verifier: Any = None,
        close_backend: bool = True,
    ) -> None:
        self.backend = backend or PsycopgBackend(dsn)
        self.close_backend = close_backend
        self.cache = cache
        self.cache_ttl_s = max(0.0, float(cache_ttl_s))
        self.cache_prefix = f"{namespace}:{'shadow' if shadow else 'live'}:approval"
        self.signer = signer
        self.approvers = approvers
        self.require_allowlist = require_allowlist
        self.ttl_s = ttl_s
        self.approver_verifier = approver_verifier
        self.rejected = 0

    def _view(self) -> InMemoryApprovalStore:
        return InMemoryApprovalStore(
            signer=self.signer,
            approvers=self.approvers,
            require_allowlist=self.require_allowlist,
            ttl_s=self.ttl_s,
            approver_verifier=self.approver_verifier,
        )

    @staticmethod
    def _tenant(tenant_id: str) -> str:
        # ``None`` means "use the default partition"; an explicitly empty or
        # whitespace-only value is a caller bug and must fail closed rather
        # than silently landing in the shared default partition.
        if tenant_id is None:
            return DEFAULT_TENANT
        tenant = tenant_id.strip()
        if not tenant or len(tenant) > 200:
            raise SecurityError("invalid tenant_id for approval store")
        return tenant

    def _key(self, tenant_id: str, approval_id: str) -> str:
        return f"{self.cache_prefix}:{tenant_id}:{approval_id}"

    def _decode(self, raw: dict | None) -> ApprovalRequest | None:
        if raw is None:
            return None
        try:
            req = ApprovalRequest.model_validate(raw)
        except ValueError:
            self.rejected += 1
            return None
        if self.signer is not None:
            ok, _ = self.signer.verify_record(
                "approval", req.model_dump(mode="json", exclude={"signature"}), req.signature
            )
            if not ok:
                self.rejected += 1
                return None
        return req

    async def _cache_get(self, tenant_id: str, approval_id: str) -> ApprovalRequest | None:
        if self.cache is None:
            return None
        try:
            raw = await self.cache.get(self._key(tenant_id, approval_id))
        except Exception:
            return None  # cache is an optimisation, never a trust boundary
        if not raw:
            return None
        try:
            return self._decode(json.loads(raw))
        except (TypeError, ValueError):
            return None

    async def _cache_set(self, tenant_id: str, req: ApprovalRequest) -> None:
        if self.cache is None or self.cache_ttl_s <= 0:
            return
        try:
            await self.cache.setex(
                self._key(tenant_id, req.id), int(self.cache_ttl_s) or 1,
                json.dumps(req.model_dump(mode="json")),
            )
        except Exception:
            pass

    async def _cache_drop(self, tenant_id: str, approval_id: str) -> None:
        if self.cache is None:
            return
        try:
            await self.cache.delete(self._key(tenant_id, approval_id))
        except Exception:
            pass

    async def request(self, req: ApprovalRequest) -> ApprovalRequest:
        tenant = self._tenant(req.tenant_id)
        await self.backend.ensure_partition(tenant)
        issued = await self._view().request(req.model_copy(update={"tenant_id": tenant}))
        if not await self.backend.insert(tenant, issued.model_dump(mode="json")):
            raise ValueError(f"approval {issued.id} already exists")
        await self._cache_set(tenant, issued)
        return issued

    async def get(self, approval_id: str, *, tenant_id: str = DEFAULT_TENANT) -> ApprovalRequest | None:
        tenant = self._tenant(tenant_id)
        cached = await self._cache_get(tenant, approval_id)
        if cached is not None:
            return cached
        await self.backend.ensure_partition(tenant)
        req = self._decode(await self.backend.fetch(tenant, approval_id, for_update=False))
        if req is not None:
            await self._cache_set(tenant, req)
        return req

    async def decide(
        self,
        approval_id: str,
        *,
        approved: bool,
        approver: str,
        note: str | None = None,
        credential: ApprovalCredential | None = None,
        tenant_id: str = DEFAULT_TENANT,
    ) -> ApprovalRequest:
        tenant = self._tenant(tenant_id)
        await self.backend.ensure_partition(tenant)

        async def apply(raw: dict | None) -> dict | None:
            req = self._decode(raw)
            if req is None:
                raise KeyError(f"no such approval: {approval_id}")
            view = self._view()
            view._items[approval_id] = req
            updated = await view.decide(
                approval_id, approved=approved, approver=approver, note=note,
                credential=credential, tenant_id=tenant,
            )
            return updated.model_dump(mode="json")

        updated_raw = await self.backend.transact_record(tenant, approval_id, apply)
        await self._cache_drop(tenant, approval_id)
        if updated_raw is None:
            raise KeyError(f"no such approval: {approval_id}")
        return ApprovalRequest.model_validate(updated_raw)

    async def consume(
        self,
        approval_id: str,
        *,
        nonce: str,
        correlation_id: str = "",
        tenant_id: str = DEFAULT_TENANT,
    ) -> ApprovalRequest | None:
        tenant = self._tenant(tenant_id)
        await self.backend.ensure_partition(tenant)

        async def apply(raw: dict | None) -> dict | None:
            req = self._decode(raw)
            if req is None:
                return None
            view = self._view()
            view._items[approval_id] = req
            spent = await view.consume(
                approval_id, nonce=nonce, correlation_id=correlation_id, tenant_id=tenant
            )
            return spent.model_dump(mode="json") if spent is not None else None

        spent_raw = await self.backend.transact_record(tenant, approval_id, apply)
        await self._cache_drop(tenant, approval_id)
        return ApprovalRequest.model_validate(spent_raw) if spent_raw is not None else None

    async def pending(self, *, tenant_id: str = DEFAULT_TENANT) -> list[ApprovalRequest]:
        tenant = self._tenant(tenant_id)
        await self.backend.ensure_partition(tenant)
        return [
            req
            for req in (self._decode(raw) for raw in await self.backend.pending(tenant))
            if req is not None
        ]

    async def close(self) -> None:
        if self.close_backend:
            await self.backend.close()
        if self.cache is not None and hasattr(self.cache, "aclose"):
            try:
                await self.cache.aclose()
            except Exception:
                pass


# -- ledger ------------------------------------------------------------------
class PostgresLedgerStore:
    """Append-only tenant-partitioned task ledger backed by PostgreSQL."""

    def __init__(self, backend: SqlBackend | None = None, *, dsn: str = "",
                 close_backend: bool = True) -> None:
        self.backend = backend or PsycopgBackend(dsn)
        self.close_backend = close_backend

    async def append(self, tenant_id: str, events: list[dict]) -> None:
        tenant = self._tenant(tenant_id)
        if events:
            await self.backend.append_events(tenant, events)

    async def events(self, tenant_id: str, trace_id: str, limit: int = 1_000) -> list[dict]:
        tenant = self._tenant(tenant_id)
        rows = await self.backend.events(tenant, trace_id, max(1, int(limit)))
        return list(reversed(rows))  # chronological order, unlike the SQL scan

    @staticmethod
    def _tenant(tenant_id: str) -> str:
        if tenant_id is None:
            return DEFAULT_TENANT
        tenant = tenant_id.strip()
        if not tenant or len(tenant) > 200:
            raise SecurityError("invalid tenant_id for ledger store")
        return tenant

    async def close(self) -> None:
        if self.close_backend:
            await self.backend.close()


class PostgresLedgerSink:
    """Append-only, unbounded ``LedgerSink`` over :class:`PostgresLedgerStore`.

    Unlike the in-process 2,048-slot ring this sink never evicts a record:
    history is queried by ``(tenant_id, trace_id)`` from PostgreSQL. It is
    observation-only -- write failures are counted and swallowed.
    """

    def __init__(
        self,
        store: PostgresLedgerStore | None = None,
        *,
        backend: SqlBackend | None = None,
        dsn: str = "",
        close_backend: bool = True,
    ) -> None:
        self.store = store or PostgresLedgerStore(
            backend, dsn=dsn, close_backend=close_backend
        )
        self._queue: list[TaskEvent] = []
        self._tasks: set[asyncio.Task[Any]] = set()
        self.failed_writes = 0
        self.written = 0

    def emit(self, event: TaskEvent) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            self._queue.append(event)
            return
        task = loop.create_task(self._write([event]))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _write(self, events: list[TaskEvent]) -> None:
        # A queued batch may span tenants; never attribute one tenant's events
        # to another tenant's partition.
        by_tenant: dict[str, list[dict[str, Any]]] = {}
        for event in events:
            by_tenant.setdefault(event.tenant_id, []).append(event.model_dump(mode="json"))
        try:
            for tenant_id, records in by_tenant.items():
                await self.store.append(tenant_id, records)
            self.written += len(events)
        except Exception:
            self.failed_writes += 1

    async def flush(self) -> None:
        queued, self._queue = self._queue, []
        if queued:
            await self._write(queued)
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
        if not trace_id:
            return []
        try:
            events = await self.store.events(tenant_id or DEFAULT_TENANT, trace_id, limit)
        except Exception:
            self.failed_writes += 1
            return []
        return [e for e in events if status is None or e.get("state") == status]

    def snapshot(self) -> dict[str, Any]:
        return {
            "backend": "postgres",
            "written": self.written,
            "failed_writes": self.failed_writes,
            "pending": len(self._queue) + len(self._tasks),
        }

    async def close(self) -> None:
        await self.flush()
        await self.store.close()


class PostgresEvidenceChain:
    """Shared-nothing OEKP evidence chain with transactional appends.

    Drop-in for :class:`~agents.evidence.EvidenceChain` when control-plane
    replicas must scale without a shared PVC. Sequence assignment and the
    previous-hash handoff happen inside one row-locked database transaction, so
    no pod can fork the chain. Verification rules are identical to the file
    chain: sequence, previous hash, recomputed content hash and keyed MAC.
    """

    def __init__(
        self,
        backend: SqlBackend,
        *,
        signer: Signer | None = None,
        tenant_id: str = DEFAULT_TENANT,
        close_backend: bool = True,
    ) -> None:
        self.backend = backend
        self.close_backend = close_backend
        self.signer = signer
        self.tenant_id = tenant_id
        self._records: list[EvidenceRecord] = []
        self._lock = asyncio.Lock()
        self._seq = 0
        self._last_hash = "genesis"
        self._loaded = False

    async def _reload(self) -> None:
        """Re-read and verify the whole chain from the database.

        Called after every append because another replica may have written the
        immediately preceding record between our load and commit. A stale local
        tail would otherwise fork the next append or report a false gap.
        """
        raw = await self.backend.evidence_records(self.tenant_id)
        self._records = [EvidenceRecord.model_validate(row) for row in raw]
        if self._records:
            self._seq = self._records[-1].seq
            self._last_hash = self._records[-1].hash
        else:
            self._seq, self._last_hash = 0, "genesis"
        ok, detail = self.verify()
        if not ok:
            raise SecurityError(f"Postgres evidence chain failed verification: {detail}")
        self._loaded = True

    async def refresh(self) -> None:
        """Operator-visible resync for read-mostly replicas."""
        async with self._lock:
            await self._reload()

    async def _ensure_loaded(self) -> None:
        if not self._loaded:
            await self._reload()

    async def append(
        self,
        *,
        kind: str,
        actor: str,
        correlation_id: str = "",
        data: dict[str, Any] | None = None,
        subsystem: str | None = None,
        mission_id: str | None = None,
        classification: str = "internal",
        provenance: list[str] | None = None,
        origin: str | None = None,
        tainted: bool = False,
        rehearsal_only: bool = False,
        shadow: bool = False,
    ) -> EvidenceRecord:
        async with self._lock:
            await self._ensure_loaded()

            def finalize(seq: int, prev: str) -> dict[str, Any]:
                record = EvidenceRecord(
                    seq=seq,
                    id=f"ev-{uuid.uuid4().hex[:12]}",
                    kind=kind,
                    actor=actor,
                    subsystem=subsystem,
                    correlation_id=correlation_id,
                    mission_id=mission_id,
                    classification=classification,
                    data=data or {},
                    provenance=list(provenance or []),
                    origin=origin,
                    tainted=bool(tainted),
                    rehearsal_only=bool(rehearsal_only),
                    shadow=bool(shadow),
                    prev_hash=prev,
                )
                record.hash = record.compute_hash()
                if self.signer is not None:
                    record.mac = self.signer.sign_record(
                        "evidence", record.model_dump(mode="json", exclude={"mac"})
                    )
                return record.model_dump(mode="json")

            completed = await self.backend.append_evidence(self.tenant_id, {}, finalize)
            # Re-read instead of trusting the local tail: another replica may
            # have committed records between our load and this append.
            await self._reload()
            wanted_seq = int(completed["seq"])
            for record in self._records:
                if record.seq == wanted_seq:
                    return record
            raise SecurityError("appended evidence record disappeared from the database")

    def records(self, limit: int | None = None) -> list[EvidenceRecord]:
        return self._records[-limit:] if limit else list(self._records)

    def verify(self) -> tuple[bool, str]:
        prev = "genesis"
        for expected_seq, record in enumerate(self._records, 1):
            if record.seq != expected_seq:
                return False, f"sequence gap at record {record.id}"
            if record.prev_hash != prev:
                return False, f"broken chain at record {record.id}"
            if record.compute_hash() != record.hash:
                return False, f"record {record.id} was modified"
            if self.signer is not None:
                ok, _ = self.signer.verify_record(
                    "evidence", record.model_dump(mode="json", exclude={"mac"}), record.mac
                )
                if not ok:
                    return False, f"record {record.id} has an invalid MAC"
            prev = record.hash
        return True, f"{len(self._records)} records verified"

    @property
    def head(self) -> tuple[int, str]:
        return self._seq, self._last_hash

    async def close(self) -> None:
        # Mesh passes close_backend=False because it owns the shared adapter;
        # CLI callers create their own and must not leak it.
        if self.close_backend:
            await self.backend.close()
