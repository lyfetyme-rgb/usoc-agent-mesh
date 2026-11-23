"""Mesh composition for the stateless, multi-replica production topology."""

from __future__ import annotations

import asyncio
import copy
import json

from agents.config import Settings
from agents.durable import FanoutLedgerSink, RedisLedgerSink
from agents.mesh import Mesh
from agents.postgres import (
    PostgresApprovalStore,
    PostgresEvidenceChain,
    PostgresLedgerSink,
    PostgresLedgerStore,
    PsycopgBackend,
)
from agents.security import SecurityError, Signer
from agents.worm import S3WormArchiveSink

SECRET = "production-cluster-key-with-at-least-32-characters"


def production_settings(**overrides) -> Settings:
    return Settings(
        _env_file=None,
        shared_secret=SECRET,
        approval_backend="postgres",
        evidence_backend="postgres",
        ledger_backend="postgres",
        postgres_dsn="postgresql://mesh:mesh@postgres:5432/usoc",
        archive_backend="s3",
        archive_bucket="usoc-evidence",
        **overrides,
    )


async def test_mesh_composes_transactional_and_worm_backends():
    mesh = Mesh(settings=production_settings())
    await mesh.start()
    try:
        assert isinstance(mesh.approvals, PostgresApprovalStore)
        assert isinstance(mesh.ledger.sink, FanoutLedgerSink)
        assert any(isinstance(t, RedisLedgerSink) for t in mesh.ledger.sink.sinks)
        assert any(isinstance(t, PostgresLedgerSink) for t in mesh.ledger.sink.sinks)
        assert isinstance(mesh.ledger.archive, S3WormArchiveSink)
        assert mesh.ledger.archive.bucket == "usoc-evidence"
        assert isinstance(mesh.evidence, PostgresEvidenceChain)
        assert not (mesh._workspace / "approvals.json").exists()
        assert not (mesh._workspace / "evidence" / "chain.jsonl").exists()
    finally:
        await mesh.stop()


async def test_s3_archive_requires_dedicated_secret_outside_local_dev():
    settings = Settings(
        _env_file=None,
        signing_mode="ed25519",
        approval_backend="postgres",
        evidence_backend="postgres",
        ledger_backend="postgres",
        postgres_dsn="postgresql://mesh:mesh@postgres:5432/usoc",
        archive_backend="s3",
        archive_bucket="usoc-evidence",
    )
    try:
        await Mesh(settings=settings).start()
    except SecurityError as exc:
        assert "AGENT_ARCHIVE_SECRET (or AGENT_ARCHIVE_SECRET_FILE) is required" in str(exc)
        assert "for S3 WORM archival outside local dev" in str(exc)
    else:
        raise AssertionError("S3 archival accepted a missing chain secret")


def test_strict_prod_rejects_file_backed_control_plane_state():
    from agents.trust import validate_strict_prod

    problems = validate_strict_prod(
        Settings(
            _env_file=None,
            shared_secret=SECRET,
            strict_prod=True,
            approval_backend="file",
            evidence_backend="file",
            ledger_backend="memory",
            archive_backend="file",
        )
    )
    assert "AGENT_APPROVAL_BACKEND=postgres is required" in problems
    assert "AGENT_EVIDENCE_BACKEND=postgres is required" in problems
    assert "AGENT_LEDGER_BACKEND=postgres is required" in problems
    assert "AGENT_ARCHIVE_BACKEND=s3 is required" in problems
    assert "AGENT_POSTGRES_DSN is required" in problems
    assert "AGENT_ARCHIVE_BUCKET is required" in problems
    assert "AGENT_ARCHIVE_SECRET_FILE is required" in problems


async def test_mesh_defaults_stay_single_host_and_file_backed():
    mesh = Mesh(settings=Settings(_env_file=None, shared_secret=SECRET))
    await mesh.start()
    try:
        assert not isinstance(mesh.approvals, PostgresApprovalStore)
        assert mesh.ledger.sink is None
        assert mesh.ledger.archive is None
    finally:
        await mesh.stop()


class FakeEventsBackend:
    """Captures appended events without a real Postgres connection."""

    def __init__(self) -> None:
        self._events: dict[tuple[str, str], list[dict]] = {}
        self.partitions: set[str] = set()

    async def ensure_partition(self, tenant_id: str) -> None:
        self.partitions.add(tenant_id)

    async def fetch(self, tenant_id: str, record_id: str, *, for_update: bool) -> dict | None:
        return None

    async def insert(self, tenant_id: str, record: dict) -> bool:
        return True

    async def update(self, tenant_id: str, record: dict) -> None:
        return None

    async def pending(self, tenant_id: str) -> list[dict]:
        return []

    async def append_events(self, tenant_id: str, events: list[dict]) -> None:
        for event in events:
            self._events.setdefault((tenant_id, event["trace_id"]), []).append(
                copy.deepcopy(event)
            )

    async def events(self, tenant_id: str, trace_id: str, limit: int) -> list[dict]:
        return list(reversed(self._events.get((tenant_id, trace_id), [])))[:limit]

    async def close(self) -> None:
        return None


async def test_postgres_ledger_has_no_2048_slot_eviction():
    backend = FakeEventsBackend()
    sink = PostgresLedgerSink(PostgresLedgerStore(backend))
    from agents.task_ledger import TaskLedger

    ledger = TaskLedger(max_events=2, sink=sink)
    for seq in range(1, 2_100):
        ledger.record(
            agent_id="oekp",
            state="completed",
            correlation_id=f"trace-{seq}:step-1",
            tenant_id="tenant-a",
        )
    await ledger.flush()

    durable = await sink.query(tenant_id="tenant-a", trace_id="trace-1")
    assert len(durable) == 1
    # The in-process ring evicted, but the Postgres tier retained every event.
    assert sum(len(v) for v in backend._events.values()) == 2_099
    assert sink.snapshot()["backend"] == "postgres"


class FakeEvidenceBackend:
    """Row-locked evidence head/append, enough to model two replicas."""

    def __init__(self) -> None:
        self.rows: list[dict] = []
        self.seq = 0
        self.last_hash = "genesis"
        self.lock = asyncio.Lock()

    async def append_evidence(self, tenant_id, record, finalize):
        async with self.lock:
            completed = finalize(self.seq + 1, self.last_hash)
            self.rows.append(copy.deepcopy(completed))
            self.seq = int(completed["seq"])
            self.last_hash = str(completed["hash"])
            return completed

    async def evidence_records(self, tenant_id):
        return copy.deepcopy(self.rows)

    async def close(self) -> None:
        return None


async def test_postgres_evidence_chain_is_shared_and_tamper_evident():
    backend = FakeEvidenceBackend()
    signer = Signer(SECRET)
    replica_a = PostgresEvidenceChain(backend, signer=signer)
    replica_b = PostgresEvidenceChain(backend, signer=signer)

    first = await replica_a.append(kind="probe", actor="oekp", data={"n": 1})
    second = await replica_b.append(kind="probe", actor="bengal", data={"n": 2})
    assert (first.seq, second.seq) == (1, 2)  # DB assigns 1 and 2

    # The first replica must catch up before verifying or appending again.
    await replica_a.refresh()
    ok, detail = replica_a.verify()
    assert ok, detail
    assert replica_a.head == replica_b.head == (2, second.hash)

    backend.rows[0]["data"]["n"] = 99
    try:
        await replica_a.refresh()
    except SecurityError as exc:
        assert "failed verification" in str(exc)
    else:
        raise AssertionError("tampered evidence was accepted")


class _Ctx:
    def __init__(self, value: object = None) -> None:
        self.value = value

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, *_exc) -> bool:
        return False


class _FakeCursor:
    def __init__(self, log: list, row: dict | None) -> None:
        self.log = log
        self.row = row

    async def execute(self, sql: str, params: tuple = ()) -> None:
        self.log.append((sql, params))

    async def fetchone(self):
        return self.row

    async def fetchall(self):
        return []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc) -> bool:
        return False


class _FakeConnection:
    def __init__(self, row: dict | None = None) -> None:
        self.log: list[tuple[str, tuple]] = []
        self.cursor_obj = _FakeCursor(self.log, row)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc) -> bool:
        return False

    def transaction(self) -> _Ctx:
        return _Ctx(self)

    def cursor(self) -> _FakeCursor:
        return self.cursor_obj


async def test_approval_lock_spans_read_modify_write_in_one_transaction():
    record = {"id": "apr-1", "status": "pending"}
    conn = _FakeConnection({"record": json.dumps(record)})
    backend = PsycopgBackend("postgresql://unused", connect=lambda: _ready(conn))

    async def apply(raw):
        assert raw == record
        return {**raw, "status": "approved"}

    updated = await backend.transact_record("default", "apr-1", apply)
    assert updated is not None and updated["status"] == "approved"
    sql = [statement for statement, _ in conn.log]
    select_at = next(i for i, item in enumerate(sql) if "FOR UPDATE" in item)
    update_at = next(i for i, item in enumerate(sql) if item.lstrip().startswith("UPDATE"))
    assert select_at < update_at


async def _ready(conn: _FakeConnection) -> _FakeConnection:
    return conn


async def test_postgres_append_assigns_sequence_under_advisory_lock():
    conn = _FakeConnection()
    backend = PsycopgBackend("postgresql://unused", connect=lambda: _ready(conn))
    backend._schema_ready = True
    for table in (backend.approval_table, backend.ledger_table):
        backend._partitions.add(backend._partition_name(table, "default"))

    # TaskEvent has no seq field; the database must assign it.
    await backend.append_events("default", [{"trace_id": "trace-1", "event": {}}])
    sql = " ".join(statement for statement, _ in conn.log)
    assert "pg_advisory_xact_lock" in sql
    assert "COALESCE(MAX(seq), 0) + 1" in sql
