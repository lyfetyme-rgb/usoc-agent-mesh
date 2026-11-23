"""Mesh-level replay: one tenant goal, one execution, deterministic lineage."""

from __future__ import annotations

import pytest

from agents.contracts import GoalResult
from agents.durable import InMemoryLedgerSink, SignedArchiveSink
from agents.mesh import Mesh


async def test_mesh_run_replays_cached_goal_result_for_identical_request(settings, monkeypatch):
    mesh = Mesh(settings, agents=[])
    await mesh.start()
    calls: list[tuple[str, str | None, str]] = []

    async def fake_run(goal: str, *, idempotency_key: str | None = None, tenant_id: str = "default"):
        calls.append((goal, idempotency_key, tenant_id))
        return GoalResult(
            goal=goal,
            ok=True,
            answer="done",
            correlation_id=f"trace-{len(calls)}",
        )

    monkeypatch.setattr(mesh.orchestrator, "run", fake_run)

    first = await mesh.run("same goal", tenant_id="tenant-a")
    replay = await mesh.run("same goal", tenant_id="tenant-a")
    other_tenant = await mesh.run("same goal", tenant_id="tenant-b")

    assert len(calls) == 2
    assert replay.correlation_id == first.correlation_id == "trace-1"
    assert other_tenant.correlation_id == "trace-2"
    assert calls[0][1] is not None and len(calls[0][1]) == 64
    assert calls[0][1] != calls[1][1]
    await mesh.stop()


async def test_mesh_quarantines_malformed_goal_before_orchestration(settings, monkeypatch):
    mesh = Mesh(settings, agents=[])
    await mesh.start()

    async def must_not_run(*args, **kwargs):
        pytest.fail("malformed input reached the orchestrator")

    monkeypatch.setattr(mesh.orchestrator, "run", must_not_run)
    with pytest.raises(ValueError, match="schema_invalid"):
        await mesh.run("")
    assert mesh.ingress.quarantine.snapshot()["quarantined"] == 1
    await mesh.stop()


async def test_mesh_composes_injected_durable_ledger_sinks(settings, tmp_path):
    sink = InMemoryLedgerSink()
    archive = SignedArchiveSink(path=tmp_path / "ledger.jsonl", secret="archive-key")
    mesh = Mesh(
        settings,
        agents=[],
        ledger_sink=sink,
        ledger_archive=archive,
    )
    await mesh.start()
    mesh.ledger.record(agent_id="ingress", state="received", correlation_id="trace:s1", tenant_id="t1")
    await mesh.ledger.flush()

    assert sink.count == 1
    assert archive.verify() is True
    assert mesh.ledger.snapshot()["storage"]["backend"] == "memory"
    assert "quarantined" in mesh.describe()
    await mesh.stop()
