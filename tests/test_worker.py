"""Horizontal scaling: worker mode and fork-free evidence growth."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from agents.config import Settings
from agents.evidence import EvidenceChain
from agents.mesh import Mesh
from agents.security import SecurityError, Signer


def test_worker_mode_starts_only_the_requested_agents_and_no_orchestrator():
    async def run():
        async with Mesh(Settings(), agents=["aicee", "oekp"], run_orchestrator=False) as mesh:
            assert set(mesh.agents) == {"aicee", "oekp"}
            assert mesh.orchestrator is None
            assert mesh._started

    asyncio.run(run())


def test_worker_mode_rejects_an_unknown_subsystem():
    async def run():
        async with Mesh(Settings(), agents=["aicee", "nope"], run_orchestrator=False):
            return None

    with pytest.raises(SecurityError, match="not in registry"):
        asyncio.run(run())


def test_worker_mode_refuses_to_run_a_goal():
    async def run():
        async with Mesh(Settings(), agents=["aicee"], run_orchestrator=False) as mesh:
            with pytest.raises(RuntimeError, match="worker mode"):
                await mesh.run("no-op for scaling test")

    asyncio.run(run())


def test_two_processes_appending_to_the_same_chain_do_not_fork(tmp_path: Path):
    signer = Signer("test-secret-that-is-long-enough-32")
    path = tmp_path / "chain.jsonl"

    async def run():
        first = EvidenceChain(path, signer=signer)
        second = EvidenceChain(path, signer=signer)
        await asyncio.gather(
            *(
                chain.append(kind="concurrency", actor="test", data={"i": i})
                for i in range(10)
                for chain in (first, second)
            )
        )
        return EvidenceChain(path, signer=signer).verify()

    ok, detail = asyncio.run(run())
    assert ok, detail
