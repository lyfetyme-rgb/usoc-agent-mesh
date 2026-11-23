"""BENGAL BAA wired into the USOC Mesh composition root and coordinator."""

from __future__ import annotations

import json

from agents.bengal import BengalCase, BengalEngine, SourceDocument, ThreatMode
from agents.mesh import Mesh


async def test_mesh_composes_bengal_engine(settings):
    async with Mesh(settings, agents=[]) as mesh:
        assert isinstance(mesh.bengal, BengalEngine)
        describe = mesh.describe()
        assert describe["bengal"]["method_version"] == "bengal-baa/v1"
        assert set(describe["bengal"]["modes"]) == {m.value for m in ThreatMode}


async def test_mesh_analyze_bengal_records_redacted_lineage(settings):
    async with Mesh(settings, agents=[]) as mesh:
        case = BengalCase(
            case_id="mesh-case",
            tenant_id="tenant-b",
            text="Obviously jane.doe@example.com is always wrong.",
        )
        report = await mesh.analyze_bengal(case)
        assert report.tenant_id == "tenant-b"
        snapshot = mesh.ledger.snapshot()
        assert any(e["state"] == "bengal_analyzed" for e in snapshot["recent"])
        assert snapshot["tenants"].get("tenant-b", 0) >= 1
        assert "jane.doe@example.com" not in json.dumps(snapshot)


async def test_mesh_accepts_an_injected_bengal_engine(settings):
    engine = BengalEngine(secret="injected")
    async with Mesh(settings, agents=[], bengal_engine=engine) as mesh:
        assert mesh.bengal is engine


async def test_bengal_agent_runs_baa_analysis_only_when_requested(settings):
    async with Mesh(settings, agents=["bengal"]) as mesh:
        agent = mesh.agents["bengal"]
        spec = type(
            "Spec",
            (),
            {
                "objective": "analyze this",
                "inputs": {
                    "bengal_analyze": True,
                    "case_id": "agent-case",
                    "text": "Obviously those people are always wrong.",
                    "claims": ["The gateway saw 42 incidents."],
                    "trusted_corpus": ["The gateway saw 12 incidents."],
                    "sources": [
                        {
                            "source_id": "s1",
                            "text": "Clearly the system was compromised.",
                            "provenance": [],
                        }
                    ],
                },
                "tenant_id": "tenant-c",
            },
        )()
        msg = type("Msg", (), {"correlation_id": "agent-case:s1"})()
        result = await agent.handle_task(spec, msg)
        assert result.ok is True
        assert result.data["bengal"]["case_id"] == "agent-case"
        assert result.data["hallucination_rate"] == 1.0
        assert result.data["tenant_id"] == "tenant-c"
        assert "those people" not in json.dumps(result.data)


async def test_bengal_agent_keeps_evidence_verification_as_default(settings):
    async with Mesh(settings, agents=["bengal"]) as mesh:
        agent = mesh.agents["bengal"]
        result = await agent.handle_task(None, type("Msg", (), {"correlation_id": "x"})())
        assert "trusted_for_execution" in result.data
        assert result.data["checked"] == "evidence.integrity"


async def test_bengal_agent_analysis_errors_never_leak_raw_input(settings):
    async with Mesh(settings, agents=["bengal"]) as mesh:
        agent = mesh.agents["bengal"]
        secret = "jane.doe@example.com-123-45-6789"
        spec = type(
            "Spec",
            (),
            {
                "objective": "analyze this",
                "inputs": {
                    "bengal_analyze": True,
                    "case_id": "leak-case",
                    "text": secret,
                    "sources": [{"source_id": "s1", "text": secret, "bogus_field": secret}],
                },
                "tenant_id": "tenant-d",
            },
        )()
        msg = type("Msg", (), {"correlation_id": "leak-case:s1"})()
        result = await agent.handle_task(spec, msg)
        assert result.kind == "error"
        assert result.code == "bengal_analysis_error"
        assert secret not in json.dumps(result.model_dump(mode="json"))
        assert len(result.message.split(": ")[-1]) == 16


async def test_bengal_engine_does_not_need_an_llm_in_the_governed_path(settings):
    async with Mesh(settings, agents=[]) as mesh:
        assert mesh.bengal.llm is None
        case = BengalCase(
            case_id="offline",
            text="The gateway emitted an alert.",
            perspectives=("analyst", "auditor"),
        )
        report = await mesh.bengal.analyze(case, modes=[ThreatMode.BIAS])
        assert report.bias.space.dialogue_turns > 0
        assert report.bias.space.diversity_score > 0
