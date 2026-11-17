from __future__ import annotations

import pytest
from pydantic import ValidationError

from agents.bus import InMemoryBus
from agents.contracts import Failure, Message, Query, TaskSpec
from agents.llm import EchoLLM
from agents.mesh import Mesh, validate_agent_tiers
from agents.observability import Metrics
from agents.registry import SubsystemSpec
from agents.runtime import NO_LLM_CODE, SubsystemAgent
from agents.security import SecurityError
from agents.store import InMemoryStore
from agents.tools import ToolError


def test_shipped_cards_mark_deterministic_coordinators(registry):
    expected = {
        "seraphim": "deterministic",
        "bengal": "deterministic",
        "oekp": "deterministic",
        "hitl": "deterministic",
        "aicee": "strong",
        "acie": "fast",
        "cohesion": "strong",
        "csssf": "fast",
        "cyber_defense": "fast",
    }
    for agent_id, tier in expected.items():
        assert registry.get(agent_id).model_tier == tier

    assert registry.get("csssf").tool_scopes == {
        "workspace.read": "sandbox/",
        "workspace.write": "sandbox/",
    }
    assert registry.get("bengal").tool_scopes == {}
    assert registry.get("oekp").tool_scopes == {}


def test_unknown_model_tier_is_rejected():
    with pytest.raises(ValidationError):
        SubsystemSpec(
            id="broken",
            name="Broken",
            description="A deliberately invalid subsystem for tier validation.",
            capabilities=["test invalid tiers"],
            model_tier="turbo",  # type: ignore[arg-type]
        )


def test_bad_tool_scope_is_rejected():
    with pytest.raises(ValidationError):
        SubsystemSpec(
            id="broken",
            name="Broken",
            description="A deliberately invalid subsystem for scope validation.",
            capabilities=["test invalid scopes"],
            tools=["workspace.write"],
            tool_scopes={"workspace.write": "../live"},
        )


def test_validate_agent_tiers_accepts_shipped_cards(registry):
    validate_agent_tiers(registry.subsystems)


def test_deterministic_card_with_generic_class_fails_closed(registry):
    with pytest.raises(SecurityError, match="does not match"):
        validate_agent_tiers([registry.get("oekp")], classes={})


async def test_deterministic_spec_refuses_generic_llm_paths(settings, tools):
    spec = SubsystemSpec(
        id="det",
        name="Det",
        description="A deterministic subsystem used by the tier enforcement test.",
        capabilities=["deterministic checks"],
        model_tier="deterministic",
    )
    llm = EchoLLM()
    agent = SubsystemAgent(
        spec,
        InMemoryBus(insecure_dev_mode=True),
        llm=llm,
        tools=tools,
        settings=settings,
        store=InMemoryStore(),
        metrics=Metrics(),
        known_agents=set(),
    )
    task = await agent.handle_task(
        TaskSpec(objective="answer this"),
        Message.task(sender="client", recipient="det", objective="answer this"),
    )
    reply = await agent.handle_query(
        Query(question="answer this"),
        Message.event(sender="client", name="query"),
    )
    tool_result = await agent._run_tool(
        {"tool_name": "workspace.write", "arguments": {"path": "x", "content": "y"}}
    )

    assert isinstance(task, Failure)
    assert task.code == NO_LLM_CODE
    assert reply.data["code"] == NO_LLM_CODE
    assert "no LLM" in reply.answer
    assert "deterministic" in tool_result["error"]
    assert llm.calls == 0
    assert agent.metrics.counters["llm.blocked"] == 2


async def test_hitl_query_never_falls_back_to_an_llm(settings):
    async with Mesh(settings, agents=["hitl"]) as mesh:

        async def forbidden(**kwargs):
            raise AssertionError("deterministic HITL called the LLM")

        mesh.llm.complete = forbidden  # type: ignore[method-assign]
        reply = await mesh.agents["hitl"].handle_query(
            Query(question="summarize the operational risk"),
            Message.event(sender="client", name="query"),
        )

    assert "no LLM" in reply.answer
    assert "pending approvals" in reply.answer


async def test_csssf_workspace_tools_are_chrooted_to_sandbox(settings):
    workspace = settings.workspace
    async with Mesh(settings, agents=["csssf"]) as mesh:
        csssf = mesh.agents["csssf"]
        assert "sandbox/" in csssf.tools.get("workspace.write").description

        await csssf.tools.call(
            "workspace.write", {"path": "rehearsal.txt", "content": "sandbox ok"}
        )
        await csssf.tools.call(
            "workspace.write", {"path": "sandbox/explicit.txt", "content": "also ok"}
        )
        assert (workspace / "sandbox" / "rehearsal.txt").read_text() == "sandbox ok"
        assert (workspace / "sandbox" / "explicit.txt").read_text() == "also ok"

        # An omitted subdir defaults to the sandbox, not the workspace root.
        listing = await csssf.tools.call("workspace.list")
        normalized = {path.replace("\\", "/") for path in listing}
        assert "sandbox/rehearsal.txt" in normalized
        assert "sandbox/explicit.txt" in normalized
        assert not any(path.startswith("inbox/") for path in normalized)

        # Names that resemble live prefixes are still relative to the sandbox:
        # the chroot rewrites them, so a rehearsal cannot address the real ones.
        await csssf.tools.call(
            "workspace.write", {"path": "evidence/chain.jsonl", "content": "fake"}
        )
        await csssf.tools.call(
            "workspace.write", {"path": "inbox/telemetry.jsonl", "content": "fake"}
        )
        assert (workspace / "sandbox" / "evidence" / "chain.jsonl").read_text() == "fake"
        assert (workspace / "sandbox" / "inbox" / "telemetry.jsonl").read_text() == "fake"

        for bad_path in (
            "../evidence/chain.jsonl",
            "sandbox/../evidence/chain.jsonl",
            "/tmp/escape.txt",
            "C:/escape.txt",
            "sandbox",
        ):
            with pytest.raises(ToolError):
                await csssf.tools.call(
                    "workspace.write", {"path": bad_path, "content": "escape"}
                )

        with pytest.raises(ToolError):
            await csssf.tools.call(
                "workspace.read", {"path": "../evidence/chain.jsonl"}
            )
        assert not (workspace / "evidence" / "chain.jsonl").exists()
        assert not (workspace / "inbox" / "telemetry.jsonl").exists()


async def test_csssf_rejects_symlink_out_of_sandbox(settings):
    workspace = settings.workspace
    sandbox = workspace / "sandbox"
    live = workspace / "evidence"
    sandbox.mkdir(parents=True, exist_ok=True)
    live.mkdir(parents=True, exist_ok=True)
    live_file = live / "secret.txt"
    live_file.write_text("original", encoding="utf-8")
    link = sandbox / "live"
    try:
        link.symlink_to(live, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks are unavailable in this environment: {exc}")

    async with Mesh(settings, agents=["csssf"]) as mesh:
        with pytest.raises(ToolError, match="escapes"):
            await mesh.agents["csssf"].tools.call(
                "workspace.write",
                {"path": "live/secret.txt", "content": "overwritten"},
            )

    assert live_file.read_text(encoding="utf-8") == "original"


async def test_other_agents_keep_the_unscoped_registry(settings):
    async with Mesh(settings) as mesh:
        assert mesh.agents["csssf"].tools is not mesh.registry.tools
        assert mesh.agents["bengal"].tools is mesh.registry.tools
        assert mesh.agents["oekp"].tools is mesh.registry.tools
