from __future__ import annotations

import pytest

from agents.registry import Registry, RegistryError, SubsystemSpec, load_registry
from agents.tools import ToolRegistry


def test_nine_usoc_subsystems_load(registry):
    assert len(registry) == 9
    assert {s.id for s in registry.subsystems} == {
        "aicee",
        "acie",
        "seraphim",
        "cohesion",
        "bengal",
        "csssf",
        "oekp",
        "cyber_strike",
        "hitl",
    }
    assert registry.roles_total == 93
    assert all(s.capabilities and s.roles for s in registry.subsystems)


def test_routing_picks_the_owner(registry):
    assert registry.best("analyse anomalies in the telemetry").id == "aicee"
    assert registry.best("collect edge telemetry from the nodes").id == "acie"
    assert registry.best("evaluate policy and authorize the action").id == "seraphim"
    assert registry.best("record the evidence and provenance for the decision").id == "oekp"
    assert registry.best("verify outcomes independently against evidence").id == "bengal"
    assert registry.best("simulate the change in a sandbox").id == "csssf"
    assert registry.best("triage the security incident").id == "cyber_strike"
    assert registry.best("route the approval to a human reviewer").id == "hitl"
    assert registry.best("interpret the mission intent and dependencies").id == "cohesion"


def test_routing_explains_itself(registry):
    ranked = registry.route("analyse trends in the telemetry")
    assert ranked and ranked[0][1].id == "aicee"
    assert all(score > 0 for score, _ in ranked)
    assert ranked == sorted(ranked, key=lambda pair: -pair[0])


def test_unmatched_text_returns_nothing(registry):
    assert registry.route("xyzzy plugh") == []
    assert registry.best("xyzzy plugh") is None


def test_wrong_count_is_rejected(settings, tools):
    with pytest.raises(RegistryError, match="expected 10 subsystems, found 9"):
        load_registry(settings.subsystems_file, tools, expected_count=10)


def test_unknown_tool_is_rejected():
    spec = SubsystemSpec(
        id="ghost",
        name="Ghost",
        description="A subsystem that claims a tool nobody registered.",
        capabilities=["do ghost things"],
        tools=["not.a.real.tool"],
    )
    with pytest.raises(RegistryError, match="unknown tools"):
        Registry(subsystems=[spec], tools=ToolRegistry())


def test_duplicate_ids_are_rejected():
    def spec(i: str) -> SubsystemSpec:
        return SubsystemSpec(id=i, name=i.title(), description="duplicate id test subsystem here", capabilities=["x"])

    with pytest.raises(RegistryError, match="duplicate"):
        Registry(subsystems=[spec("dup"), spec("dup")], tools=ToolRegistry())
