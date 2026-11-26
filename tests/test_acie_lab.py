"""REQ-006: deterministic ACIE edge-lab replay evidence."""

from __future__ import annotations

from pathlib import Path

import pytest

from agents.acie_lab import (
    EdgeReducer,
    LabEvent,
    LabReplay,
    LabScenario,
    OmegaScorer,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "acie" / "lab-network.jsonl"


def test_committed_acie_fixture_replays_a_connected_path():
    scenario = LabReplay.load(FIXTURE)
    assert scenario.scenario_id == "edge-connectivity-001"
    assert scenario.expected_paths

    result = LabReplay.run(scenario)
    assert result.scenario_id == scenario.scenario_id
    assert result.passed is True
    assert result.connected_edges >= 2
    assert len(result.evidence_fingerprint) == 64


def test_dropped_link_fails_the_replay_without_leaking_payloads():
    scenario = LabReplay.load(FIXTURE)
    broken = scenario.model_copy(
        update={
            "scenario_id": "edge-connectivity-broken",
            "events": [
                *scenario.events,
                LabEvent(
                    seq=99,
                    kind="drop",
                    source="edge-01",
                    target="core-01",
                    observed_at="2026-01-01T00:10:00Z",
                ),
            ],
        }
    )
    result = LabReplay.run(broken)
    assert result.passed is False
    assert result.failed_paths
    assert "edge-01" not in result.evidence_fingerprint


def test_unknown_lab_event_fails_closed():
    scenario = LabScenario(
        scenario_id="bad",
        tenant_id="tenant-a",
        events=[
            LabEvent.model_construct(
                seq=1,
                kind="explode",
                source="a",
                target="b",
                observed_at="2026-01-01T00:00:00Z",
            )
        ],
        expected_paths=[("a", "b")],
    )
    with pytest.raises(ValueError, match="unknown lab event"):
        LabReplay.run(scenario)


def test_edge_reducer_measures_a_bounded_reduction_ratio():
    scenario = LabReplay.load(FIXTURE)
    reduction = EdgeReducer().reduce(scenario.events)

    assert reduction.raw_events == len(scenario.events)
    assert reduction.aggregated_events <= reduction.raw_events
    assert reduction.reasoning_inputs <= reduction.aggregated_events
    assert reduction.reduction_ratio >= 2.0
    assert len(reduction.evidence_fingerprint) == 64

    noisy = [
        *scenario.events,
        LabEvent(
            seq=5,
            kind="connect",
            source="edge-01",
            target="core-01",
            observed_at="2026-01-01T00:00:30Z",
        ),
    ]
    deduped = EdgeReducer().reduce(noisy)
    assert deduped.raw_events > reduction.raw_events
    assert deduped.aggregated_events == reduction.aggregated_events


def test_omega_score_is_bounded_deterministic_and_advisory_only():
    scenario = LabReplay.load(FIXTURE)
    result = LabReplay.run(scenario)
    reduction = EdgeReducer().reduce(scenario.events)
    scorer = OmegaScorer()

    first = scorer.score(result, reduction)
    second = scorer.score(result, reduction)
    assert first == second
    assert 0.0 <= first.value <= 1.0
    assert first.rehearsal_only is True
    assert first.tainted is True
    assert first.shadow is True
    assert len(first.evidence_fingerprint) == 64
