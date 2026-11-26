"""ACIE: deterministic edge-lab connectivity replay.

The lab consumes bounded fixture events, replays them without egress and emits
only a verdict plus a SHA-256 fingerprint. It never calls a live cluster and
never copies raw telemetry into evidence.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class LabEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    seq: int = Field(ge=1)
    kind: Literal["connect", "drop", "expected_path"]
    source: str = Field(min_length=1, max_length=200)
    target: str = Field(min_length=1, max_length=200)
    observed_at: str = Field(max_length=64)


class LabScenario(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_id: str = Field(min_length=1, max_length=200)
    tenant_id: str = Field(min_length=1, max_length=200)
    events: list[LabEvent] = Field(default_factory=list, max_length=5_000)
    expected_paths: list[tuple[str, str]] = Field(default_factory=list, max_length=200)


class LabResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_id: str
    tenant_id: str
    passed: bool
    connected_edges: int
    failed_paths: list[str] = Field(default_factory=list)
    evidence_fingerprint: str


class LabReduction(BaseModel):
    """Measured edge reduction. Counts only; no raw event text is retained."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    raw_events: int
    aggregated_events: int
    reasoning_inputs: int
    reduction_ratio: float
    evidence_fingerprint: str


class OmegaScore(BaseModel):
    """Advisory, rehearsal-only lab score. It grants no authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    value: float
    rehearsal_only: bool = True
    tainted: bool = True
    shadow: bool = True
    evidence_fingerprint: str


class LabReplay:
    """Small graph replay used for ACIE simulation evidence."""

    @staticmethod
    def load(path: str | Path) -> LabScenario:
        source = Path(path)
        scenario_id = source.stem
        tenant_id = "default"
        events: list[LabEvent] = []
        for lineno, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{source} line {lineno}: invalid JSON: {exc}") from exc
            if "kind" not in raw:
                scenario_id = str(raw.get("scenario_id", scenario_id))
                tenant_id = str(raw.get("tenant_id", tenant_id))
                continue
            try:
                events.append(LabEvent.model_validate(raw))
            except ValueError as exc:
                raise ValueError(f"{source} line {lineno}: invalid lab event: {exc}") from exc
        expected_paths = [
            (item.source, item.target)
            for item in events
            if item.kind == "expected_path"
        ]
        return LabScenario(
            scenario_id=scenario_id,
            tenant_id=tenant_id,
            events=events,
            expected_paths=expected_paths,
        )

    @staticmethod
    def run(scenario: LabScenario) -> LabResult:
        edges: set[tuple[str, str]] = set()
        for event in sorted(scenario.events, key=lambda item: item.seq):
            if event.kind == "connect":
                edges.add((event.source, event.target))
            elif event.kind == "drop":
                edges.discard((event.source, event.target))
            elif event.kind == "expected_path":
                continue
            else:
                raise ValueError(f"unknown lab event {event.kind!r}")

        adjacency: dict[str, list[str]] = defaultdict(list)
        for source, target in edges:
            adjacency[source].append(target)

        failed_paths: list[str] = []
        for source, target in scenario.expected_paths:
            if not LabReplay._reachable(adjacency, source, target):
                failed_paths.append(f"{source}->{target}")

        body: dict[str, Any] = {
            "scenario_id": scenario.scenario_id,
            "tenant_id": scenario.tenant_id,
            "edges": sorted(edges),
            "failed_paths": sorted(failed_paths),
            "passed": not failed_paths,
        }
        blob = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return LabResult(
            scenario_id=scenario.scenario_id,
            tenant_id=scenario.tenant_id,
            passed=not failed_paths,
            connected_edges=len(edges),
            failed_paths=sorted(failed_paths),
            evidence_fingerprint=hashlib.sha256(blob).hexdigest(),
        )

    @staticmethod
    def _reachable(adjacency: dict[str, list[str]], source: str, target: str) -> bool:
        seen: set[str] = set()
        queue = deque([source])
        while queue:
            current = queue.popleft()
            if current == target:
                return True
            if current in seen:
                continue
            seen.add(current)
            queue.extend(adjacency.get(current, []))
        return False


class EdgeReducer:
    """Collapse noisy lab events into bounded, repeatable reasoning inputs."""

    @staticmethod
    def reduce(events: list[LabEvent]) -> LabReduction:
        edges: set[tuple[str, str, str, str]] = set()
        expectations: set[tuple[str, str, str]] = set()
        for event in sorted(events, key=lambda item: item.seq):
            minute = event.observed_at[:16]
            if event.kind in ("connect", "drop"):
                edges.add((event.kind, event.source, event.target, minute))
            elif event.kind == "expected_path":
                expectations.add((event.source, event.target, minute))
            else:
                raise ValueError(f"unknown lab event {event.kind!r}")

        reasoning_inputs = len(edges)
        aggregated_events = reasoning_inputs + len(expectations)
        raw_events = len(events)
        ratio = round(raw_events / reasoning_inputs, 4) if reasoning_inputs else 1.0
        body: dict[str, Any] = {
            "raw_events": raw_events,
            "aggregated_events": aggregated_events,
            "reasoning_inputs": reasoning_inputs,
            "reduction_ratio": ratio,
            "edges": sorted(edges),
        }
        blob = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return LabReduction(
            raw_events=raw_events,
            aggregated_events=aggregated_events,
            reasoning_inputs=reasoning_inputs,
            reduction_ratio=ratio,
            evidence_fingerprint=hashlib.sha256(blob).hexdigest(),
        )


class OmegaScorer:
    """Combine replay and reduction evidence into one bounded advisory value."""

    @staticmethod
    def score(result: LabResult, reduction: LabReduction) -> OmegaScore:
        connectivity = result.connected_edges / max(
            1, result.connected_edges + len(result.failed_paths)
        )
        efficiency = min(1.0, reduction.reduction_ratio / 4.0)
        value = round(
            0.60 * (1.0 if result.passed else 0.0)
            + 0.25 * connectivity
            + 0.15 * efficiency,
            4,
        )
        blob = json.dumps(
            {
                "scenario_id": result.scenario_id,
                "passed": result.passed,
                "connectivity": round(connectivity, 6),
                "reduction_ratio": reduction.reduction_ratio,
                "value": value,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return OmegaScore(value=value, evidence_fingerprint=hashlib.sha256(blob).hexdigest())
