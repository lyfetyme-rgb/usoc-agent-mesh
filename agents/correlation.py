"""Cross-source correlation.

The value of the USOC layer is not another dashboard. It is the ability to see
that a CPU spike in observability, a critical CVE in vulnerability management,
a cost anomaly in the cloud account, a C2 alert in the SOC, failed logins in
identity, packet loss in networking, an open ticket, a failed backup and a
recent deployment are all the *same operational event*.

This module does that deterministically:

1. deduplicate redelivered signals
2. resolve entities across tools (host name, instance id, service account, ...)
3. cluster signals per entity inside a time window
4. score risk from severity, source diversity, category diversity and known
   attack/change patterns
5. return ranked incidents with full provenance and human-readable reasons

No model is involved, so a score is reproducible and explainable. A model can
consume the output later; it cannot change the arithmetic.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from datetime import datetime, timezone
from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field

from .connectors import EntityType, Severity, Signal, SourceType, canonical_entity
from .contracts import Classification, RiskLevel

SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
SEVERITY_POINTS: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 30,
    Severity.CRITICAL: 45,
}
CLASSIFICATION_RANK: dict[Classification, int] = {
    Classification.PUBLIC: 0,
    Classification.INTERNAL: 1,
    Classification.CONFIDENTIAL: 2,
    Classification.RESTRICTED: 3,
}


class CorrelationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_s: int = Field(default=900, ge=60, le=86_400)
    min_sources: int = Field(default=2, ge=1, le=12)
    min_score: float = Field(default=40.0, ge=0, le=100)
    max_signals_per_incident: int = Field(default=200, ge=1, le=5_000)


class CorrelatedIncident(BaseModel):
    """One entity-centred cluster of signals from distinct incumbent systems."""

    model_config = ConfigDict(extra="forbid")

    id: str
    entity: str
    entity_type: EntityType
    aliases: list[str] = Field(default_factory=list)
    window_start: datetime
    window_end: datetime
    risk: RiskLevel
    score: float = Field(ge=0, le=100)
    sources: list[str] = Field(default_factory=list)
    source_types: list[SourceType] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    signal_ids: list[str] = Field(default_factory=list)
    signals: list[Signal] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    summary: str
    classification: Classification = Classification.INTERNAL
    truncated: bool = False


class CorrelationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incidents: list[CorrelatedIncident] = Field(default_factory=list)
    signals_total: int = 0
    signals_considered: int = 0
    duplicates: int = 0
    unmatched: int = 0
    window_s: int = 900
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def top(self) -> CorrelatedIncident | None:
        return self.incidents[0] if self.incidents else None


class CorrelationEngine:
    """Deterministic entity/time correlation across source types."""

    def __init__(self, config: CorrelationConfig | None = None) -> None:
        self.config = config or CorrelationConfig()

    def correlate(self, signals: Iterable[Signal]) -> CorrelationResult:
        raw = list(signals)
        unique, duplicates = _dedupe_signals(raw)
        if not unique:
            return CorrelationResult(
                signals_total=len(raw),
                duplicates=duplicates,
                window_s=self.config.window_s,
            )

        # Stable order makes union-find roots, incident ids and output order
        # reproducible across runs and across processes.
        unique.sort(key=lambda s: (s.observed_at, s.source, s.id))

        union = _UnionFind()
        for signal in unique:
            keys = _entity_keys(signal)
            for key in keys:
                union.add(key)
            for key in keys[1:]:
                union.union(keys[0], key)

        groups: dict[str, list[Signal]] = {}
        for signal in unique:
            root = union.find(canonical_entity(signal.entity))
            groups.setdefault(root, []).append(signal)

        incidents: list[CorrelatedIncident] = []
        for group in groups.values():
            for cluster in _clusters(group, self.config.window_s):
                incident = _build_incident(cluster, self.config.max_signals_per_incident)
                if len(incident.source_types) < self.config.min_sources:
                    continue
                if incident.score < self.config.min_score:
                    continue
                incidents.append(incident)

        incidents.sort(
            key=lambda i: (-i.score, -i.window_end.timestamp(), i.entity, i.id)
        )
        covered = sum(len(i.signal_ids) for i in incidents)
        return CorrelationResult(
            incidents=incidents,
            signals_total=len(raw),
            signals_considered=len(unique),
            duplicates=duplicates,
            unmatched=max(0, len(unique) - covered),
            window_s=self.config.window_s,
        )


# ---------------------------------------------------------------------------
# internals
# ---------------------------------------------------------------------------
class _UnionFind:
    """Merge entity aliases without a graph library."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def add(self, key: str) -> None:
        self.parent.setdefault(key, key)

    def find(self, key: str) -> str:
        self.add(key)
        root = key
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[key] != key:
            nxt = self.parent[key]
            self.parent[key] = root
            key = nxt
        return root

    def union(self, left: str, right: str) -> None:
        root_left, root_right = self.find(left), self.find(right)
        if root_left != root_right:
            self.parent[root_right] = root_left


def _entity_keys(signal: Signal) -> list[str]:
    keys = [canonical_entity(signal.entity)]
    keys.extend(canonical_entity(alias) for alias in signal.aliases)
    seen: set[str] = set()
    out: list[str] = []
    for key in keys:
        if key and key not in seen:
            seen.add(key)
            out.append(key)
    return out


def _dedupe_signals(signals: list[Signal]) -> tuple[list[Signal], int]:
    """Keep one signal per source/external id, preferring the newest copy."""
    chosen: dict[str, Signal] = {}
    duplicates = 0
    for signal in signals:
        key = (
            f"{signal.source}|{signal.external_id}"
            if signal.external_id
            else f"{signal.source}|{signal.fingerprint}"
        )
        previous = chosen.get(key)
        if previous is None:
            chosen[key] = signal
            continue
        duplicates += 1
        if signal.observed_at > previous.observed_at:
            chosen[key] = signal
    return list(chosen.values()), duplicates


def _clusters(signals: list[Signal], window_s: int) -> list[list[Signal]]:
    ordered = sorted(signals, key=lambda s: (s.observed_at, s.source, s.id))
    clusters: list[list[Signal]] = []
    current: list[Signal] = []
    for signal in ordered:
        if not current:
            current = [signal]
            continue
        if (signal.observed_at - current[0].observed_at).total_seconds() > window_s:
            clusters.append(current)
            current = [signal]
        else:
            current.append(signal)
    if current:
        clusters.append(current)
    return clusters


def _build_incident(cluster: list[Signal], max_signals: int) -> CorrelatedIncident:
    truncated = len(cluster) > max_signals
    if truncated:
        cluster = sorted(
            cluster,
            key=lambda s: (-SEVERITY_RANK[s.severity], -s.observed_at.timestamp(), s.id),
        )[:max_signals]
    cluster = sorted(cluster, key=lambda s: (s.observed_at, s.source, s.id))

    entity = _representative_entity(cluster)
    entity_type = _representative_entity_type(cluster)
    raw_entities = {canonical_entity(s.entity) for s in cluster}
    alias_set = {canonical_entity(a) for s in cluster for a in s.aliases}
    aliases = sorted((raw_entities | alias_set) - {entity})

    sources = sorted({s.source for s in cluster})
    source_types = sorted({s.source_type for s in cluster}, key=lambda t: t.value)
    categories = sorted({s.category for s in cluster})
    score, reasons = _score(cluster, source_types, categories)
    risk = _risk_level(score)
    window_start = cluster[0].observed_at
    window_end = cluster[-1].observed_at
    signal_ids = [s.id for s in cluster]
    incident_id = _incident_id(entity, window_start, signal_ids)
    classification = _classification_of(cluster)
    summary = (
        f"{entity}: {len(cluster)} signals across {len(source_types)} source types "
        f"({', '.join(sources[:6])}); risk {risk.value} ({score}/100)"
    )
    return CorrelatedIncident(
        id=incident_id,
        entity=entity,
        entity_type=entity_type,
        aliases=aliases,
        window_start=window_start,
        window_end=window_end,
        risk=risk,
        score=score,
        sources=sources,
        source_types=source_types,
        categories=categories,
        signal_ids=signal_ids,
        signals=cluster,
        reasons=reasons,
        summary=summary,
        classification=classification,
        truncated=truncated,
    )


def _score(
    cluster: list[Signal],
    source_types: list[SourceType],
    categories: list[str],
) -> tuple[float, list[str]]:
    highest = max(cluster, key=lambda s: SEVERITY_RANK[s.severity]).severity
    score = float(SEVERITY_POINTS[highest])

    # Cross-system evidence is the point: reward distinct source types, not
    # duplicate alerts from one tool.
    score += min(24, 8 * max(0, len(source_types) - 1))
    score += min(15, 5 * max(0, len(categories) - 1))
    if highest is Severity.CRITICAL:
        score += 10
    if SourceType.WORKFLOW in source_types:
        score += 5
    if {SourceType.IDENTITY, SourceType.NETWORK, SourceType.SOC} <= set(source_types):
        score += 10
    if {SourceType.INFRASTRUCTURE, SourceType.OBSERVABILITY} <= set(source_types):
        score += 5

    span_s = (cluster[-1].observed_at - cluster[0].observed_at).total_seconds()
    if span_s <= 300:
        score += 10
    elif span_s <= 900:
        score += 5
    score = min(100.0, round(score, 1))

    reasons = [
        f"{len(source_types)} source types: {', '.join(t.value for t in source_types)}",
        f"{len(categories)} categories: {', '.join(categories[:6])}",
        f"highest severity: {highest.value}",
    ]
    if highest is Severity.CRITICAL:
        reasons.append("critical severity present")
    if SourceType.WORKFLOW in source_types:
        reasons.append("an incident or ticket is already open")
    if {SourceType.IDENTITY, SourceType.NETWORK, SourceType.SOC} <= set(source_types):
        reasons.append("identity, network and SOC signals form a possible attack chain")
    if {SourceType.INFRASTRUCTURE, SourceType.OBSERVABILITY} <= set(source_types):
        reasons.append("a recent change overlaps the operational anomaly")
    reasons.append(f"signals span {int(span_s)}s")
    return score, reasons


def _risk_level(score: float) -> RiskLevel:
    if score >= 80:
        return RiskLevel.CRITICAL
    if score >= 60:
        return RiskLevel.HIGH
    if score >= 35:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _representative_entity(cluster: list[Signal]) -> str:
    counts = Counter(canonical_entity(s.entity) for s in cluster)
    return sorted(counts.items(), key=lambda item: (-item[1], len(item[0]), item[0]))[0][0]


def _representative_entity_type(cluster: list[Signal]) -> EntityType:
    counts = Counter(s.entity_type for s in cluster if s.entity_type is not EntityType.OTHER)
    if not counts:
        counts = Counter(s.entity_type for s in cluster)
    return sorted(counts.items(), key=lambda item: (-item[1], item[0].value))[0][0]


def _classification_of(cluster: list[Signal]) -> Classification:
    return max(cluster, key=lambda s: CLASSIFICATION_RANK[s.classification]).classification


def _incident_id(entity: str, window_start: datetime, signal_ids: list[str]) -> str:
    material = "|".join([entity, window_start.isoformat(), "|".join(signal_ids)])
    return f"inc-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:12]}"
