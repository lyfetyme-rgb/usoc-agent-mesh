"""Waste Optimization Agent: advisory analysis plus HITL-gated proposals.

This module never applies a change. It produces bounded candidates, namespaced
approval requests and before/after savings validation. Raw telemetry stays in
the caller's observations; evidence carries fingerprints only.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import defaultdict
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .contracts import ActionClass, RiskLevel
from .governance import ApprovalRequest, ApprovalStatus


def _fingerprint(body: dict[str, Any]) -> str:
    blob = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _money(value: Decimal) -> str:
    return str(value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def _identifier(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_-]", "-", value).strip("-")
    return safe or "unknown"


class ResourceObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=200)
    resource_id: str = Field(min_length=1, max_length=200)
    metric: Literal["cpu_utilization_pct", "memory_utilization_pct"] = "cpu_utilization_pct"
    value: float
    window_hours: int = Field(default=24, ge=1, le=8_760)
    observed_at: datetime
    mission_id: str | None = Field(default=None, max_length=200)
    mission_protected: bool = False

    @field_validator("value")
    @classmethod
    def _bounded(cls, value: float) -> float:
        if not math.isfinite(value) or value < 0 or value > 100:
            raise ValueError("observation value must be a finite percentage")
        return value


class WasteCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str
    resource_id: str
    category: Literal["idle", "overprovisioned"]
    metric: str
    average_value: float
    estimated_monthly_saving_usd: str
    confidence: float
    evidence_fingerprint: str
    mission_id: str | None = None
    suppressed: bool = False
    suppression_reason: str | None = None


class SavingsValidation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str
    resource_id: str
    estimated_monthly_saving_usd: str
    observed_monthly_saving_usd: str
    realized_ratio: float
    validated: bool


class WasteOptimizer:
    """Deterministic FinOps analysis with an explicit human decision boundary."""

    def __init__(
        self,
        *,
        idle_cpu_pct: float = 5.0,
        overprovisioned_cpu_pct: float = 15.0,
        monthly_hours: float = 730.0,
        usd_per_resource_hour: float = 0.08,
        min_observations: int = 2,
    ) -> None:
        if not 0 <= idle_cpu_pct <= overprovisioned_cpu_pct <= 100:
            raise ValueError("waste thresholds must be ordered percentages")
        if monthly_hours <= 0 or usd_per_resource_hour <= 0:
            raise ValueError("cost basis must be positive")
        if min_observations < 2:
            raise ValueError("min_observations must be at least 2")
        self.idle_cpu_pct = idle_cpu_pct
        self.overprovisioned_cpu_pct = overprovisioned_cpu_pct
        self.monthly_hours = Decimal(str(monthly_hours))
        self.usd_per_resource_hour = Decimal(str(usd_per_resource_hour))
        self.min_observations = min_observations

    def analyze(self, observations: list[ResourceObservation]) -> list[WasteCandidate]:
        if not observations:
            raise ValueError("waste analysis requires observations")
        tenants = {item.tenant_id for item in observations}
        if len(tenants) != 1:
            raise ValueError("waste analysis requires a single tenant")
        tenant_id = tenants.pop()

        grouped: dict[str, list[ResourceObservation]] = defaultdict(list)
        for item in observations:
            grouped[item.resource_id].append(item)

        candidates: list[WasteCandidate] = []
        for resource_id in sorted(grouped):
            points = grouped[resource_id]
            if len(points) < self.min_observations:
                continue
            metrics = {item.metric for item in points}
            if len(metrics) != 1:
                raise ValueError(f"resource {resource_id} mixes incompatible metrics")
            metric = metrics.pop()
            average = sum(item.value for item in points) / len(points)
            mission_ids = {item.mission_id for item in points if item.mission_id}
            mission_id = sorted(mission_ids)[0] if len(mission_ids) == 1 else None
            mission_protected = any(item.mission_protected for item in points)

            if average <= self.idle_cpu_pct:
                category: Literal["idle", "overprovisioned"] = "idle"
                reclaimable = 1.0 - average / 100.0
                confidence = round(1.0 - average / 100.0, 2)
            elif average <= self.overprovisioned_cpu_pct:
                category = "overprovisioned"
                reclaimable = (100.0 - average) / 200.0
                confidence = round((100.0 - average) / 200.0, 2)
            else:
                continue

            saving = (
                self.monthly_hours
                * self.usd_per_resource_hour
                * Decimal(str(reclaimable))
            )
            fingerprint = _fingerprint(
                {
                    "kind": "waste-candidate",
                    "tenant_id": tenant_id,
                    "resource_id": resource_id,
                    "category": category,
                    "average": round(average, 2),
                }
            )
            candidates.append(
                WasteCandidate(
                    tenant_id=tenant_id,
                    resource_id=resource_id,
                    category=category,
                    metric=metric,
                    average_value=round(average, 4),
                    estimated_monthly_saving_usd=_money(saving),
                    confidence=confidence,
                    evidence_fingerprint=fingerprint,
                    mission_id=mission_id,
                    suppressed=mission_protected,
                    suppression_reason=(
                        "mission-protected capacity is suppressed before any HITL request"
                        if mission_protected
                        else None
                    ),
                )
            )
        return candidates

    def build_approval_request(
        self,
        candidate: WasteCandidate,
        *,
        requested_by: str,
        correlation_id: str = "",
    ) -> ApprovalRequest:
        """Create a pending HITL decision. There is deliberately no apply path."""
        if not requested_by:
            raise ValueError("requested_by is required")
        if candidate.suppressed:
            raise ValueError("mission-protected candidate cannot enter HITL")
        target = (
            f"sandbox/waste/{_identifier(candidate.tenant_id)}/"
            f"{_identifier(candidate.resource_id)}"
        )
        return ApprovalRequest(
            tenant_id=candidate.tenant_id,
            action_class=ActionClass.EXECUTE,
            target=target,
            risk=RiskLevel.HIGH,
            requested_by=requested_by,
            justification=(
                f"waste candidate {candidate.category} requires human review before any change"
            ),
            correlation_id=correlation_id,
            provenance=["waste-optimizer", "telemetry"],
            tainted=True,
            quorum=1,
            status=ApprovalStatus.PENDING,
        )

    def validate_savings(
        self,
        candidate: WasteCandidate,
        before: list[ResourceObservation],
        after: list[ResourceObservation],
    ) -> SavingsValidation:
        """Compare an approved change's measured outcome with its estimate."""
        if not before:
            raise ValueError("before-window observations are required")
        if not after:
            raise ValueError("after-window observations are required")
        relevant_after = [
            item for item in after if item.resource_id == candidate.resource_id
        ]
        if not relevant_after:
            raise ValueError("after-window has no observation for the candidate resource")

        before_avg = sum(item.value for item in before) / len(before)
        after_avg = sum(item.value for item in relevant_after) / len(relevant_after)
        if candidate.category == "idle" and after_avg <= self.idle_cpu_pct:
            # An idle resource driven to/below the idle threshold is reclaimed,
            # so the realized saving is the bounded full-resource cost basis.
            realized_fraction = 1.0 - after_avg / 100.0
        else:
            realized_fraction = max(0.0, min(1.0, (before_avg - after_avg) / 100.0))
        observed = (
            self.monthly_hours
            * self.usd_per_resource_hour
            * Decimal(str(realized_fraction))
        )
        estimated = Decimal(candidate.estimated_monthly_saving_usd)
        ratio = float(observed / estimated) if estimated > 0 else 0.0
        return SavingsValidation(
            tenant_id=candidate.tenant_id,
            resource_id=candidate.resource_id,
            estimated_monthly_saving_usd=_money(estimated),
            observed_monthly_saving_usd=_money(observed),
            realized_ratio=round(ratio, 4),
            validated=ratio >= 0.8,
        )
