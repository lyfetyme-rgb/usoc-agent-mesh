"""AICEE: deterministic advisory analytics for the production control plane.

AICEE observes, forecasts and recommends. It never executes: every output is an
``ADVISORY`` recommendation with no target and no execution authority. Raw
telemetry values stay in the caller's request; evidence carries only SHA-256
fingerprints, so no payload can leak into OEKP or health surfaces.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .contracts import ActionClass, RiskLevel


def _fingerprint(body: dict[str, Any]) -> str:
    blob = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


class Signal(BaseModel):
    """One bounded, labelled telemetry observation. Never a raw payload blob."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=200)
    source: str = Field(min_length=1, max_length=128)
    key: str = Field(min_length=1, max_length=128)
    value: float
    observed_at: datetime
    labels: dict[str, str] = Field(default_factory=dict, max_length=16)

    @field_validator("value")
    @classmethod
    def _finite(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("signal value must be finite")
        return value

    @field_validator("labels")
    @classmethod
    def _bounded_labels(cls, labels: dict[str, str]) -> dict[str, str]:
        for key, item in labels.items():
            if len(key) > 64 or len(item) > 64:
                raise ValueError("signal labels are bounded to 64 characters")
        return labels


class Anomaly(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str
    key: str
    score: float
    direction: Literal["high", "low"]
    fingerprint: str


class ForecastPoint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str
    key: str
    at: datetime
    expected: float
    lower: float
    upper: float


class Recommendation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    tenant_id: str
    action: str
    rationale: str
    evidence_fingerprints: list[str]
    action_class: ActionClass = ActionClass.RECOMMEND
    risk: RiskLevel = RiskLevel.LOW


class AiceeReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str
    anomalies: list[Anomaly] = Field(default_factory=list)
    forecasts: list[ForecastPoint] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)
    evidence_fingerprints: list[str] = Field(default_factory=list)


class AiceeEngine:
    """Small, explainable control-plane analytics with no model in the loop."""

    def __init__(
        self,
        *,
        anomaly_z: float = 2.0,
        min_samples: int = 4,
        horizon: int = 3,
    ) -> None:
        if not math.isfinite(anomaly_z) or anomaly_z <= 0:
            raise ValueError("anomaly_z must be a positive finite number")
        if min_samples < 2:
            raise ValueError("min_samples must be at least 2")
        if horizon < 1:
            raise ValueError("horizon must be at least 1")
        self.anomaly_z = anomaly_z
        self.min_samples = min_samples
        self.horizon = horizon

    def analyze(self, signals: list[Signal]) -> AiceeReport:
        if not signals:
            raise ValueError("AICEE analysis requires at least one signal")
        tenants = {item.tenant_id for item in signals}
        if len(tenants) != 1:
            raise ValueError("AICEE analysis requires a single tenant")
        tenant_id = tenants.pop()

        series: dict[str, list[Signal]] = defaultdict(list)
        for item in signals:
            series[item.key].append(item)

        anomalies: list[Anomaly] = []
        forecasts: list[ForecastPoint] = []
        fingerprints: list[str] = []

        for key in sorted(series):
            points = sorted(series[key], key=lambda item: item.observed_at)
            values = [item.value for item in points]
            mean = sum(values) / len(values)
            variance = sum((value - mean) ** 2 for value in values) / len(values)
            stdev = math.sqrt(variance)

            if len(values) >= self.min_samples and stdev > 0:
                delta = values[-1] - mean
                score = abs(delta) / stdev
                if score >= self.anomaly_z:
                    direction = "high" if delta > 0 else "low"
                    fingerprint = _fingerprint(
                        {
                            "kind": "anomaly",
                            "tenant_id": tenant_id,
                            "key": key,
                            "direction": direction,
                            "score": round(score, 6),
                        }
                    )
                    anomalies.append(
                        Anomaly(
                            tenant_id=tenant_id,
                            key=key,
                            score=round(score, 6),
                            direction=direction,
                            fingerprint=fingerprint,
                        )
                    )
                    fingerprints.append(fingerprint)

            last_at = points[-1].observed_at
            if last_at.tzinfo is None:
                last_at = last_at.replace(tzinfo=timezone.utc)
            slope, intercept = _trend(values)
            band = stdev if stdev > 0 else 0.01
            for step in range(1, self.horizon + 1):
                index = len(values) - 1 + step
                expected = intercept + slope * index
                point = ForecastPoint(
                    tenant_id=tenant_id,
                    key=key,
                    at=last_at + timedelta(minutes=step),
                    expected=round(expected, 6),
                    lower=round(expected - band * (1 + step), 6),
                    upper=round(expected + band * (1 + step), 6),
                )
                forecasts.append(point)
                fingerprints.append(
                    _fingerprint(
                        {
                            "kind": "forecast",
                            "tenant_id": tenant_id,
                            "key": key,
                            "step": step,
                            "expected": point.expected,
                        }
                    )
                )

        recommendations = [
            Recommendation(
                id=f"aicee-rec-{index:04d}",
                tenant_id=tenant_id,
                action=f"investigate_{item.key}",
                rationale="statistical anomaly detected; human review required",
                evidence_fingerprints=[item.fingerprint],
            )
            for index, item in enumerate(anomalies, 1)
        ]

        return AiceeReport(
            tenant_id=tenant_id,
            anomalies=anomalies,
            forecasts=forecasts,
            recommendations=recommendations,
            evidence_fingerprints=fingerprints,
        )


def _trend(values: list[float]) -> tuple[float, float]:
    """Least-squares slope/intercept over positional samples."""
    count = len(values)
    if count < 2:
        return 0.0, values[0]
    mean_x = (count - 1) / 2
    mean_y = sum(values) / count
    numerator = sum((index - mean_x) * (value - mean_y) for index, value in enumerate(values))
    denominator = sum((index - mean_x) ** 2 for index in range(count))
    slope = numerator / denominator if denominator else 0.0
    return slope, mean_y - slope * mean_x
