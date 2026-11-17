"""The fragmentation layer: ingest -> correlate -> govern -> record.

This is the composition that addresses the business problem directly. It does
not replace the incumbent systems. It reads from them, produces one ranked
operational picture, and then routes any consequential action through the same
deterministic governance chain the rest of USOC uses.

The service is deliberately read-only up to the policy gate. It can *propose*
containment; it cannot execute it. A human approval is required for a governed
action, exactly as it is for a subsystem agent.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from pydantic import BaseModel, ConfigDict, Field

from .config import Settings, get_settings
from .connectors import (
    Connector,
    IngestResult,
    Signal,
    ingest_connectors,
)
from .contracts import ActionClass, Classification, RiskLevel
from .correlation import (
    CorrelatedIncident,
    CorrelationConfig,
    CorrelationEngine,
    CorrelationResult,
)
from .evidence import EvidenceChain
from .governance import DecisionType, GovernanceDecision, PolicyEngine

SAFE_TARGET = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}/[a-z0-9][a-z0-9._-]{0,63}$")


class ProposedAction(BaseModel):
    """A recommendation that is not authority until the policy gate allows it."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str
    action_class: ActionClass
    target: str
    risk: RiskLevel
    classification: Classification = Classification.INTERNAL
    justification: str
    mission_id: str | None = None
    # Connector telemetry is untrusted input. Record where the recommendation
    # came from and require the approval to disclose that taint.
    provenance: list[str] = Field(default_factory=list)
    tainted: bool = False
    # FinOps/Banking: the exact transaction the human will be asked to approve.
    amount: str | None = Field(default=None, max_length=40)
    currency: str | None = Field(default=None, max_length=12)
    # Clinical: PII/PHI labels detected in every contributing connector.
    sensitive_labels: list[str] = Field(default_factory=list)


class FragmentationReport(BaseModel):
    """Everything one run produced, including the evidence references."""

    model_config = ConfigDict(extra="forbid")

    ingest: IngestResult
    correlation: CorrelationResult
    action: ProposedAction | None = None
    decision: GovernanceDecision | None = None
    approval_ref: str | None = None
    authorization_ref: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class FragmentationService:
    """Read-only connectors plus deterministic correlation and governance."""

    def __init__(
        self,
        connectors: Iterable[Connector],
        policy: PolicyEngine | None = None,
        evidence: EvidenceChain | None = None,
        settings: Settings | None = None,
        *,
        requested_by: str = "fragmentation",
        engine: CorrelationEngine | None = None,
    ) -> None:
        self.connectors = list(connectors)
        self.policy = policy
        self.evidence = evidence
        self.settings = settings or get_settings()
        self.requested_by = requested_by
        self.engine = engine or CorrelationEngine(
            CorrelationConfig(
                window_s=self.settings.correlation_window_s,
                min_sources=self.settings.correlation_min_sources,
                min_score=self.settings.correlation_min_score,
            )
        )
        self._evidence_refs: list[str] = []

    # -- lifecycle ----------------------------------------------------------
    async def close(self) -> None:
        for connector in self.connectors:
            try:
                await connector.close()
            except Exception:
                pass

    def describe(self) -> dict[str, Any]:
        return {
            "connectors": [c.describe() for c in self.connectors],
            "window_s": self.engine.config.window_s,
            "min_sources": self.engine.config.min_sources,
            "min_score": self.engine.config.min_score,
            "governed": self.policy is not None,
            "evidence": self.evidence is not None,
        }

    # -- work ---------------------------------------------------------------
    async def ingest(self) -> IngestResult:
        result = await ingest_connectors(
            self.connectors, timeout_s=self.settings.connector_timeout_s
        )
        await self._audit(
            "fragmentation.ingested",
            {
                "connectors": len(self.connectors),
                "signals": len(result.signals),
                "sources": result.counts_by_source,
                "source_types": result.counts_by_source_type,
                "truncated": result.truncated_sources,
                "errors": result.errors[:20],
            },
        )
        return result

    async def correlate(
        self, signals: Iterable[Signal], *, mission_id: str | None = None
    ) -> CorrelationResult:
        result = self.engine.correlate(signals)
        for incident in result.incidents[:50]:
            await self._audit(
                "fragmentation.correlated",
                incident.model_dump(mode="json", exclude={"signals"}),
                mission_id=mission_id,
                classification=incident.classification.value,
                correlation_id=incident.id,
                tainted=incident.tainted,
            )
        return result

    def propose(self, incident: CorrelatedIncident, *, mission_id: str | None = None) -> ProposedAction:
        """Turn the top incident into one explicit, governed containment proposal."""
        return ProposedAction(
            incident_id=incident.id,
            action_class=ActionClass.CONTAIN,
            target=_containment_target(incident),
            risk=incident.risk,
            classification=incident.classification,
            justification=(
                f"Correlated incident {incident.id} on {incident.entity}: "
                f"{incident.summary}. {', '.join(incident.reasons[:3])}."
            )[:2_000],
            mission_id=mission_id,
            provenance=list(incident.sources),
            tainted=True,
            amount=_money_from_signals(incident.signals, "amount"),
            currency=_money_from_signals(incident.signals, "currency"),
            sensitive_labels=_sensitive_labels(incident.signals),
        )

    async def authorize(
        self,
        action: ProposedAction,
        *,
        mission_id: str | None = None,
        approval_ref: str | None = None,
    ) -> GovernanceDecision:
        if self.policy is None:
            decision = GovernanceDecision(
                decision=DecisionType.DENY,
                policy_ref="pol-unavailable",
                reasons=["policy engine is not configured; governed actions are refused"],
            )
        else:
            decision = await self.policy.evaluate(
                action=action.action_class,
                target=action.target,
                risk=action.risk,
                mission_id=mission_id or action.mission_id,
                classification=action.classification,
                approval_ref=approval_ref,
                requested_by=self.requested_by,
                justification=action.justification,
                correlation_id=action.incident_id,
                provenance=action.provenance,
                tainted=action.tainted,
                amount=action.amount,
                currency=action.currency,
            )
        await self._audit(
            "fragmentation.policy_decision",
            {
                "incident_id": action.incident_id,
                "action_class": action.action_class.value,
                "target": action.target,
                "risk": action.risk.value,
                "decision": decision.decision.value,
                "policy_ref": decision.policy_ref,
                "approval_ref": decision.approval_ref,
                "authorization_ref": decision.authorization_ref,
                "reasons": decision.reasons,
                "provenance": decision.provenance,
                "tainted": decision.tainted,
                "amount": action.amount,
                "currency": action.currency,
                "sensitive_labels": action.sensitive_labels,
            },
            mission_id=mission_id or action.mission_id,
            classification=action.classification.value,
            correlation_id=action.incident_id,
            tainted=action.tainted,
        )
        return decision

    async def run(
        self,
        *,
        mission_id: str | None = None,
        approval_ref: str | None = None,
        propose: bool = True,
    ) -> FragmentationReport:
        """Ingest, correlate and optionally request a governed containment decision."""
        self._evidence_refs = []
        ingest = await self.ingest()
        correlation = await self.correlate(ingest.signals, mission_id=mission_id)
        report = FragmentationReport(ingest=ingest, correlation=correlation)
        top = correlation.top()
        if top is None:
            report.notes.append(
                "no cross-source incident met the correlation threshold; "
                "signals are retained with provenance for the next window"
            )
            report.evidence_refs = list(self._evidence_refs)
            return report

        if not propose:
            report.notes.append(
                f"top incident {top.id} on {top.entity}: risk {top.risk.value}, "
                f"score {top.score}/100, {len(top.source_types)} source types"
            )
            report.evidence_refs = list(self._evidence_refs)
            return report

        action = self.propose(top, mission_id=mission_id)
        report.action = action
        await self._audit(
            "fragmentation.action_proposed",
            action.model_dump(mode="json"),
            mission_id=mission_id,
            classification=action.classification.value,
            correlation_id=top.id,
            tainted=action.tainted,
        )
        decision = await self.authorize(
            action, mission_id=mission_id, approval_ref=approval_ref
        )
        report.decision = decision
        report.approval_ref = decision.approval_ref
        report.authorization_ref = decision.authorization_ref
        if decision.decision is DecisionType.HOLD:
            report.notes.append(
                f"human approval required: python -m agents approve "
                f"{decision.approval_ref} --by <human>"
            )
        elif decision.decision is DecisionType.DENY:
            report.notes.append("policy denied the proposed containment action")
        elif decision.decision is DecisionType.ALLOW:
            report.notes.append(
                "containment authorized; dispatch the action through the governed "
                "runtime so execution and validation are recorded"
            )
        report.evidence_refs = list(self._evidence_refs)
        return report

    # -- evidence -----------------------------------------------------------
    async def _audit(
        self,
        kind: str,
        data: dict[str, Any],
        *,
        mission_id: str | None = None,
        classification: str = "internal",
        correlation_id: str = "",
        tainted: bool = False,
    ) -> str | None:
        if self.evidence is None:
            return None
        record = await self.evidence.append(
            kind=kind,
            actor=self.requested_by,
            subsystem="fragmentation",
            correlation_id=correlation_id,
            mission_id=mission_id or self.settings.mission_id,
            classification=classification,
            data=data,
            tainted=tainted,
        )
        self._evidence_refs.append(record.id)
        return record.id


_AMOUNT_KEYS = ("amount", "transaction_amount", "wire_amount", "transfer_amount")
_CURRENCY_KEYS = ("currency", "currency_code")


def _money_from_signals(signals: list[Signal], kind: str) -> str | None:
    """Extract the first well-formed amount/currency from connector attributes."""
    keys = _AMOUNT_KEYS if kind == "amount" else _CURRENCY_KEYS
    pattern = r"\d+(\.\d{1,4})?" if kind == "amount" else r"[A-Za-z]{3}"
    for signal in signals:
        for key in keys:
            value = signal.attributes.get(key)
            if value is None:
                continue
            text = str(value).strip()
            if re.fullmatch(pattern, text):
                return text.upper() if kind == "currency" else text
    return None


def _sensitive_labels(signals: list[Signal]) -> list[str]:
    labels: set[str] = set()
    for signal in signals:
        labels.update(getattr(signal, "sensitive_labels", []) or [])
    return sorted(labels)


def _containment_target(incident: CorrelatedIncident) -> str:
    """Choose an explicit target; never let a vendor field widen the blast radius."""
    for signal in incident.signals:
        raw = signal.attributes.get("containment_target")
        if isinstance(raw, str) and _safe_target(raw):
            return raw
    slug = re.sub(r"[^a-z0-9._-]+", "-", incident.entity.lower()).strip("-.")[:60]
    return f"sandbox/{slug or 'unknown'}"


def _safe_target(value: str) -> bool:
    if not SAFE_TARGET.match(value):
        return False
    if ".." in value or value.startswith(("/", ".")):
        return False
    return True
