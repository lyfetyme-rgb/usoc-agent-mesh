"""Deterministic USOC agent implementations.

The generic ``SubsystemAgent`` handles LLM work. These four subsystems are
different on purpose: their core duty must not be probabilistic.

* SERAPHIM  -> policy decision point (deterministic engine)
* OEKP      -> append-only evidence writer (hash chain)
* BENGAL    -> independent verification (recomputes the chain)
* HITL      -> human approval queue (creates Handoff, never self-approves)

CYBER DEFENSE keeps the LLM path but its runtime gate hard-denies prohibited
offensive intent before any model call.
"""

from __future__ import annotations

from typing import Any

from .contracts import (
    ActionClass,
    Failure,
    Handoff,
    Message,
    Query,
    QueryReply,
    RiskLevel,
    TaskResult,
    TaskSpec,
)
from .evidence import sandbox_origin
from .governance import ApprovalRequest, taint_disclosure_hash
from .runtime import SubsystemAgent
from .observability import log


class AiceeAgent(SubsystemAgent):
    """Operational intelligence with a deterministic path for correlation output.

    The correlation engine is platform code, so when its output is supplied the
    summary is deterministic too. Without that input this falls back to the
    normal model path; the model never recomputes a correlation score.
    """

    async def handle_task(self, spec: TaskSpec, msg: Message) -> TaskResult | Handoff | Failure:
        incidents = spec.inputs.get("correlated_incidents")
        if not incidents:
            return await super().handle_task(spec, msg)
        if not isinstance(incidents, list):
            return Failure(code="bad_request", message="correlated_incidents must be a list")

        lines: list[str] = []
        for item in incidents[:10]:
            if not isinstance(item, dict):
                continue
            sources = item.get("sources") or []
            source_text = ", ".join(str(s) for s in sources[:6]) if isinstance(sources, list) else str(sources)
            lines.append(
                f"- {item.get('id', '?')} {item.get('entity', '?')} "
                f"risk={item.get('risk', '?')} score={item.get('score', '?')} "
                f"sources={source_text}"
            )
        output = "Correlated operational incidents:\n" + ("\n".join(lines) if lines else "none")
        return TaskResult(
            ok=True,
            output=output,
            data={"incidents": incidents[:10], "count": len(incidents)},
        )


class SeraphimAgent(SubsystemAgent):
    """Binding policy decisions come from code, never from the model."""

    deterministic = True

    async def handle_task(self, spec: TaskSpec, msg: Message) -> TaskResult | Handoff | Failure:
        if self.policy is None:
            return Failure(code="policy_unavailable", message="policy engine not configured")
        data: dict[str, Any] = spec.inputs
        try:
            action = ActionClass(data.get("action_class", spec.action_class.value))
            risk = RiskLevel(data.get("risk", spec.risk.value))
        except ValueError as exc:
            return Failure(code="bad_request", message=f"invalid action_class or risk: {exc}")
        decision = await self.policy.evaluate(
            action=action,
            target=data.get("target", spec.target),
            risk=risk,
            mission_id=data.get("mission_id", spec.mission_id or msg.mission_id),
            classification=msg.classification,
            approval_ref=data.get("approval_ref", spec.approval_ref),
            requested_by=msg.sender,
            justification=data.get("justification") or spec.justification or spec.objective,
            correlation_id=msg.correlation_id,
            provenance=list(data.get("provenance") or spec.provenance),
            tainted=bool(data.get("tainted", spec.tainted)),
            amount=data.get("amount", spec.amount),
            currency=data.get("currency", spec.currency),
        )
        self.metrics.inc("policy.evaluated")
        log("seraphim.decision", decision=decision.decision.value, target=data.get("target", spec.target))
        return TaskResult(
            ok=decision.allowed,
            output=f"{decision.decision.value}: " + "; ".join(decision.reasons),
            data={"decision": decision.decision.value, **decision.model_dump(mode="json")},
            policy_decision_ref=decision.policy_ref,
            authorization_ref=decision.authorization_ref,
        )


class HitlAgent(SubsystemAgent):
    """Presents decisions and records approvals. It can never approve for a human."""

    deterministic = True

    async def handle_task(self, spec: TaskSpec, msg: Message) -> TaskResult | Handoff | Failure:
        if self.approvals is None:
            return Failure(code="hitl_unavailable", message="approval store not configured")

        approval_id = spec.inputs.get("approval_id")
        if approval_id:
            request = await self.approvals.get(str(approval_id))
            if request is None:
                return Failure(code="not_found", message=f"no approval {approval_id}")
            return TaskResult(
                ok=True,
                output=f"{request.id} is {request.status.value}",
                data=request.model_dump(mode="json"),
            )

        try:
            action = ActionClass(spec.inputs.get("action_class", spec.action_class.value))
            risk = RiskLevel(spec.inputs.get("risk", spec.risk.value))
        except ValueError as exc:
            return Failure(code="bad_request", message=f"invalid action_class or risk: {exc}")

        request = await self.approvals.request(
            ApprovalRequest(
                action_class=action,
                target=str(spec.inputs.get("target") or spec.target or ""),
                risk=risk,
                mission_id=spec.mission_id or msg.mission_id,
                requested_by=msg.sender,
                justification=str(spec.inputs.get("justification") or spec.justification or spec.objective),
                correlation_id=msg.correlation_id,
                provenance=list(spec.inputs.get("provenance") or spec.provenance),
                tainted=bool(spec.inputs.get("tainted", spec.tainted)),
                taint_hash=taint_disclosure_hash(
                    list(spec.inputs.get("provenance") or spec.provenance),
                    bool(spec.inputs.get("tainted", spec.tainted)),
                ),
            )
        )
        self.metrics.inc("hitl.requested")
        return Handoff(
            instruction=(
                f"Human approval required for {action.value} on {request.target or '(no target)'}. "
                f"Approval id {request.id}. Approve with: python -m agents approve {request.id}"
            ),
            reason="approval",
            approval_ref=request.id,
        )

    async def handle_query(self, query: Query, msg: Message) -> QueryReply:
        if self.approvals is None:
            return QueryReply(answer="approval store unavailable")
        if "pending" in query.question.lower():
            pending = await self.approvals.pending()
            listing = "\n".join(f"- {r.id} {r.action_class.value} {r.target} ({r.requested_by})" for r in pending)
            return QueryReply(answer=f"{len(pending)} pending approvals\n{listing}".strip())
        # Never fall back to the generic LLM query path. HITL is deterministic:
        # either it can answer from the approval store or it says what it needs.
        return QueryReply(
            answer=(
                "HITL is deterministic (no LLM). Ask for 'pending approvals' or "
                "submit an approval request task with an action_class and target."
            )
        )


class OekpAgent(SubsystemAgent):
    """Append-only evidence writer. Original records are never modified."""

    deterministic = True

    async def handle_task(self, spec: TaskSpec, msg: Message) -> TaskResult | Handoff | Failure:
        if self.evidence is None:
            return Failure(code="oekp_unavailable", message="evidence chain not configured")
        kind = str(spec.inputs.get("kind") or "operational.event")
        provenance = list(spec.inputs.get("provenance") or spec.provenance)
        # Origin comes from the authenticated envelope, never from the payload.
        origin = msg.sender
        from_csssf = sandbox_origin(
            origin=origin,
            provenance=provenance,
            sender=msg.sender,
        ) or spec.action_class is ActionClass.SIMULATE
        rehearsal_only = bool(spec.inputs.get("rehearsal_only", False)) or from_csssf
        if from_csssf and not spec.inputs.get("rehearsal_only", False):
            return Failure(
                code="rehearsal_only",
                message=(
                    "CSSSF sandbox evidence requires rehearsal_only=true; "
                    "refusing to record a rehearsal as execution proof"
                ),
            )
        record = await self.evidence.append(
            kind=kind,
            actor=str(spec.inputs.get("actor") or msg.sender),
            subsystem=self.id,
            correlation_id=msg.correlation_id,
            mission_id=spec.mission_id or msg.mission_id,
            classification=msg.classification.value,
            provenance=provenance,
            origin=origin,
            tainted=bool(spec.tainted),
            rehearsal_only=rehearsal_only,
            data={"objective": spec.objective, "inputs": spec.inputs},
        )
        self.metrics.inc("evidence.appended")
        return TaskResult(
            ok=True,
            output=f"recorded {record.id} at seq {record.seq}",
            data={
                "id": record.id,
                "seq": record.seq,
                "hash": record.hash,
                "rehearsal_only": record.rehearsal_only,
            },
            evidence_ref=record.id,
        )


class BengalAgent(SubsystemAgent):
    """Independent verification: recomputes the evidence chain from disk."""

    deterministic = True

    async def handle_task(self, spec: TaskSpec, msg: Message) -> TaskResult | Handoff | Failure:
        if self.evidence is None:
            return Failure(code="bengal_unavailable", message="evidence chain not configured")
        ok, detail = self.evidence.verify()
        head_seq, head_hash = self.evidence.head
        records = self.evidence.records()
        rehearsals = [r for r in records if r.rehearsal_only]
        untrusted_sandbox = [
            r
            for r in records
            if not r.rehearsal_only
            and sandbox_origin(origin=r.origin, provenance=r.provenance)
        ]
        self.metrics.inc("bengal.verified")
        notes = [detail]
        if rehearsals:
            notes.append(f"{len(rehearsals)} rehearsal-only record(s) are not execution proof")
        if untrusted_sandbox:
            notes.append(f"{len(untrusted_sandbox)} unmarked sandbox-origin record(s) found")
        trusted_for_execution = ok and not rehearsals and not untrusted_sandbox
        return TaskResult(
            ok=ok,
            output="evidence chain: " + "; ".join(notes),
            data={
                "verified": ok,
                "detail": "; ".join(notes),
                "head_seq": head_seq,
                "head_hash": head_hash,
                "checked": "evidence.integrity",
                "rehearsal_only_count": len(rehearsals),
                "rehearsal_ids": [r.id for r in rehearsals],
                "untrusted_sandbox_count": len(untrusted_sandbox),
                "trusted_for_execution": trusted_for_execution,
            },
            evidence_ref=head_hash[:32],
        )
