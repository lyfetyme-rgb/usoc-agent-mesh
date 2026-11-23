"""Adaptive production-readiness benchmark: fixed validation, evolving variants.

Inspired by the Nature paper on agentic evolution of transition-state workflows:
the candidate is never trusted to grade itself. A fixed validator (the mesh's
deterministic policy engine plus hard invariants) scores every candidate, an
archive of signed evidence records the lineage, and adaptive mode spends its
remaining evaluation budget only on cases a variant has not resolved.

This module is observation-only. It never invokes a tool, handler, bus, live
approval or external sink. The only object it may touch is the injected
``PolicyEngine`` -- and the CLI supplies one backed by a fresh in-memory store
-- so a benchmark run cannot consume a live nonce or change governance state.

The "variants" are three deterministic screening strategies that already exist
as ideas inside the runtime boundary. They are not promoted automatically: the
report is a proposal with ``rehearsal_only=True`` and ``shadow=True`` literals.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .config import Settings
from .contracts import ActionClass, Classification, RiskLevel
from .evidence import EvidenceChain
from .governance import DecisionType, PolicyEngine
from .observability import new_trace

ORIGIN = "benchmark"
PROVENANCE = ("benchmark", "untrusted-candidate-input")
VARIANTS = ("strict", "policy_only", "screen_only")


def _digest(value: Any) -> str:
    blob = value if isinstance(value, str) else json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class BenchmarkCase(BaseModel):
    """One labeled scenario. ALLOW can never be a success expectation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=64)
    text: str = Field(min_length=1, max_length=4_000)
    action: ActionClass = ActionClass.EXECUTE
    target: str = Field(min_length=1, max_length=256)
    risk: RiskLevel = RiskLevel.HIGH
    classification: Classification = Classification.INTERNAL
    expected_decision: DecisionType
    expected_hits: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    mission_id: str | None = None
    amount: str | None = None
    currency: str | None = None

    @field_validator("expected_decision")
    @classmethod
    def _never_expect_allow(cls, value: DecisionType) -> DecisionType:
        if value not in (DecisionType.HOLD, DecisionType.DENY):
            raise ValueError(
                "benchmark expectations must be HOLD or DENY; an ALLOW is never "
                "execution proof and cannot be a validation success criterion"
            )
        return value


class CaseOutcome(BaseModel):
    """Measured result of one case under one variant and one adaptive round."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    variant: str
    round: int
    decision: DecisionType
    expected_decision: DecisionType
    screen_hits: list[str]
    decision_correct: bool
    screen_correct: bool
    resolved: bool
    latency_ms: int
    text_sha256: str
    policy_ref: str


class RoundRecord(BaseModel):
    """Evidence-backed lineage entry for one adaptive round."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    variant: str
    round: int
    case_ids: list[str]
    resolved: int
    unresolved: int
    evaluations: int
    score: float
    digest: str


class VariantResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    cases: list[CaseOutcome]
    lineage: list[RoundRecord]
    score: float
    resolved: int
    unresolved: int
    evaluations: int
    hard_violations: dict[str, int]


class BenchmarkReport(BaseModel):
    """Signed-run summary. Both promotion flags are literals, not caller input."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    mode: Literal["full", "adaptive"]
    cases: int
    variants: dict[str, VariantResult]
    best: str | None
    rejected: list[str]
    hard_pass: bool
    hard_invariants: dict[str, bool]
    totals: dict[str, int]
    # Cost of re-running every case for every variant in every available round.
    # Adaptive mode should spend less; the saving is measured, not asserted.
    naive_evaluations: int
    evaluation_saving_pct: float
    verified: bool
    verification_detail: str
    chain_head: dict[str, Any]
    rehearsal_only: Literal[True] = True
    shadow: Literal[True] = True


def load_cases(path: str | Path) -> list[BenchmarkCase]:
    """Read and strictly validate a JSONL scenario suite."""
    cases: list[BenchmarkCase] = []
    source = Path(path)
    for lineno, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            cases.append(BenchmarkCase.model_validate(json.loads(line)))
        except Exception as exc:
            raise ValueError(f"{source} line {lineno}: invalid benchmark case: {exc}") from exc
    if not cases:
        raise ValueError(f"{source}: no benchmark cases")
    return cases


async def _evaluate(
    case: BenchmarkCase,
    variant: str,
    *,
    policy: PolicyEngine,
    run_id: str,
    round_no: int,
) -> CaseOutcome:
    started = time.perf_counter()
    hits = policy.screen_text(case.text) if variant in ("strict", "screen_only") else []
    policy_ref = PolicyEngine.policy_ref(case.action, case.target, case.risk)

    if variant == "screen_only":
        # Deliberately incomplete: a screening-only workflow invents an ALLOW.
        decision = DecisionType.DENY if hits else DecisionType.ALLOW
    elif hits:
        # The runtime's defensive boundary runs before any policy/HITL path.
        decision = DecisionType.DENY
    else:
        verdict = await policy.evaluate(
            action=case.action,
            target=case.target,
            risk=case.risk,
            mission_id=case.mission_id,
            classification=case.classification,
            approval_ref=None,
            requested_by=ORIGIN,
            # A digest, not the scenario text: no secret can enter the
            # isolated approval request through a justification field.
            justification=f"benchmark:{case.id}:{_digest(case.text)[:12]}",
            correlation_id=run_id,
            provenance=list(PROVENANCE),
            tainted=True,
            amount=case.amount,
            currency=case.currency,
        )
        decision = verdict.decision
        policy_ref = verdict.policy_ref or policy_ref

    decision_correct = decision is case.expected_decision
    screen_correct = set(hits) == set(case.expected_hits)
    return CaseOutcome(
        case_id=case.id,
        variant=variant,
        round=round_no,
        decision=decision,
        expected_decision=case.expected_decision,
        screen_hits=list(hits),
        decision_correct=decision_correct,
        screen_correct=screen_correct,
        resolved=decision_correct and screen_correct,
        latency_ms=int((time.perf_counter() - started) * 1000),
        text_sha256=_digest(case.text),
        policy_ref=policy_ref,
    )


def _hard_violations(outcomes: list[CaseOutcome]) -> dict[str, int]:
    """Non-negotiable properties no candidate is allowed to redefine."""
    return {
        "unapproved_allow": sum(1 for item in outcomes if item.decision is DecisionType.ALLOW),
        "policy_ref_missing": sum(1 for item in outcomes if not item.policy_ref),
    }


async def _append_case_evidence(
    evidence: EvidenceChain, *, settings: Settings, run_id: str, outcome: CaseOutcome
) -> None:
    await evidence.append(
        kind="benchmark.case",
        actor=ORIGIN,
        subsystem=ORIGIN,
        correlation_id=run_id,
        mission_id=settings.mission_id,
        provenance=list(PROVENANCE),
        origin=ORIGIN,
        tainted=True,
        rehearsal_only=True,
        shadow=True,
        data={
            "run_id": run_id,
            "record_nonce": uuid.uuid4().hex,
            "case_id": outcome.case_id,
            "variant": outcome.variant,
            "round": outcome.round,
            "decision": outcome.decision.value,
            "expected_decision": outcome.expected_decision.value,
            "screen_hits": outcome.screen_hits,
            "decision_correct": outcome.decision_correct,
            "screen_correct": outcome.screen_correct,
            "resolved": outcome.resolved,
            "text_sha256": outcome.text_sha256,
            "latency_ms": outcome.latency_ms,
            "policy_ref": outcome.policy_ref,
        },
    )


async def _append_round_evidence(
    evidence: EvidenceChain, *, settings: Settings, run_id: str, record: RoundRecord
) -> None:
    await evidence.append(
        kind="benchmark.round",
        actor=ORIGIN,
        subsystem=ORIGIN,
        correlation_id=run_id,
        mission_id=settings.mission_id,
        provenance=list(PROVENANCE),
        origin=ORIGIN,
        tainted=True,
        rehearsal_only=True,
        shadow=True,
        data={
            "run_id": run_id,
            "record_nonce": uuid.uuid4().hex,
            **record.model_dump(),
        },
    )


async def run_benchmark(
    *,
    settings: Settings,
    evidence: EvidenceChain,
    policy: PolicyEngine,
    cases: list[BenchmarkCase],
    adaptive: bool = True,
    max_rounds: int = 3,
    run_id: str | None = None,
) -> BenchmarkReport:
    """Score every variant with a fixed validator and archive its lineage."""
    if not cases:
        raise ValueError("no benchmark cases supplied")
    if max_rounds < 1:
        raise ValueError("max_rounds must be positive")
    run_id = run_id or new_trace()
    mode = "full" if not adaptive else "adaptive"
    results: dict[str, VariantResult] = {}

    for variant in VARIANTS:
        pending = list(cases)
        outcomes: list[CaseOutcome] = []
        lineage: list[RoundRecord] = []
        previous_unresolved: tuple[str, ...] | None = None

        for round_no in range(1, max_rounds + 1):
            round_outcomes: list[CaseOutcome] = []
            for case in pending:
                outcome = await _evaluate(
                    case, variant, policy=policy, run_id=run_id, round_no=round_no
                )
                round_outcomes.append(outcome)
                await _append_case_evidence(
                    evidence, settings=settings, run_id=run_id, outcome=outcome
                )
            outcomes.extend(round_outcomes)
            resolved = sum(1 for item in round_outcomes if item.resolved)
            unresolved = len(round_outcomes) - resolved
            record = RoundRecord(
                variant=variant,
                round=round_no,
                case_ids=[item.case_id for item in round_outcomes],
                resolved=resolved,
                unresolved=unresolved,
                evaluations=len(round_outcomes),
                score=round(100 * resolved / len(cases), 2),
                digest=_digest(
                    [(item.case_id, item.decision.value, item.resolved) for item in round_outcomes]
                ),
            )
            lineage.append(record)
            await _append_round_evidence(
                evidence, settings=settings, run_id=run_id, record=record
            )

            unresolved_ids = tuple(sorted(item.case_id for item in round_outcomes if not item.resolved))
            stable = unresolved_ids == previous_unresolved
            previous_unresolved = unresolved_ids
            if not adaptive or unresolved == 0 or stable or round_no == max_rounds:
                break
            pending = [
                case
                for case in cases
                if not any(item.case_id == case.id and item.resolved for item in outcomes)
            ]
            if not pending:
                break

        # A case re-evaluated in a later round is still one case. Report the
        # final known state per case, with evaluations carrying the cost.
        final: dict[str, CaseOutcome] = {}
        for item in outcomes:
            final[item.case_id] = item
        resolved_total = sum(1 for item in final.values() if item.resolved)
        results[variant] = VariantResult(
            name=variant,
            cases=outcomes,
            lineage=lineage,
            score=round(100 * resolved_total / len(cases), 2),
            resolved=resolved_total,
            unresolved=len(final) - resolved_total,
            evaluations=len(outcomes),
            hard_violations=_hard_violations(outcomes),
        )

    ok, detail = evidence.verify()
    records = evidence.records()
    head = {
        "seq": records[-1].seq if records else 0,
        "hash": records[-1].hash if records else "genesis",
    }
    hard_invariants = {
        "evidence_verified": ok,
        "all_records_shadow": all(
            bool(record.shadow) and bool(record.rehearsal_only) for record in records
        ),
        "no_allow_expectation": all(
            case.expected_decision is not DecisionType.ALLOW for case in cases
        ),
        "bounded_rounds": all(len(item.lineage) <= max_rounds for item in results.values()),
    }
    rejected = sorted(
        name for name, item in results.items() if any(item.hard_violations.values())
    )
    eligible = [name for name in results if name not in rejected]
    best = sorted(eligible, key=lambda name: (-results[name].score, name))[0] if eligible else None
    hard_pass = best is not None and all(hard_invariants.values())
    totals = {
        "cases": len(cases),
        "variants": len(results),
        "evaluations": sum(item.evaluations for item in results.values()),
        "rejected": len(rejected),
        "resolved": sum(item.resolved for item in results.values()),
        "unresolved": sum(item.unresolved for item in results.values()),
    }

    naive_evaluations = len(cases) * len(VARIANTS) * max_rounds
    evaluation_saving_pct = round(
        100 * (naive_evaluations - totals["evaluations"]) / naive_evaluations, 2
    )

    await evidence.append(
        kind="benchmark.summary",
        actor=ORIGIN,
        subsystem=ORIGIN,
        correlation_id=run_id,
        mission_id=settings.mission_id,
        provenance=list(PROVENANCE),
        origin=ORIGIN,
        tainted=True,
        rehearsal_only=True,
        shadow=True,
        data={
            "run_id": run_id,
            "record_nonce": uuid.uuid4().hex,
            "mode": mode,
            "best": best,
            "rejected": rejected,
            "totals": totals,
            "naive_evaluations": naive_evaluations,
            "evaluation_saving_pct": evaluation_saving_pct,
            "hard_pass": hard_pass,
            "hard_invariants": hard_invariants,
        },
    )
    ok, detail = evidence.verify()
    records = evidence.records()
    head = {
        "seq": records[-1].seq if records else 0,
        "hash": records[-1].hash if records else "genesis",
    }

    return BenchmarkReport(
        run_id=run_id,
        mode=mode,  # type: ignore[arg-type]
        cases=len(cases),
        variants=results,
        best=best,
        rejected=rejected,
        hard_pass=hard_pass,
        hard_invariants=hard_invariants,
        totals=totals,
        naive_evaluations=naive_evaluations,
        evaluation_saving_pct=evaluation_saving_pct,
        verified=ok,
        verification_detail=detail,
        chain_head=head,
    )
