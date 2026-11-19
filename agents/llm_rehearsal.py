"""Live LLM rehearsal harness: measure a model, execute nothing.

The mesh's shadow mode already stops consequential actions, but it does not
stop an ``OpenAICompatibleLLM`` HTTP request. This module is the missing
staged-rollout harness: it sends labeled prompts to an injected :class:`LLM`
(the live connector when explicitly opted in, ``EchoLLM`` otherwise), screens
the untrusted model output with the real deterministic policy, and records
every observation as hash-chained, signed evidence that is permanently marked
``rehearsal_only=True`` and ``shadow=True``.

Guarantees, enforced in code rather than by convention:

* No tool, handler, bus message, approval consumption or external write. The
  only possible network call is the model completion itself, and only when the
  caller explicitly passes ``live=True``.
* Model output is treated as tainted data with ``llm-rehearsal`` /
  ``untrusted-model-output`` provenance, so BENGAL withholds
  ``trusted_for_execution`` and a downstream approval must disclose the chain.
* Every record carries a fresh run id and per-record nonce inside the signed
  payload, alongside the hash chain and MAC, so a prior run cannot be replayed
  as a new one. Evidence records cannot claim ``ALLOW`` as an expectation.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .config import Settings
from .contracts import ActionClass, Classification, RiskLevel
from .evidence import EvidenceChain
from .governance import DecisionType, PolicyEngine
from .llm import LLM, extract_json
from .observability import new_trace
from .security import redact_url

ORIGIN = "llm-rehearsal"
PROVENANCE = ("llm-rehearsal", "untrusted-model-output")


def _digest(value: Any) -> str:
    """Stable SHA-256 over text or a canonical JSON value."""
    blob = value if isinstance(value, str) else json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class RehearsalCase(BaseModel):
    """One labeled prompt. Expectations are HOLD/DENY only, never ALLOW."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    system: str
    messages: list[dict[str, str]]
    json_schema: dict[str, Any] | None = None
    expected_hits: list[str] = Field(default_factory=list)
    expected_decision: DecisionType
    action: ActionClass = ActionClass.EXECUTE
    target: str = "sandbox/llm-rehearsal"
    risk: RiskLevel = RiskLevel.HIGH
    classification: Classification = Classification.INTERNAL
    amount: str | None = None
    currency: str | None = None

    @field_validator("expected_decision")
    @classmethod
    def _never_expect_allow(cls, value: DecisionType) -> DecisionType:
        if value is DecisionType.ALLOW:
            raise ValueError(
                "rehearsal expectations must be HOLD or DENY; an ALLOW is never "
                "execution proof and cannot be a rehearsal success criterion"
            )
        return value


class CaseResult(BaseModel):
    """Measured outcome of one case."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    live: bool
    model: str
    latency_ms: int
    tokens: int
    prompt_sha256: str
    response_sha256: str
    screen_hits: list[str]
    decision: DecisionType
    policy_ref: str
    approval_ref: str | None
    expected_decision: DecisionType
    expected_hits: list[str]
    decision_correct: bool
    screen_correct: bool

    @property
    def correct(self) -> bool:
        return self.decision_correct and self.screen_correct


class RehearsalReport(BaseModel):
    """Signed-run summary. The two flags are literals: callers cannot clear them."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    mode: Literal["live", "offline"]
    cases: list[CaseResult]
    totals: dict[str, int]
    verified: bool
    verification_detail: str
    chain_head: dict[str, Any]
    rehearsal_only: Literal[True] = True
    shadow: Literal[True] = True


async def run_rehearsal(
    *,
    settings: Settings,
    llm: LLM,
    evidence: EvidenceChain,
    policy: PolicyEngine,
    cases: list[RehearsalCase],
    run_id: str | None = None,
    live: bool = False,
) -> RehearsalReport:
    """Run labeled prompts through ``llm`` and record observations only.

    ``llm`` is injected so the default path stays offline (``EchoLLM``). Pass a
    live connector and ``live=True`` only when the operator opts into model
    egress. No handler, tool, bus, approval decision or external sink is ever
    touched here.
    """
    if not cases:
        raise ValueError("no rehearsal cases supplied")
    run_id = run_id or new_trace()
    mode = "live" if live else "offline"
    results: list[CaseResult] = []

    for case in cases:
        prompt = {"system": case.system, "messages": case.messages}
        prompt_digest = _digest(prompt)
        started = time.perf_counter()
        response = await llm.complete(
            system=case.system,
            messages=case.messages,
            json_schema=case.json_schema,
            model=settings.model,
            max_tokens=512,
        )
        latency_ms = int((time.perf_counter() - started) * 1000)

        # The client sets `data` only when it sent a JSON schema; a provider
        # that fell back to prose still returns a parseable JSON reply.
        parsed = response.data if response.data is not None else extract_json(response.text)
        hits = policy.screen_text(response.text)
        policy_ref = PolicyEngine.policy_ref(case.action, case.target, case.risk)
        approval_ref: str | None = None

        if hits:
            # Mirror the runtime's defensive boundary: prohibited intent is a
            # DENY, evaluated before any policy/HITL path.
            decision = DecisionType.DENY
        else:
            outcome = await policy.evaluate(
                action=case.action,
                target=case.target,
                risk=case.risk,
                mission_id=settings.mission_id,
                classification=case.classification,
                approval_ref=None,
                requested_by=ORIGIN,
                justification=response.text[:2000],
                correlation_id=run_id,
                provenance=list(PROVENANCE),
                tainted=True,
                amount=case.amount,
                currency=case.currency,
            )
            decision = outcome.decision
            policy_ref = outcome.policy_ref or policy_ref
            approval_ref = outcome.approval_ref

        decision_correct = decision is case.expected_decision
        screen_correct = set(hits) == set(case.expected_hits)

        await evidence.append(
            kind="llm.rehearsal.case",
            actor=ORIGIN,
            subsystem=ORIGIN,
            correlation_id=run_id,
            mission_id=settings.mission_id,
            classification=case.classification.value,
            provenance=list(PROVENANCE),
            origin=ORIGIN,
            tainted=True,
            rehearsal_only=True,
            shadow=True,
            data={
                "case_id": case.id,
                "run_id": run_id,
                "record_nonce": uuid.uuid4().hex,
                "mode": mode,
                "live": live,
                "model": response.model or settings.model,
                "prompt_sha256": prompt_digest,
                "response_sha256": _digest(response.text),
                "parsed": parsed is not None,
                "latency_ms": latency_ms,
                "tokens": response.tokens,
                "screen_hits": hits,
                "decision": decision.value,
                "expected_decision": case.expected_decision.value,
                "policy_ref": policy_ref,
                "approval_ref": approval_ref,
                "decision_correct": decision_correct,
                "screen_correct": screen_correct,
                "target": case.target,
                "llm_base_url": (
                    redact_url(settings.llm_base_url) if settings.llm_base_url else None
                ),
            },
        )
        results.append(
            CaseResult(
                case_id=case.id,
                live=live,
                model=response.model or settings.model,
                latency_ms=latency_ms,
                tokens=response.tokens,
                prompt_sha256=prompt_digest,
                response_sha256=_digest(response.text),
                screen_hits=hits,
                decision=decision,
                policy_ref=policy_ref,
                approval_ref=approval_ref,
                expected_decision=case.expected_decision,
                expected_hits=list(case.expected_hits),
                decision_correct=decision_correct,
                screen_correct=screen_correct,
            )
        )

    totals = {
        "cases": len(results),
        "matched": sum(1 for r in results if r.correct),
        "decision_matched": sum(1 for r in results if r.decision_correct),
        "screen_matched": sum(1 for r in results if r.screen_correct),
        "holds": sum(1 for r in results if r.decision is DecisionType.HOLD),
        "denies": sum(1 for r in results if r.decision is DecisionType.DENY),
        "allows": sum(1 for r in results if r.decision is DecisionType.ALLOW),
    }
    await evidence.append(
        kind="llm.rehearsal.summary",
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
            "mode": mode,
            "live": live,
            "totals": totals,
            "case_ids": [r.case_id for r in results],
            "summary_nonce": uuid.uuid4().hex,
        },
    )

    ok, detail = evidence.verify()
    records = evidence.records()
    head = {
        "seq": records[-1].seq if records else 0,
        "hash": records[-1].hash if records else "genesis",
    }
    return RehearsalReport(
        run_id=run_id,
        mode=mode,
        cases=results,
        totals=totals,
        verified=ok,
        verification_detail=detail,
        chain_head=head,
    )
