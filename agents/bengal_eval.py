"""Quantitative T&E protocol for the BENGAL four-topic analyzer.

The protocol is deliberately closed and replicable:

* a fixed, labeled JSONL corpus (``fixtures/bengal/cases.jsonl``) fixes the
  ground truth; editing labels to suit a run is out of scope;
* the analyzer is fixed (``agents.bengal.BengalEngine``) and any LLM is
  injected by the caller, so scores are model-agnostic and comparable across
  model families; every case is analyzed in its own mode only;
* each topic is scored with a confusion matrix, precision, recall, F1,
  rank-based AUC and a Wilson score confidence interval on accuracy; the
  macro F1/AUC average over all four topics is reported alongside them;
* results contain case ids, labels, counts and scores only -- no raw case
  text, claim or source value is copied into the report, so an evaluation
  artifact is safe for the evidence chain and the public health surface.

No network, tool or governance side effect occurs here. The harness observes
an injected engine and fails closed on malformed corpora.
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .bengal import (
    BengalCase,
    BengalEngine,
    BengalReport,
    Severity,
    SourceDocument,
    ThreatMode,
    Verdict,
)

PROTOCOL_VERSION = "bengal-eval/v1"

POSITIVE_LABEL: dict[ThreatMode, str] = {
    ThreatMode.BIAS: "biased",
    ThreatMode.HALLUCINATION: "spurious",
    ThreatMode.SAFE_INFO_FLOW: "unsafe",
    ThreatMode.POISONED_SOURCE: "unreliable",
}
NEGATIVE_LABEL: dict[ThreatMode, str] = {
    ThreatMode.BIAS: "neutral",
    ThreatMode.HALLUCINATION: "clean",
    ThreatMode.SAFE_INFO_FLOW: "safe",
    ThreatMode.POISONED_SOURCE: "reliable",
}


# -- statistical primitives --------------------------------------------------
def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion, clamped to [0, 1].

    An empty sample has no information and returns ``(0.0, 0.0)``. With zero
    successes the lower bound is exactly zero; with all successes the upper
    bound is exactly one, as required by the closed unit interval.
    """
    if isinstance(successes, bool) or isinstance(total, bool):
        raise ValueError("successes and total must be integers")
    successes, total = int(successes), int(total)
    if total < 0 or not 0 <= successes <= total:
        raise ValueError("successes must satisfy 0 <= successes <= total")
    if z <= 0 or not math.isfinite(z):
        raise ValueError("z must be a positive finite number")
    if total == 0:
        return (0.0, 0.0)
    rate = successes / total
    z2 = z * z
    denominator = 1.0 + z2 / total
    centre = (rate + z2 / (2.0 * total)) / denominator
    half = (z / denominator) * math.sqrt(
        rate * (1.0 - rate) / total + z2 / (4.0 * total * total)
    )
    return (max(0.0, centre - half), min(1.0, centre + half))


def roc_auc(labels: Sequence[int], scores: Sequence[float]) -> float:
    """Rank-based (Mann-Whitney U) AUC with average ranks for ties.

    Labels must be binary (1 = positive). A sample with only one class has no
    ranking information and returns 0.5 instead of failing or inventing a
    score. Inputs of unequal length or non-finite scores fail closed.
    """
    if len(labels) != len(scores):
        raise ValueError("labels and scores must have the same length")
    if any(label not in (0, 1) for label in labels):
        raise ValueError("labels must be 0 or 1")
    if any(not math.isfinite(float(score)) for score in scores):
        raise ValueError("scores must be finite")
    positives = [float(s) for label, s in zip(labels, scores) if label == 1]
    negatives = [float(s) for label, s in zip(labels, scores) if label == 0]
    if not positives or not negatives:
        return 0.5

    order = sorted(range(len(scores)), key=lambda i: float(scores[i]))
    ranks = [0.0] * len(scores)
    start = 0
    while start < len(order):
        end = start + 1
        while end < len(order) and float(scores[order[end]]) == float(scores[order[start]]):
            end += 1
        average_rank = (start + 1 + end) / 2.0
        for position in range(start, end):
            ranks[order[position]] = average_rank
        start = end
    positive_rank_sum = sum(
        rank for label, rank in zip(labels, ranks) if label == 1
    )
    n_pos, n_neg = len(positives), len(negatives)
    auc = (positive_rank_sum - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)
    return round(min(1.0, max(0.0, auc)), 6)


# -- prediction mapping ------------------------------------------------------
def predict(report: BengalReport, mode: ThreatMode) -> tuple[str, float]:
    """Translate a redacted analyzer report into (label, continuous score)."""
    selected = ThreatMode(mode)
    if selected is ThreatMode.BIAS:
        assessment = report.bias
        if assessment is None:
            raise ValueError("BIAS report has no bias assessment")
        positive = assessment.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
        return (POSITIVE_LABEL[selected] if positive else NEGATIVE_LABEL[selected], assessment.bias_score)
    if selected is ThreatMode.HALLUCINATION:
        assessment = report.hallucination
        if assessment is None:
            raise ValueError("HALLUCINATION report has no hallucination assessment")
        positive = assessment.hallucination_rate >= 0.34
        return (
            POSITIVE_LABEL[selected] if positive else NEGATIVE_LABEL[selected],
            assessment.hallucination_rate,
        )
    if selected is ThreatMode.SAFE_INFO_FLOW:
        assessment = report.safe_flow
        if assessment is None:
            raise ValueError("SAFE_INFO_FLOW report has no safe_flow assessment")
        severe = assessment.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
        verdict = assessment.access.verdict
        positive = severe or verdict is not Verdict.ALLOW
        score = (
            0.9
            if assessment.severity in (Severity.HIGH, Severity.CRITICAL) or verdict is Verdict.BLOCK
            else 0.6
            if assessment.severity is Severity.MEDIUM or verdict is Verdict.REVIEW
            else 0.0
        )
        return (POSITIVE_LABEL[selected] if positive else NEGATIVE_LABEL[selected], score)
    assessment = report.sources
    if assessment is None:
        raise ValueError("POISONED_SOURCE report has no sources assessment")
    unreliable = assessment.severity in (Severity.HIGH, Severity.CRITICAL) or any(
        corroboration.verdict == "conflicted" for corroboration in assessment.corroborations
    )
    return (POSITIVE_LABEL[selected] if unreliable else NEGATIVE_LABEL[selected], 0.9 if unreliable else 0.1)


# -- strict records ----------------------------------------------------------
class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class EvalCase(Strict):
    """One labeled case; raw payload stays in the corpus, not in results."""

    case_id: str = Field(min_length=1, max_length=64)
    mode: ThreatMode
    expected_label: str
    text: str = Field(min_length=1)
    claims: tuple[str, ...] = ()
    trusted_corpus: tuple[str, ...] = ()
    sources: tuple[SourceDocument, ...] = ()
    records: tuple[dict[str, Any], ...] = ()
    perspectives: tuple[str, ...] = ()
    query: str = ""
    response: str = ""

    @field_validator("expected_label")
    @classmethod
    def _known_label(cls, value: str, info: Any) -> str:
        mode = info.data.get("mode")
        if mode is not None and value not in (POSITIVE_LABEL[mode], NEGATIVE_LABEL[mode]):
            raise ValueError(f"expected_label {value!r} is not valid for mode {mode.value}")
        return value


class CaseResult(Strict):
    case_id: str
    mode: ThreatMode
    expected: str
    predicted: str
    correct: bool
    score: float = Field(ge=0.0, le=1.0)


class ModeMetrics(Strict):
    mode: ThreatMode
    tp: int = Field(ge=0)
    fp: int = Field(ge=0)
    fn: int = Field(ge=0)
    tn: int = Field(ge=0)
    precision: float = Field(ge=0.0, le=1.0)
    recall: float = Field(ge=0.0, le=1.0)
    f1: float = Field(ge=0.0, le=1.0)
    accuracy: float = Field(ge=0.0, le=1.0)
    auc: float = Field(ge=0.0, le=1.0)
    cases: int = Field(ge=0)
    ci_low: float = Field(ge=0.0, le=1.0)
    ci_high: float = Field(ge=0.0, le=1.0)


class EvalReport(Strict):
    protocol_version: str = PROTOCOL_VERSION
    model_id: str = ""
    modes: dict[str, ModeMetrics]
    macro_f1: float = Field(ge=0.0, le=1.0)
    macro_auc: float = Field(ge=0.0, le=1.0)
    total_cases: int = Field(ge=0)
    verified: bool


# -- metric assembly ---------------------------------------------------------
def _metrics_from_counts(
    mode: ThreatMode,
    *,
    tp: int,
    fp: int,
    fn: int,
    tn: int,
    scores: Sequence[float] = (),
) -> ModeMetrics:
    """Build metrics from counts; ``scores`` follow ``tp, fp, fn, tn`` order.

    Without explicit scores the binary prediction is used as the score
    (tp/fp = 1.0, fn/tn = 0.0), so the default AUC accounts for those tied
    ranks. Callers with a continuous detector score should pass it explicitly.
    """
    values = (tp, fp, fn, tn)
    if any(isinstance(value, bool) or value < 0 for value in values):
        raise ValueError("confusion counts must be non-negative integers")
    if not scores:
        scores = [1.0] * tp + [1.0] * fp + [0.0] * fn + [0.0] * tn
    if len(scores) != tp + fp + fn + tn:
        raise ValueError("scores must align with the confusion counts")
    labels = [1] * tp + [0] * fp + [1] * fn + [0] * tn
    cases = tp + fp + fn + tn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / cases if cases else 0.0
    ci_low, ci_high = wilson_interval(tp + tn, cases)
    return ModeMetrics(
        mode=ThreatMode(mode),
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        precision=round(precision, 6),
        recall=round(recall, 6),
        f1=round(f1, 6),
        accuracy=round(accuracy, 6),
        auc=roc_auc(labels, scores),
        cases=cases,
        ci_low=ci_low,
        ci_high=ci_high,
    )


async def run_eval(
    cases: Iterable[EvalCase],
    engine: BengalEngine,
    *,
    model_id: str = "",
) -> EvalReport:
    """Evaluate every case in its declared mode and reconcile every count."""
    case_list = tuple(cases)
    results: list[CaseResult] = []
    score_buckets: dict[ThreatMode, dict[str, list[float]]] = {
        mode: {"tp": [], "fp": [], "fn": [], "tn": []} for mode in ThreatMode
    }
    counts: dict[ThreatMode, dict[str, int]] = {
        mode: {key: 0 for key in ("tp", "fp", "fn", "tn")} for mode in ThreatMode
    }

    for case in case_list:
        analyzer_case = BengalCase(
            case_id=case.case_id,
            text=case.text,
            trusted_corpus=case.trusted_corpus,
            claims=case.claims,
            sources=case.sources,
            perspectives=case.perspectives,
            records=case.records,
            query=case.query,
            response=case.response,
        )
        report = await engine.analyze(analyzer_case, modes=(case.mode,))
        predicted, score = predict(report, case.mode)
        correct = predicted == case.expected_label
        results.append(
            CaseResult(
                case_id=case.case_id,
                mode=case.mode,
                expected=case.expected_label,
                predicted=predicted,
                correct=correct,
                score=score,
            )
        )
        expected_positive = case.expected_label == POSITIVE_LABEL[case.mode]
        predicted_positive = predicted == POSITIVE_LABEL[case.mode]
        bucket = (
            "tp" if expected_positive and predicted_positive
            else "fp" if not expected_positive and predicted_positive
            else "fn" if expected_positive and not predicted_positive
            else "tn"
        )
        counts[case.mode][bucket] += 1
        score_buckets[case.mode][bucket].append(score)

    metrics = {
        mode.value: _metrics_from_counts(
            mode,
            tp=counts[mode]["tp"],
            fp=counts[mode]["fp"],
            fn=counts[mode]["fn"],
            tn=counts[mode]["tn"],
            scores=(
                score_buckets[mode]["tp"]
                + score_buckets[mode]["fp"]
                + score_buckets[mode]["fn"]
                + score_buckets[mode]["tn"]
            ),
        )
        for mode in ThreatMode
    }
    verified = (
        len(results) == len(case_list)
        and all(result.case_id == case.case_id for result, case in zip(results, case_list))
        and sum(item.cases for item in metrics.values()) == len(case_list)
        and all(
            item.tp + item.fp + item.fn + item.tn == item.cases for item in metrics.values()
        )
        and all(result.predicted in (POSITIVE_LABEL[result.mode], NEGATIVE_LABEL[result.mode]) for result in results)
    )
    order = tuple(mode.value for mode in ThreatMode)
    return EvalReport(
        protocol_version=PROTOCOL_VERSION,
        model_id=model_id,
        modes=metrics,
        macro_f1=round(sum(metrics[key].f1 for key in order) / len(order), 6),
        macro_auc=round(sum(metrics[key].auc for key in order) / len(order), 6),
        total_cases=len(case_list),
        verified=verified,
    )


def load_cases(path: str | Path) -> tuple[EvalCase, ...]:
    """Read a JSONL corpus in file order; malformed records fail closed."""
    source = Path(path)
    cases: list[EvalCase] = []
    seen: set[str] = set()
    for lineno, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise ValueError("record must be a JSON object")
            case = EvalCase.model_validate(payload)
        except Exception as exc:
            raise ValueError(f"{source} line {lineno}: invalid eval case: {exc}") from exc
        if case.case_id in seen:
            raise ValueError(f"{source} line {lineno}: duplicate case_id {case.case_id!r}")
        seen.add(case.case_id)
        cases.append(case)
    if not cases:
        raise ValueError(f"{source}: no eval cases")
    return tuple(cases)


__all__ = [
    "PROTOCOL_VERSION",
    "POSITIVE_LABEL",
    "NEGATIVE_LABEL",
    "ThreatMode",
    "EvalCase",
    "CaseResult",
    "ModeMetrics",
    "EvalReport",
    "wilson_interval",
    "roc_auc",
    "predict",
    "run_eval",
    "load_cases",
]
