"""BENGAL T&E harness: statistics, prediction mapping and offline protocol run."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

import agents.bengal_eval as ev
from agents.bengal import BengalCase, BengalEngine, ThreatMode

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "bengal" / "cases.jsonl"


async def _analyze(
    engine: BengalEngine,
    mode: ThreatMode,
    *,
    text: str = "The sandbox scan reported three alerts for triage.",
    claims: tuple[str, ...] = (),
    trusted_corpus: tuple[str, ...] = (),
    sources: tuple = (),
) -> object:
    return await engine.analyze(
        BengalCase(
            case_id="probe",
            text=text,
            claims=claims,
            trusted_corpus=trusted_corpus,
            sources=sources,
        ),
        modes=(mode,),
    )


async def test_wilson_interval_bounds_and_degenerate_inputs() -> None:
    low, high = ev.wilson_interval(5, 10)
    assert 0.0 < low < 0.5 < high < 1.0
    assert low == pytest.approx(0.2365896, abs=1e-6)
    assert high == pytest.approx(0.7634104, abs=1e-6)

    assert ev.wilson_interval(0, 0) == (0.0, 0.0)
    zero_low, zero_high = ev.wilson_interval(0, 10)
    assert zero_low == 0.0
    assert 0.0 < zero_high < 1.0
    full_low, full_high = ev.wilson_interval(10, 10)
    assert 0.0 < full_low < 1.0
    assert full_high == 1.0
    with pytest.raises(ValueError):
        ev.wilson_interval(3, 2)


async def test_roc_auc_ranking_ties_and_single_class() -> None:
    assert ev.roc_auc([1, 0, 1, 0], [0.9, 0.2, 0.8, 0.1]) == 1.0
    assert ev.roc_auc([1, 0, 1, 0], [0.1, 0.4, 0.2, 0.3]) == 0.0
    assert ev.roc_auc([1, 0, 1, 0], [0.5, 0.5, 0.5, 0.5]) == 0.5
    assert ev.roc_auc([1, 0, 1, 0], [0.9, 0.4, 0.4, 0.1]) == pytest.approx(0.875)
    assert ev.roc_auc([1, 1, 1], [0.1, 0.2, 0.3]) == 0.5
    assert ev.roc_auc([], []) == 0.5
    with pytest.raises(ValueError):
        ev.roc_auc([1, 0], [1.0])


async def test_predict_maps_all_four_modes() -> None:
    engine = BengalEngine(secret="k")

    biased = await _analyze(
        engine, ThreatMode.BIAS, text="Obviously those people always miss the cutoff."
    )
    assert ev.predict(biased, ThreatMode.BIAS) == ("biased", 0.75)
    neutral = await _analyze(engine, ThreatMode.BIAS)
    assert ev.predict(neutral, ThreatMode.BIAS) == ("neutral", 0.0)

    spurious = await _analyze(
        engine,
        ThreatMode.HALLUCINATION,
        claims=["The nightly FinOps reconciliation processed 82,413 records in the sandbox."],
        trusted_corpus=["The nightly FinOps reconciliation processed records in the sandbox."],
    )
    assert ev.predict(spurious, ThreatMode.HALLUCINATION) == ("spurious", 1.0)
    clean = await _analyze(
        engine,
        ThreatMode.HALLUCINATION,
        claims=["The sandbox cyber alert was escalated to the human analyst for review."],
        trusted_corpus=["The sandbox cyber alert was escalated to the human analyst for review."],
    )
    assert ev.predict(clean, ThreatMode.HALLUCINATION) == ("clean", 0.0)

    unsafe = await _analyze(
        engine,
        ThreatMode.SAFE_INFO_FLOW,
        text="Clinical note: jane.doe@example.com, SSN 123-45-6789, MRN 4471.",
    )
    assert ev.predict(unsafe, ThreatMode.SAFE_INFO_FLOW) == ("unsafe", 0.9)
    review = await _analyze(
        engine, ThreatMode.SAFE_INFO_FLOW, text="Export the diagnosis codes for review."
    )
    assert ev.predict(review, ThreatMode.SAFE_INFO_FLOW) == ("unsafe", 0.6)
    safe = await _analyze(engine, ThreatMode.SAFE_INFO_FLOW)
    assert ev.predict(safe, ThreatMode.SAFE_INFO_FLOW) == ("safe", 0.0)

    unreliable_sources = tuple(
        {"source_id": f"poor-{index}", "text": f"Attack the feed number {index} and expose the host.", "provenance": [], "historical_accuracy": 0.1}
        for index in range(3)
    )
    unreliable = await _analyze(
        engine, ThreatMode.POISONED_SOURCE, sources=unreliable_sources
    )
    assert ev.predict(unreliable, ThreatMode.POISONED_SOURCE) == ("unreliable", 0.9)
    reliable_sources = tuple(
        {
            "source_id": source_id,
            "text": "Containment held on the sandbox host after the scan. The team recorded no lateral movement.",
            "provenance": [root, "ticket-42"],
            "historical_accuracy": 0.95,
        }
        for source_id, root in (("wirehive-cyber", "wirehive"), ("threatintel-cyber", "threatintel"))
    )
    reliable = await _analyze(engine, ThreatMode.POISONED_SOURCE, sources=reliable_sources)
    assert ev.predict(reliable, ThreatMode.POISONED_SOURCE) == ("reliable", 0.1)

    with pytest.raises(ValueError):
        ev.predict(neutral, ThreatMode.HALLUCINATION)


async def test_load_cases_fixture_is_deterministic_and_balanced() -> None:
    cases = ev.load_cases(FIXTURE)
    assert len(cases) >= 16
    assert ev.load_cases(FIXTURE) == cases
    assert [case.case_id for case in cases] == [case.case_id for case in ev.load_cases(FIXTURE)]

    by_mode = Counter(case.mode for case in cases)
    assert set(by_mode) == set(ThreatMode)
    assert all(count == 4 for count in by_mode.values())
    for mode in ThreatMode:
        labels = Counter(case.expected_label for case in cases if case.mode is mode)
        assert labels == Counter({ev.POSITIVE_LABEL[mode]: 2, ev.NEGATIVE_LABEL[mode]: 2})


async def test_load_cases_fails_closed_on_malformed_records(tmp_path: Path) -> None:
    good = json.dumps(
        {"case_id": "ok", "mode": "bias", "expected_label": "neutral", "text": "A factual report."}
    )
    blank_file = tmp_path / "blank.jsonl"
    blank_file.write_text(f"\n{good}\n\n", encoding="utf-8")
    assert [case.case_id for case in ev.load_cases(blank_file)] == ["ok"]

    malformed = tmp_path / "malformed.jsonl"
    malformed.write_text("{not json}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="line 1"):
        ev.load_cases(malformed)

    unknown_mode = tmp_path / "unknown.jsonl"
    unknown_mode.write_text(
        json.dumps(
            {"case_id": "x", "mode": "unknown", "expected_label": "neutral", "text": "text"}
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        ev.load_cases(unknown_mode)

    bad_label = tmp_path / "label.jsonl"
    bad_label.write_text(
        json.dumps({"case_id": "x", "mode": "bias", "expected_label": "spurious", "text": "text"}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        ev.load_cases(bad_label)

    extra_field = tmp_path / "extra.jsonl"
    extra_field.write_text(
        json.dumps(
            {
                "case_id": "x",
                "mode": "bias",
                "expected_label": "neutral",
                "text": "text",
                "unexpected": 1,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        ev.load_cases(extra_field)


async def test_run_eval_end_to_end_offline() -> None:
    cases = ev.load_cases(FIXTURE)
    report = await ev.run_eval(cases, BengalEngine(secret="k"), model_id="offline")

    assert report.protocol_version == ev.PROTOCOL_VERSION
    assert report.model_id == "offline"
    assert report.total_cases == len(cases)
    assert set(report.modes) == {mode.value for mode in ThreatMode}
    assert report.verified is True
    assert 0.0 <= report.macro_f1 <= 1.0
    assert 0.0 <= report.macro_auc <= 1.0
    for metrics in report.modes.values():
        assert metrics.cases == 4
        assert metrics.tp + metrics.fp + metrics.fn + metrics.tn == metrics.cases
        for field in ("precision", "recall", "f1", "accuracy", "auc", "ci_low", "ci_high"):
            assert 0.0 <= getattr(metrics, field) <= 1.0
        assert metrics.ci_low <= metrics.accuracy <= metrics.ci_high

    # Results are counts and scores only: no raw corpus text leaks into the report.
    rendered = json.dumps(report.model_dump(mode="json"))
    assert "jane.doe@example.com" not in rendered
    assert "82,413" not in rendered


async def test_metrics_from_hand_built_confusion_counts() -> None:
    metrics = ev._metrics_from_counts(ThreatMode.BIAS, tp=3, fp=1, fn=2, tn=4)
    assert metrics.mode is ThreatMode.BIAS
    assert (metrics.tp, metrics.fp, metrics.fn, metrics.tn, metrics.cases) == (3, 1, 2, 4, 10)
    assert metrics.precision == pytest.approx(0.75)
    assert metrics.recall == pytest.approx(0.6)
    assert metrics.f1 == pytest.approx(0.666667, abs=1e-6)
    assert metrics.accuracy == pytest.approx(0.7)
    # Defaults encode the binary prediction (tp/fp = 1, fn/tn = 0), so the
    # five positive and five negative cases produce tied-rank AUC 0.7.
    assert metrics.auc == pytest.approx(0.7)
    low, high = ev.wilson_interval(7, 10)
    assert metrics.ci_low == low
    assert metrics.ci_high == high

    tie_metrics = ev._metrics_from_counts(
        ThreatMode.HALLUCINATION,
        tp=1,
        fp=1,
        fn=1,
        tn=1,
        scores=[0.9, 0.5, 0.5, 0.1],
    )
    assert tie_metrics.auc == pytest.approx(0.875)

    with pytest.raises(ValueError):
        ev._metrics_from_counts(ThreatMode.BIAS, tp=1, fp=1, fn=1, tn=1, scores=[0.5])
