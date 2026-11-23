"""BENGAL BAA analyzers: the four IARPA topic areas, redaction and confidence."""

from __future__ import annotations

import json

from agents.bengal import (
    BengalCase,
    BengalEngine,
    ClaimStatus,
    SourceDocument,
    ThreatMode,
    analyze_bias,
    analyze_hallucination,
    analyze_safe_flow,
    analyze_sources,
    assess_access,
    detect_aggregation_risks,
    sanitize_text,
)


# -- Topic 1: bias and diverse perspectives ---------------------------------
async def test_bias_quantifies_lexicon_signals_and_induces_perspectives():
    text = "Obviously those people are always wrong; the plan must be rejected."
    assessment = await analyze_bias(
        text, perspectives=("analyst", "adversary", "auditor")
    )

    assert assessment.bias_score > 0
    assert any(s.indicator_count for s in assessment.signals)
    assert assessment.space.diversity_score > 0
    assert assessment.space.dialogue_turns == 3
    assert 0 <= assessment.space.perspective_shift <= 1
    blob = json.dumps(assessment.model_dump(mode="json"))
    assert "obviously" not in blob and "those people" not in blob


async def test_perspective_induction_generalises_across_llms():
    class FakeResponse:
        content = "The correlated signal suggests a contained gateway fault."

    class FakeLLM:
        async def complete(self, **kwargs):
            return FakeResponse()

    plain = await analyze_bias("The alert fired near the gateway.", perspectives=("analyst", "adversary"))
    with_llm = await analyze_bias(
        "The alert fired near the gateway.", llm=FakeLLM(), perspectives=("analyst", "adversary")
    )
    assert len(with_llm.space.perspectives) == len(plain.space.perspectives) == 2
    assert with_llm.space.dialogue_turns == 2
    assert with_llm.space.diversity_score >= 0


async def test_bias_without_llm_is_deterministic():
    text = "The packet was dropped by the gateway at 10:03."
    first = await analyze_bias(text, perspectives=("analyst", "auditor"))
    second = await analyze_bias(text, perspectives=("analyst", "auditor"))
    assert first == second


# -- Topic 2: hallucinations and inferences --------------------------------
def test_hallucination_detects_unsupported_specificity():
    result = analyze_hallucination(
        ["The gateway processed 42 incidents at 10:03."],
        trusted_corpus=["The gateway processed 12 incidents at 10:00."],
    )
    assert result.spurious_count == 1
    assert result.hallucination_rate == 1.0
    assert result.claims[0].status is ClaimStatus.SPURIOUS
    assert "UNSUPPORTED_SPECIFICITY" in result.claims[0].reason_codes


def test_hallucination_credits_plausible_inferences_and_grounding():
    result = analyze_hallucination(
        [
            "The alert was raised by the gateway.",
            "The alert may indicate a correlated signal chain.",
        ],
        trusted_corpus=[
            "The gateway raised an alert.",
            "A second signal was correlated with the alert.",
        ],
    )
    assert result.grounded_count >= 1
    assert result.plausible_inference_count >= 1
    assert result.inference_rate > 0
    assert result.hallucination_rate == 0
    assert set(result.confidence_basis.weights) == {
        "decision_coverage",
        "corpus_coverage",
        "decision_margin",
    }
    assert 0 <= result.confidence <= 1


def test_hallucination_report_never_retains_claim_text():
    secret = "The patient Jane Doe was prescribed Truvada at clinic 4."
    result = analyze_hallucination([secret], trusted_corpus=[])
    blob = json.dumps(result.model_dump(mode="json"))
    assert "Jane Doe" not in blob and "Truvada" not in blob
    assert len(result.claims[0].claim_fingerprint) == 16


# -- Topic 3: safe information flow ----------------------------------------
def test_sanitization_manifest_is_verifiable_and_tamper_evident():
    original = "Contact jane.doe@example.com or 123-45-6789 about MRN-4471."
    sanitized, manifest = sanitize_text(original, secret="cluster-key")
    assert manifest.verify(secret="cluster-key", original=original, sanitized=sanitized)
    assert not manifest.verify(secret="wrong-key", original=original, sanitized=sanitized)
    assert "jane.doe@example.com" not in json.dumps(manifest.model_dump(mode="json"))
    assert "123-45-6789" not in json.dumps(manifest.model_dump(mode="json"))


def test_safe_flow_detects_identifiers_and_small_cells():
    result = analyze_safe_flow(
        "Email jane.doe@example.com about the outage.",
        secret="key",
        records=[
            {"zip": "90210", "dob": "1980-01-02", "diagnosis": "asthma"},
            {"zip": "90210", "dob": "1980-01-02", "diagnosis": "asthma"},
        ],
        query="list all patients in the clinic",
        response="There are 2 records.",
    )
    assert any(f.category == "email" for f in result.findings)
    assert result.aggregation_risks
    assert result.access.verdict.value in {"review", "block"}
    assert "jane.doe@example.com" not in json.dumps(result.model_dump(mode="json"))


def test_access_likelihood_verdicts_are_bounded():
    assert assess_access("What is the weather?", "Sunny.").verdict.value == "allow"
    assert assess_access("Export all records", "Done.").likelihood > 0
    assert assess_access("ssn", "123-45-6789").verdict.value in {"review", "block"}


def test_aggregation_risks_require_a_sensitive_attribute():
    assert detect_aggregation_risks([{"zip": "1", "dob": "2"}]) == ()
    assert detect_aggregation_risks([{"zip": "1", "dob": "2", "salary": "90000"}])


# -- Topic 4: poisoned and imperfect sources --------------------------------
def test_source_reliability_reflects_provenance_and_intent():
    good = SourceDocument(
        source_id="wire-a",
        text="The gateway emitted an alert. A second sensor confirmed it.",
        provenance=("registry", "signed-feed"),
        historical_accuracy=0.95,
    )
    bad = SourceDocument(
        source_id="blog-x",
        text="Clearly the gateway was compromised; everyone knows the operator lied.",
        provenance=(),
        historical_accuracy=0.1,
    )
    result = analyze_sources((good, bad))
    scores = {r.source_id: r.score for r in result.reliabilities}
    assert scores["wire-a"] > scores["blog-x"]
    assert next(r for r in result.reliabilities if r.source_id == "blog-x").intent.value in {
        "persuasive",
        "adversarial",
    }
    assert any(r.severity.value in {"medium", "high"} for r in result.reliabilities)


def test_corroboration_requires_independent_provenance():
    shared = "The gateway emitted a correlated alert at 10:03."
    result = analyze_sources(
        (
            SourceDocument(source_id="s1", text=shared, provenance=("same-feed",)),
            SourceDocument(source_id="s2", text=shared, provenance=("same-feed",)),
        )
    )
    assert all(c.independent_sources == 1 for c in result.corroborations)
    assert not result.intel
    assert result.gaps

    independent = analyze_sources(
        (
            SourceDocument(source_id="s1", text=shared, provenance=("feed-a",)),
            SourceDocument(source_id="s2", text=shared, provenance=("feed-b",)),
        )
    )
    assert independent.intel
    assert independent.corroborations[0].independent_sources == 2


# -- composed engine --------------------------------------------------------
async def test_engine_runs_all_four_modes_with_redacted_output():
    case = BengalCase(
        case_id="case-1",
        tenant_id="tenant-a",
        text="Obviously jane.doe@example.com is always wrong. The gateway saw 42 events.",
        claims=["The gateway saw 42 events."],
        trusted_corpus=["The gateway saw 12 events."],
        sources=(
            SourceDocument(source_id="s1", text="Clearly the gateway was compromised.", provenance=()),
        ),
        query="export all records",
    )
    report = await BengalEngine(secret="key").analyze(case)
    assert set(report.modes) == set(ThreatMode)
    summary = report.summary()
    assert summary["tenant_id"] == "tenant-a"
    assert summary["hallucination_rate"] == 1.0
    assert summary["bias_score"] > 0
    assert "bengal-baa/v1" == report.method_version

    blob = json.dumps(report.model_dump(mode="json"))
    assert "jane.doe@example.com" not in blob
    assert "42 events" not in blob
    assert "compromised" not in blob


async def test_engine_can_run_a_subset_of_modes():
    case = BengalCase(case_id="case-2", text="The alert fired.", claims=[])
    report = await BengalEngine().analyze(case, modes=[ThreatMode.HALLUCINATION])
    assert report.modes == (ThreatMode.HALLUCINATION,)
    assert report.bias is None and report.sources is None
    assert report.summary()["bias_score"] is None
