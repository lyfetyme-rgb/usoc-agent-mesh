"""Focused tests for Industry Starter Profiles and their vertical controls.

Covers the packaging claims made to buyers: exact role counts, transaction
ceilings, dual-approver quorum, PII/PHI taint propagation, signed egress,
compliance exports and the cross-vertical Money Shot storyboards.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pytest

from agents.config import Settings
from agents.connectors import MappingAdapter, Provenance, Severity, Signal, SourceType
from agents.contracts import ActionClass, Classification, RiskLevel
from agents.correlation import CorrelationConfig, CorrelationEngine
from agents.egress import EgressError, EgressGuard
from agents.evidence import EXPORT_FORMATS, EvidenceRecord, render_export
from agents.governance import (
    ApprovalRequest,
    ApprovalStatus,
    ApprovalVerification,
    DecisionType,
    InMemoryApprovalStore,
    PolicyConfig,
    PolicyEngine,
    decision_payload_digest,
    parse_money,
)
from agents.profiles import (
    PROFILES,
    apply_role_profile,
    get_profile,
    parse_amount,
    settings_for_profile,
)
from agents.registry import RegistryError
from agents.security import detect_sensitive_data
from agents.storyboards import STORYBOARDS, get_storyboard, render_storyboard


# -- profiles ----------------------------------------------------------------

@pytest.mark.parametrize(
    ("profile_id", "count"),
    [
        ("core", 12),
        ("finops_banking", 24),
        ("clinical_healthcare", 22),
        ("full_usoc", 93),
    ],
)
def test_exact_pack_role_counts(profile_id: str, count: int):
    profile = get_profile(profile_id)
    assert profile.expected_roles == count
    actual = 93 if profile.all_roles else profile.role_count
    assert actual == count


def test_all_four_packs_shipped():
    assert set(PROFILES) == {"core", "finops_banking", "clinical_healthcare", "full_usoc"}


def test_unknown_profile_fails_closed():
    with pytest.raises(RegistryError, match="unknown role profile"):
        get_profile("does-not-exist")


@pytest.mark.parametrize("profile_id", ["core", "finops_banking", "clinical_healthcare", "full_usoc"])
def test_profile_keeps_all_nine_coordinators(registry, profile_id: str):
    view = apply_role_profile(registry, profile_id)
    assert len(view) == 9
    assert {spec.id for spec in view.subsystems} == {spec.id for spec in registry.subsystems}
    assert view.roles_total == get_profile(profile_id).expected_roles


def test_full_profile_is_identity_view(registry):
    assert apply_role_profile(registry, "full_usoc") is registry


def test_profile_only_filters_role_views(registry):
    full = {spec.id: set(spec.roles) for spec in registry.subsystems}
    view = apply_role_profile(registry, "core")
    for spec in view.subsystems:
        assert set(spec.roles) <= full[spec.id]
        # Tool scopes and tier/ACL data are untouched by the profile.
        assert spec.tools == next(s for s in registry.subsystems if s.id == spec.id).tools


def test_unknown_profile_rejected_by_apply(registry):
    with pytest.raises(RegistryError, match="unknown role profile"):
        apply_role_profile(registry, "bogus")


def test_profile_control_defaults_and_env_override(settings: Settings, monkeypatch):
    for env in (
        "AGENT_MAX_TRANSACTION_AMOUNT",
        "AGENT_APPROVAL_QUORUM",
        "AGENT_PHI_DETECTION_ENABLED",
        "AGENT_BLOCK_TAINTED_EGRESS",
        "AGENT_EVIDENCE_EXPORT_FORMATS",
    ):
        monkeypatch.delenv(env, raising=False)

    fin = settings_for_profile(settings, "finops_banking")
    assert fin.max_transaction_amount == "5000.00"
    assert fin.approval_quorum == 2

    clinical = settings_for_profile(settings, "clinical_healthcare")
    assert clinical.phi_detection_enabled is True
    assert clinical.block_tainted_egress is True

    # With the env var present, an explicit operator value must survive rather
    # than being replaced by the profile default (2). In real use get_settings()
    # has already parsed AGENT_APPROVAL_QUORUM into the Settings object.
    monkeypatch.setenv("AGENT_APPROVAL_QUORUM", "3")
    explicit = settings.model_copy(update={"approval_quorum": 3})
    overridden = settings_for_profile(explicit, "finops_banking")
    assert overridden.approval_quorum == 3


def test_parse_amount():
    assert parse_amount("5000.00") == Decimal("5000.00")
    assert parse_amount(None) is None
    with pytest.raises(RegistryError):
        parse_amount("-1")
    with pytest.raises(RegistryError):
        parse_amount("not-a-number")


# -- governance helpers ------------------------------------------------------

def make_finops_policy() -> tuple[PolicyEngine, InMemoryApprovalStore]:
    store = InMemoryApprovalStore()
    config = PolicyConfig(
        allowed_targets=["sandbox/*", "staging/*"],
        max_transaction_amount=Decimal("5000.00"),
        transaction_currency="USD",
        approval_quorum=2,
    )
    return PolicyEngine(config, store), store


async def finops_evaluate(policy: PolicyEngine, **overrides):
    params = dict(
        action=ActionClass.EXECUTE,
        target="sandbox/merchant-account-884",
        risk=RiskLevel.HIGH,
        mission_id="mission-1",
        classification=Classification.INTERNAL,
        approval_ref=None,
        requested_by="planner",
        justification="test",
        correlation_id="corr-1",
        provenance=["cloud_cost", "identity"],
        tainted=True,
    )
    params.update(overrides)
    return await policy.evaluate(**params)


# -- transaction limits ------------------------------------------------------

def test_parse_money_strict():
    assert parse_money("4820.00") == Decimal("4820.00")
    assert parse_money(None) is None
    for bad in ("-5", "+5", "abc", "NaN", "Infinity", "1.12345"):
        with pytest.raises(ValueError):
            parse_money(bad)


async def test_amount_over_ceiling_is_denied():
    policy, store = make_finops_policy()
    decision = await finops_evaluate(policy, amount="6000.00", currency="USD")
    assert decision.decision is DecisionType.DENY
    assert "exceeds the configured ceiling" in " ".join(decision.reasons)
    assert await store.pending() == []


async def test_amount_under_ceiling_holds_with_transaction_gate_reason():
    policy, _ = make_finops_policy()
    decision = await finops_evaluate(policy, amount="4820.00", currency="USD")
    assert decision.decision is DecisionType.HOLD
    reasons = " ".join(decision.reasons)
    assert "transaction limit gate: 4820.00 USD" in reasons
    assert "2 distinct human(s)" in reasons


async def test_unauthorized_currency_is_denied():
    policy, _ = make_finops_policy()
    decision = await finops_evaluate(policy, amount="100.00", currency="EUR")
    assert decision.decision is DecisionType.DENY
    assert "currency 'EUR' is not authorized" in " ".join(decision.reasons)


async def test_approval_amount_binding_denies_a_different_sum():
    policy, store = make_finops_policy()
    held = await finops_evaluate(policy, amount="4820.00", currency="USD")
    await store.decide(held.approval_ref, approved=True, approver="alice")
    await store.decide(held.approval_ref, approved=True, approver="bob")

    # 1000 is under the ceiling but not the amount the humans signed.
    decision = await finops_evaluate(
        policy, approval_ref=held.approval_ref, amount="1000.00", currency="USD"
    )
    assert decision.decision is DecisionType.DENY
    assert "is bound to" in " ".join(decision.reasons)


# -- dual-approver quorum ----------------------------------------------------

async def test_partial_quorum_stays_pending_then_clears():
    policy, store = make_finops_policy()
    held = await finops_evaluate(policy, amount="4820.00", currency="USD")

    first = await store.decide(held.approval_ref, approved=True, approver="alice")
    assert first.status is ApprovalStatus.PENDING
    assert [d.approver for d in first.decisions] == ["alice"]

    still_held = await finops_evaluate(
        policy, approval_ref=held.approval_ref, amount="4820.00", currency="USD"
    )
    assert still_held.decision is DecisionType.HOLD
    # A partial quorum produces HOLD, not a consumed nonce or a cached ALLOW.
    pending = await store.get(held.approval_ref)
    assert pending is not None and pending.consumed_at is None

    second = await store.decide(held.approval_ref, approved=True, approver="bob")
    assert second.status is ApprovalStatus.APPROVED
    assert len(second.decisions) == 2

    allowed = await finops_evaluate(
        policy, approval_ref=held.approval_ref, amount="4820.00", currency="USD"
    )
    assert allowed.decision is DecisionType.ALLOW
    assert allowed.authorization_ref


async def test_quorum_requires_distinct_humans():
    policy, store = make_finops_policy()
    held = await finops_evaluate(policy, amount="4820.00", currency="USD")
    await store.decide(held.approval_ref, approved=True, approver="alice")
    with pytest.raises(ValueError, match="distinct humans"):
        await store.decide(held.approval_ref, approved=True, approver="alice")


async def test_pending_quorum_never_consumes_the_nonce():
    policy, store = make_finops_policy()
    held = await finops_evaluate(policy, amount="4820.00", currency="USD")
    req = await store.get(held.approval_ref)
    assert req is not None

    # Neither an untouched nor a partially signed approval is consumable.
    assert await store.consume(held.approval_ref, nonce=req.nonce) is None
    partial = await store.decide(held.approval_ref, approved=True, approver="alice")
    assert partial.status is ApprovalStatus.PENDING
    assert await store.consume(held.approval_ref, nonce=req.nonce) is None
    untouched = await store.get(held.approval_ref)
    assert untouched is not None and untouched.consumed_at is None

    final = await store.decide(held.approval_ref, approved=True, approver="bob")
    assert final.status is ApprovalStatus.APPROVED
    spent = await store.consume(held.approval_ref, nonce=req.nonce)
    assert spent is not None and spent.consumed_at is not None
    # Single use survives a completed quorum: a replay is still refused.
    assert await store.consume(held.approval_ref, nonce=req.nonce) is None


async def test_policy_binds_egress_target_and_payload_digest():
    store = InMemoryApprovalStore()
    policy = PolicyEngine(
        PolicyConfig(egress_target="atlassian:https://example.atlassian.net"), store
    )
    held = await policy.evaluate(
        action=ActionClass.EXECUTE,
        target="sandbox/node-1",
        risk=RiskLevel.HIGH,
        mission_id="m1",
        classification=Classification.RESTRICTED,
        approval_ref=None,
        requested_by="planner",
        tainted=True,
    )
    req = await store.get(held.approval_ref)
    assert req is not None
    assert req.egress_target == "atlassian:https://example.atlassian.net"
    assert req.egress_payload_digest == decision_payload_digest(req)


async def test_single_approver_quorum_still_works():
    store = InMemoryApprovalStore()
    policy = PolicyEngine(PolicyConfig(approval_quorum=1), store)
    held = await policy.evaluate(
        action=ActionClass.EXECUTE,
        target="sandbox/node-1",
        risk=RiskLevel.HIGH,
        mission_id="m1",
        classification=Classification.INTERNAL,
        approval_ref=None,
        requested_by="planner",
    )
    await store.decide(held.approval_ref, approved=True, approver="alice")
    allowed = await policy.evaluate(
        action=ActionClass.EXECUTE,
        target="sandbox/node-1",
        risk=RiskLevel.HIGH,
        mission_id="m1",
        classification=Classification.INTERNAL,
        approval_ref=held.approval_ref,
        requested_by="planner",
    )
    assert allowed.decision is DecisionType.ALLOW


# -- PHI / PII detection -----------------------------------------------------

def test_detect_sensitive_data_key_and_value_labels():
    assert detect_sensitive_data({"patient_id": "PT-1", "diagnosis": "E11.9"}, enabled=True) == [
        "phi",
        "pii",
    ]
    assert "ssn" in detect_sensitive_data({"note": "123-45-6789"}, enabled=True)
    assert detect_sensitive_data({"patient_id": "PT-1"}, enabled=False) == []


def test_connector_detection_raises_taint_and_classification():
    now = datetime.now(timezone.utc)
    provenance = Provenance(connector="health", location="fixture", fetched_at=now)
    raw = {
        "id": "r1",
        "timestamp": "2026-11-14T11:00:00Z",
        "entity": "patient-1",
        "patient_id": "PT-1",
        "diagnosis": "E11.9",
    }

    clean = MappingAdapter(phi_detection_enabled=False).adapt(
        raw, source="health", source_type=SourceType.OBSERVABILITY, provenance=provenance
    )
    assert clean.tainted is False
    assert clean.classification is Classification.INTERNAL

    flagged = MappingAdapter(phi_detection_enabled=True).adapt(
        raw, source="health", source_type=SourceType.OBSERVABILITY, provenance=provenance
    )
    assert flagged.tainted is True
    assert flagged.classification is Classification.RESTRICTED
    assert set(flagged.sensitive_labels) >= {"phi", "pii"}


def _tainted_signal(source: str, source_type: SourceType, now: datetime, labels: list[str]) -> Signal:
    provenance = Provenance(connector=source, location="fixture", fetched_at=now)
    return Signal(
        source=source,
        source_type=source_type,
        entity="patient-1",
        observed_at=now,
        category="medication_conflict",
        severity=Severity.CRITICAL,
        title="conflicting feeds",
        classification=Classification.RESTRICTED,
        sensitive_labels=labels,
        tainted=True,
        provenance=provenance,
    )


def test_correlation_propagates_taint_and_labels():
    now = datetime.now(timezone.utc)
    engine = CorrelationEngine(CorrelationConfig(min_score=0))
    result = engine.correlate(
        [
            _tainted_signal("medication", SourceType.OBSERVABILITY, now, ["phi"]),
            _tainted_signal("lab", SourceType.IDENTITY, now, ["pii"]),
        ]
    )
    assert len(result.incidents) == 1
    incident = result.incidents[0]
    assert incident.tainted is True
    assert incident.classification is Classification.RESTRICTED
    assert set(incident.sensitive_labels) >= {"phi", "pii"}


# -- egress guard ------------------------------------------------------------

EGRESS_TARGET = "atlassian:https://example.atlassian.net"
PAYLOAD_DIGEST = "a" * 64


def approved_signoff(
    *,
    target: str = EGRESS_TARGET,
    digest: str | None = PAYLOAD_DIGEST,
    verified: bool = True,
    method: str = "detached",
) -> ApprovalRequest:
    return ApprovalRequest(
        action_class=ActionClass.EXECUTE,
        target="sandbox/target",
        risk=RiskLevel.HIGH,
        requested_by="planner",
        status=ApprovalStatus.APPROVED,
        decided_by="alice",
        egress_target=target,
        egress_payload_digest=digest,
        verification=ApprovalVerification(
            verified=verified, method=method, approver_id="alice"  # type: ignore[arg-type]
        ),
    )


def test_egress_blocks_tainted_data_without_signed_signoff():
    guard = EgressGuard(block_tainted=True)
    with pytest.raises(EgressError, match="verified signed sign-off"):
        guard.assert_allowed(target=EGRESS_TARGET, tainted=True)
    with pytest.raises(EgressError):
        guard.assert_allowed(
            target=EGRESS_TARGET, classification=Classification.RESTRICTED
        )


def test_egress_allows_only_digest_bound_target_matching_signoff():
    guard = EgressGuard(block_tainted=True)
    guard.assert_allowed(
        target=EGRESS_TARGET,
        tainted=True,
        signoffs=[approved_signoff()],
        payload_digest=PAYLOAD_DIGEST,
    )


def test_egress_rejects_unverified_wrong_target_or_pending():
    guard = EgressGuard(block_tainted=True)
    with pytest.raises(EgressError):
        guard.assert_allowed(
            target=EGRESS_TARGET,
            tainted=True,
            signoffs=[approved_signoff(target="atlassian:https://other.example")],
            payload_digest=PAYLOAD_DIGEST,
        )
    with pytest.raises(EgressError):
        guard.assert_allowed(
            target=EGRESS_TARGET,
            tainted=True,
            signoffs=[approved_signoff(verified=False)],
            payload_digest=PAYLOAD_DIGEST,
        )
    with pytest.raises(EgressError):
        guard.assert_allowed(
            target=EGRESS_TARGET,
            tainted=True,
            signoffs=[approved_signoff(method="none")],
            payload_digest=PAYLOAD_DIGEST,
        )
    pending = approved_signoff()
    pending.status = ApprovalStatus.PENDING
    with pytest.raises(EgressError):
        guard.assert_allowed(
            target=EGRESS_TARGET, tainted=True, signoffs=[pending], payload_digest=PAYLOAD_DIGEST
        )


def test_egress_rejects_a_governed_action_target_as_a_sink_binding():
    """An approval for sandbox/target may not authorize any external sink."""
    guard = EgressGuard(block_tainted=True)
    with pytest.raises(EgressError):
        guard.assert_allowed(
            target=EGRESS_TARGET,
            tainted=True,
            signoffs=[approved_signoff(target="sandbox/target")],
            payload_digest=PAYLOAD_DIGEST,
            also_targets=["sandbox/target"],
        )


def test_egress_rejects_digest_mismatch_or_missing_binding():
    guard = EgressGuard(block_tainted=True)
    for signoff, digest in (
        (approved_signoff(), "b" * 64),
        (approved_signoff(digest=None), PAYLOAD_DIGEST),
        (approved_signoff(), None),
    ):
        with pytest.raises(EgressError):
            guard.assert_allowed(
                target=EGRESS_TARGET,
                tainted=True,
                signoffs=[signoff],
                payload_digest=digest,
            )


def test_egress_disabled_allows_anything():
    EgressGuard(block_tainted=False).assert_allowed(target=EGRESS_TARGET, tainted=True)


# -- compliance exports ------------------------------------------------------

def sample_records() -> list[EvidenceRecord]:
    return [
        EvidenceRecord(seq=1, id="ev-1", kind="fragmentation.correlated", actor="fragmentation"),
        EvidenceRecord(
            seq=2,
            id="ev-2",
            kind="governance.decision",
            actor="seraphim",
            classification="restricted",
            tainted=True,
        ),
    ]


def test_export_formats_render_and_fail_closed():
    assert EXPORT_FORMATS == {"jsonl", "oekp", "bengal", "oekp_bengal"}
    records = sample_records()

    jsonl = render_export(records, "jsonl")
    assert len(jsonl.strip().splitlines()) == 2

    import json

    oekp = json.loads(render_export(records, "oekp", verified=True, detail="ok"))
    assert oekp["format"] == "oekp-compliance/v1"
    assert oekp["chain"]["verified"] is True
    assert len(oekp["records"]) == 2

    bengal = json.loads(render_export(records, "bengal", verified=True))
    assert bengal["format"] == "bengal-assurance/v1"
    assert bengal["assurance"] == "PASS"
    assert bengal["totals"]["tainted"] == 1
    assert bengal["totals"]["restricted"] == 1

    combined = json.loads(render_export(records, "oekp_bengal", verified=False))
    assert combined["format"] == "usoc-compliance/v1"
    assert combined["bengal"]["assurance"] == "FAIL"

    with pytest.raises(ValueError, match="unknown evidence export format"):
        render_export(records, "csv")


# -- storyboards -------------------------------------------------------------

EXPECTED_MONEY_SHOTS = {
    "cyber": "Malicious IP signals -> CONTAIN prod-db-01 -> HOLD for SecOps lead",
    "finance": "Anomalous wire pattern -> FREEZE merchant-account-884 -> HOLD for Risk Officer",
    "healthcare": (
        "Conflicting medication/lab feed -> PAUSE automated-dispense-queue "
        "-> HOLD for Attending Clinician"
    ),
}


def test_exact_vertical_money_shots():
    assert set(STORYBOARDS) == {"cyber", "finance", "healthcare"}
    for vertical, expected in EXPECTED_MONEY_SHOTS.items():
        assert get_storyboard(vertical).money_shot == expected


def test_storyboards_share_the_five_beat_shape():
    for board in STORYBOARDS.values():
        assert len(board.beats) == 5
        assert [beat.title for beat in board.beats] == [
            "Messy signals",
            "Entity resolution",
            "Ranked risk",
            "Proposed high-impact action",
            "Deterministic HOLD",
        ]
        assert "HOLD" in board.beats[-1].on_screen


def test_storyboard_maps_to_a_real_profile_and_fixtures():
    assert get_storyboard("finance").profile_id == "finops_banking"
    assert get_storyboard("healthcare").profile_id == "clinical_healthcare"
    assert get_storyboard("cyber").profile_id == "full_usoc"
    for board in STORYBOARDS.values():
        assert board.fixtures_dir.exists(), f"missing fixtures: {board.fixtures_dir}"


def test_render_storyboard_contains_money_shot_and_fail_closed():
    text = render_storyboard("healthcare")
    assert EXPECTED_MONEY_SHOTS["healthcare"] in text
    with pytest.raises(RegistryError, match="unknown storyboard"):
        get_storyboard("retail")
