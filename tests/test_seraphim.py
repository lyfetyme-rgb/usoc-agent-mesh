"""REQ-005: Seraphim admission, egress and quarantine controls."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agents.contracts import ActionClass, RiskLevel
from agents.governance import ApprovalVerification
from agents.seraphim import (
    AdmissionRequest,
    ContainerProfile,
    CredentialProof,
    DecisionType,
    KevCatalog,
    KevEntry,
    SeraphimPolicy,
    credential_binding_digest,
)


class _Verifier:
    """Test double for the approval/OIDC verifier injected into Seraphim."""

    def __init__(self, *, verified: bool = True, method: str = "oidc") -> None:
        self.verified = verified
        self.method = method
        self.calls: list[CredentialProof] = []

    def __call__(self, proof: CredentialProof, request: AdmissionRequest) -> ApprovalVerification:
        self.calls.append(proof)
        return ApprovalVerification(
            verified=self.verified,
            method=self.method,  # type: ignore[arg-type]
            approver_id=proof.approver,
            detail="test verifier",
        )


def _request(**overrides: object) -> AdmissionRequest:
    fields: dict[str, object] = {
        "tenant_id": "tenant-a",
        "subject": "svc-aicee",
        "action_class": ActionClass.EXECUTE,
        "target": "sandbox/tenant-a/job-1",
        "risk": RiskLevel.HIGH,
        "container": ContainerProfile(),
        "egress_hosts": ["api.example.com"],
        "kev_ids": [],
    }
    fields.update(overrides)
    unsigned = AdmissionRequest.model_validate({**fields, "credential_proof": None})
    if "credential_proof" not in overrides:
        fields["credential_proof"] = CredentialProof(
            approval_id="apr-1",
            approver="alice",
            binding_digest=credential_binding_digest(unsigned),
        )
    return AdmissionRequest.model_validate(fields)


def _policy(**overrides: object) -> SeraphimPolicy:
    fields: dict[str, object] = {
        "allowed_egress_hosts": frozenset({"api.example.com"}),
        "kev_catalog": KevCatalog(entries=[]),
        "credential_verifier": _Verifier(),
        "shadow_mode": False,
    }
    fields.update(overrides)
    return SeraphimPolicy(**fields)  # type: ignore[arg-type]


def test_seraphim_allows_a_verified_constrained_request():
    decision = _policy().evaluate(_request())
    assert decision.decision is DecisionType.ALLOW
    assert decision.policy_ref == "seraphim/admission/v1"
    assert decision.quarantine_plan is None


def test_seraphim_never_accepts_self_asserted_credential_flags():
    with pytest.raises(ValueError):
        _request(credential_verified=True, credential_method="oidc")


def test_seraphim_rejects_a_forged_binding_digest():
    forged = CredentialProof(
        approval_id="apr-1", approver="alice", binding_digest="0" * 64
    )
    decision = _policy().evaluate(_request(credential_proof=forged))
    assert decision.decision is DecisionType.HOLD
    assert "credential" in decision.reasons


def test_seraphim_fails_closed_when_no_credential_verifier_is_configured():
    decision = _policy(credential_verifier=None).evaluate(_request())
    assert decision.decision is DecisionType.HOLD
    assert "credential" in decision.reasons


def test_seraphim_holds_when_the_trusted_verifier_rejects_the_credential():
    decision = _policy(credential_verifier=_Verifier(verified=False)).evaluate(_request())
    assert decision.decision is DecisionType.HOLD
    assert "credential" in decision.reasons


def test_seraphim_denies_unsafe_container_profiles():
    for profile in (
        ContainerProfile(run_as_non_root=False),
        ContainerProfile(read_only_root_fs=False),
        ContainerProfile(privileged=True),
        ContainerProfile(capabilities=["NET_ADMIN"]),
    ):
        decision = _policy().evaluate(_request(container=profile))
        assert decision.decision is DecisionType.DENY
        assert "container" in decision.reasons


def test_unsafe_container_denies_even_when_egress_also_fails():
    decision = _policy().evaluate(
        _request(container=ContainerProfile(privileged=True), egress_hosts=["evil.example"])
    )
    assert decision.decision is DecisionType.DENY
    assert "container" in decision.reasons
    assert "egress" in decision.reasons
    assert decision.quarantine_plan is None


def test_seraphim_contains_unapproved_egress_with_default_deny_quarantine():
    decision = _policy().evaluate(_request(egress_hosts=["evil.example"]))
    assert decision.decision is DecisionType.CONTAIN
    assert "egress" in decision.reasons
    assert decision.quarantine_plan is not None
    plan = decision.quarantine_plan
    assert plan.namespace == "usoc-quarantine"
    assert plan.network_policy["spec"]["policyTypes"] == ["Ingress", "Egress"]
    assert plan.network_policy["spec"]["egress"] == []


def test_seraphim_contains_exploited_kev():
    catalog = KevCatalog(
        entries=[
            KevEntry(
                id="CVE-2026-0001",
                severity="critical",
                exploited=True,
                published="2026-11-01",
            )
        ],
        fetched_at=datetime.now(timezone.utc).date(),
    )
    decision = _policy(kev_catalog=catalog).evaluate(_request(kev_ids=["CVE-2026-0001"]))
    assert decision.decision is DecisionType.CONTAIN
    assert "kev" in decision.reasons


def test_future_dated_kev_catalog_is_stale_not_fresh():
    future = datetime.now(timezone.utc) + timedelta(days=30)
    catalog = KevCatalog(entries=[], fetched_at=future.date())
    assert catalog.is_stale(datetime.now(timezone.utc)) is True
    decision = _policy(
        kev_catalog=catalog,
        now=datetime.now(timezone.utc),
    ).evaluate(_request(kev_ids=[]))
    assert decision.decision is DecisionType.ALLOW


def test_seraphim_shadow_mode_is_fail_closed():
    decision = _policy(shadow_mode=True).evaluate(_request())
    assert decision.decision is DecisionType.DENY
    assert "shadow" in decision.reasons
    assert decision.quarantine_plan is None


def test_seraphim_decision_never_carries_credential_material():
    verifier = _Verifier()
    decision = _policy(credential_verifier=verifier).evaluate(_request())
    dumped = decision.model_dump()
    assert "credential" not in dumped
    assert "approval_id" not in dumped
    assert "id_token" not in dumped
    assert "signature" not in dumped
    assert len(verifier.calls) == 1
