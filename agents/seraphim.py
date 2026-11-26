"""Seraphim: deterministic admission, egress, KEV and quarantine controls.

Seraphim is a policy decision point. It does not execute remediation and never
carries credential material into a decision or evidence record. Every check is
plain code so a model output cannot relax a control.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from datetime import date, datetime, timezone
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .contracts import ActionClass, RiskLevel
from .governance import ApprovalVerification, DecisionType
from .security import canonical

__all__ = [
    "AdmissionRequest",
    "ContainerProfile",
    "CredentialProof",
    "CredentialVerifier",
    "DecisionType",
    "KevCatalog",
    "KevEntry",
    "QuarantinePlan",
    "SeraphimDecision",
    "SeraphimPolicy",
    "credential_binding_digest",
]


class ContainerProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_as_non_root: bool = True
    read_only_root_fs: bool = True
    privileged: bool = False
    allow_privilege_escalation: bool = False
    capabilities: list[str] = Field(default_factory=list, max_length=32)
    seccomp_profile: str = "RuntimeDefault"


class KevEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=64)
    severity: Literal["low", "medium", "high", "critical"]
    exploited: bool
    published: str


class KevCatalog(BaseModel):
    """Read-only KEV snapshot. A stale or unusable feed contains no trust."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entries: list[KevEntry] = Field(default_factory=list, max_length=10_000)
    fetched_at: date | None = None
    max_age_days: int = Field(default=30, ge=1, le=365)

    @field_validator("fetched_at", mode="before")
    @classmethod
    def _parse_date(cls, value: Any) -> date | None:
        if value is None:
            return None
        if isinstance(value, date):
            return value
        return date.fromisoformat(str(value)[:10])

    def is_stale(self, now: datetime | None = None) -> bool:
        if self.fetched_at is None:
            return True
        current = (now or datetime.now(timezone.utc)).date()
        if self.fetched_at > current:
            # A future-dated snapshot is never fresh: a caller that controls the
            # feed could otherwise suppress KEV containment indefinitely.
            return True
        return (current - self.fetched_at).days > self.max_age_days

    def is_exploited(self, identifier: str, *, now: datetime | None = None) -> bool:
        # Fail closed: never trust an absent or stale KEV snapshot.
        if self.is_stale(now):
            return True
        return any(
            item.id == identifier and item.exploited for item in self.entries
        )


class CredentialProof(BaseModel):
    """A reference to a trusted credential decision, never the credential itself.

    Seraphim does not accept caller-asserted booleans. ``binding_digest`` commits
    the proof to the exact tenant, subject, action, target and risk being
    admitted, and the injected verifier performs the actual Ed25519/OIDC check.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str = Field(min_length=1, max_length=200)
    approver: str = Field(min_length=1, max_length=200)
    binding_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class CredentialVerifier(Protocol):
    """Trusted credential verifier supplied by the approval/OIDC subsystem."""

    def __call__(
        self, proof: CredentialProof, request: "AdmissionRequest"
    ) -> ApprovalVerification: ...


class AdmissionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=200)
    subject: str = Field(min_length=1, max_length=200)
    action_class: ActionClass
    target: str = Field(min_length=1, max_length=300)
    risk: RiskLevel
    container: ContainerProfile = Field(default_factory=ContainerProfile)
    egress_hosts: list[str] = Field(default_factory=list, max_length=64)
    credential_proof: CredentialProof | None = None
    kev_ids: list[str] = Field(default_factory=list, max_length=64)


def credential_binding_digest(request: AdmissionRequest) -> str:
    """Digest the exact admission context a credential must be bound to."""
    body = {
        "tenant_id": request.tenant_id,
        "subject": request.subject,
        "action_class": request.action_class.value,
        "target": request.target,
        "risk": request.risk.value,
    }
    return hashlib.sha256(canonical(body)).hexdigest()


class QuarantinePlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    namespace: str = "usoc-quarantine"
    tenant_id: str
    labels: dict[str, str] = Field(
        default_factory=lambda: {"security.usoc/quarantine": "isolate"}
    )
    network_policy: dict[str, Any]


class SeraphimDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: DecisionType
    policy_ref: str
    reasons: list[str] = Field(default_factory=list)
    quarantine_plan: QuarantinePlan | None = None


class SeraphimPolicy:
    """Evaluate admission inputs without side effects or raw payload storage."""

    def __init__(
        self,
        *,
        allowed_egress_hosts: frozenset[str],
        kev_catalog: KevCatalog | None = None,
        credential_verifier: CredentialVerifier | None = None,
        shadow_mode: bool = False,
        now: datetime | None = None,
    ) -> None:
        self.allowed_egress_hosts = frozenset(
            item.strip().lower() for item in allowed_egress_hosts if item.strip()
        )
        self.kev_catalog = kev_catalog or KevCatalog()
        # No verifier means no credential can ever be accepted: an untrusted
        # caller must not be able to self-assert a verified human identity.
        self.credential_verifier = credential_verifier
        self.shadow_mode = shadow_mode
        self.now = now

    def evaluate(self, request: AdmissionRequest) -> SeraphimDecision:
        if self.shadow_mode:
            return SeraphimDecision(
                decision=DecisionType.DENY,
                policy_ref="seraphim/admission/v1",
                reasons=["shadow", "fail_closed"],
            )

        reasons: list[str] = []
        container = request.container
        if (
            not container.run_as_non_root
            or not container.read_only_root_fs
            or container.privileged
            or container.allow_privilege_escalation
            or container.capabilities
            or container.seccomp_profile != "RuntimeDefault"
        ):
            reasons.append("container")
        if any(host.strip().lower() not in self.allowed_egress_hosts for host in request.egress_hosts):
            reasons.append("egress")
        if any(self.kev_catalog.is_exploited(item, now=self.now) for item in request.kev_ids):
            reasons.append("kev")

        needs_credential = request.action_class in (
            ActionClass.EXECUTE,
            ActionClass.CONTAIN,
        ) or request.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        if needs_credential:
            verified = False
            proof = request.credential_proof
            if (
                proof is not None
                and self.credential_verifier is not None
                and hmac.compare_digest(
                    proof.binding_digest, credential_binding_digest(request)
                )
            ):
                result = self.credential_verifier(proof, request)
                verified = bool(result.verified) and result.method in (
                    "detached",
                    "oidc",
                )
            if not verified:
                reasons.append("credential")

        # Unsafe runtime posture is never merely contained: it is denied even
        # when an egress or KEV failure would also require quarantine.
        if "container" in reasons:
            decision = DecisionType.DENY
        elif {"egress", "kev"} & set(reasons):
            decision = DecisionType.CONTAIN
        elif "credential" in reasons:
            decision = DecisionType.HOLD
        else:
            decision = DecisionType.ALLOW

        plan = None
        if decision is DecisionType.CONTAIN:
            plan = QuarantinePlan(
                tenant_id=request.tenant_id,
                network_policy={
                    "apiVersion": "networking.k8s.io/v1",
                    "kind": "NetworkPolicy",
                    "metadata": {
                        "name": "seraphim-quarantine",
                        "namespace": "usoc-quarantine",
                    },
                    "spec": {
                        "podSelector": {
                            "matchLabels": {"security.usoc/quarantine": "isolate"}
                        },
                        "policyTypes": ["Ingress", "Egress"],
                        "ingress": [],
                        "egress": [],
                    },
                },
            )

        return SeraphimDecision(
            decision=decision,
            policy_ref="seraphim/admission/v1",
            reasons=reasons,
            quarantine_plan=plan,
        )
