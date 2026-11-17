"""Industry Starter Profiles: curated capability-card role views.

A profile changes *what buyers see*, not what runs. All nine coordinators stay
up under the hood, keep their ACLs, tiers and signed capability cards, and keep
routing work exactly as before. The profile only narrows the ``roles`` list on
each card ("active capability-card roles").

Two fail-closed rules make the packaging honest:

* an unknown profile id is rejected instead of silently falling back to "all";
* every role a profile names must actually exist on that coordinator's signed
  card, so a renamed role can never leave a profile quietly incomplete.

Profiles may also supply conservative control defaults (transaction ceiling,
approval quorum, PHI detection, egress sign-off, export formats). An explicit
``AGENT_*`` environment variable always wins over a profile default.
"""

from __future__ import annotations

import os
from decimal import Decimal, InvalidOperation
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .config import Settings
from .registry import Registry, RegistryError


class RoleProfile(BaseModel):
    """A curated view over the 93 declared roles.

    ``roles`` maps coordinator id -> role titles shown for that coordinator.
    An empty mapping with ``all_roles=True`` is the full USOC view.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str
    roles: dict[str, list[str]] = Field(default_factory=dict)
    all_roles: bool = False
    expected_roles: int
    controls: dict[str, Any] = Field(default_factory=dict)

    @property
    def role_count(self) -> int:
        return sum(len(names) for names in self.roles.values())


_CORE = {
    "seraphim": [
        "Identity Verification Agent",
        "Authorization Evaluation Agent",
        "Policy-as-Code Agent",
        "Governance Decision Agent",
    ],
    "cohesion": [
        "Mission Intent Interpretation Agent",
        "Workflow Coordination Agent",
        "Mission Reporting Agent",
    ],
    "hitl": [
        "Decision Presentation Agent",
        "Approval Routing Agent",
        "Review Queue Agent",
    ],
    "oekp": [
        "Evidence Collection Agent",
        "Audit Trail Agent",
    ],
}

_FINOPS = {
    "aicee": [
        "Cloud Cost Intelligence Agent",
        "Resource Allocation Agent",
        "Anomaly Detection Agent",
        "Predictive Forecasting Agent",
    ],
    "seraphim": [
        "Risk Assessment Agent",
        "Compliance Mapping Agent",
        "Authorization Evaluation Agent",
        "Zero-Trust Policy Agent",
    ],
    "bengal": [
        "Requirements Verification Agent",
        "Security Control Verification Agent",
        "Assurance Reporting Agent",
        "Model Assurance Agent",
    ],
    "oekp": [
        "Evidence Collection Agent",
        "Audit Trail Agent",
        "Decision Lineage Agent",
        "Retention and Classification Agent",
        "Evidence Retrieval Agent",
    ],
    "hitl": [
        "Decision Presentation Agent",
        "Approval Routing Agent",
        "Risk Explanation Agent",
        "Decision Accountability Agent",
        "Operational Oversight Agent",
    ],
    "cohesion": [
        "Mission Constraint Agent",
        "Operational Priority Agent",
    ],
}

_CLINICAL = {
    "seraphim": [
        "Identity Verification Agent",
        "Zero-Trust Policy Agent",
        "Risk Assessment Agent",
        "Compliance Mapping Agent",
        "Governance Decision Agent",
    ],
    "cohesion": [
        "Mission Constraint Agent",
        "Dependency Mapping Agent",
    ],
    "bengal": [
        "Architecture Assurance Agent",
        "Security Control Verification Agent",
        "Requirements Verification Agent",
    ],
    "oekp": [
        "Evidence Collection Agent",
        "Event Provenance Agent",
        "Retention and Classification Agent",
        "Audit Trail Agent",
    ],
    "hitl": [
        "Risk Explanation Agent",
        "Decision Presentation Agent",
        "Approval Routing Agent",
        "Decision Accountability Agent",
        "Operational Oversight Agent",
    ],
    "aicee": [
        "Anomaly Detection Agent",
        "Incident Correlation Agent",
    ],
    "cyber_defense": [
        "Detection Engineering Agent",
    ],
}

PROFILES: dict[str, RoleProfile] = {
    "core": RoleProfile(
        id="core",
        name="Core Governance Pack",
        description=(
            "General enterprise automation, SaaS operations and internal IT "
            "workflows with the smallest governed-role surface."
        ),
        roles=_CORE,
        expected_roles=12,
        controls={"evidence_export_formats": "jsonl"},
    ),
    "finops_banking": RoleProfile(
        id="finops_banking",
        name="FinOps & Banking Pack",
        description=(
            "Cost and payment operations with transaction-limit gates, "
            "dual-approver HITL and OEKP/BENGAL compliance exports."
        ),
        roles=_FINOPS,
        expected_roles=24,
        controls={
            "max_transaction_amount": "5000.00",
            "approval_quorum": 2,
            "evidence_export_formats": "jsonl,oekp,bengal",
        },
    ),
    "clinical_healthcare": RoleProfile(
        id="clinical_healthcare",
        name="Clinical & Healthcare Pack",
        description=(
            "Patient-facing workflows with PII/PHI taint on every connector and "
            "external egress blocked without a verified signed sign-off."
        ),
        roles=_CLINICAL,
        expected_roles=22,
        controls={
            "phi_detection_enabled": True,
            "block_tainted_egress": True,
            "evidence_export_formats": "jsonl,oekp,bengal",
        },
    ),
    "full_usoc": RoleProfile(
        id="full_usoc",
        name="Full USOC Defense & Critical Infrastructure Pack",
        description=(
            "Every declared role across CYBER DEFENSE, ACIE edge telemetry and "
            "the CSSSF fault-injection suite."
        ),
        all_roles=True,
        expected_roles=93,
        controls={"evidence_export_formats": "jsonl,oekp,bengal"},
    ),
}

DEFAULT_PROFILE = "full_usoc"

# Settings fields a profile is allowed to supply, mapped to the environment
# variable that counts as an explicit operator override.
_CONTROL_ENV = {
    "max_transaction_amount": "AGENT_MAX_TRANSACTION_AMOUNT",
    "approval_quorum": "AGENT_APPROVAL_QUORUM",
    "phi_detection_enabled": "AGENT_PHI_DETECTION_ENABLED",
    "block_tainted_egress": "AGENT_BLOCK_TAINTED_EGRESS",
    "evidence_export_formats": "AGENT_EVIDENCE_EXPORT_FORMATS",
}


def _validate_profiles() -> None:
    for profile in PROFILES.values():
        actual = profile.role_count if not profile.all_roles else 93
        if actual != profile.expected_roles:
            raise RegistryError(
                f"profile {profile.id!r} declares {profile.expected_roles} roles "
                f"but selects {actual}"
            )
        if profile.all_roles and profile.roles:
            raise RegistryError(f"profile {profile.id!r} cannot mix all_roles with roles")


_validate_profiles()


def get_profile(profile_id: str | None) -> RoleProfile:
    """Resolve a profile id, failing closed on anything unknown."""
    pid = str(profile_id or DEFAULT_PROFILE).strip()
    profile = PROFILES.get(pid)
    if profile is None:
        raise RegistryError(
            f"unknown role profile {pid!r}; choose one of: {', '.join(sorted(PROFILES))}"
        )
    return profile


def apply_role_profile(registry: Registry, profile_id: str | None = None) -> Registry:
    """Return a registry with each card's roles narrowed to the profile.

    The returned registry keeps all nine coordinators, every tool scope and the
    original tool registry. Only ``SubsystemSpec.roles`` changes.
    """
    profile = get_profile(profile_id)
    if profile.all_roles:
        return registry

    known = {spec.id: spec for spec in registry.subsystems}
    unknown_cards = sorted(set(profile.roles) - set(known))
    if unknown_cards:
        raise RegistryError(
            f"profile {profile.id!r} names unknown coordinators: {', '.join(unknown_cards)}"
        )

    specs = []
    for spec in registry.subsystems:
        selected = profile.roles.get(spec.id, [])
        missing = [role for role in selected if role not in spec.roles]
        if missing:
            raise RegistryError(
                f"profile {profile.id!r} names roles absent from {spec.id}: {', '.join(missing)}"
            )
        # Duplicates would inflate the advertised role count.
        if len(set(selected)) != len(selected):
            raise RegistryError(f"profile {profile.id!r} repeats roles on {spec.id}")
        specs.append(spec.model_copy(update={"roles": list(selected)}))

    total = sum(len(s.roles) for s in specs)
    if total != profile.expected_roles:
        raise RegistryError(
            f"profile {profile.id!r} resolved to {total} roles, expected {profile.expected_roles}"
        )
    return Registry(subsystems=specs, tools=registry.tools)


def settings_for_profile(settings: Settings, profile_id: str | None = None) -> Settings:
    """Apply a profile's control defaults without overriding explicit env vars.

    The ``AGENT_ROLE_PROFILE`` variable itself is the source of truth; callers
    pass ``settings.role_profile`` so a CLI ``--profile`` override can win.
    """
    pid = str(profile_id or getattr(settings, "role_profile", DEFAULT_PROFILE) or DEFAULT_PROFILE)
    profile = get_profile(pid)
    if not profile.controls:
        return settings
    updates: dict[str, Any] = {}
    for key, value in profile.controls.items():
        env = _CONTROL_ENV.get(key)
        if env and os.environ.get(env) is not None:
            continue
        updates[key] = value
    if not updates:
        return settings
    return settings.model_copy(update=updates)


def parse_amount(value: Any) -> Decimal | None:
    """Parse a configured money ceiling; None means 'no limit configured'."""
    if value is None or value == "":
        return None
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise RegistryError(f"invalid transaction amount {value!r}: {exc}") from exc
    if not amount.is_finite() or amount < 0:
        raise RegistryError(f"transaction amount must be a finite, non-negative number: {value!r}")
    return amount
