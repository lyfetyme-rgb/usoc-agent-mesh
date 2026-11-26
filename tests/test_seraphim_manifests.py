"""REQ-005: enforceable Seraphim admission, RBAC and quarantine manifests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "deploy" / "kubernetes" / "base"
RBAC = BASE / "06-rbac.yaml"
ADMISSION = BASE / "21-admission-policy.yaml"
QUARANTINE = BASE / "22-seraphim-quarantine.yaml"
IDENTITY = BASE / "23-workload-identity.yaml"


def _documents(path: Path) -> list[dict[str, Any]]:
    return [
        item
        for item in yaml.safe_load_all(path.read_text(encoding="utf-8"))
        if isinstance(item, dict)
    ]


def _kind(docs: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [item for item in docs if item.get("kind") == kind]


def test_rbac_is_least_privilege_and_separates_recovery_identity():
    docs = _documents(RBAC)
    roles = _kind(docs, "Role")
    bindings = _kind(docs, "RoleBinding")
    assert roles and bindings

    forbidden = {"secrets", "pods/exec", "pods/portforward", "nodes", "*", "cluster-admin"}
    for role in roles:
        rules = role.get("rules") or []
        assert rules, role.get("metadata", {}).get("name")
        for rule in rules:
            assert not forbidden.intersection(set(rule.get("apiGroups") or []))
            assert not forbidden.intersection(set(rule.get("resources") or []))
            assert not forbidden.intersection(set(rule.get("verbs") or []))

    recovery_bindings = [
        binding
        for binding in bindings
        if (binding.get("roleRef") or {}).get("name") == "usoc-recovery"
    ]
    assert recovery_bindings
    subjects = {
        subject.get("name")
        for binding in recovery_bindings
        for subject in binding.get("subjects") or []
    }
    assert subjects == {"usoc-recovery-sa"}
    assert not _kind(docs, "ClusterRoleBinding")


def test_admission_policy_is_enforce_and_covers_section_six_hardening():
    docs = _documents(ADMISSION)
    policies = _kind(docs, "ValidatingAdmissionPolicy")
    bindings = _kind(docs, "ValidatingAdmissionPolicyBinding")
    assert len(policies) == 1 and len(bindings) == 1

    policy = policies[0]
    assert (policy.get("spec") or {}).get("failurePolicy") == "Fail"
    match = (policy.get("spec") or {}).get("matchConstraints") or {}
    assert any("pods" in rule.get("resources", []) for rule in match.get("resourceRules") or [])
    expressions = " ".join(
        str(item.get("expression") or "")
        for item in (policy.get("spec") or {}).get("validations") or []
    )
    for marker in (
        "runAsNonRoot",
        "readOnlyRootFilesystem",
        "privileged",
        "allowPrivilegeEscalation",
        "capabilities",
        "hostNetwork",
        "hostPath",
    ):
        assert marker in expressions
    # Digest pinning is enforced by render_overlay.py in the deployment workflow,
    # not by the runtime admission policy: the committed base manifests use tags
    # by design and must not be rejected before the signed overlay is rendered.
    assert "sha256" not in expressions

    binding_spec = bindings[0].get("spec") or {}
    assert binding_spec.get("policyName") == policy["metadata"]["name"]
    assert "Deny" in binding_spec.get("validationActions") or []
    selector = (binding_spec.get("matchResources") or {}).get("namespaceSelector") or {}
    assert selector.get("matchLabels", {}).get("security.usoc/protected") == "true"


def test_quarantine_network_policy_default_denies_all_directions():
    docs = _documents(QUARANTINE)
    policies = _kind(docs, "NetworkPolicy")
    assert policies
    for policy in policies:
        spec = policy.get("spec") or {}
        selector = spec.get("podSelector") or {}
        assert selector.get("matchLabels", {}).get("security.usoc/quarantine") == "isolate"
        assert set(spec.get("policyTypes") or []) == {"Ingress", "Egress"}
        assert spec.get("ingress") == [] and spec.get("egress") == []
        assert "0.0.0.0/0" not in json.dumps(spec)


def test_workload_identity_config_is_bounded_and_never_carries_a_token():
    docs = _documents(IDENTITY)
    configmaps = _kind(docs, "ConfigMap")
    assert configmaps
    raw = json.dumps(configmaps)
    for marker in ("audience", "coordinatorKeyring", "automountServiceAccountToken"):
        assert marker in raw
    for forbidden in ("id_token", "client_secret", "AGENT_HEALTH_TOKEN", "Bearer "):
        assert forbidden not in raw


def test_seraphim_manifests_introduce_no_privileged_or_host_scope():
    for path in (RBAC, ADMISSION, QUARANTINE, IDENTITY):
        raw = path.read_text(encoding="utf-8")
        assert "hostNetwork: true" not in raw
        assert "hostPath:" not in raw
        assert "privileged: true" not in raw
