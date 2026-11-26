"""Guardrails for Phase 0 repository, CI/CD and deployment foundations."""

from __future__ import annotations

import argparse
import importlib.util
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GITHUB = ROOT / ".github"
WORKFLOWS = GITHUB / "workflows"
K8S = ROOT / "deploy" / "kubernetes"


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def load_yaml(relative: str) -> dict:
    return yaml.safe_load(read(relative))


def text_of_workflow(name: str) -> str:
    return read(f".github/workflows/{name}")


def load_render_overlay_module():
    path = ROOT / "toolbox" / "scripts" / "render_overlay.py"
    spec = importlib.util.spec_from_file_location("usoc_render_overlay", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ci_has_all_three_required_checks():
    data = load_yaml(".github/workflows/ci.yml")
    assert {"pytest", "traceability", "security"} <= set(data["jobs"])

    pytest_steps = str(data["jobs"]["pytest"])
    assert "python -m pytest -q" in pytest_steps
    assert "python -m agents doctor" in pytest_steps
    assert "h-lift" in pytest_steps

    traceability_steps = str(data["jobs"]["traceability"])
    assert "python toolbox/scripts/traceability_check.py" in traceability_steps

    security_steps = str(data["jobs"]["security"])
    for marker in (
        "pip_audit",
        "bandit",
        "gitleaks",
        "aquasecurity/trivy-action@v0.36.0",
    ):
        assert marker in security_steps


def test_release_workflow_signs_attests_and_publishes_sboms():
    data = load_yaml(".github/workflows/release.yml")
    assert data["permissions"]["contents"] == "read"
    assert data["permissions"]["packages"] == "write"
    assert data["permissions"]["id-token"] == "write"

    text = text_of_workflow("release.yml")
    for marker in (
        "docker/build-push-action@v6",
        "syft dir:. -o spdx-json",
        "syft dir:. -o cyclonedx-json",
        "cosign sign --yes",
        "cosign attest --yes --type spdxjson",
        "cosign attest --yes --type slsaprovenance",
        "actions/upload-artifact@v4",
    ):
        assert marker in text
    assert "secrets.REGISTRY" not in text


def test_deploy_workflow_only_deploys_verified_digests():
    data = load_yaml(".github/workflows/deploy.yml")
    # PyYAML 1.1 parses the YAML key `on` as boolean True.
    trigger = data.get("on", data.get(True))
    inputs = trigger["workflow_dispatch"]["inputs"]
    assert set(inputs) == {"environment", "mesh_digest", "dashboard_digest"}
    assert data["jobs"]["deploy"]["environment"] == "${{ inputs.environment }}"

    text = text_of_workflow("deploy.yml")
    for marker in (
        "cosign verify",
        "cosign verify-attestation",
        "slsaprovenance",
        "toolbox/scripts/render_overlay.py",
        "kubectl apply -f rendered.yaml",
        "NAMESPACE=usoc-staging",
        "NAMESPACE=usoc-prod",
        "job/usoc-doctor-preflight",
        "smoke.log",
    ):
        assert marker in text

    # Tags and post-apply mutation would let an unverified image reach pods.
    assert "kubectl set image" not in text
    assert "kubectl apply -k" not in text
    assert "usoc-production" not in text


def test_kustomize_layout_keeps_templates_out_and_namespaces_isolated():
    base = load_yaml("deploy/kubernetes/base/kustomization.yaml")
    assert base["resources"]
    assert not any(".example" in resource for resource in base["resources"])
    assert load_yaml("deploy/kubernetes/kustomization.yaml")["resources"] == ["base"]

    for environment, namespace in (("staging", "usoc-staging"), ("production", "usoc-prod")):
        overlay = load_yaml(
            f"deploy/kubernetes/overlays/{environment}/kustomization.yaml"
        )
        assert overlay["namespace"] == namespace
        assert overlay["resources"] == ["../../base"]

    staging_text = read("deploy/kubernetes/overlays/staging/kustomization.yaml")
    assert "usoc-dashboard.usoc-staging.svc.cluster.local" in staging_text


@pytest.mark.skipif(shutil.which("kubectl") is None, reason="kubectl is not installed")
@pytest.mark.parametrize(
    ("environment", "namespace", "forbidden"),
    [
        ("staging", "usoc-staging", "usoc-prod"),
        ("production", "usoc-prod", "usoc-staging"),
    ],
)
def test_rendered_overlay_targets_one_namespace(environment, namespace, forbidden):
    result = subprocess.run(
        ["kubectl", "kustomize", str(K8S / "overlays" / environment)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    docs = [doc for doc in yaml.safe_load_all(result.stdout) if doc]
    namespaces = {
        doc["metadata"]["namespace"]
        for doc in docs
        if doc.get("kind") != "Namespace"
    }
    assert namespaces == {namespace}
    assert [doc["metadata"]["name"] for doc in docs if doc.get("kind") == "Namespace"] == [
        namespace
    ]
    assert forbidden not in result.stdout


def test_render_overlay_pins_every_workload_and_rejects_tags():
    module = load_render_overlay_module()
    mesh_digest = "ghcr.io/lyfetyme-rgb/usoc-mesh@sha256:" + "a" * 64
    dashboard_digest = "ghcr.io/lyfetyme-rgb/usoc-dashboard@sha256:" + "b" * 64

    docs = [
        {
            "kind": "Deployment",
            "spec": {
                "template": {
                    "spec": {"containers": [{"image": "ghcr.io/lyfetyme-rgb/usoc-mesh:0.2.1"}]}
                }
            },
        },
        {
            "kind": "Job",
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {"image": "ghcr.io/lyfetyme-rgb/usoc-dashboard:0.2.0"}
                        ]
                    }
                }
            },
        },
    ]
    _, mesh_count, dashboard_count = module.pin_images(
        docs, mesh_digest, dashboard_digest
    )
    assert (mesh_count, dashboard_count) == (1, 1)
    assert docs[0]["spec"]["template"]["spec"]["containers"][0]["image"] == mesh_digest
    assert docs[1]["spec"]["template"]["spec"]["containers"][0]["image"] == dashboard_digest

    with pytest.raises(ValueError, match="sha256 digest"):
        module.validate_image("ghcr.io/lyfetyme-rgb/usoc-mesh:0.2.1", "--mesh-image")


def test_repository_control_files_declare_owner_and_traceability():
    codeowners = read(".github/CODEOWNERS")
    assert "* @lyfetyme-rgb" in codeowners

    template = read(".github/pull_request_template.md")
    for marker in (
        "Requirement ID(s)",
        "Engineering issue(s)",
        "python toolbox/scripts/traceability_check.py",
        "Image digest or workflow artifact",
        "gateway-cloud-functions/",
        "SECURITY.md",
    ):
        assert marker in template

    bandit = load_yaml("toolbox/security/bandit.yaml")
    assert "B608" in bandit["skips"]
    assert {"tests", "atlas", "gateway-cloud-functions", "h-lift"} <= set(
        bandit["exclude_dirs"]
    )


def test_release_docs_match_single_maintainer_guards():
    docs = read("docs/release-engineering.md")
    assert "required_approving_review_count` remains `0`" in docs
    assert "prevent_self_review` is currently `false`" in docs
    assert "kubectl apply -f rendered.yaml" in docs


def test_probe_rejects_non_http_url_schemes(monkeypatch):
    import agents.__main__ as cli

    settings = SimpleNamespace(
        health_host="127.0.0.1",
        health_port=8080,
        health_token=None,
        health_token_file=None,
    )
    monkeypatch.setattr(cli, "_settings", lambda _args: settings)
    args = argparse.Namespace(url="file:///etc/passwd", token="unused")
    with pytest.raises(ValueError, match="http or https"):
        cli.cmd_probe(args)
