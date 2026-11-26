"""REQ-007: isolated cyber-defense range proposal guardrails."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "toolbox" / "scripts" / "validate_range_isolation.py"
RANGE = ROOT / "deploy" / "range"


def test_committed_range_scaffold_passes_isolation_validator():
    from importlib.util import module_from_spec, spec_from_file_location

    spec = spec_from_file_location("validate_range_isolation", VALIDATOR)
    assert spec and spec.loader
    module = module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.validate_range(RANGE) == []


def test_validator_cli_succeeds_for_committed_scaffold():
    result = subprocess.run(
        [sys.executable, str(VALIDATOR)], cwd=ROOT, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert "range isolation ok" in result.stdout


def test_validator_rejects_privileged_and_production_linked_manifests(tmp_path: Path):
    from importlib.util import module_from_spec, spec_from_file_location

    (tmp_path / "README.md").write_text(
        "# Range\nseparate repository; no production credentials; default-deny egress.\n",
        encoding="utf-8",
    )
    (tmp_path / "unsafe.yaml").write_text(
        """apiVersion: v1
kind: Pod
metadata:
  name: attacker
  namespace: usoc-prod
spec:
  hostNetwork: true
  containers:
    - name: attacker
      image: example:latest
      securityContext:
        privileged: true
""",
        encoding="utf-8",
    )
    spec = spec_from_file_location("validate_range_isolation_tmp", VALIDATOR)
    assert spec and spec.loader
    module = module_from_spec(spec)
    spec.loader.exec_module(module)

    errors = module.validate_range(tmp_path)
    assert any("privileged" in error for error in errors)
    assert any("production" in error for error in errors)
    assert any("hostNetwork" in error for error in errors)
    assert any("default-deny" in error for error in errors)


def test_validator_rejects_placeholder_image_digests(tmp_path: Path):
    from importlib.util import module_from_spec, spec_from_file_location

    (tmp_path / "README.md").write_text(
        "# Range\nseparate repository; no production credentials; default-deny egress.\n",
        encoding="utf-8",
    )
    (tmp_path / "quota.yaml").write_text(
        """apiVersion: v1
kind: ResourceQuota
metadata:
  name: range
  namespace: usoc-range
spec:
  hard:
    pods: "4"
""",
        encoding="utf-8",
    )
    (tmp_path / "deny.yaml").write_text(
        """apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: usoc-range
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
  ingress: []
  egress: []
""",
        encoding="utf-8",
    )
    (tmp_path / "workload.yaml").write_text(
        """apiVersion: v1
kind: Pod
metadata:
  name: placeholder
  namespace: usoc-range
spec:
  containers:
    - name: runner
      image: example@sha256:0000000000000000000000000000000000000000000000000000000000000000
""",
        encoding="utf-8",
    )
    spec = spec_from_file_location("validate_range_placeholder", VALIDATOR)
    assert spec and spec.loader
    module = module_from_spec(spec)
    spec.loader.exec_module(module)

    errors = module.validate_range(tmp_path)
    assert any("placeholder digest" in error for error in errors)


def test_range_design_is_explicitly_out_of_band():
    readme = (RANGE / "README.md").read_text(encoding="utf-8")
    for marker in ("separate repository", "no production credentials", "default-deny"):
        assert marker in readme
    for manifest in RANGE.rglob("*.yaml"):
        assert "usoc-prod" not in manifest.read_text(encoding="utf-8")
