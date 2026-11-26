#!/usr/bin/env python3
"""Offline gate for REQ-010 security and production readiness assurance.

This checker ties each Section 6 invariant to an automated test and verifies
that the required readiness procedures exist. It does not claim that a manual
penetration test or recovery drill has been performed. It runs offline; no live
system or production credential is needed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs" / "readiness"
MATRIX = DOCS / "assurance-matrix.md"
RECOVERY = DOCS / "recovery-drill.md"

INVARIANTS = (
    "non-root",
    "read-only rootfs",
    "zero browser token exposure",
    "strict egress",
    "Ed25519 signatures",
    "single-use nonce atomicity",
    "OIDC/detached credential checks",
    "shadow fail-closed",
    "immutable OEKP evidence",
    "no raw payloads in ledger/evidence/health",
)
REQUIRED_TESTS = (
    "tests/test_kubernetes_manifests.py",
    "tests/test_dashboard_server.py",
    "tests/test_security.py",
    "tests/test_production_trust.py",
    "tests/test_production_signing.py",
    "tests/test_shadow_mode.py",
    "tests/test_observability_hardening.py",
)
REQUIRED_DOCS = {
    "assurance-matrix.md": ("Section 6", "Automated test"),
    "threat-model.md": ("trust boundary", "adversary"),
    "vulnerability-disclosure.md": ("report", "disclosure"),
    "incident-response.md": ("containment", "recovery"),
    "penetration-test.md": ("offline", "finding"),
    "recovery-drill.md": ("offline simulation", "RTO", "RPO"),
}


def validate_readiness(root: Path = ROOT) -> list[str]:
    root = root.resolve()
    docs = root / "docs" / "readiness"
    errors: list[str] = []

    for name, markers in REQUIRED_DOCS.items():
        path = docs / name
        if not path.is_file():
            errors.append(f"missing readiness document: docs/readiness/{name}")
            continue
        text = path.read_text(encoding="utf-8")
        if len(text.strip()) < 80:
            errors.append(f"docs/readiness/{name} is too short to be assurance evidence")
        lower = text.lower()
        for marker in markers:
            if marker.lower() not in lower:
                errors.append(f"docs/readiness/{name} is missing marker: {marker}")

    matrix_path = docs / "assurance-matrix.md"
    if matrix_path.is_file():
        matrix = matrix_path.read_text(encoding="utf-8")
        for label in INVARIANTS:
            if label not in matrix:
                errors.append(f"assurance matrix is missing invariant: {label}")
        for test in REQUIRED_TESTS:
            if test not in matrix:
                errors.append(f"assurance matrix is missing test mapping: {test}")
            elif not (root / test).is_file():
                errors.append(f"assurance matrix maps a missing test: {test}")

    recovery_path = docs / "recovery-drill.md"
    if recovery_path.is_file():
        drill = recovery_path.read_text(encoding="utf-8").lower()
        if "raw payload" in drill:
            errors.append("recovery drill must not describe retaining raw payloads")
        if "live production" not in drill:
            errors.append("recovery drill must state that no live production system is used")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    errors = validate_readiness(args.root)
    if errors:
        for error in errors:
            print(f"readiness assurance error: {error}", file=sys.stderr)
        return 1
    print("readiness assurance ok: Section 6 matrix and IR/recovery procedures present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
