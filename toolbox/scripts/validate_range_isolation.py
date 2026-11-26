"""Offline guardrail for the isolated cyber-defense range scaffold.

The range is an out-of-band environment. This validator proves the committed
scaffold carries no production namespace, no privileged workload, no host
network, and an explicit default-deny NetworkPolicy before it is ever moved to
its own repository.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RANGE = ROOT / "deploy" / "range"
PLACEHOLDER_DIGEST = "@sha256:" + "0" * 64
REQUIRED_README_MARKERS = (
    "separate repository",
    "no production credentials",
    "default-deny",
)


def _walk(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def validate_range(path: Path | None = None) -> list[str]:
    root = path or DEFAULT_RANGE
    errors: list[str] = []
    readme = root / "README.md"
    if not readme.is_file():
        errors.append("range README.md is missing")
    else:
        text = readme.read_text(encoding="utf-8").lower()
        for marker in REQUIRED_README_MARKERS:
            if marker not in text:
                errors.append(f"range README is missing marker: {marker}")

    manifests = sorted(root.rglob("*.yaml"))
    if not manifests:
        errors.append("range has no manifests")

    has_default_deny = False
    has_quota = False
    for manifest in manifests:
        raw = manifest.read_text(encoding="utf-8")
        if "usoc-prod" in raw or "namespace: production" in raw:
            errors.append(f"{manifest.name}: production namespace is not allowed in the range")
        try:
            documents = list(yaml.safe_load_all(raw))
        except yaml.YAMLError as exc:
            errors.append(f"{manifest.name}: invalid YAML: {exc}")
            continue
        for document in documents:
            if not isinstance(document, dict):
                continue
            if document.get("kind") == "ResourceQuota":
                has_quota = True
            if document.get("kind") == "NetworkPolicy":
                spec = document.get("spec") or {}
                if (
                    spec.get("podSelector") == {}
                    and {"Ingress", "Egress"} <= set(spec.get("policyTypes") or [])
                    and not spec.get("ingress")
                    and not spec.get("egress")
                ):
                    has_default_deny = True
            for node in _walk(document):
                if node.get("hostNetwork") is True:
                    errors.append(f"{manifest.name}: hostNetwork is forbidden")
                image = node.get("image")
                if isinstance(image, str) and PLACEHOLDER_DIGEST in image:
                    errors.append(f"{manifest.name}: placeholder digest is not a deployable image")
                context = node.get("securityContext") or {}
                if context.get("privileged") is True:
                    errors.append(f"{manifest.name}: privileged containers are forbidden")

    if not has_default_deny:
        errors.append("range requires a default-deny ingress/egress NetworkPolicy")
    if not has_quota:
        errors.append("range requires a ResourceQuota")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_RANGE)
    args = parser.parse_args(argv)
    errors = validate_range(args.root)
    if errors:
        for error in errors:
            print(f"range isolation error: {error}", file=sys.stderr)
        return 1
    print("range isolation ok: separate environment, default-deny, no production linkage")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
