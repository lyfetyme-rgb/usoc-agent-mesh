#!/usr/bin/env python3
"""Validate the USOC Mesh requirement traceability catalog offline.

The catalog in docs/requirements/catalog.yaml is the machine-readable source of
truth for the Mission Requirement -> ... -> Operational Validation chain. This
check fails when a requirement is missing a field, an issue link, a code path,
a test path, or — for implemented items — build artifact and deployment
evidence paths. No network access is required.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CATALOG = ROOT / "docs" / "requirements" / "catalog.yaml"
ISSUE_SUFFIX = re.compile(r"/issues/(\d+)$")
EXPECTED_CHAIN = [
    "mission_requirement",
    "capability",
    "operational_function",
    "system_requirement",
    "issue",
    "code",
    "tests",
    "artifacts",
    "deployment_approval",
    "operational_validation",
]
EXPECTED_ENGINEERING_ISSUES = {
    "ENG-001": 37,
    "ENG-002": 38,
    "ENG-003": 39,
    "ENG-004": 40,
    "ENG-005": 41,
}
ALLOWED_STATUSES = {"planned", "in_progress", "implemented", "blocked"}


def load_catalog(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return data


def validate(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []

    if data.get("chain") != EXPECTED_CHAIN:
        errors.append("chain does not match the required ten-step traceability contract")
    if data.get("tracker") != "github-issues":
        errors.append("tracker must be github-issues")

    entries = data.get("requirements")
    if not isinstance(entries, list) or not entries:
        return ["requirements must be a non-empty list"] + errors

    ids: set[str] = set()
    issues: set[int] = set()
    by_id: dict[str, dict[str, Any]] = {}

    for index, entry in enumerate(entries):
        label = f"requirements[{index}] ({entry.get('id', '?') if isinstance(entry, dict) else '?'})"
        if not isinstance(entry, dict):
            errors.append(f"{label}: entry is not a mapping")
            continue

        rid = entry.get("id")
        if not isinstance(rid, str) or not rid.strip():
            errors.append(f"{label}: missing id")
        else:
            if rid in ids:
                errors.append(f"{label}: duplicate id {rid}")
            ids.add(rid)
            by_id[rid] = entry

        for field in ("title", "mission_requirement", "capability",
                      "operational_function", "system_requirement",
                      "issue_url", "deployment_approval", "operational_validation"):
            value = entry.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{label}: missing or empty {field}")

        issue = entry.get("issue")
        if not isinstance(issue, int) or isinstance(issue, bool) or issue <= 0:
            errors.append(f"{label}: issue must be a positive GitHub issue number")
        else:
            if issue in issues:
                errors.append(f"{label}: duplicate issue number {issue}")
            issues.add(issue)
            url = str(entry.get("issue_url") or "")
            match = ISSUE_SUFFIX.search(url)
            if not match or int(match.group(1)) != issue:
                errors.append(f"{label}: issue_url must end with /issues/{issue}")
            repo = str(data.get("repository") or "")
            if repo and repo not in url:
                errors.append(f"{label}: issue_url must point at {repo}")

        status = entry.get("status")
        if status not in ALLOWED_STATUSES:
            errors.append(f"{label}: status must be one of {sorted(ALLOWED_STATUSES)}")

        phase = entry.get("phase")
        if not isinstance(phase, int) or isinstance(phase, bool) or not 0 <= phase <= 4:
            errors.append(f"{label}: phase must be an integer from 0 to 4")

        parent = entry.get("parent")
        if parent is not None and (not isinstance(parent, str) or not parent.strip()):
            errors.append(f"{label}: parent must be null or a requirement id")

        for field in ("code", "tests", "artifacts"):
            value = entry.get(field)
            if not isinstance(value, list):
                errors.append(f"{label}: {field} must be a list")
                continue
            if field in ("code", "tests") and not value:
                errors.append(f"{label}: {field} must not be empty")
            for item in value:
                if not isinstance(item, str) or not item.strip():
                    errors.append(f"{label}: {field} contains an empty path")
                    continue
                if not (root / item).exists():
                    errors.append(f"{label}: {field} path does not exist: {item}")

        if status == "implemented" and not entry.get("artifacts"):
            errors.append(f"{label}: implemented requirement needs at least one build artifact")

    for rid, issue_number in EXPECTED_ENGINEERING_ISSUES.items():
        entry = by_id.get(rid)
        if entry is None:
            errors.append(f"missing Phase 0 engineering issue {rid}")
        elif entry.get("issue") != issue_number:
            errors.append(
                f"{rid}: expected issue {issue_number}, found {entry.get('issue')}"
            )

    for rid, entry in by_id.items():
        parent = entry.get("parent")
        if parent is not None and parent not in by_id:
            errors.append(f"{rid}: parent {parent} is not in the catalog")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()

    try:
        data = load_catalog(args.catalog)
    except Exception as exc:
        print(f"traceability check failed: {exc}", file=sys.stderr)
        return 1

    errors = validate(data, args.root.resolve())
    if errors:
        print("traceability check failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    entries = data["requirements"]
    print(
        f"traceability ok: {len(entries)} requirements, "
        f"{sum(1 for item in entries if item.get('phase') == 0)} Phase 0 items"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
