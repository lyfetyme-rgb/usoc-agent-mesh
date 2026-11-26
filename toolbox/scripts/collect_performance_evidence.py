#!/usr/bin/env python3
"""Collect checked-in, offline benchmark evidence for REQ-009.

The command is the repository's real ``agents benchmark`` harness. It never
creates a task-dispatch HTTP endpoint or sends traffic to a live service. The
result artifact contains counts, flags and digests only -- no raw case text.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "docs" / "performance" / "benchmark-run.json"
GENERATED_BY = "toolbox/scripts/collect_performance_evidence.py"
COMMAND = "python -m agents benchmark --rounds 2"
FORBIDDEN_ENDPOINT = "/v1/tasks/dispatch"
FORBIDDEN_FIELDS = ("text", "payload", "token", "secret", "credential")


def collect(root: Path = ROOT) -> dict[str, Any]:
    """Run the real offline benchmark and return a bounded evidence record."""
    with tempfile.TemporaryDirectory(prefix="usoc-perf-") as workspace:
        env = os.environ.copy()
        env["AGENT_WORKSPACE"] = workspace
        env.pop("AGENT_STRICT_PROD", None)
        result = subprocess.run(
            [sys.executable, "-m", "agents", "benchmark", "--rounds", "2"],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
    if result.returncode != 0:
        raise RuntimeError(f"benchmark failed: {result.stderr.strip() or result.stdout.strip()}")
    try:
        benchmark = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"benchmark output was not JSON: {exc}") from exc

    invariants = benchmark.get("hard_invariants") or {}
    totals = benchmark.get("totals") or {}
    evidence = {
        "generated_by": GENERATED_BY,
        "command": COMMAND,
        "scope": "offline governance readiness benchmark; not a hyperscale claim",
        "benchmark": {
            "run_id": benchmark.get("run_id"),
            "mode": benchmark.get("mode"),
            "best": benchmark.get("best"),
            "verified": invariants.get("evidence_verified") is True,
            "hard_pass": benchmark.get("hard_pass") is True,
            "rehearsal_only": benchmark.get("rehearsal_only") is True,
            "shadow": benchmark.get("shadow") is True,
            "chain_head": benchmark.get("chain_head"),
            "totals": {
                "cases": totals.get("cases"),
                "evaluations": totals.get("evaluations"),
                "variants": totals.get("variants"),
                "resolved": totals.get("resolved"),
                "unresolved": totals.get("unresolved"),
            },
        },
    }
    errors = validate_evidence(root, evidence)
    if errors:
        raise RuntimeError("; ".join(errors))
    return evidence


def validate_evidence(root: Path = ROOT, data: dict[str, Any] | None = None) -> list[str]:
    """Validate a checked-in artifact without running any benchmark."""
    if data is None:
        try:
            data = json.loads((root / ARTIFACT.relative_to(ROOT)).read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError) as exc:
            return [f"benchmark artifact is missing or invalid: {exc}"]
    errors: list[str] = []
    if data.get("generated_by") != GENERATED_BY:
        errors.append("generated_by mismatch")
    if data.get("command") != COMMAND:
        errors.append("command does not record the real offline benchmark")
    benchmark = data.get("benchmark")
    if not isinstance(benchmark, dict):
        return errors + ["benchmark section is missing"]

    for flag in ("verified", "hard_pass", "rehearsal_only", "shadow"):
        if benchmark.get(flag) is not True:
            errors.append(f"benchmark.{flag} must be true")
    totals = benchmark.get("totals")
    if not isinstance(totals, dict):
        errors.append("benchmark.totals is missing")
    else:
        cases = totals.get("cases")
        evaluations = totals.get("evaluations")
        if not isinstance(cases, int) or cases < 1:
            errors.append("benchmark.totals.cases must be at least 1")
        if not isinstance(evaluations, int) or evaluations < (cases or 0):
            errors.append("benchmark.totals.evaluations must be at least cases")
    if not isinstance(benchmark.get("chain_head"), dict):
        errors.append("benchmark.chain_head is missing")

    blob = json.dumps(data, sort_keys=True).lower()
    if FORBIDDEN_ENDPOINT in blob:
        errors.append("artifact contains an invented task-dispatch endpoint")
    for field in FORBIDDEN_FIELDS:
        if f'"{field}"' in blob:
            errors.append(f"artifact contains a forbidden field: {field}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate the checked-in artifact")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)

    root = args.root.resolve()
    if args.check:
        errors = validate_evidence(root)
        if errors:
            for error in errors:
                print(f"performance evidence error: {error}", file=sys.stderr)
            return 1
        print("performance evidence ok: offline benchmark artifact is verified")
        return 0

    try:
        evidence = collect(root)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"performance evidence collection failed: {exc}", file=sys.stderr)
        return 1
    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"performance evidence ok: wrote {ARTIFACT.relative_to(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
