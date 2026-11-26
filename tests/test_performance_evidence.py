"""REQ-009: checked-in benchmark evidence without invented endpoints."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "docs" / "performance" / "benchmark-run.json"
COLLECTOR = ROOT / "toolbox" / "scripts" / "collect_performance_evidence.py"


def test_benchmark_artifact_records_an_actual_offline_run():
    data = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    benchmark = data["benchmark"]
    assert data["generated_by"] == "toolbox/scripts/collect_performance_evidence.py"
    assert "python -m agents benchmark" in data["command"]
    assert benchmark["verified"] is True
    assert benchmark["hard_pass"] is True
    assert benchmark["rehearsal_only"] is True
    assert benchmark["shadow"] is True
    assert benchmark["totals"]["cases"] >= 1
    assert benchmark["totals"]["evaluations"] >= benchmark["totals"]["cases"]


def test_performance_validator_accepts_committed_evidence():
    from importlib.util import module_from_spec, spec_from_file_location

    spec = spec_from_file_location("collect_performance_evidence", COLLECTOR)
    assert spec and spec.loader
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.validate_evidence(ROOT) == []


def test_performance_validator_cli_succeeds():
    result = subprocess.run(
        [sys.executable, str(COLLECTOR), "--check"], cwd=ROOT, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert "performance evidence ok" in result.stdout


def test_no_invented_task_dispatch_endpoint_anywhere_in_performance_surface():
    forbidden = "/v1/tasks/dispatch"
    warning_markers = ("do not", "never", "must not", "no ")
    for path in [*(ROOT / "tests" / "loadtest").rglob("*"), *(ROOT / "docs" / "performance").rglob("*")]:
        if not path.is_file():
            continue
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for index, line in enumerate(lines):
            if forbidden not in line:
                continue
            context = " ".join(lines[max(0, index - 1):index + 2]).lower()
            assert any(marker in context for marker in warning_markers), (path, line)
