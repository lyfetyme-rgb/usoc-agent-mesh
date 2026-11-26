"""Guardrails for the machine-readable requirements traceability catalog."""

from __future__ import annotations

import copy
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "docs" / "requirements" / "catalog.yaml"
CHECKER = ROOT / "toolbox" / "scripts" / "traceability_check.py"
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


def load_catalog() -> dict:
    return yaml.safe_load(CATALOG.read_text(encoding="utf-8"))


def run_checker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def write_catalog(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "catalog.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def test_committed_catalog_passes_offline_validator():
    result = run_checker()
    assert result.returncode == 0, result.stderr
    assert "traceability ok" in result.stdout
    assert "15 requirements" in result.stdout


def test_catalog_covers_full_chain_and_all_roadmap_requirements():
    data = load_catalog()
    assert data["chain"] == EXPECTED_CHAIN
    assert data["tracker"] == "github-issues"
    assert data["repository"] == "lyfetyme-rgb/usoc-agent-mesh"

    entries = {item["id"]: item for item in data["requirements"]}
    assert {f"REQ-{n:03d}" for n in range(1, 11)} <= set(entries)
    assert {f"ENG-{n:03d}" for n in range(1, 6)} <= set(entries)
    parents = {
        "ENG-001": "REQ-002",
        "ENG-002": "REQ-001",
        "ENG-003": "REQ-010",
        "ENG-004": "REQ-001",
        "ENG-005": "REQ-001",
    }
    for engineering_id, parent in parents.items():
        assert entries[engineering_id]["parent"] == parent

    for item in data["requirements"]:
        assert item["issue_url"] == (
            "https://github.com/lyfetyme-rgb/usoc-agent-mesh/issues/"
            f"{item['issue']}"
        )
        assert item["code"] and item["tests"]


def test_implemented_items_declare_build_and_deployment_evidence():
    for item in load_catalog()["requirements"]:
        assert (ROOT / item["code"][0]).exists(), item["id"]
        assert (ROOT / item["tests"][0]).exists(), item["id"]
        if item["status"] == "implemented":
            assert item["artifacts"], item["id"]
            assert (ROOT / item["artifacts"][0]).exists(), item["id"]
            assert item["deployment_approval"], item["id"]
            assert item["operational_validation"], item["id"]


def test_validator_rejects_a_missing_issue_link(tmp_path: Path):
    data = copy.deepcopy(load_catalog())
    del data["requirements"][0]["issue_url"]
    result = run_checker("--catalog", str(write_catalog(tmp_path, data)))
    assert result.returncode == 1
    assert "issue_url" in result.stderr


def test_validator_rejects_a_nonexistent_test_path(tmp_path: Path):
    data = copy.deepcopy(load_catalog())
    data["requirements"][0]["tests"].append("tests/test_does_not_exist.py")
    result = run_checker("--catalog", str(write_catalog(tmp_path, data)))
    assert result.returncode == 1
    assert "tests/test_does_not_exist.py" in result.stderr


def test_validator_rejects_implemented_item_without_artifacts(tmp_path: Path):
    data = copy.deepcopy(load_catalog())
    for item in data["requirements"]:
        if item["id"] == "ENG-001":
            item["artifacts"] = []
    result = run_checker("--catalog", str(write_catalog(tmp_path, data)))
    assert result.returncode == 1
    assert "implemented requirement needs at least one build artifact" in result.stderr
