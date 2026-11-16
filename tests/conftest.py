from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.config import Settings  # noqa: E402
from agents.tools import build_default_tools  # noqa: E402


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        bus="memory",
        subsystems_file=ROOT / "subsystems.yaml",
        workspace=tmp_path / "workspace",
        log_level="CRITICAL",
        task_timeout_s=5,
        max_attempts=2,
        max_concurrency=4,
    )


@pytest.fixture
def tools(settings: Settings):
    from agents.evidence import EvidenceChain
    from agents.tools import build_default_tools

    evidence = EvidenceChain(settings.workspace / "evidence" / "chain.jsonl")
    return build_default_tools(settings.workspace, evidence)


@pytest.fixture
def registry(settings: Settings, tools):
    from agents.registry import load_registry

    return load_registry(settings.subsystems_file, tools, expected_count=9)
