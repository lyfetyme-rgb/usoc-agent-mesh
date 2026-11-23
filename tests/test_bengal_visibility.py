"""Redacted, read-only BENGAL BAA visibility on health, diagnostics and UI."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from agents.bengal import ThreatMode
from agents.bus import InMemoryBus
from agents.mesh import Mesh
from agents.observability import Metrics
from agents.shell import Shell

ROOT = Path(__file__).resolve().parents[1]

_EXPECTED_MODES = {m.value for m in ThreatMode}


def _shell(registry, bengal_status=None, agents=None):
    return Shell(
        registry,
        agents if agents is not None else {},
        InMemoryBus(insecure_dev_mode=True),
        Metrics(),
        None,
        bengal_status=bengal_status,
    )


def test_public_health_exposes_only_static_bengal_metadata(registry):
    status = {
        "enabled": True,
        "method_version": "bengal-baa/v1",
        "protocol_version": "bengal-eval/v1",
        "modes": sorted(_EXPECTED_MODES),
    }
    public = asyncio.run(_shell(registry, status).health(detailed=False))
    assert public["bengal"] == status
    # Capability metadata only: no case ids, fingerprints or raw payload text.
    text = json.dumps(public).lower()
    assert "case_id" not in text
    assert "fingerprint" not in text
    assert "payload" not in text


def test_detailed_health_includes_the_same_bengal_block(registry):
    status = {"enabled": True, "method_version": "bengal-baa/v1"}
    detailed = asyncio.run(_shell(registry, status).health(detailed=True))
    assert detailed["bengal"] == status


def test_shell_defaults_to_bengal_disabled(registry):
    public = asyncio.run(_shell(registry).health(detailed=False))
    assert public["bengal"]["enabled"] is False


async def test_mesh_injects_enabled_bengal_status(settings):
    async with Mesh(settings, agents=[]) as mesh:
        public = await mesh.shell.health(detailed=False)
        status = public["bengal"]
        assert status["enabled"] is True
        assert status["method_version"] == "bengal-baa/v1"
        assert status["protocol_version"] == "bengal-eval/v1"
        assert set(status["modes"]) == _EXPECTED_MODES
        assert "fingerprint" not in json.dumps(status).lower()


async def test_mesh_describe_bengal_matches_health_status(settings):
    async with Mesh(settings, agents=[]) as mesh:
        public = await mesh.shell.health(detailed=False)
        described = mesh.describe()["bengal"]
        assert set(described["modes"]) == set(public["bengal"]["modes"])
        assert described["method_version"] == public["bengal"]["method_version"]


def test_dashboard_wires_the_bengal_readonly_fields():
    html = (ROOT / "dashboard" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "dashboard" / "app.js").read_text(encoding="utf-8")
    for element_id in ("bengal-method", "bengal-modes", "bengal-protocol"):
        assert f'id="{element_id}"' in html
        assert f'"{element_id}"' in js
    assert "health?.bengal" in js
