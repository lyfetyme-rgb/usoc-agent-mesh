"""SHELL hardening: config integrity, topic ACLs and diagnostic disclosure."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace

import pytest

from agents.bus import (
    ConfigurationError,
    InMemoryBus,
    acls_from_specs,
    has_wildcard,
)
from agents.config import Settings, subsystems_integrity, verify_subsystems_file
from agents.contracts import Message
from agents.observability import Metrics
from agents.security import SecurityError, Signer
from agents.service import HealthServer
from agents.shell import Shell

SECRET = "s" * 48


# -- capability card integrity ----------------------------------------------
def test_pinned_manifest_hash_accepts_the_exact_file_and_rejects_tampering(tmp_path: Path):
    cards = tmp_path / "subsystems.yaml"
    cards.write_text("subsystems: []\n", encoding="utf-8")
    digest, _ = subsystems_integrity(cards, Settings(shared_secret=SECRET))
    pinned = Settings(subsystems_manifest_hash=digest)

    assert verify_subsystems_file(cards, pinned) == digest

    cards.write_text("subsystems: [tampered]\n", encoding="utf-8")
    with pytest.raises(SecurityError, match="SHA-256"):
        verify_subsystems_file(cards, pinned)


def test_integrity_is_mandatory_when_required(tmp_path: Path):
    cards = tmp_path / "subsystems.yaml"
    cards.write_text("subsystems: []\n", encoding="utf-8")

    with pytest.raises(SecurityError, match="REQUIRE_SUBSYSTEMS_INTEGRITY"):
        verify_subsystems_file(cards, Settings(require_subsystems_integrity=True))


def test_signature_binds_the_manifest_to_the_cluster_secret(tmp_path: Path):
    cards = tmp_path / "subsystems.yaml"
    cards.write_text("subsystems: []\n", encoding="utf-8")
    _, signature = subsystems_integrity(cards, Settings(shared_secret=SECRET))
    assert signature

    verify_subsystems_file(
        cards, Settings(shared_secret=SECRET, subsystems_signature=signature)
    )

    with pytest.raises(SecurityError, match="HMAC"):
        verify_subsystems_file(
            cards, Settings(shared_secret="x" * 48, subsystems_signature=signature)
        )


def test_signature_without_a_cluster_secret_fails_closed(tmp_path: Path):
    cards = tmp_path / "subsystems.yaml"
    cards.write_text("subsystems: []\n", encoding="utf-8")
    data = cards.read_bytes()
    signature = hmac.new(SECRET.encode(), data, hashlib.sha256).hexdigest()

    with pytest.raises(SecurityError, match="AGENT_SHARED_SECRET"):
        verify_subsystems_file(cards, Settings(subsystems_signature=signature))


# -- wildcard topic ACLs -----------------------------------------------------
def test_domain_agent_may_not_use_a_wildcard_publish_rule():
    with pytest.raises(ConfigurationError, match="wildcard publish"):
        InMemoryBus(insecure_dev_mode=True, publish_acl={"aicee": ["inbox.*"]})


def test_domain_agent_may_not_use_a_wildcard_subscribe_rule():
    with pytest.raises(ConfigurationError, match="wildcard subscribe"):
        InMemoryBus(insecure_dev_mode=True, subscribe_acl={"aicee": ["topic.*"]})


def test_audit_sink_may_subscribe_to_topic_wildcard_when_authenticated():
    bus = InMemoryBus(
        insecure_dev_mode=True,
        signer=Signer(SECRET),
        subscribe_acl={"oekp": ["topic.*"]},
    )
    asyncio.run(bus.subscribe("oekp", ["topic.*"]))
    assert bus._patterns["oekp"] == ["inbox.oekp", "topic.*"]


def test_audit_wildcard_requires_message_authentication():
    with pytest.raises(ConfigurationError, match="authentication"):
        InMemoryBus(insecure_dev_mode=True, subscribe_acl={"oekp": ["topic.*"]})


def test_audit_wildcard_must_stay_inside_topic_namespace():
    with pytest.raises(ConfigurationError, match="topic"):
        InMemoryBus(
            insecure_dev_mode=True,
            signer=Signer(SECRET),
            subscribe_acl={"oekp": ["inbox.*"]},
        )


def test_control_plane_may_use_a_publish_pattern():
    bus = InMemoryBus(
        insecure_dev_mode=True, publish_acl={"orchestrator": ["inbox.*"]}
    )
    assert bus.publish_acl == {"orchestrator": ["inbox.*"]}


def test_publishing_to_a_wildcard_topic_is_rejected():
    async def run():
        bus = InMemoryBus(insecure_dev_mode=True)
        with pytest.raises(PermissionError, match="concrete"):
            await bus.publish(Message.event(sender="orchestrator", name="x", topic="topic.*"))

    asyncio.run(run())


def test_generated_acls_enumerate_domain_topics(registry):
    publish, subscribe = acls_from_specs(registry.subsystems)

    # Domain agents never get a wildcard publish/subscribe rule.
    for agent, patterns in publish.items():
        if agent != "orchestrator":
            assert not any(has_wildcard(p) for p in patterns)
    for patterns in subscribe.values():
        assert not any(has_wildcard(p) for p in patterns)

    assert subscribe["cyber_defense"] == ["topic.alert"]
    assert "inbox.orchestrator" in publish["cyber_defense"]
    assert {"inbox.orchestrator", "inbox.aicee", "topic.plan", "topic.goal"} <= set(
        publish["orchestrator"]
    )


# -- SHELL diagnostics -------------------------------------------------------
def make_shell(registry, *, fragmentation_error: str | None = None) -> Shell:
    agents = {
        spec.id: SimpleNamespace(id=spec.id, uptime_s=1.0, _tasks=set())
        for spec in registry.subsystems
    }
    return Shell(
        registry,
        agents,
        InMemoryBus(insecure_dev_mode=True),
        Metrics(),
        None,
        fragmentation_error=fragmentation_error,
    )


def test_public_health_is_minimal_and_never_leaks_topology(registry):
    shell = make_shell(registry)

    async def run():
        return await shell.health(detailed=False)

    public = asyncio.run(run())
    assert public["status"] == "ok"
    assert public["agents_running"] == 9
    for key in ("agents", "bus", "transport", "metrics", "fragmentation", "roles"):
        assert key not in public


def test_health_diagnostics_redact_connection_secrets(registry):
    leak = "redis://mesh:supersecret@internal-redis:6379/0"
    shell = make_shell(registry, fragmentation_error=f"ConnectorConfigError: {leak}")

    async def run():
        return (
            await shell.health(detailed=True),
            await shell.diagnostics(),
            await shell.ready(detailed=False),
        )

    detailed, issues, ready = asyncio.run(run())
    for payload in (detailed, ready):
        text = json.dumps(payload)
        assert "supersecret" not in text
    assert all("supersecret" not in issue for issue in issues)
    assert any("fragmentation disabled" in issue for issue in issues)
    assert "missing_agents" not in ready


def test_ready_public_view_hides_agent_identities(registry):
    shell = make_shell(registry)

    async def run():
        return await shell.ready(detailed=False)

    ok, info = asyncio.run(run())
    assert ok is True
    assert "missing_agents" not in info
    assert "agents" not in info


# -- HTTP diagnostics authentication ----------------------------------------
async def _http(port: int, path: str, token: str | None = None) -> tuple[int, dict]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    lines = [f"GET {path} HTTP/1.1", "Host: localhost", "Connection: close"]
    if token:
        lines.append(f"Authorization: Bearer {token}")
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
    await writer.drain()
    raw = await reader.read()
    writer.close()
    with suppress(ConnectionError, OSError):
        await writer.wait_closed()
    head, _, body = raw.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1])
    return status, json.loads(body or b"{}")


def test_diagnostics_route_is_hidden_without_an_admin_token():
    async def provider(path: str) -> tuple[int, dict]:
        return 200, {"path": path}

    async def run():
        server = HealthServer("127.0.0.1", 0, provider, token="health-token")
        await server.start()
        try:
            assert (await _http(server.port, "/diagnostics", token="health-token"))[0] == 404
        finally:
            await server.stop()

    asyncio.run(run())


def test_diagnostics_requires_the_admin_token_not_the_probe_token():
    async def provider(path: str) -> tuple[int, dict]:
        return 200, {"path": path, "topology": "internal"}

    async def run():
        server = HealthServer(
            "127.0.0.1", 0, provider, token="health-token", admin_token="admin-token"
        )
        await server.start()
        try:
            assert (await _http(server.port, "/diagnostics"))[0] == 401
            assert (
                await _http(server.port, "/diagnostics", token="health-token")
            )[0] == 401
            status, body = await _http(
                server.port, "/diagnostics", token="admin-token"
            )
            assert status == 200 and body["topology"] == "internal"
            # The probe token still works on the public routes.
            assert (await _http(server.port, "/health", token="health-token"))[0] == 200
        finally:
            await server.stop()

    asyncio.run(run())


def test_public_routes_work_without_a_probe_token():
    async def provider(path: str) -> tuple[int, dict]:
        return 200, {"path": path}

    async def run():
        server = HealthServer("127.0.0.1", 0, provider, admin_token="admin-token")
        await server.start()
        try:
            assert (await _http(server.port, "/health"))[0] == 200
            assert (await _http(server.port, "/ready"))[0] == 200
        finally:
            await server.stop()

    asyncio.run(run())
