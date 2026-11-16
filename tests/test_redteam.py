from __future__ import annotations

import asyncio

import pytest

from agents.bus import ConfigurationError, InMemoryBus, build_bus
from agents.config import Settings
from agents.contracts import Message, TaskSpec


def test_omit_acls_in_production_raises():
    settings = Settings(bus="memory")
    with pytest.raises(ConfigurationError):
        build_bus(settings)  # no insecure_dev_mode


def test_omit_acls_in_dev_mode_allowed():
    settings = Settings(bus="memory")
    bus = build_bus(settings, insecure_dev_mode=True)
    assert bus is not None


def test_spoofed_sender_blocked_by_verifier():
    async def run():
        def verifier(sender, msg):
            return sender == "legit"

        bus = InMemoryBus(insecure_dev_mode=True, sender_verifier=verifier)
        await bus.subscribe("recv", ["topic.x"])
        msg = Message(
            sender="attacker",
            recipient="recv",
            topic="topic.x",
            payload=TaskSpec(objective="hi", budget_tokens=1000),
        )
        with pytest.raises(PermissionError):
            await bus.publish(msg)

    asyncio.run(run())


def test_legit_sender_allowed_by_verifier():
    async def run():
        def verifier(sender, msg):
            return sender == "legit"

        bus = InMemoryBus(insecure_dev_mode=True, sender_verifier=verifier)
        await bus.subscribe("recv", ["topic.x"])
        msg = Message(
            sender="legit",
            recipient="recv",
            topic="topic.x",
            payload=TaskSpec(objective="hi", budget_tokens=1000),
        )
        await bus.publish(msg)
        assert len(bus.history) == 1

    asyncio.run(run())