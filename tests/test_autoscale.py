"""Demand-based autoscaling: policy math and bus backlog signal."""

from __future__ import annotations

import asyncio
import json

import pytest

from agents.autoscale import ReplicaTarget, ScalePolicy
from agents.bus import InMemoryBus
from agents.contracts import Message
from agents.security import SecurityError


def test_policy_never_shrinks_below_min_or_above_max():
    policy = ScalePolicy(min_replicas=1, max_replicas=4, messages_per_replica=8)
    assert policy.desired(0) == 1
    assert policy.desired(7) == 1
    assert policy.desired(8) == 1
    assert policy.desired(9) == 2
    assert policy.desired(16) == 2
    assert policy.desired(17) == 3
    assert policy.desired(1000) == 4


def test_policy_rejects_inverted_bounds():
    with pytest.raises(SecurityError):
        ScalePolicy(min_replicas=2, max_replicas=1)
    with pytest.raises(SecurityError):
        ScalePolicy(min_replicas=0, max_replicas=1)
    with pytest.raises(SecurityError):
        ScalePolicy(messages_per_replica=0)


def test_targets_reports_steady_state_and_reasons():
    policy = ScalePolicy(min_replicas=1, max_replicas=4, messages_per_replica=8)
    targets = policy.targets({"oekp": 0, "aicee": 30, "bengal": 8}, current={"oekp": 1})
    by_agent = {t.agent: t for t in targets}
    assert by_agent["oekp"].desired == 1 and by_agent["oekp"].reason == "steady state"
    assert by_agent["aicee"].desired == 4
    assert by_agent["bengal"].desired == 1


def test_json_output_is_machine_consumable():
    policy = ScalePolicy(min_replicas=1, max_replicas=4, messages_per_replica=8)
    payload = json.loads(policy.as_json(policy.targets({"oekp": 20})))
    assert payload["policy"]["messages_per_replica"] == 8
    assert payload["targets"][0]["agent"] == "oekp"
    assert payload["targets"][0]["desired"] == 3


def test_inmemory_bus_reports_queue_backlog():
    async def run():
        bus = InMemoryBus(insecure_dev_mode=True)
        await bus.subscribe("oekp", [])
        msg = Message.task(sender="client", recipient="oekp", objective="work")
        await bus.publish(msg)
        assert (await bus.backlog())["oekp"] == 1
        picked = await bus.receive("oekp", timeout=1)
        assert picked is not None
        return await bus.backlog()

    assert asyncio.run(run())["oekp"] == 0
