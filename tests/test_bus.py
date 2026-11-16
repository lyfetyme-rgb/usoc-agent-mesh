from __future__ import annotations

from agents.bus import InMemoryBus
from agents.contracts import Event, Message


async def test_direct_message_reaches_only_the_recipient():
    bus = InMemoryBus(insecure_dev_mode=True)
    await bus.subscribe("a", [])
    await bus.subscribe("b", [])
    msg = Message.task(sender="orchestrator", recipient="a", objective="work")
    await bus.publish(msg)

    assert await bus.receive("a", timeout=0.2) is not None
    assert await bus.receive("b", timeout=0.05) is None


async def test_broadcast_reaches_every_subscriber():
    bus = InMemoryBus(insecure_dev_mode=True)
    await bus.subscribe("a", ["topic.alert"])
    await bus.subscribe("b", ["topic.alert"])
    await bus.publish(Message.event(sender="a", name="alert.raised", data={"level": "high"}))

    first = await bus.receive("a", timeout=0.2)
    second = await bus.receive("b", timeout=0.2)
    assert first and second and first.payload.name == "alert.raised"


async def test_nack_requeues_with_higher_attempt():
    bus = InMemoryBus(insecure_dev_mode=True)
    await bus.subscribe("a", [])
    await bus.publish(Message.task(sender="x", recipient="a", objective="retry me"))
    first = await bus.receive("a", timeout=0.2)
    assert first is not None

    await bus.nack("a", first, requeue=True)
    second = await bus.receive("a", timeout=0.2)
    assert second is not None
    assert second.attempt == 1
    assert second.correlation_id == first.correlation_id


async def test_nack_without_requeue_dead_letters():
    bus = InMemoryBus(insecure_dev_mode=True)
    await bus.subscribe("a", [])
    await bus.publish(Message.task(sender="x", recipient="a", objective="doomed"))
    msg = await bus.receive("a", timeout=0.2)
    assert msg is not None

    await bus.nack("a", msg, requeue=False)
    assert bus.dlq == [msg]
    assert await bus.receive("a", timeout=0.05) is None


async def test_unrouted_broadcast_is_counted_not_dropped():
    bus = InMemoryBus(insecure_dev_mode=True)
    await bus.subscribe("a", [])
    await bus.publish(Message.event(sender="a", name="nobody.listens"))
    assert bus.stats["unrouted"] == 1
