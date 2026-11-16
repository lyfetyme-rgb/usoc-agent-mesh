"""Transport.

``Bus`` is the only thing the runtime knows about. Two adapters ship:

``InMemoryBus``
    One process, no infra. Every subscriber gets its own asyncio queue, so
    publish never blocks on a slow agent. Used by the demo and the tests.

``RedisBus``
    Redis Streams with one consumer group per agent. Durable across restarts,
    multiple workers can share an agent id, and unacked messages stay in the
    pending list. This is the adapter you deploy.

Delivery contract: at-least-once. Agents therefore use ``idempotency_key``
for anything with side effects.
"""

from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from fnmatch import fnmatchcase
from typing import Any, Protocol, runtime_checkable

from .contracts import Message
from .observability import log
from .security import Signer

STREAM_PREFIX = "mesh:"

# Wildcards are control-plane conveniences, not domain-agent features. Only the
# orchestrator may publish with a pattern, and only the audit sink may subscribe
# to a topic.* pattern. Everyone else must enumerate exact topics.
CONTROL_PLANE_AGENTS = frozenset({"orchestrator"})
AUDIT_SINK_AGENTS = frozenset({"oekp"})
WILDCARD_CHARS = ("*", "?", "[")


class ConfigurationError(ValueError):
    """Raised when the bus is constructed without required ACL configuration."""


def has_wildcard(pattern: str) -> bool:
    return any(char in pattern for char in WILDCARD_CHARS)


def validate_topic_acls(
    *,
    publish_acl: dict[str, list[str]] | None,
    subscribe_acl: dict[str, list[str]] | None,
    signer: Signer | None,
    control_agents: frozenset[str] = CONTROL_PLANE_AGENTS,
    audit_sinks: frozenset[str] = AUDIT_SINK_AGENTS,
) -> None:
    """Reject wildcard ACLs that would defeat least-privilege routing.

    Rules:
    * A domain agent may not publish to a pattern (it would reach arbitrary
      inboxes/topics). Only control-plane identities may use publish patterns.
    * A domain agent may not subscribe to a pattern. Only the audit sink may,
      and only under ``topic.*``.
    * An audit-sink wildcard requires message authentication: an unauthenticated
      sink must never be able to observe every broadcast.
    """
    for agent, patterns in (publish_acl or {}).items():
        for pattern in patterns:
            if has_wildcard(pattern) and agent not in control_agents:
                raise ConfigurationError(
                    f"agent {agent!r} may not use a wildcard publish pattern "
                    f"({pattern!r}); enumerate exact topics"
                )

    wildcard_subscription = False
    for agent, patterns in (subscribe_acl or {}).items():
        for pattern in patterns:
            if not has_wildcard(pattern):
                continue
            wildcard_subscription = True
            if agent not in audit_sinks:
                raise ConfigurationError(
                    f"agent {agent!r} may not use a wildcard subscribe pattern "
                    f"({pattern!r}); only audit sinks may subscribe broadly"
                )
            if not pattern.startswith("topic."):
                raise ConfigurationError(
                    f"audit sink {agent!r} wildcard subscription must be scoped "
                    f"to topic.* (got {pattern!r})"
                )
    if wildcard_subscription and signer is None:
        raise ConfigurationError(
            "wildcard audit subscriptions require message authentication; "
            "configure AGENT_SHARED_SECRET or disable the wildcard subscription"
        )


def acls_from_specs(
    specs: list[Any],
    *,
    control_agents: frozenset[str] = CONTROL_PLANE_AGENTS,
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Build least-privilege topic ACLs from capability cards.

    Domain agents may publish only to exact ``inbox.<recipient>`` topics they
    are authorized for (their declared recipients plus the control plane), and
    subscribe only to the exact topics on their card. The control plane may
    publish to every subsystem inbox plus its own plan/goal event topics.
    """
    ids = {str(spec.id) for spec in specs}
    publish: dict[str, list[str]] = {}
    subscribe: dict[str, list[str]] = {}
    for spec in specs:
        recipients = {str(r) for r in (getattr(spec, "allowed_recipients", None) or [])}
        recipients |= control_agents
        topics = {f"inbox.{r}" for r in recipients if r in ids or r in control_agents}
        publish[str(spec.id)] = sorted(topics)
        subscribe[str(spec.id)] = [str(t) for t in (getattr(spec, "subscribes", None) or [])]
    for control in control_agents:
        publish[control] = sorted({f"inbox.{agent}" for agent in ids | {control}} | {"topic.plan", "topic.goal"})
        subscribe.setdefault(control, [])
    return publish, subscribe


@runtime_checkable
class Bus(Protocol):
    async def subscribe(self, agent: str, topics: list[str]) -> None: ...
    async def publish(self, msg: Message) -> None: ...
    async def receive(self, agent: str, timeout: float) -> Message | None: ...
    async def ack(self, agent: str, msg: Message) -> None: ...
    async def nack(self, agent: str, msg: Message, *, requeue: bool) -> None: ...
    async def close(self) -> None: ...

    @property
    def history(self) -> list[Message]: ...


def _bump(msg: Message) -> Message:
    """Re-publish as a fresh message: new id, higher attempt, same correlation."""
    data = msg.model_dump()
    data["id"] = _new_id()
    data["attempt"] = msg.attempt + 1
    return Message(**data)


def _new_id() -> str:
    from uuid import uuid4

    return uuid4().hex


class InMemoryBus:
    """Fan-out queues with per-agent backpressure and a dead-letter list."""

    def __init__(
        self,
        max_queue: int = 1_000,
        *,
        signer: Signer | None = None,
        publish_acl: dict[str, list[str]] | None = None,
        subscribe_acl: dict[str, list[str]] | None = None,
        insecure_dev_mode: bool = False,
        sender_verifier: Any = None,
    ) -> None:
        self._queues: dict[str, asyncio.Queue[Message]] = {}
        self._patterns: dict[str, list[str]] = defaultdict(list)
        self._max_queue = max_queue
        self.signer = signer
        self.publish_acl = publish_acl
        self.subscribe_acl = subscribe_acl
        self.insecure_dev_mode = insecure_dev_mode
        self.sender_verifier = sender_verifier
        validate_topic_acls(
            publish_acl=publish_acl,
            subscribe_acl=subscribe_acl,
            signer=signer,
        )
        self.history: list[Message] = []
        self.dlq: list[Message] = []
        self.stats: dict[str, int] = defaultdict(int)

    async def subscribe(self, agent: str, topics: list[str]) -> None:
        if self.subscribe_acl is None:
            if not self.insecure_dev_mode:
                raise PermissionError("subscribe denied: no subscribe_acl configured (set insecure_dev_mode=True for dev)")
        else:
            allowed = self.subscribe_acl.get(agent, [])
            for t in topics:
                if has_wildcard(t) and agent not in AUDIT_SINK_AGENTS:
                    raise PermissionError(
                        f"{agent} may not subscribe to wildcard topic {t!r}; "
                        "only audit sinks may subscribe broadly"
                    )
                if not any(fnmatchcase(t, p) for p in allowed):
                    raise PermissionError(f"{agent} is not allowed to subscribe to {t}")
        if agent not in self._queues:
            self._queues[agent] = asyncio.Queue(maxsize=self._max_queue)
        patterns = [f"inbox.{agent}", *topics]
        self._patterns[agent] = list(dict.fromkeys(patterns))

    def _subscribers(self, topic: str) -> list[str]:
        return [a for a, pats in self._patterns.items() if any(fnmatchcase(topic, p) for p in pats)]

    async def publish(self, msg: Message) -> None:
        if self.sender_verifier is not None and not self.sender_verifier(msg.sender, msg):
            self.stats["sender_rejected"] = self.stats.get("sender_rejected", 0) + 1
            log("bus.sender_rejected", sender=msg.sender, topic=msg.topic)
            raise PermissionError(f"sender {msg.sender} failed identity verification")
        if has_wildcard(msg.topic):
            raise PermissionError("publish topic must be concrete, not a wildcard pattern")
        if self.publish_acl is None:
            if not self.insecure_dev_mode:
                self.stats["acl_denied"] += 1
                log("bus.acl_denied", sender=msg.sender, topic=msg.topic, reason="no acl configured")
                raise PermissionError("publish denied: no publish_acl configured (set insecure_dev_mode=True for dev)")
        else:
            allowed = self.publish_acl.get(msg.sender, [])
            if not any(fnmatchcase(msg.topic, p) for p in allowed):
                self.stats["acl_denied"] += 1
                log("bus.acl_denied", sender=msg.sender, topic=msg.topic)
                raise PermissionError(f"{msg.sender} is not allowed to publish to {msg.topic}")
        if self.signer is not None:
            msg = self.signer.sign_message(msg)
        self.history.append(msg)
        self.stats["published"] += 1
        targets = self._subscribers(msg.topic)
        if not targets:
            self.stats["unrouted"] += 1
        for agent in targets:
            q = self._queues[agent]
            try:
                q.put_nowait(msg)
                self.stats["delivered"] += 1
            except asyncio.QueueFull:
                # Backpressure: dropping is worse than blocking the publisher,
                # but a stuck agent must not stall the mesh. Dead-letter it.
                self.dlq.append(msg)
                self.stats["overflow"] += 1
                log("bus.overflow", agent=agent, topic=msg.topic)

    async def receive(self, agent: str, timeout: float) -> Message | None:
        q = self._queues.get(agent)
        if q is None:
            return None
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(0.0, timeout)
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                # Still allow one queued item when timeout is zero.
                if timeout > 0:
                    return None
                try:
                    msg = q.get_nowait()
                except asyncio.QueueEmpty:
                    return None
            else:
                try:
                    msg = await asyncio.wait_for(q.get(), remaining)
                except (asyncio.TimeoutError, TimeoutError):
                    return None
            if self.signer is None:
                return msg
            ok, detail = self.signer.verify_message(msg)
            if ok:
                return msg
            self.stats["rejected"] += 1
            self.dlq.append(msg)
            log("bus.rejected", agent=agent, reason=detail, sender=msg.sender, topic=msg.topic)
            if timeout <= 0:
                return None

    async def backlog(self) -> dict[str, int]:
        """Number of queued-but-undelivered messages per agent."""
        return {agent: queue.qsize() for agent, queue in self._queues.items()}

    async def ack(self, agent: str, msg: Message) -> None:
        self.stats["acked"] += 1

    async def nack(self, agent: str, msg: Message, *, requeue: bool) -> None:
        if requeue:
            await self.publish(_bump(msg))
        else:
            self.dlq.append(msg)
            self.stats["dead_lettered"] += 1
            log("bus.dead_letter", agent=agent, message=msg.summary())

    async def drain(self) -> int:
        """Wait until every queue is empty. Tests use this instead of sleeping."""
        while any(not q.empty() for q in self._queues.values()):
            await asyncio.sleep(0.01)
        return sum(q.qsize() for q in self._queues.values())

    async def ping(self) -> bool:
        return True

    async def close(self) -> None:
        return None


class RedisBus:
    """Redis Streams: one stream per topic, one consumer group per agent."""

    def __init__(
        self,
        url: str,
        group: str = "mesh",
        consumer: str | None = None,
        maxlen: int = 10_000,
        *,
        signer: Signer | None = None,
        socket_timeout_s: float = 5.0,
        publish_acl: dict[str, list[str]] | None = None,
        subscribe_acl: dict[str, list[str]] | None = None,
        insecure_dev_mode: bool = False,
        sender_verifier: Any = None,
    ) -> None:
        import redis.asyncio as aioredis

        self._redis = aioredis.from_url(
            url,
            decode_responses=True,
            socket_timeout=socket_timeout_s,
            socket_connect_timeout=socket_timeout_s,
            health_check_interval=30,
            retry_on_timeout=True,
        )
        self._group = group
        self._consumer = consumer or f"worker-{_new_id()[:8]}"
        self._streams: dict[str, list[str]] = defaultdict(list)
        self._inflight: dict[str, str] = {}
        self._maxlen = maxlen
        self.signer = signer
        self.publish_acl = publish_acl
        self.subscribe_acl = subscribe_acl
        self.insecure_dev_mode = insecure_dev_mode
        self.sender_verifier = sender_verifier
        validate_topic_acls(
            publish_acl=publish_acl,
            subscribe_acl=subscribe_acl,
            signer=signer,
        )
        self._history: list[Message] = []
        self.stats: dict[str, int] = defaultdict(int)
        self.dlq_stream = f"{STREAM_PREFIX}dlq"

    @property
    def history(self) -> list[Message]:
        return self._history

    def _stream(self, topic: str) -> str:
        return f"{STREAM_PREFIX}{topic}"

    async def subscribe(self, agent: str, topics: list[str]) -> None:
        if self.subscribe_acl is None:
            if not self.insecure_dev_mode:
                raise PermissionError("subscribe denied: no subscribe_acl configured (set insecure_dev_mode=True for dev)")
        else:
            allowed = self.subscribe_acl.get(agent, [])
            for t in topics:
                if has_wildcard(t) and agent not in AUDIT_SINK_AGENTS:
                    raise PermissionError(
                        f"{agent} may not subscribe to wildcard topic {t!r}; "
                        "only audit sinks may subscribe broadly"
                    )
                if not any(fnmatchcase(t, p) for p in allowed):
                    raise PermissionError(f"{agent} is not allowed to subscribe to {t}")
        streams = [self._stream(f"inbox.{agent}")]
        for topic in topics:
            if "*" in topic:
                async for key in self._redis.scan_iter(match=self._stream(topic)):
                    streams.append(key)
            else:
                streams.append(self._stream(topic))
        # One group per agent: two agents may read the same topic independently.
        group = f"{self._group}:{agent}"
        for stream in dict.fromkeys(streams):
            try:
                await self._redis.xgroup_create(stream, group, id="0", mkstream=True)
            except Exception as exc:  # BUSYGROUP == already created
                if "BUSYGROUP" not in str(exc):
                    raise
        self._streams[agent] = list(dict.fromkeys(streams))

    async def publish(self, msg: Message) -> None:
        if self.sender_verifier is not None and not self.sender_verifier(msg.sender, msg):
            self.stats["sender_rejected"] = self.stats.get("sender_rejected", 0) + 1
            log("bus.sender_rejected", sender=msg.sender, topic=msg.topic)
            raise PermissionError(f"sender {msg.sender} failed identity verification")
        if has_wildcard(msg.topic):
            raise PermissionError("publish topic must be concrete, not a wildcard pattern")
        if self.publish_acl is None:
            if not self.insecure_dev_mode:
                self.stats["acl_denied"] += 1
                log("bus.acl_denied", sender=msg.sender, topic=msg.topic, reason="no acl configured")
                raise PermissionError("publish denied: no publish_acl configured (set insecure_dev_mode=True for dev)")
        else:
            allowed = self.publish_acl.get(msg.sender, [])
            if not any(fnmatchcase(msg.topic, p) for p in allowed):
                self.stats["acl_denied"] += 1
                log("bus.acl_denied", sender=msg.sender, topic=msg.topic)
                raise PermissionError(f"{msg.sender} is not allowed to publish to {msg.topic}")
        if self.signer is not None:
            msg = self.signer.sign_message(msg)
        self._history.append(msg)
        self.stats["published"] += 1
        await self._redis.xadd(
            self._stream(msg.topic),
            {"msg": msg.model_dump_json()},
            maxlen=self._maxlen,
            approximate=True,
        )

    async def receive(self, agent: str, timeout: float) -> Message | None:
        streams = self._streams.get(agent)
        if not streams:
            return None
        if len(self._history) > self._maxlen:
            del self._history[: -self._maxlen]
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(0.0, timeout)
        group = f"{self._group}:{agent}"
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0 and timeout > 0:
                return None
            block_ms = max(1, int(max(0.001, remaining) * 1000)) if remaining > 0 else 1
            resp = await self._redis.xreadgroup(
                group,
                self._consumer,
                {s: ">" for s in streams},
                count=1,
                block=block_ms,
            )
            if not resp:
                return None
            stream, entries = resp[0]
            if not entries:
                return None
            raw_id, fields = entries[0]
            msg = Message.model_validate_json(fields["msg"])
            if self.signer is not None:
                ok, detail = self.signer.verify_message(msg)
                if not ok:
                    # Never process an unauthenticated message: ack and quarantine.
                    await self._redis.xack(stream, group, raw_id)
                    await self._redis.xadd(
                        self.dlq_stream,
                        {"msg": msg.model_dump_json(), "reason": detail},
                        maxlen=self._maxlen,
                        approximate=True,
                    )
                    self.stats["rejected"] += 1
                    log("bus.rejected", agent=agent, reason=detail, sender=msg.sender, topic=msg.topic)
                    continue
            # Broker id is needed to ack later; key it by message id.
            self._inflight[msg.id] = raw_id
            self.stats["delivered"] += 1
            return msg

    async def backlog(self) -> dict[str, int]:
        """Pending messages per subscribed agent (per its consumer group).

        Demand signal for scaling: pending entries that no replica has
        acknowledged yet, summed across the streams this bus tracks.
        """
        out: dict[str, int] = {}
        for agent, streams in self._streams.items():
            total = 0
            for stream in streams:
                try:
                    info = await self._redis.xinfo_groups(stream)
                except Exception:
                    info = []
                for g in info:
                    if isinstance(g, dict) and g.get("name") == f"{self._group}:{agent}":
                        total += int(g.get("pending", 0) or 0)
                        break
            out[agent] = total
        return out

    async def ack(self, agent: str, msg: Message) -> None:
        stream_id = self._inflight.pop(msg.id, None)
        if stream_id:
            await self._redis.xack(self._stream(msg.topic), f"{self._group}:{agent}", stream_id)
            self.stats["acked"] += 1

    async def nack(self, agent: str, msg: Message, *, requeue: bool) -> None:
        stream_id = self._inflight.pop(msg.id, None)
        if stream_id:
            await self._redis.xack(self._stream(msg.topic), f"{self._group}:{agent}", stream_id)
        if requeue:
            await self.publish(_bump(msg))
        else:
            await self._redis.xadd(self.dlq_stream, {"msg": msg.model_dump_json()}, maxlen=self._maxlen, approximate=True)
            self.stats["dead_lettered"] += 1

    async def reclaim_stale(self, agent: str, min_idle_ms: int = 60_000) -> int:
        """Recover messages a crashed worker left pending.

        Claimed entries are re-published with a higher attempt and the original
        entry is acked. Returning the count without re-publishing would strand
        the work forever, because ``receive`` only reads the ``>`` cursor.
        """
        recovered = 0
        group = f"{self._group}:{agent}"
        for stream in self._streams.get(agent, []):
            resp = await self._redis.xautoclaim(
                stream,
                group,
                self._consumer,
                min_idle_time=min_idle_ms,
                start_id="0-0",
                count=50,
            )
            entries = resp[1] if resp and len(resp) > 1 else []
            for raw_id, fields in entries:
                if not fields or "msg" not in fields:
                    await self._redis.xack(stream, group, raw_id)
                    continue
                try:
                    msg = Message.model_validate_json(fields["msg"])
                except ValueError as exc:
                    log("bus.reclaim_invalid", stream=stream, error=repr(exc))
                    await self._redis.xack(stream, group, raw_id)
                    continue
                await self.publish(_bump(msg))
                await self._redis.xack(stream, group, raw_id)
                recovered += 1
        if recovered:
            self.stats["reclaimed"] += recovered
            log("bus.reclaimed", agent=agent, count=recovered)
        return recovered

    async def ping(self) -> bool:
        return bool(await self._redis.ping())

    async def close(self) -> None:
        await self._redis.aclose()


def build_bus(
    settings: Any,
    consumer: str | None = None,
    *,
    signer: Signer | None = None,
    publish_acl: dict[str, list[str]] | None = None,
    subscribe_acl: dict[str, list[str]] | None = None,
    insecure_dev_mode: bool = False,
    sender_verifier: Any = None,
) -> Bus:
    if publish_acl is None and subscribe_acl is None and not insecure_dev_mode:
        raise ConfigurationError(
            "build_bus requires publish_acl/subscribe_acl in production; "
            "pass insecure_dev_mode=True only for development"
        )
    if settings.bus == "redis":
        return RedisBus(
            settings.redis_url,
            group=settings.consumer_group,
            consumer=consumer,
            signer=signer,
            socket_timeout_s=settings.redis_socket_timeout_s,
            publish_acl=publish_acl,
            subscribe_acl=subscribe_acl,
            insecure_dev_mode=insecure_dev_mode,
            sender_verifier=sender_verifier,
        )
    return InMemoryBus(
        signer=signer,
        publish_acl=publish_acl,
        subscribe_acl=subscribe_acl,
        insecure_dev_mode=insecure_dev_mode,
        sender_verifier=sender_verifier,
    )
