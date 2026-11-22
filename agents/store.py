"""Small state/idempotency store.

The bus is at-least-once, so an agent that sends email or writes a file must be
able to recognise a redelivered task. Key on ``TaskSpec.idempotency_key`` (or a
hash of the task) and short-circuit with the stored result.
"""

from __future__ import annotations

import json
import time
from typing import Any, Protocol


class StateStore(Protocol):
    async def get(self, key: str) -> Any | None: ...
    async def set(self, key: str, value: Any, ttl_s: float | None = None) -> None: ...
    async def close(self) -> None: ...


class InMemoryStore:
    def __init__(self) -> None:
        self._data: dict[str, tuple[Any, float | None]] = {}

    async def get(self, key: str) -> Any | None:
        item = self._data.get(key)
        if item is None:
            return None
        value, expires = item
        if expires is not None and time.monotonic() > expires:
            self._data.pop(key, None)
            return None
        return value

    async def set(self, key: str, value: Any, ttl_s: float | None = None) -> None:
        # Expired keys are otherwise never revisited when a task is unique:
        # get() is only called on a redelivery. Sweep opportunistically here so
        # a long-running process does not accumulate one entry per executed task.
        now = time.monotonic()
        expired = [k for k, (_, expires) in self._data.items() if expires is not None and now > expires]
        for k in expired:
            self._data.pop(k, None)
        self._data[key] = (value, None if ttl_s is None else now + ttl_s)

    async def close(self) -> None:
        self._data.clear()


class RedisStore:
    def __init__(
        self,
        url: str,
        prefix: str = "mesh:state:",
        *,
        socket_timeout_s: float = 5.0,
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
        self._prefix = prefix

    async def get(self, key: str) -> Any | None:
        raw = await self._redis.get(self._prefix + key)
        return None if raw is None else json.loads(raw)

    async def set(self, key: str, value: Any, ttl_s: float | None = None) -> None:
        await self._redis.set(
            self._prefix + key, json.dumps(value, default=str), px=int(ttl_s * 1000) if ttl_s else None
        )

    async def close(self) -> None:
        await self._redis.aclose()
