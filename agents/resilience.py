"""Resilience and end-to-end idempotency primitives.

This module is deliberately independent of the mesh, policy and approvals. It
answers three operational questions without ever changing a governance decision:

* when is a dependency too unhealthy to call (circuit breaker);
* how long should a bounded, jittered retry wait (backoff);
* has this exact unit of work already been claimed (idempotency).

All clocks, sleeps and random sources are injectable so behaviour is testable
without wall-clock waits. Failures are reduced to 16-hex reason fingerprints;
no raw error text, payload or secret is retained by the registry.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import random
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Literal

from .task_ledger import reason_fingerprint


class ResilienceError(Exception):
    """Base class for fail-closed resilience outcomes."""

    code = "resilience_error"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.fingerprint = reason_fingerprint(message)


class CircuitOpenError(ResilienceError):
    code = "circuit_open"


class RetryExhausted(ResilienceError):
    code = "retry_exhausted"

    def __init__(self, message: str, *, attempts: int) -> None:
        super().__init__(message)
        self.attempts = attempts


class IdempotencyConflict(ResilienceError):
    code = "idempotency_conflict"


@dataclass(frozen=True)
class Claim:
    """Result of an idempotency claim. ``new`` is the only execution licence."""

    state: Literal["new", "inflight", "completed"]
    new: bool
    completed_digest: str | None = None


class CircuitBreaker:
    """Per-dependency breaker with closed / open / half-open states.

    A closed breaker allows calls. After ``failure_threshold`` failures it
    opens and refuses calls for ``reset_timeout_s``. The first call after that
    window is a half-open probe; a success closes the breaker, a failure reopens
    it for a fresh window. Observation only: no decision here can authorize a
    live action, it merely refuses to attempt one.
    """

    def __init__(
        self,
        *,
        name: str = "dependency",
        failure_threshold: int = 5,
        reset_timeout_s: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be positive")
        if reset_timeout_s <= 0:
            raise ValueError("reset_timeout_s must be positive")
        self.name = name
        self.failure_threshold = failure_threshold
        self.reset_timeout_s = reset_timeout_s
        self._clock = clock
        self._state: Literal["closed", "open", "half_open"] = "closed"
        self._failures = 0
        self._opened_at = 0.0
        self._probe_in_flight = False
        self._last_failure: str | None = None

    @property
    def state(self) -> str:
        # A half-open window is evaluated lazily so tests and idle systems do
        # not need a timer thread to advance the breaker.
        if self._state == "open" and self._clock() - self._opened_at >= self.reset_timeout_s:
            self._state = "half_open"
            self._probe_in_flight = False
        return self._state

    def allow(self) -> bool:
        state = self.state
        if state == "open":
            raise CircuitOpenError(f"{self.name}: circuit open, refusing call")
        if state == "half_open":
            if self._probe_in_flight:
                raise CircuitOpenError(f"{self.name}: half-open probe already in flight")
            self._probe_in_flight = True
            return True
        return True

    def record_success(self) -> None:
        self._state = "closed"
        self._failures = 0
        self._last_failure = None
        self._probe_in_flight = False

    def record_failure(self, error: BaseException | str) -> None:
        self._last_failure = reason_fingerprint(error)
        if self._state == "half_open":
            self._trip()
            return
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._trip()

    def _trip(self) -> None:
        self._state = "open"
        self._opened_at = self._clock()
        self._probe_in_flight = False

    def snapshot(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state,
            "failures": self._failures,
            "last_failure": self._last_failure,
        }


class BreakerRegistry:
    """Named breakers, one per downstream dependency, safe for diagnostics."""

    def __init__(
        self,
        *,
        failure_threshold: int = 5,
        reset_timeout_s: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.reset_timeout_s = reset_timeout_s
        self._clock = clock
        self._breakers: dict[str, CircuitBreaker] = {}

    def get(self, name: str) -> CircuitBreaker:
        breaker = self._breakers.get(name)
        if breaker is None:
            breaker = CircuitBreaker(
                name=name,
                failure_threshold=self.failure_threshold,
                reset_timeout_s=self.reset_timeout_s,
                clock=self._clock,
            )
            self._breakers[name] = breaker
        return breaker

    def snapshot(self) -> dict[str, dict[str, Any]]:
        return {name: breaker.snapshot() for name, breaker in sorted(self._breakers.items())}


def backoff_delay(
    retry_index: int,
    *,
    base_s: float,
    max_s: float,
    jitter: bool = True,
    rng: random.Random | None = None,
) -> float:
    """Exponential delay for ``retry_index`` (0-based), capped and jittered.

    Full jitter is used: a uniformly random value in ``[0, capped]``. This
    decorrelates retries across tenants and avoids synchronized retry storms.
    """
    if retry_index < 0:
        raise ValueError("retry_index must be >= 0")
    if base_s < 0 or max_s < 0:
        raise ValueError("backoff bounds must be non-negative")
    capped = min(max_s, base_s * (2**retry_index))
    if not jitter or capped == 0:
        return capped
    source = rng or random
    return source.uniform(0.0, capped)


async def bounded_retry(
    operation: Callable[[int], Awaitable[Any]],
    *,
    max_attempts: int = 3,
    base_s: float = 0.25,
    max_s: float = 2.0,
    jitter: bool = True,
    rng: random.Random | None = None,
    breaker: CircuitBreaker | None = None,
    sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
    on_attempt: Callable[[int, BaseException | None], None] | None = None,
) -> Any:
    """Call ``operation`` at most ``max_attempts`` times, backing off between tries.

    Only exceptions marked ``retryable`` (or subclasses of ``RetryableError``)
    are retried. An open circuit short-circuits before the first call. Exhaustion
    is reported as ``RetryExhausted`` with an opaque fingerprint so the caller
    can record a ``timed_out`` / ``failed`` state without leaking raw text.
    """
    if max_attempts < 1:
        raise ValueError("max_attempts must be positive")
    if max_s < base_s:
        raise ValueError("max_s must be >= base_s")

    last: BaseException | None = None
    for attempt in range(1, max_attempts + 1):
        if breaker is not None:
            breaker.allow()
        try:
            result = await operation(attempt)
        except Exception as exc:
            last = exc
            retryable = bool(getattr(exc, "retryable", False))
            if on_attempt is not None:
                on_attempt(attempt, exc)
            if breaker is not None:
                breaker.record_failure(exc)
            if not retryable:
                raise
            if attempt == max_attempts:
                break
            await sleep(
                backoff_delay(attempt - 1, base_s=base_s, max_s=max_s, jitter=jitter, rng=rng)
            )
            continue
        if on_attempt is not None:
            on_attempt(attempt, None)
        if breaker is not None:
            breaker.record_success()
        return result

    if last is None:  # pragma: no cover - defensive
        raise RetryExhausted("retry exhausted without an error", attempts=max_attempts)
    raise RetryExhausted(f"{type(last).__name__} after {max_attempts} attempts: {last}", attempts=max_attempts)


def deterministic_idempotency_key(
    *,
    tenant_id: str,
    correlation_id: str,
    agent_id: str,
    step_id: str = "",
    action: str = "",
    payload_digest: str = "",
    secret: str = "",
) -> str:
    """Stable 64-hex execution token for one logical unit of work.

    The key intentionally excludes attempt counters and wall-clock time: a
    network retry of the same tenant/trace/step must map to the same token. An
    HMAC key binds the token to the cluster when a secret is configured; the
    unkeyed digest is only for local/offline development.
    """
    canonical = json.dumps(
        [tenant_id, correlation_id, agent_id, step_id, action, payload_digest],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    if secret:
        return hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    return hashlib.sha256(canonical).hexdigest()


class IdempotencyRegistry:
    """Claim / complete registry with TTL and payload-conflict detection."""

    def __init__(
        self,
        *,
        ttl_s: float = 86_400.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_s <= 0:
            raise ValueError("ttl_s must be positive")
        self.ttl_s = ttl_s
        self._clock = clock
        self._entries: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    def _live(self, key: str) -> dict[str, Any] | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        if self._clock() - entry["created_at"] >= self.ttl_s:
            del self._entries[key]
            return None
        return entry

    async def claim(self, key: str, *, digest: str) -> Claim:
        async with self._lock:
            entry = self._live(key)
            if entry is None:
                self._entries[key] = {
                    "digest": digest,
                    "state": "new",
                    "created_at": self._clock(),
                    "completed_digest": None,
                }
                return Claim(state="new", new=True)
            if entry["digest"] != digest:
                raise IdempotencyConflict(
                    f"idempotency key reused with a different payload ({key[:16]})"
                )
            if entry["state"] == "completed":
                return Claim(
                    state="completed", new=False, completed_digest=entry["completed_digest"]
                )
            return Claim(state="inflight", new=False)

    async def complete(self, key: str, *, digest: str) -> None:
        async with self._lock:
            entry = self._live(key)
            if entry is None:
                return
            entry["state"] = "completed"
            entry["completed_digest"] = digest

    async def release(self, key: str) -> None:
        """Drop an unfinished claim so the next attempt can try again."""
        async with self._lock:
            self._entries.pop(key, None)

    def snapshot(self) -> dict[str, int]:
        expired = [
            key
            for key, entry in self._entries.items()
            if self._clock() - entry["created_at"] >= self.ttl_s
        ]
        for key in expired:
            del self._entries[key]
        return {
            "active": len(self._entries),
            "completed": sum(1 for e in self._entries.values() if e["state"] == "completed"),
        }
