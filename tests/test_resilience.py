"""Resilience primitives: fail-fast breakers, bounded retries, idempotency.

These tests reproduce the failure modes from the production-hardening brief:
an unresponsive dependency must not cascade, retries must be bounded and
jittered, and a replayed request must resolve as an idempotent hit instead of
executing a second time. All clocks and randomness are injected so the tests
are deterministic and offline.
"""

from __future__ import annotations

import asyncio
import random

import pytest

from agents.resilience import (
    CircuitBreaker,
    CircuitOpenError,
    IdempotencyConflict,
    IdempotencyRegistry,
    RetryExhausted,
    backoff_delay,
    bounded_retry,
    deterministic_idempotency_key,
)


class FlakyError(Exception):
    def __init__(self, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable


def test_circuit_breaker_fails_fast_and_recovers_with_injected_clock():
    now = [0.0]
    breaker = CircuitBreaker(failure_threshold=2, reset_timeout_s=10.0, clock=lambda: now[0])

    assert breaker.state == "closed"
    breaker.record_failure(FlakyError("upstream timeout"))
    assert breaker.state == "closed"
    breaker.record_failure(FlakyError("upstream timeout"))
    assert breaker.state == "open"

    with pytest.raises(CircuitOpenError) as exc:
        breaker.allow()
    assert exc.value.code == "circuit_open"
    assert breaker.snapshot()["failures"] == 2

    now[0] = 9.9
    with pytest.raises(CircuitOpenError):
        breaker.allow()
    now[0] = 10.0
    assert breaker.allow() is True
    assert breaker.state == "half_open"

    breaker.record_success()
    assert breaker.state == "closed"
    assert breaker.snapshot()["failures"] == 0


def test_circuit_breaker_reopens_when_half_open_probe_fails():
    now = [0.0]
    breaker = CircuitBreaker(failure_threshold=1, reset_timeout_s=5.0, clock=lambda: now[0])
    breaker.record_failure(FlakyError("down"))
    now[0] = 5.0
    assert breaker.allow() is True
    breaker.record_failure(FlakyError("still down"))
    assert breaker.state == "open"
    # The failed probe starts a fresh window: 9.9s later it is still open.
    now[0] = 9.9
    with pytest.raises(CircuitOpenError):
        breaker.allow()


def test_backoff_is_exponential_bounded_and_jitter_is_injectable():
    rng = random.Random(7)
    exact = [backoff_delay(i, base_s=0.25, max_s=2.0, jitter=False) for i in range(5)]
    assert exact == [0.25, 0.5, 1.0, 2.0, 2.0]

    jittered = [backoff_delay(i, base_s=0.25, max_s=2.0, jitter=True, rng=rng) for i in range(5)]
    assert all(0.0 <= value <= min(2.0, 0.25 * 2**i) for i, value in enumerate(jittered))
    assert jittered != exact


async def test_bounded_retry_stops_at_limit_without_cascading():
    calls: list[int] = []
    sleeps: list[float] = []

    async def operation(attempt: int) -> str:
        calls.append(attempt)
        raise FlakyError("downstream unavailable")

    with pytest.raises(RetryExhausted) as exc:
        await bounded_retry(
            operation,
            max_attempts=3,
            base_s=0.01,
            max_s=0.04,
            jitter=False,
            sleep=lambda delay: sleeps.append(delay) or asyncio.sleep(0),
        )

    assert calls == [1, 2, 3]
    assert sleeps == [0.01, 0.02]
    assert exc.value.code == "retry_exhausted"
    assert exc.value.fingerprint and len(exc.value.fingerprint) == 16


async def test_bounded_retry_returns_first_success_and_skips_non_retryable():
    calls: list[int] = []

    async def flaky(attempt: int) -> str:
        calls.append(attempt)
        if attempt < 2:
            raise FlakyError("transient")
        return "ok"

    assert await bounded_retry(flaky, max_attempts=4, base_s=0.0, jitter=False) == "ok"
    assert calls == [1, 2]

    async def fatal(attempt: int) -> str:
        raise FlakyError("bad request", retryable=False)

    with pytest.raises(FlakyError):
        await bounded_retry(fatal, max_attempts=4, base_s=0.0, jitter=False)


async def test_bounded_retry_respects_an_open_circuit():
    breaker = CircuitBreaker(failure_threshold=1, reset_timeout_s=60.0)
    breaker.record_failure(FlakyError("down"))

    async def operation(attempt: int) -> str:
        pytest.fail("operation must not run while the circuit is open")

    with pytest.raises(CircuitOpenError):
        await bounded_retry(operation, max_attempts=3, base_s=0.0, breaker=breaker)


def test_idempotency_key_is_deterministic_tenant_scoped_and_keyed():
    fields = dict(
        tenant_id="tenant-a",
        correlation_id="trace-123",
        agent_id="oekp",
        step_id="s1",
        action="execute",
        payload_digest="abc123",
    )
    key = deterministic_idempotency_key(secret="cluster-secret", **fields)
    assert key == deterministic_idempotency_key(secret="cluster-secret", **fields)
    assert len(key) == 64
    assert deterministic_idempotency_key(secret="other-secret", **fields) != key
    assert deterministic_idempotency_key(secret="cluster-secret", **{**fields, "tenant_id": "tenant-b"}) != key
    assert deterministic_idempotency_key(secret="cluster-secret", **{**fields, "step_id": "s2"}) != key


async def test_idempotency_registry_deduplicates_and_detects_conflicts():
    now = [0.0]
    registry = IdempotencyRegistry(ttl_s=30.0, clock=lambda: now[0])

    claim = await registry.claim("key-1", digest="digest-a")
    assert claim.state == "new" and claim.completed_digest is None
    duplicate = await registry.claim("key-1", digest="digest-a")
    assert duplicate.state == "inflight" and duplicate.new is False

    with pytest.raises(IdempotencyConflict):
        await registry.claim("key-1", digest="digest-b")

    await registry.complete("key-1", digest="digest-a")
    replay = await registry.claim("key-1", digest="digest-a")
    assert replay.state == "completed" and replay.new is False

    now[0] = 31.0
    expired = await registry.claim("key-1", digest="digest-a")
    assert expired.state == "new"

    assert registry.snapshot()["active"] == 1
