"""Multi-tenant / nonce-contention load harness for the real approval backend.

This drives the same transaction path the mesh uses in production. It does not
call an HTTP dispatch API (there is none): approvals are requested, decided and
consumed through ``PostgresApprovalStore``. Redis is used only as the hot cache
the mesh configures; disable it with ``--no-cache`` to prove Postgres alone is
authoritative.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import time
import uuid

from agents.config import Settings
from agents.contracts import ActionClass, RiskLevel
from agents.governance import ApprovalRequest
from agents.postgres import PostgresApprovalStore, PsycopgBackend
from agents.security import build_signer


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(fraction * (len(ordered) - 1) + 0.5))
    return round(ordered[index], 2)


async def run(args: argparse.Namespace) -> dict:
    dsn = args.dsn or os.environ.get("AGENT_POSTGRES_DSN")
    if not dsn:
        raise SystemExit("provide --dsn or AGENT_POSTGRES_DSN")
    settings = Settings(_env_file=None, shared_secret=os.environ.get("AGENT_SHARED_SECRET"))
    signer = build_signer(settings)
    backend = PsycopgBackend(dsn)
    cache = None
    if not args.no_cache:
        try:
            import redis.asyncio as aioredis

            cache = aioredis.Redis.from_url(
                args.redis_url or settings.redis_url,
                decode_responses=True,
                socket_timeout=settings.redis_socket_timeout_s,
            )
        except ImportError:
            print("redis extra not installed; falling back to Postgres-only")
    approvals = PostgresApprovalStore(
        backend,
        cache=cache,
        signer=signer,
        approvers={"loadtest-approver"},
        require_allowlist=True,
        cache_ttl_s=2.0,
    )

    semaphore = asyncio.Semaphore(args.concurrency)
    run_id = uuid.uuid4().hex[:8]
    latencies: list[float] = []
    counts = {
        "tenants": 0,
        "spends": 0,
        "replay_attempts": 0,
        "replays_blocked": 0,
        "errors": 0,
    }

    async def one_tenant(index: int) -> None:
        async with semaphore:
            tenant = f"loadtest-{run_id}-{index:06d}"
            approval_id = f"lt-{run_id}-{index}"
            try:
                issued = await approvals.request(
                    ApprovalRequest(
                        id=approval_id,
                        tenant_id=tenant,
                        action_class=ActionClass.EXECUTE,
                        target="sandbox/loadtest",
                        risk=RiskLevel.LOW,
                        requested_by="loadtest",
                    )
                )
                await approvals.decide(
                    approval_id,
                    tenant_id=tenant,
                    approved=True,
                    approver="loadtest-approver",
                )
                started = time.perf_counter()
                spent = await approvals.consume(
                    approval_id,
                    tenant_id=tenant,
                    nonce=issued.nonce,
                    correlation_id=f"trace-{run_id}-{index}",
                )
                latencies.append((time.perf_counter() - started) * 1000)
                if spent is None:
                    return
                counts["spends"] += 1

                if random.random() < args.replay_rate:
                    burst = await asyncio.gather(
                        *(
                            approvals.consume(
                                approval_id,
                                tenant_id=tenant,
                                nonce=issued.nonce,
                                correlation_id=f"replay-{run_id}-{index}-{n}",
                            )
                            for n in range(args.replay_burst)
                        ),
                        return_exceptions=True,
                    )
                    counts["replay_attempts"] += args.replay_burst
                    counts["replays_blocked"] += sum(
                        1 for result in burst if result is None
                    )
                counts["tenants"] += 1
            except Exception as exc:  # counted, never fatal for the whole run
                counts["errors"] += 1
                if counts["errors"] <= 3:
                    print(f"tenant {tenant} failed: {type(exc).__name__}: {exc}")

    started = time.perf_counter()
    await asyncio.gather(*(one_tenant(i) for i in range(args.tenants)))
    elapsed = time.perf_counter() - started

    try:
        await backend.close()
    finally:
        if cache is not None:
            await cache.aclose()

    return {
        "protocol_version": "usoc-loadtest/v1",
        "backend": "postgres" + ("+redis-cache" if cache is not None else ""),
        "seconds": round(elapsed, 2),
        **counts,
        "latency_ms": {
            "p50": _percentile(latencies, 0.50),
            "p95": _percentile(latencies, 0.95),
            "p99": _percentile(latencies, 0.99),
        },
        "passed": (
            counts["errors"] == 0
            and counts["spends"] == args.tenants
            and counts["replays_blocked"] == counts["replay_attempts"]
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn", default=None, help="Postgres DSN (or AGENT_POSTGRES_DSN)")
    parser.add_argument("--redis-url", default=None, help="Redis URL (or AGENT_REDIS_URL)")
    parser.add_argument("--tenants", type=int, default=10_000)
    parser.add_argument("--concurrency", type=int, default=100)
    parser.add_argument("--replay-rate", type=float, default=0.15)
    parser.add_argument("--replay-burst", type=int, default=4)
    parser.add_argument("--no-cache", action="store_true", help="bypass the Redis hot cache")
    args = parser.parse_args()
    if args.tenants < 1 or args.concurrency < 1:
        parser.error(" tenants and concurrency must be positive")
    if not 0.0 <= args.replay_rate <= 1.0:
        parser.error("--replay-rate must be between 0 and 1")
    print(json.dumps(asyncio.run(run(args)), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
