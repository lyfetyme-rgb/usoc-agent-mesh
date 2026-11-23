# USOC load tests

These scripts exercise the **real** USOC surfaces. They deliberately do not
invent a `/v1/tasks/dispatch` endpoint: the mesh HTTP service is read-only
(`/health`, `/ready`, admin-only `/diagnostics`) and work enters over the
authenticated Redis bus.

| Script | Target | What it proves |
|---|---|---|
| `k6-health-probe.js` | `/health` and `/ready` through the dashboard proxy or an in-cluster port-forward | proxy token isolation, readiness under HPA scale-out, no browser-visible token |
| `nonce_contention.py` | real `PostgresApprovalStore` (+ optional Redis hot cache) | 10,000 tenant partitions in parallel, same-tenant nonce spends are atomic, replays never execute twice |

## k6: read-only HTTP surface

```powershell
$env:USOC_BASE_URL = "http://127.0.0.1:8090"      # dashboard proxy route
$env:AGENT_HEALTH_TOKEN = "<server-side token only>"
k6 run tests/loadtest/k6-health-probe.js
```

The token is read from the **k6 process environment**, never from a browser,
URL, or bundle. The thresholds mirror a 1% → 10% → 50% → 100% ramp; adjust the
stages to match your rollout. `usoc_ready_failures` counts any non-200.

## Python: tenant partitions and nonce contention

Requires the optional drivers (`pip install -e '.[postgres,redis]'`) and a real
managed Postgres. The script creates one approval per synthetic tenant, decides
it, spends its nonce once, then fires a burst of duplicate spends for a slice of
tenants. Postgres row locks must allow exactly one spend.

```powershell
$env:AGENT_POSTGRES_DSN = "postgresql://user:pass@postgres.internal:5432/usoc"
$env:AGENT_REDIS_URL = "rediss://user:pass@redis.internal:6379/0"
python tests/loadtest/nonce_contention.py --tenants 10000 --concurrency 100 --replay-rate 0.15
```

Output is a single JSON summary: tenant count, per-stage latencies, successful
spends, replay attempts blocked, and unexpected errors. A correct run has
`spends == tenants`, `replays_blocked == replay_attempts`, and `errors == 0`.
Use `--no-cache` to prove that Postgres alone remains authoritative.
