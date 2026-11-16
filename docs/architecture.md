# USOC Agent Mesh Architecture

This document describes the implemented skeleton of the USOC multi-agent
architecture: nine subsystem coordinators on a typed message bus, a deterministic
governance gate, human approvals, and an append-only evidence chain.

The conceptual baseline is the USOC master architecture: **9 subsystems, 93
logical subsystem roles, plus 7 SHELL roles (100 logical agents)**. The
implementation decision is to run **one coordinator per subsystem** and treat the
roles as declared capabilities. See [§11](#11-roles-vs-runtime-workers).

## 1. Topology

```
                         +---------------------------------------+
   goal ---------------> | Orchestrator                          |
                         | plan -> validate -> dispatch waves    |
                         +-------------------+-------------------+
                                             |
          publish typed envelope             |        receive inbox.<id>
   +----------+----------+----------+--------+--------+----------+----------+
   |          |          |          |        |        |          |          |
 AICEE      ACIE     SERAPHIM    COHESION  BENGAL   CSSSF      OEKP   CYBER DEFENSE
                                                                       HITL
   +----------+----------+----------+--------+--------+----------+----------+
                     peer-to-peer delegate() / ask()
```

Three planes:

| plane | owner | responsibility |
|---|---|---|
| control | Orchestrator | turn a goal into a DAG, assign owners, run waves, aggregate |
| data | subsystem agents | domain work; can call peers directly |
| governance | PolicyEngine, ApprovalStore, EvidenceChain | authorize, gate, record |
| transport | Bus | at-least-once delivery, broadcast, dead letters |

The orchestrator is deliberately *not* an agent. It has no capability card and
does no domain work, so "who plans" and "who executes" have separate failure
modes.

SHELL is not a domain agent either. Its seven roles are platform functions:

| SHELL role | implementation |
|---|---|
| Service Discovery | `registry.py`, `Shell.discovery()` |
| Communication Routing | `bus.py` (`inbox.*`, `topic.*`) |
| Workflow Lifecycle | `orchestrator.py` |
| Contract Validation | `contracts.py` (pydantic, `extra="forbid"`) |
| Runtime Health | `shell.py::health`, `python -m agents health` |
| Configuration Coordination | `config.py`, `subsystems.yaml` |
| Integration Diagnostics | `shell.py::diagnostics` |

## 2. The operational workflow

The master prompt defines twelve steps. The skeleton supports all of them as
agents; the planner selects the subset a goal needs.

| step | owner | status in this repo |
|---|---|---|
| 1 Observation | ACIE | implemented as coordinator |
| 2 Intelligence | AICEE | implemented as coordinator |
| 3 Mission interpretation | COHESION | implemented as coordinator |
| 4 Security analysis | CYBER DEFENSE | implemented, defensive-only screen |
| 5 Risk and policy evaluation | SERAPHIM + PolicyEngine | deterministic, implemented |
| 6 Simulation | CSSSF | implemented as coordinator |
| 7 Independent assurance | BENGAL | deterministic evidence verification |
| 8 Human authorization | HITL + ApprovalStore | implemented, file-backed |
| 9 Controlled execution | runtime + target allowlist | implemented, bounded |
| 10 Independent validation | BENGAL | evidence chain verification |
| 11 Evidence preservation | OEKP + EvidenceChain | append-only, hash-chained |
| 12 Controlled improvement | AICEE | proposal-only path |

The demo goal exercises steps 1, 2, 5 and 11. The governance tests exercise
steps 5, 8, 9 and 11, including approval replay and denial paths.

## 3. Message lifecycle

```
caller                     bus                    callee
  |                         |                        |
  |-- TaskSpec (task) ----->|                        |
  |   corr=C, hop=h         |---- deliver ---------->|
  |                         |                        | validate schema
  |                         |                        | deadline / hop / attempt
  |                         |                        | governance gate
  |                         |                        |   ALLOW -> handle_task
  |                         |                        |   HOLD  -> Handoff
  |                         |                        |   DENY  -> Failure
  |                         |                        | idempotency lookup
  |<-- TaskResult (result) -|<---- publish ----------|
  |   corr=C, hop=h         |                        |
  |   policy/auth/evidence  |                        |
  |   refs attached         |                        |
```

Every message carries:

| field | why |
|---|---|
| `id` | unique per delivery |
| `correlation_id` | one goal/task tree; the request/response key |
| `causation_id` | which message caused this one (audit, traces) |
| `sender` / `recipient` | routing; `recipient` null for broadcasts |
| `topic` | `inbox.<agent>` or `topic.<name>` |
| `payload` | discriminated union, validated on both ends |
| `hop` | delegations so far; hard cap 8 |
| `attempt` | redelivery count; drives retry and dead-lettering |
| `deadline` | absolute UTC; expired work is refused, not run |
| `schema_version` | contract evolution without guesswork |
| `mission_id` | mission contract binding |
| `tenant_id` | tenant isolation |
| `classification` | public / internal / confidential / restricted |
| `policy_decision_ref` | which policy decision authorized this message |
| `authorization_ref` | scoped, short-lived authorization artifact |
| `evidence_ref` | OEKP record for this decision or result |

The payload union: `TaskSpec`, `TaskResult`, `Query`, `QueryReply`, `Event`,
`Failure`, `Handoff`. `extra="forbid"` everywhere, so an accidental field is a
test failure rather than silent drift.

## 4. Governance gate

The gate runs inside `BaseAgent._on_task`, before idempotency and before any
model call.

```
TaskSpec
   |
   | action_class in {execute, contain}?
   +-- no --> ordinary work, no gate
   |
   +-- yes --> CYBER DEFENSE intent screen
                 | prohibited -> DENY
                 v
              PolicyEngine.evaluate
                 |
        +--------+---------+----------+-----------+
        |                  |          |           |
      DENY               HOLD       ALLOW      (never)
   Failure          Handoff +     run handler,
   to caller        approval id   attach refs
```

`PolicyEngine` is deterministic Python. It has no model, no network and no
exception for urgency. An LLM cannot turn a DENY into an ALLOW.

### Decision matrix

| condition | decision |
|---|---|
| `read_only` / `recommend` / `simulate` | **ALLOW** — no approval needed |
| governed action without an explicit target | **DENY** |
| target outside `AGENT_ALLOWED_TARGETS` | **DENY** |
| `restricted` data without a `mission_id` | **DENY** |
| governed action, no approval reference | **HOLD** — approval request created |
| approval still pending | **HOLD** |
| approval denied | **DENY** |
| approval has expired since it was decided | **DENY** |
| approval does not cover this action, target and mission | **DENY** |
| approval approved and covering | **ALLOW** + authorization ref (TTL 900 s) |
| CYBER DEFENSE prohibited intent | **DENY** before the model runs |

Default allowlist: `sandbox/*,staging/*`. An approval for `sandbox/node-1`
cannot be replayed against `sandbox/node-2` or `prod/db-primary`; a wildcard
approval target does not authorize concrete hosts, and an approval expires
`AGENT_APPROVAL_TTL_S` after it was decided.

### Approval lifecycle

```
agent          policy engine        approval store          human
  |                  |                     |                  |
  |-- execute ------>|                     |                  |
  |                  |-- create request -->|                  |
  |<-- HOLD ---------|                     |                  |
  |-- Handoff (apr-id) ------------------------------> 
  |                                        |<-- approve -----|
  |-- re-dispatch with approval_ref ------>|                  |
  |                  |-- load + match ---->|                  |
  |<-- ALLOW + auth -|                     |                  |
```

A held task is re-dispatched with `approval_ref`. This is explicit by design: the
skeleton does not silently resume work after a human decision, and it does not
let an agent approve its own request. `HitlAgent` can present and record
decisions; only `FileApprovalStore`/`InMemoryApprovalStore` transitions produce
an approval.

## 4a. Fragmentation layer

The business problem is fragmented tooling, not a missing agent. The mesh adds
one operational-intelligence layer above the incumbent systems rather than
replacing them:

```
incumbent tools                     USOC platform                    outcome
---------------                     -------------                    -------
observability  --+
cloud cost     --+
vulnerability  --+  read-only   +-----------+  deterministic  +-----------+
SOC            --+  connectors  |  Signal   |  correlation    |  ranked   |
identity       --+  (GET/file)  |  schema   |  entity + time  | incidents |
network        --+              +-----------+                 +-----+-----+
infrastructure --+                                                 |
backup/tickets --+                                   propose CONTAIN sandbox/<entity>
                                                                   |
                                              policy -> HOLD -> human -> ALLOW
                                                                   |
                                              evidence chain + MAC
```

**Ingestion.** `agents/connectors.py` defines `SourceType` for the eleven
categories, a narrow `Signal` schema, and two transports: `JsonlConnector` for
exports/air-gapped drops and `HttpJsonConnector` for incumbent APIs. A
`FieldMap` maps vendor field names; adding a source is configuration, not code.
Connectors are read-only by contract: GET-only HTTP, HTTPS by default, host
allowlist, no redirects, bounded bytes/records/time, JSONL confined to a root,
tokens from environment variables, and attribute redaction before storage.

**Correlation.** `agents/correlation.py` is deterministic:

1. deduplicate redelivered signals by `source|external_id` (or fingerprint)
2. resolve aliases with union-find, so `edge-02`, `i-0abc123` and
   `svc-edge-02` become one entity
3. cluster per entity inside `AGENT_CORRELATION_WINDOW_S`
4. score from severity, distinct source types, distinct categories, known
   attack-chain combinations, change/observability overlap and time span
5. emit ranked incidents with provenance, reasons and a stable id

No model participates, so the score is reproducible and explainable. AICEE gets
a deterministic summary path when given `correlated_incidents`; otherwise it
falls back to normal model work.

**Governance.** `agents/fragmentation.py` turns the top incident into one
explicit `contain` proposal with a safe target (`sandbox/<entity>` unless a
vendor-supplied `containment_target` passes the strict pattern). It then calls
the same `PolicyEngine` as every other agent. `HOLD` creates a human approval;
`ALLOW` carries an authorization ref; a missing policy engine fails closed with
`DENY`. Ingest, correlation, proposal and decision are written to the evidence
chain.

**Failure semantics.** One broken connector is reported and skipped; it does not
stop the others or the nine agents. A malformed connectors file disables the
fragmentation layer, and SHELL reports the error in `health()`/`diagnostics()`.
The mesh itself stays ready because connectors are an optional integration.

## 5. Evidence chain

`agents/evidence.py` writes one JSON record per line:

```json
{"seq": 1, "id": "ev-...", "kind": "policy.decision", "actor": "seraphim",
 "prev_hash": "genesis", "hash": "sha256(...)", "mac": "hmac(...)", "data": {...}}
```

* `hash = sha256(canonical record without hash and mac)`
* each record commits to `prev_hash`
* `mac = HMAC-SHA256(secret, canonical record without mac)`
* verification checks sequence continuity, chain linkage, each hash and each MAC
* modifying or deleting an entry breaks verification; recomputing a hash without
  the cluster secret still fails the MAC

OEKP appends. BENGAL independently recomputes and reports failure. The runtime
also records `task.result` for every governed execution that produced an
authorization.

## 6. Delivery and failure semantics

The bus is at-least-once. That is the only sane default for a network broker,
and it means every side effect needs a key.

| situation | behaviour |
|---|---|
| handler raises `RetryableError` | `nack(requeue=True)`, new attempt, same correlation |
| attempts exhausted | `Failure` to caller + dead-letter entry |
| handler exceeds `task_timeout_s` | cancelled, `Failure(code=timeout)` |
| message deadline already past | refused with `Failure(code=deadline)`, no model call |
| policy returns HOLD | `Handoff` with approval id; no execution |
| policy returns DENY | `Failure(code=policy_denied)`; no model call |
| no subscriber for a topic | counted as `unrouted`; direct sends time out at the caller |
| duplicate task with same `idempotency_key` | cached `TaskResult` replayed, handler not run |
| hop > 8 | contract rejects the message at construction |
| payload > 256 KiB | contract rejects before it reaches the broker |
| plan names an unknown agent | plan rejected before any step runs |
| independent step fails | wave aborts, completed results are returned with the error |

Idempotency keys must be stable across retries. The orchestrator derives them
from `trace | goal | step | objective`; domain code should derive them from the
business event, not from wall-clock time.

## 7. Planning and routing

`LLMPlanner` gives the model the nine capability cards and a strict JSON schema,
then validates the result:

* every `agent` exists in the registry
* step ids are unique
* `depends_on` only references earlier steps (this also rules out cycles)
* a governed step (`execute`/`contain`) declares a target

Failure is not fatal: `Mesh` uses `RouterPlanner` when no model is configured.
It splits the goal on clause boundaries, scores each clause against capability
phrases and routing keywords (token overlap with length normalisation,
exact-phrase bonus, id/name boost), merges consecutive wins by the same agent,
and chains the rest.

`subsystems.yaml` matters more than the prompt. Capabilities are shared
vocabulary; `keywords` are what distinguish similar subsystems:

| subsystem | distinctive keywords |
|---|---|
| AICEE | anomaly, forecast, capacity, root cause, trend, recommendation |
| ACIE | edge, network, digital twin, connectivity, compression, node |
| SERAPHIM | policy, authorize, identity, risk, compliance, zero trust |
| COHESION | mission, intent, requirement, dependency, priority |
| BENGAL | assurance, independent, verify, resilience, acceptance criteria |
| CSSSF | sandbox, simulate, fault injection, rehearsal, isolation |
| OEKP | evidence, provenance, audit trail, hash, lineage, retention |
| CYBER DEFENSE | security incident, triage, vulnerability, threat, detection |
| HITL | approval, approver, human, reviewer, escalate, oversight |

Routing is explainable on purpose: `registry.route(text)` returns scored
candidates, so a wrong assignment is a one-line investigation.

## 8. Concurrency, cost and latency

* Independent steps in a wave run concurrently (`asyncio.gather`).
* Each agent caps in-flight work with a semaphore (`max_concurrency`), so a
  burst queues at the mailbox instead of spawning unbounded tasks.
* Each step carries a token budget; overruns are flagged in the result.
* `model_tier: fast` sends light coordinators to the cheap model; `strong` is
  reserved for analysis, coordination and assurance.
* Agents send only the objective, declared inputs and prior results — not the
  whole conversation. Context grows with the DAG, not with the transcript.
* `EchoLLM` makes the entire test suite run in seconds with no network.

## 9. Observability

* `trace_id` is a `ContextVar`, set once per goal, attached to every log line
  and to every event the orchestrator emits.
* Structured logs (`AGENT_LOG_JSON=true`) are one JSON object per line with
  `trace`, `agent`, `event`, plus bounded fields.
* Metrics: `task.received/completed/failed/retried/timeout/idempotent_hit`,
  `policy.hold`, `policy.denied`, `policy.evaluated`, `evidence.appended`,
  `bengal.verified`, `tool.called`, `goal.completed/failed`.
* `python -m agents health` reports agent uptime, inflight work, transport
  counters, pending approvals and diagnostics.
* Orchestrator events (`plan.created`, `goal.completed`) give a low-cost audit
  trail without touching agent internals.

Swap `Metrics` for Prometheus/OTel at the composition root; nothing else needs
to change.

## 10. Security boundaries

* **Tools are the boundary.** An agent can only call tools named on its card;
  the model asking for anything else gets a typed refusal.
* **Policy is the authority boundary.** An agent cannot authorize its own
  consequence, and no model output is treated as an authorization.
* **Approvals are human.** HITL presents and records; it never self-approves.
* **Execution is scoped.** Governed actions require an allowlisted target and a
  matching, non-expired approval.
* Workspace tools resolve paths and reject escapes from the workspace root.
* Agent-to-agent messages are data, never instructions. A task result is
  untrusted input to the next agent: it is delivered as `inputs`.
* No credentials travel in messages. Model keys live in the runtime
  environment; domain connectors should use per-agent credentials.
* `Handoff` exists so an agent can stop and ask a human instead of guessing at
  an approval, auth or judgement call.

For production, add: per-agent service identity on the bus (the shared-secret
HMAC proves cluster membership, not which agent sent a message), an egress
allowlist for network tools, and signed authorization artifacts. Message
authentication, sender-bound signatures, payload redaction and file-based
secret loading are implemented.

## 11. Roles vs. runtime workers

The master prompt is explicit that the 100-agent allocation is a target
capability model, not a requirement to run 100 LLM instances, and that each role
should be evaluated as an AI agent, deterministic service, background worker,
policy engine, human function or shared capability.

Current split:

* **9 runtime coordinators** — one per subsystem, declared in
  `subsystems.yaml`, each carrying all roles for its domain.
* **Deterministic components** — policy engine, approval store, evidence chain,
  CYBER DEFENSE intent screen. These are not LLM calls.
* **Platform SHELL** — registry, bus, orchestrator, contracts, health and
  diagnostics.

Candidate next split:

| role group | likely form | reason |
|---|---|---|
| OEKP writers | separate worker | append contention and audit isolation |
| HITL routing | separate service | must stay independent of the requester |
| CYBER DEFENSE detection jobs | background workers | scheduled, high volume, narrow scope |
| AICEE analysis / COHESION planning | capabilities in coordinator | single reasoning pass |
| BENGAL reporting | capability in coordinator | reads evidence, no side effects |

The bus contract supports either choice. Only `subsystems.yaml` and the worker
entry point change.

## 12. Scaling out

`Mesh` runs all nine coordinators in one event loop by default. It also supports
process boundaries with nothing shared in memory, and now has a worker entry
point:

1. `python -m agents worker --agents oekp,bengal --port 8091` starts only those
   subsystems, without the orchestrator, and exposes its own `/health` and
   `/ready`. `python -m agents serve --agents … --no-orchestrator` is the
   equivalent on the full-service path. Unknown subsystem ids fail closed.
2. Use the same consumer group for replicas of one agent; Redis splits the
   stream between them, and `reclaim_stale(agent)` recovers a crashed worker's
   pending messages.
3. `RedisStore` is shared across replicas, so a redelivered task produces one
   handler execution.
4. Multiple workers may append to the same evidence chain: the appender
   re-reads the tail under the shared file lock before writing, so concurrent
   processes cannot fork the chain.
5. Keep the orchestrator stateless per goal; it already keys everything by
   trace id.
6. Move `FileApprovalStore` to a transactional multi-host store with
   authenticated approver identities before production on multiple machines.
   On one host the approval file is already serialized through the same lock.
7. Ship the evidence chain to immutable storage and sign the head.

A complete example is in `docker-compose.workers.example.yml`: one control
plane plus scale-on-demand workers (`--scale`). Demand scaling is a closed
loop: `python -m agents scale-advice [--json]` reads pending entries per
consumer group from Redis and prints the desired replica count per subsystem
(`AGENT_SCALE_MIN_REPLICAS` ≤ desired ≤ `AGENT_SCALE_MAX_REPLICAS`, one replica
per `AGENT_SCALE_MESSAGES_PER_REPLICA` pending messages). Feed the JSON to
`docker compose --scale` or an HPA custom metric.

Partitioning rule of thumb: scale the agents with the most fan-in (SERAPHIM,
OEKP, HITL first), not all nine equally.

## 13. Extending

| need | where |
|---|---|
| new domain logic per subsystem | subclass `SubsystemAgent`, override `handle_task` |
| new integration | register a `ToolSpec` and add its name to that subsystem's card |
| different planner | implement `Planner.plan()`; it must return a validated `Plan` |
| different broker | implement the `Bus` protocol |
| different policy | implement `ApprovalStore`; keep decisions deterministic |
| richer tool use | extend `handle_task`'s loop; keep it bounded |
| human approval step | return `Handoff` from a handler; never auto-approve |
| new routing vocabulary | edit `capabilities` and `keywords` in `subsystems.yaml` |

Keep the asymmetry: the bus and contracts are stable, the nine cards are cheap
to change.

## 14. Testing strategy

The suite covers the invariants that break multi-agent systems:

* contract round-trips, size/hop/deadline limits, unknown-field rejection
* direct vs broadcast delivery, nack/requeue, dead-lettering
* delegation, unknown recipient, dead recipient timeout, expiry
* idempotency (handler runs once, same result twice)
* tool allowlist enforcement
* routing correctness for all nine cards
* plan validation (unknown agent, forward dependency, duplicate id)
* end-to-end mesh run, unplannable goal, parallel wave timing, prior-result
  propagation
* policy matrix: ALLOW, HOLD, DENY, target allowlist, restricted data
* approval lifecycle: approve, deny, target mismatch, persistence
* HITL never self-approves; runtime returns `Handoff`, not execution
* CYBER DEFENSE prohibited-intent denial before the model
* evidence append, verification and tamper detection
* connector mapping, redaction, path confinement, HTTPS/host allowlist, token
  requirements and per-source fault isolation
* deterministic correlation: alias merge, dedupe, time windows, score filters,
  truncation and repeatability
* fragmentation governance: HOLD, cross-process approval, mission scoping,
  fail-closed policy, safe target selection and evidence
* AICEE deterministic correlated-incident summary

Run with `python -m pytest -q`. Add a Redis integration job before deploying the
Redis adapter.

## 15. Implementation roadmap and deliverables

The master prompt asks for deliverables A–H and for foundational contracts and
governance to land before higher-risk autonomy.

| deliverable | this repository | remaining work |
|---|---|---|
| A — Architecture inventory | `subsystems.yaml`, this document | connect and audit real USOC repositories |
| B — Agent registry | 93 roles declared with tools/subscriptions; 9 runtime agents | per-role I/O contracts and permission matrix |
| C — Communication architecture | `contracts.py`, `bus.py`, this document | Protobuf/gRPC, authenticated service identity |
| D — Implementation blueprint | package layout and composition root | service boundaries for role workers |
| E — Security and governance | `governance.py`, `evidence.py`, `security.py`, `usoc_agents.py` | OPA/Rego, per-agent keys, signed authorization artifacts |
| F — Test and verification | 186 tests across contracts, bus, runtime, routing, governance, security | integration, performance, fault-injection suites |
| G — Phased roadmap | phases below | resource and delivery schedule |
| H — Operational readiness | `health` and diagnostics | evidence-backed maturity assessment per subsystem |

Phased plan:

1. **Contracts and transport** — typed envelopes, bus adapters, deadlines,
   retries, idempotency, dead letters. *Done.*
2. **Governance foundation** — policy engine, approvals, evidence chain,
   deterministic SERAPHIM/OEKP/BENGAL/HITL. *Done.*
3. **Governed workflow slice** — observation → intelligence → policy → evidence
   end to end, plus approval pause and controlled execution. *Done for the demo
   slice.*
4. **Production hardening** — authenticated bus identities, durable approvals,
   immutable evidence and read-only health are implemented; remaining work is
   per-agent keys, OPA/Rego and signed authorization artifacts.
5. **Role decomposition** — split OEKP/HITL/CYBER DEFENSE workers where isolation
   or load requires it; keep the rest as coordinator capabilities.
6. **Full operational validation** — BENGAL acceptance suite, fault injection,
   tenant isolation, performance and security evidence.

A subsystem is not production-ready because source code exists. Each phase needs
tests, evidence and an accountable reviewer.
