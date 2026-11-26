# USOC Agent Mesh Architecture

This document describes the implemented skeleton of the USOC multi-agent
architecture: nine subsystem coordinators on a typed message bus, a deterministic
governance gate, human approvals, and an append-only evidence chain.

The in-repo capability baseline is `subsystems.yaml`: **9 subsystems, 93 logical
subsystem roles, plus 7 SHELL roles (100 logical agents)**. The delivery rules
are in [toolbox/CONSTITUTION.md](../toolbox/CONSTITUTION.md). The implementation
decision is to run **one coordinator per subsystem** and treat the roles as
declared capabilities. See [§11](#11-roles-vs-runtime-workers).

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

The governed workflow has twelve steps, as recorded in
[toolbox/PLAYBOOK.md](../toolbox/PLAYBOOK.md) with the delivery rules in
[toolbox/CONSTITUTION.md](../toolbox/CONSTITUTION.md). The skeleton supports all
of them as agents; the planner selects the subset a goal needs.

| step | owner | status in this repo |
|---|---|---|
| 1 Observation | ACIE | implemented as coordinator |
| 2 Intelligence | AICEE | implemented as coordinator |
| 3 Mission interpretation | COHESION | implemented as coordinator |
| 4 Security analysis | CYBER DEFENSE | implemented, defensive-only screen |
| 5 Risk and policy evaluation | SERAPHIM + PolicyEngine | deterministic / no LLM, implemented |
| 6 Simulation | CSSSF | LLM-backed coordinator, sandboxed tool scope |
| 7 Independent assurance | BENGAL | deterministic / no LLM evidence verification + BAA threat-mode analysis |
| 8 Human authorization | HITL + ApprovalStore | deterministic / no LLM, Postgres-backed in production |
| 9 Controlled execution | runtime + target allowlist | implemented, bounded |
| 10 Independent validation | BENGAL | evidence chain verification + redacted BAA assessments |
| 11 Evidence preservation | OEKP + EvidenceChain | deterministic / no LLM, append-only, hash-chained |
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
   Failure          Handoff +     ALLOW + AGENT_SHADOW_MODE?
   to caller        approval id        | yes -> record shadow.decision,
                                      |        skip handler (no execution)
                                      | no  -> run handler, attach refs
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
| `AGENT_SHADOW_MODE=true` with a policy ALLOW | **OBSERVE** — emit `shadow.decision` evidence, skip the handler; no tool/task/sink is touched |

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
decisions; only an `ApprovalStore` transition produces an approval. In local dev
that is the file/in-memory store; in production it is the tenant-partitioned
`PostgresApprovalStore`, whose decision and nonce spend share one row lock.

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

## 4b. Industry Starter Profiles and vertical controls

Four buyer-facing packs are packaged on top of the same mesh:

| profile id | pack | active roles | vertical controls |
|---|---|---|---|
| `core` | Core Governance Pack | 12 | baseline governance; JSONL evidence |
| `finops_banking` | FinOps & Banking Pack | 24 | transaction ceiling, dual-approver quorum, OEKP/BENGAL exports |
| `clinical_healthcare` | Clinical & Healthcare Pack | 22 | PII/PHI taint on every connector, signed egress guard |
| `full_usoc` | Full USOC Defense & Critical Infrastructure Pack | 93 | all declared roles (default) |

`agents/profiles.py` owns the exact role selections and validates them against
the signed cards at import. `apply_role_profile()` narrows only each card's
`roles` list; the nine coordinators, topic ACLs, tool scopes, tiers and message
routing are unchanged. This is deliberate: a pack can show a buyer a smaller
surface without creating a second, weaker execution path. Unknown profile ids
fail closed, and profile control defaults are applied only when the matching
explicit `AGENT_*` variable is unset.

**FinOps & Banking.** `PolicyEngine.evaluate()` enforces
`AGENT_MAX_TRANSACTION_AMOUNT` as a hard execution-time ceiling (strict parse:
finite, non-negative, at most four decimal places). Amount and currency are
bound into the approval request, so a re-dispatch with a different sum or a
foreign currency is DENIED. `AGENT_APPROVAL_QUORUM=2` requires two distinct
verified humans; a first decision stays `PENDING`, duplicates are rejected, and
the execution gate rechecks every credential and `max_tier`. A partial quorum
never spends the single-use nonce (`ApprovalStore.consume()` requires an
`APPROVED`, complete, distinct quorum) and a HOLD is returned as a `Handoff`
without writing to the idempotency result cache, so a redelivery rechecks the
current state instead of replaying a stale terminal verdict.

**Clinical & Healthcare.** `security.detect_sensitive_data()` runs on every
connector record when `AGENT_PHI_DETECTION_ENABLED=true`. A positive label raises
classification to `RESTRICTED`, sets monotone taint and attaches
`sensitive_labels`, which survive correlation, the proposal, the approval
`taint_hash` disclosure and evidence. `agents/egress.py` blocks external
publication of tainted/restricted decisions unless a verified detached/OIDC
sign-off binds to both the exact destination (`egress_target`) and a digest of
the exact decision payload (`egress_payload_digest`)
(`AGENT_BLOCK_TAINTED_EGRESS=true`). Both fields are signed into the approval and
into the human credential; `also_targets` naming a governed action never
satisfies the sink binding. `agents publish-decision <id> --signoff <approved-id>`
supplies the sign-off.

**Compliance exports.** `agents/evidence.py:render_export()` renders read-only
`jsonl`, `oekp`, `bengal` and `oekp_bengal` views over the verified hash/MAC
chain, failing closed when verification fails. The canonical store remains
append-only JSONL.

## 4c. Cross-vertical Money Shot storyboards

`agents/storyboards.py` holds five-beat demos for three verticals. The shape is
identical; only nouns change:

1. messy signals
2. entity resolution
3. ranked risk
4. proposed high-impact action
5. **deterministic HOLD** (never autonomous execution)

| vertical | money shot | profile | fixtures |
|---|---|---|---|
| cyber / infra | `Malicious IP signals -> CONTAIN prod-db-01 -> HOLD for SecOps lead` | `full_usoc` | `fixtures/fragmentation/` |
| finance | `Anomalous wire pattern -> FREEZE merchant-account-884 -> HOLD for Risk Officer` | `finops_banking` | `fixtures/finance/` |
| healthcare | `Conflicting medication/lab feed -> PAUSE automated-dispense-queue -> HOLD for Attending Clinician` | `clinical_healthcare` | `fixtures/healthcare/` |

`agents storyboard --vertical <id>` prints the beats; `agents demo-fragmentation
--vertical <id>` and `agents ingest --vertical <id>` swap profile, fixtures,
target nouns and mission defaults in lockstep. Governed targets are namespaced
(`sandbox/<noun>`) so a vendor field cannot widen the blast radius; the noun
above is the buyer-facing label.

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
authorization. In shadow mode every record additionally carries a `shadow: true`
flag (covered by hash/MAC); OEKP exports it, BENGAL totals `shadow_only`, and
BENGAL withholds `trusted_for_execution` for chains containing shadow records.
Shadow state lives under `<workspace>/shadow` so it cannot be mistaken for live
evidence.

## 6. Delivery and failure semantics

The bus is at-least-once. That is the only sane default for a network broker,
and it means every side effect needs a key.

| situation | behaviour |
|---|---|
| handler raises `RetryableError` | bounded exponential backoff, then `nack(requeue=True)`, new attempt, same correlation |
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
| independent step fails | wave aborts; every step that ran is reported; declared undos run in reverse through policy/HITL; undeclared successes are listed as `uncompensated`; `goal.failed` event published |
| two governed steps would share a wave | plan rejected before dispatch; a second mutating step must depend on an earlier one |
| upstream step is tainted | taint and full provenance flow to every dependent step; governed work needs an approval that discloses the same chain |

Idempotency keys must be stable across retries. The orchestrator derives them
from `trace | goal | step | objective`; domain code should derive them from the
business event, not from wall-clock time.

## 7. Planning and routing

`LLMPlanner` gives the model the nine capability cards and a strict JSON schema,
then validates the result:

* every `agent` exists in the registry
* step ids are unique
* `depends_on` only references earlier steps (this also rules out cycles)
* a governed step (`execute`/`contain`) declares a target, may carry a human
  `approval_ref`, and should declare a structured `compensate` (undo) — the
  orchestrator never invents one
* at most one governed step per topological wave; a second mutating step must
  declare an explicit dependency so the wave cannot split state
* compensation is dispatched as an ordinary task, so it inherits the policy
  gate, approval scope, provenance and evidence chain
* taint is monotone across dependencies, so downstream governed work always
  sees the original untrusted provenance

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

* Independent **non-mutating** steps in a wave run concurrently (`asyncio.gather`);
  governed steps are serialized by plan validation and a runtime pre-dispatch check.
* Each agent caps in-flight work with a semaphore (`max_concurrency`), so a
  burst queues at the mailbox instead of spawning unbounded tasks.
* Each step carries a token budget; overruns are flagged in the result.
* `model_tier: fast` sends light LLM-backed coordinators to the cheap model;
  `strong` is reserved for LLM-backed analysis and coordination.
* `model_tier: deterministic` means no LLM at all. SERAPHIM, BENGAL, OEKP and
  HITL must map to deterministic classes at startup; `BaseAgent` refuses generic
  task/query/tool paths for them, so the label is a runtime contract.
* CSSSF's `tool_scopes` gives its LLM a separate `ToolRegistry` rooted at
  `workspace/sandbox/`. Paths, traversal and symlink targets are resolved before
  the base tool runs, so rehearsal output cannot overwrite live workspace files.
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
  `bengal.verified`, `tool.called`, `goal.completed/failed`,
  `compensation.done/hold/denied/failed`.
* `python -m agents health` reports agent uptime, inflight work, transport
  counters, pending approvals and diagnostics.
* Orchestrator events (`plan.created`, `goal.completed`) give a low-cost audit
  trail without touching agent internals.

Swap `Metrics` for Prometheus/OTel at the composition root; nothing else needs
to change.

## 9a. Task ledger and adaptive benchmark (0.2.0)

`TaskLedger` is the missing middle layer between counters and traces. It keeps a
bounded, TTL-swept record of each lifecycle transition, correlated by the same
`trace_id:step_id` used by the orchestrator and agents. It stores no goal, output
or error text: reasons become 16-hex digests of redacted text, and
`extra="forbid"` rejects any attempt to add a free-text field. `Shell.health`
publishes only counts on the public probe; the full snapshot requires the
admin-gated diagnostics route.

`agents benchmark` applies the paper's lesson that an optimizer can change the
method but never the definition of success:

* **Fixed validator** — the real deterministic `PolicyEngine` plus hard
  invariants (`unapproved_allow`, `policy_ref_missing`, verified chain, shadow
  flags, bounded rounds). Variants cannot redefine them.
* **Evidence-backed archive** — each case, round and summary is appended to a
  signed hash chain with a fresh run id and per-record nonce.
* **Adaptive focus** — a variant's next round contains only cases it has not
  resolved; the loop stops when the residual set is stable, so compute is not
  spent re-proving solved cases.
* **Proposal only** — the report is permanently `rehearsal_only` / `shadow`,
  uses an isolated in-memory approval store, and never promotes a variant. A
  human still owns the merge decision.

## 9b. BENGAL BAA threat-mode analysis (IARPA BAA-24-03)

`agents/bengal.py` turns BENGAL from an evidence-chain verifier into a real,
model-agnostic LLM-threat-mode analyzer while keeping every governed path
deterministic. Four analyzers cover the targeted topic areas:

| Topic | Analyzer | Redacted output |
|---|---|---|
| Bias / diverse perspectives | lexicon signals + perspective vectors; optional injected LLM induces perspectives and simulated dialogue | bias score, diversity score, pairwise similarity, perspective shift, indicator counts and 16-hex fingerprints |
| Hallucination / inference / confidence | trusted-corpus overlap with an explicit plausible-inference allowance and unsupported-specificity check | per-claim status, support, hallucination/inference rates, confidence with its coverage/margin basis |
| Safe information flow | verifiable redaction, small-cell aggregation detection, sensitive-access likelihood | HMAC sanitization manifest (categories + digests only), group fingerprints, access verdict |
| Poisoned / imperfect sources | provenance, historical accuracy, intent and corroboration across independent roots | source reliability factors, intent, corroboration verdicts, reliable-intel fingerprints |

Design invariants:

* **Observation only.** BENGAL never approves, denies or executes an action.
  Reports are consumed by policy/HITL/egress controls, not substituted for them.
* **No raw payloads.** Reports carry opaque case ids, 16-hex fingerprints,
  counts and scores only — safe for the task ledger, OEKP and public health.
* **Model agnostic.** Lexical/statistical paths are deterministic and offline.
  An injected `agents.llm.LLM` enriches perspective induction without changing
  the scoring contract or the governance boundary. The governed BENGAL
  coordinator stays `model_tier: deterministic` (no LLM call).
* **Scoped opt-in.** `BengalAgent.handle_task` keeps evidence verification as
  its default; BAA analysis runs only when `inputs.bengal_analyze` is present.

`agents/bengal_eval.py` implements a replicable T&E protocol: a fixed labeled
JSONL corpus (`fixtures/bengal/cases.jsonl`), the fixed analyzer, and per-mode
confusion counts (TP/FP/FN/TN), precision, recall, F1, accuracy, tie-aware
rank ROC/AUC and Wilson 95% confidence bounds, macro-averaged across modes.
Results contain no raw text. Run it with `python -m agents bengal-eval` (acceptance
threshold via `--min-f1`); analyze a single case with
`python -m agents bengal-analyze case.json`. The offline corpus is calibrated to
the analyzer's documented rules, so its scores are reproducible, not an estimate
of real-world generalization; widen and re-label the corpus before trusting it
as an operational capability baseline.

The dashboard shows only static capability metadata (method/protocol version,
mode count) from the public health payload; T&E thresholds and the eval corpus
path are visible only on the admin-gated diagnostics route. No case data is
ever published to either surface.

## 10. Security boundaries

* **Tools are the boundary.** An agent can only call tools named on its card;
  the model asking for anything else gets a typed refusal.
* **Policy is the authority boundary.** An agent cannot authorize its own
  consequence, and no model output is treated as an authorization.
* **Approvals are human.** HITL presents and records; it never self-approves.
* **Execution is scoped.** Governed actions require an allowlisted target and a
  matching, non-expired approval. FinOps adds a hard transaction ceiling and
  dual-approver quorum; Clinical adds PII/PHI taint classification and a signed
  egress guard (see [§4b](#4b-industry-starter-profiles-and-vertical-controls)).
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

The 100-agent allocation is a target capability model, not a requirement to run
100 LLM instances. `subsystems.yaml` declares the 93 subsystem roles, and
[toolbox/CONSTITUTION.md](../toolbox/CONSTITUTION.md) fixes the fail-closed,
least-privilege rules; each role is therefore evaluated as an AI agent,
deterministic service, background worker, policy engine, human function or
shared capability.

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
4. Multiple workers may append to the same evidence chain. In production,
   `PostgresEvidenceChain` serialises appends with a row-locked head, assigns
   sequence numbers in the database, and reloads/re-verifies after each append;
   the local file chain with its file lock remains a dev-only path.
5. Keep the orchestrator stateless per goal; it already keys everything by
   trace id.
6. `PostgresApprovalStore` is the transactional multi-host approval store. The
   `tenant_id` partition isolates approvals, and the decision/governance check
   plus nonce spend happen inside one `SELECT ... FOR UPDATE` transaction. Redis
   caches reads only; it never authorises a spend.
7. `S3WormArchiveSink` ships redacted, HMAC-chained ledger segments to S3 Object
   Lock. Tenants have independent chains and key prefixes, and Object Lock plus
   SSE (AES256 by default, or `AGENT_ARCHIVE_SSE_KMS_KEY_ID` for SSE-KMS/CMEK)
   makes the archive immutable at rest. Control-plane pods keep no approval,
   evidence or archive state on disk and can be autoscaled.

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
* plan validation (unknown agent, forward dependency, duplicate id, at most one
  mutating step per wave)
* wave isolation and monotone taint propagation across downstream governed steps
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
* exact role counts for all four Starter Packs, fail-closed unknown profiles,
  profile views never widening card ACLs, explicit `AGENT_*` overrides
* strict money parsing, hard transaction ceiling, currency pinning, exact
  amount/currency approval binding
* dual-approver quorum: distinct humans, partial `PENDING`, single-approver
  fallback, no nonce consumption before quorum, HOLD not cached as a terminal
  verdict
* PII/PHI detection (keys and values), `MappingAdapter` reclassification to
  `RESTRICTED`, monotone taint/label propagation through correlation
* egress guard: verified detached/OIDC sign-off bound to exact destination and
  payload digest; rejection of governed-action targets, mismatched digests,
  pending and unverified records
* all four export formats plus fail-closed verification
* exact cross-vertical Money Shot mappings and shared five-beat shape

Run with `python -m pytest -q`. Add a Redis integration job before deploying the
Redis adapter.

## 15. Implementation roadmap and deliverables

Deliverables A–H are listed below. As required by
[toolbox/CONSTITUTION.md](../toolbox/CONSTITUTION.md), foundational contracts
and governance land before higher-risk autonomy.

| deliverable | this repository | remaining work |
|---|---|---|
| A — Architecture inventory | `subsystems.yaml`, this document | connect and audit real USOC repositories |
| B — Agent registry | 93 roles declared with tools/subscriptions; 9 runtime agents; four Starter Pack role views | per-role I/O contracts and permission matrix |
| C — Communication architecture | `contracts.py`, `bus.py`, this document | Protobuf/gRPC, authenticated service identity |
| D — Implementation blueprint | package layout and composition root | service boundaries for role workers |
| E — Security and governance | `governance.py`, `evidence.py`, `security.py`, `usoc_agents.py`, `egress.py`, `trust.py`, `oidc.py`, `profiles.py` | OPA/Rego, per-agent keys, signed authorization artifacts |
| F — Test and verification | 489 passed + 1 skip across contracts, bus, runtime, routing, governance, security, wave recovery, zero-trust tiers, role profiles, vertical controls, shadow-mode negatives, traceability, release engineering and live-LLM rehearsal | integration, performance, fault-injection suites |
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
6. **Buyer packaging** — four Industry Starter Profiles (role views only),
   FinOps transaction/quorum controls, Clinical PII/PHI taint and signed egress,
   OEKP/BENGAL exports and cross-vertical Money Shot storyboards. *Done.*
7. **Full operational validation** — BENGAL acceptance suite, fault injection,
   tenant isolation, performance and security evidence.

A subsystem is not production-ready because source code exists. Each phase needs
tests, evidence and an accountable reviewer.
