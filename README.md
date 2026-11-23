# USOC Agent Mesh

A working skeleton of the **Unified System Operations Center** agent architecture:
nine governed subsystem coordinators that communicate over one typed message bus,
wrapped in the deterministic controls USOC requires — a policy decision point,
human approvals, and an append-only evidence chain.

The USOC capability model calls for **93 subsystem roles plus 7 SHELL roles =
100 logical agents**. The declared inventory lives in `subsystems.yaml`; the
delivery rules live in [toolbox/CONSTITUTION.md](toolbox/CONSTITUTION.md). This
repository implements the **9 subsystem coordinators** and the SHELL as platform
infrastructure, and declares all 93 roles on the capability cards so the full
surface is visible and routable. See
[Roles vs. runtime workers](#roles-vs-runtime-workers).

```
                        +---------------------------+
   goal --------------> |  Orchestrator (control)   |
                        |  plan -> validate -> wave |
                        +-------------+-------------+
                                      |
               typed messages on one bus (at-least-once)
                                      |
  +-------+-------+-------+-------+--+----+-------+-------+-------+
  |       |       |       |       |       |       |       |       |
 AICEE   ACIE  SERAPHIM COHESION BENGAL CSSSF   OEKP  CYBER    HITL
 (14)    (10)    (12)      (9)     (9)   (10)    (8)   DEFENSE   (10)
                                                        (11)
  +-------+-------+-------+-------+-------+-------+-------+-------+
                    peer-to-peer delegate() / ask()
```

## Version 0.2.0 — task-aware, evidence-driven improvement

`0.1.1` was a governed message bus with deterministic policy, HITL and an
append-only evidence chain. `0.2.0` keeps that authority boundary unchanged and
adds the two missing operational layers:

| Capability | 0.1.1 | 0.2.0 |
|---|---|---|
| Task awareness | Counters plus a trace id; no per-task lifecycle state | Bounded, TTL-swept `TaskLedger` records received / retried / held / denied / shadow-blocked / failed / completed with attempt, latency, tokens and a redacted reason fingerprint. Public probes expose counts only; admin diagnostics expose the full redacted view. |
| Improvement loop | Ad hoc audit → fix → verify | `agents benchmark` scores workflow variants against a fixed policy validator, re-evaluates only unresolved cases (adaptive focus), stops when the residual set is stable, and archives every round as signed OEKP/BENGAL evidence with lineage digests. |
| Efficiency | Every regression run re-executed the whole suite | Adaptive benchmark re-runs only residual cases; `naive_evaluations`, `evaluations` and `evaluation_saving_pct` make the cost explicit. The shipped 5-case suite used 20 evaluations instead of 45 (55.6% saving) with the same validated winner. |
| Promotion safety | CI plus human review | Benchmark reports are literal `rehearsal_only=True` / `shadow=True`, use a fresh in-memory approval store, never call a tool, bus, handler or live nonce, and reject any variant that emits `ALLOW`. |
| Governance invariants | 9 coordinators, 93/24/22/12 role packs, exact shadow wording | Unchanged. No policy, approval, evidence, role or shadow-mode semantics were modified. |

Run it with:

```powershell
python -m agents benchmark                       # offline, signed, no egress
python -m agents benchmark --output exports/     # also write an oekp_bengal export
python -m agents health                          # includes tasks_unresolved counts
```

## Quickstart

```powershell
pip install -e ".[dev]"
python -m agents doctor          # config, registry, bus, model, security
python -m agents list            # nine cards and all 93 roles
python -m agents profiles        # the four Industry Starter Packs and role counts
python -m agents storyboard --vertical finance   # 3-minute Money Shot storyboard
python -m agents export --format oekp_bengal --output exports/  # compliance export
python -m agents shadow          # observe-only: policy/HITL/evidence, NO execution or writes
python -m agents demo            # one governed goal end to end
python -m agents health          # SHELL health + diagnostics + task counts
python -m agents benchmark       # adaptive governance-readiness benchmark
python -m agents ingest --fixtures fixtures/fragmentation
python -m agents demo-fragmentation --fixtures fixtures/fragmentation
python -m agents demo-fragmentation --vertical finance      # transaction gate + dual HITL
python -m agents demo-fragmentation --vertical healthcare   # PII/PHI taint + signed egress
python -m pytest -q              # 359 passed, 1 env-gated skip, no network
```

The demo runs fully offline with a deterministic echo model, so the whole message
flow is visible before you wire a provider. It preflights the evidence chain and
fails closed with an actionable message if the workspace holds records signed by
a different process secret — use `python -m agents --workspace <fresh-dir> demo`
or set `AGENT_SHARED_SECRET` to the original key. It seeds
`workspace/inbox/telemetry.jsonl` and plans:

```
acie -> aicee -> seraphim -> oekp
```

The output shows the policy reference and evidence id produced by the governed
steps, the full message flow, and runtime metrics.

## 3-minute demo storyboard (testing-bay)

Live smoke test — **PASS**, 2026-11-16, `testing-bay.atlassian.net`
(cloudId `a1a0914e-e3aa-4080-a0fb-a67dec49c1a3`): the decision ADR page
`786434` is `current` at version 3, and Jira project `KAN` returns four issues
(KAN-2 **Done**, KAN-1/3/4 **To Do**). No live publisher write is performed —
the bridge is opt-in and its tests use an injected HTTP transport.

| Time | Show | Point |
|---|---|---|
| 0:00–0:30 | `git log --oneline -3` and `python -m pytest -q` | Offline Ed25519 keys, multi-key trust bundle, approval-gated Atlassian bridge, and the four Starter Packs. Clean remote, 359 passing with 1 symlink skip. |
| 0:30–1:00 | `SECURITY.md` rotation section and `ed25519_keys.json` | Verification tries the whole `kid → public_key` bundle, so rotation does not break in-flight waves or historical evidence. Missing active kid fails closed. |
| 1:00–1:45 | ADR: <https://testing-bay.atlassian.net/wiki/spaces/SD/pages/786434/Decision+Ed25519+offline+KMS+signing+for+USOC+agent+mesh> | Decision record generated from the shipped work; KAN-2 is Done, page version 3. |
| 1:45–2:20 | Jira project `KAN` | Four tracked follow-ups: three operational, one closed by the trust-bundle commit. |
| 2:20–3:00 | `python -m agents approve apr-… --by alice` then `python -m agents publish-decision apr-…` | A human decision creates a mesh-signed ADR (and JSM ticket when configured), idempotently. No AI recommendation can write externally. |

To make the last beat live rather than narrated, configure the opt-in bridge:

```powershell
$env:AGENT_ATLASSIAN_BRIDGE_ENABLED = "true"
$env:AGENT_ATLASSIAN_BASE_URL = "https://testing-bay.atlassian.net"
$env:AGENT_ATLASSIAN_API_KEY_FILE = "/run/secrets/atlassian_api_key"
$env:AGENT_ATLASSIAN_CONFLUENCE_SPACE_KEY = "SD"
$env:AGENT_ATLASSIAN_JSM_ENABLED = "false"   # no JSM desk exists on this site yet
```

The service-account key must be mounted as a secret; never paste it into
configuration or chat. See
[SECURITY.md](SECURITY.md#atlassian-publishing-bridge-opt-in) for the write gate,
rotation procedure and verified SSRF/XSS properties.

### Cross-vertical Money Shot storyboard (`agents storyboard`)

One 3-minute demo shape is reused across verticals: messy signals -> entity
resolution -> ranked risk -> proposed high-impact action -> **deterministic HOLD**.
Only the nouns change; the last beat is always a machine-enforced HOLD, never an
autonomous execution.

```powershell
python -m agents storyboard --vertical all        # print all three
python -m agents storyboard --vertical finance
python -m agents demo-fragmentation --vertical healthcare
```

| vertical | money shot |
|---|---|
| Cyber / infra | `Malicious IP signals -> CONTAIN prod-db-01 -> HOLD for SecOps lead` |
| Finance | `Anomalous wire pattern -> FREEZE merchant-account-884 -> HOLD for Risk Officer` |
| Healthcare | `Conflicting medication/lab feed -> PAUSE automated-dispense-queue -> HOLD for Attending Clinician` |

The five beats are 0:00 messy signals, 0:30 entity resolution, 1:00 ranked risk,
1:40 proposed action, 2:20 HOLD. The governed target is namespaced
(`sandbox/<noun>`) so a vendor field cannot widen the blast radius; the buyer-facing
noun above is what the audience sees. `--vertical` swaps the profile, fixtures,
connector/target nouns and mission defaults in lockstep.

The build-to-demo order, the non-negotiable rules, and what "done" means are
pinned in [toolbox/PLAYBOOK.md](toolbox/PLAYBOOK.md). The delivery
constitution and reusable scripts/templates live in [toolbox/](toolbox/README.md).

## The nine subsystems

| id | tier | roles | job |
|---|---|---|---|
| `aicee` | `strong` (LLM) | 14 | Operational intelligence: anomalies, forecasts, root cause, recommendations. Advises only. |
| `acie` | `fast` (LLM) | 10 | Edge telemetry, network state, digital twin, connectivity and edge integrity. |
| `seraphim` | `deterministic` / no LLM | 12 | Policy decision point: identity, scope, risk, compliance, ALLOW/HOLD/DENY/CONTAIN. |
| `cohesion` | `strong` (LLM) | 9 | Mission intent, requirements, dependencies, priorities and cross-subsystem plans. |
| `bengal` | `deterministic` / no LLM | 9 | Independent assurance and validation against evidence. |
| `csssf` | `fast` (LLM), sandboxed tools | 10 | Controlled sandboxes, change rehearsal, fault injection, simulation results. |
| `oekp` | `deterministic` / no LLM | 8 | Evidence, provenance, integrity hashes, audit trail, decision lineage. |
| `cyber_defense` | `fast` (LLM) | 11 | Defensive security: vulnerability assessment, triage, detection, containment planning. |
| `hitl` | `deterministic` / no LLM | 10 | Human governance: decision presentation, approval routing, escalation, oversight. |

`deterministic` is a runtime contract, not a label: those cards must map to
deterministic Python implementations at startup, and `BaseAgent` refuses any
LLM call or model-driven tool call for them. No model is secretly in the loop.
CSSSF is LLM-backed, but every `workspace.read`/`workspace.write` path is
chrooted to `workspace/sandbox/` by its per-agent `ToolRegistry`.

**93 subsystem roles.** The seven SHELL roles are implemented as infrastructure,
not as a tenth domain agent:

| SHELL role | implementation |
|---|---|
| Service Discovery | `registry.py` capability cards / `Shell.discovery()` |
| Communication Routing | `bus.py` (`inbox.*`, `topic.*`) |
| Workflow Lifecycle | `orchestrator.py` (waves, retries, timeouts) |
| Contract Validation | `contracts.py` (pydantic, `extra="forbid"`) |
| Runtime Health | `shell.py::health` / `python -m agents health` |
| Configuration Coordination | `config.py`, `subsystems.yaml` |
| Integration Diagnostics | `shell.py::diagnostics` |

Capability cards are the only thing the planner sees. Renaming or rewiring a
subsystem never touches orchestration code. Each card carries `capabilities`,
`keywords`, `roles`, `tools` and optional `subscribes` topics; both routing
quality and least-privilege tool access come from that file. A card may also
declare `tool_scopes`; CSSSF declares `workspace.read` and `workspace.write` as
`sandbox/`, so the mesh builds it a separate, path-chrooted `ToolRegistry`.
Traversal (`../`), absolute paths and symlinks that resolve outside `sandbox/`
are rejected before the base tool runs.

Cards are also the authorization matrix. Each declares `allowed_recipients`,
`allowed_senders`, `allowed_action_classes` and `allowed_targets`, and the topic
ACLs are generated from them. The shipped mesh is consistent by construction:
if A may delegate to B, B must name A in `allowed_senders`. Only CSSSF
(`execute`, `sandbox/*`) and CYBER DEFENSE (`contain`, `sandbox/*` and
`staging/*`) can receive governed actions; every other coordinator is limited
to read-only/recommend work. `python -m pytest` checks that matrix so a card
cannot quietly widen a peer's privileges.

## Industry Starter Profiles

Four buyer-facing packs ship with the mesh. A profile changes **what is shown**,
not what runs: all nine coordinators stay up with their signed capability cards,
ACLs, tool scopes and tiers. The profile only narrows the `roles` list on each
card ("active capability-card roles"), so the routing and governance surface is
identical in every pack.

| profile id | pack | active roles | controls it turns on |
|---|---|---|---|
| `core` | Core Governance Pack | 12 | JSONL evidence only — smallest governed surface for general enterprise/SaaS work |
| `finops_banking` | FinOps & Banking Pack | 24 | hard transaction ceiling (5000.00 USD), dual-approver HITL, OEKP/BENGAL exports |
| `clinical_healthcare` | Clinical & Healthcare Pack | 22 | PII/PHI detection on every connector, restricted classification + monotone taint, signed egress guard |
| `full_usoc` | Full USOC Defense & Critical Infrastructure Pack | 93 | every declared role (the default) |

```powershell
python -m agents profiles                        # list packs, counts and controls
python -m agents --profile finops_banking list   # filter the role view for one run
# or set AGENT_ROLE_PROFILE=finops_banking for the process
```

Selection is fail-closed: an unknown profile id is rejected (never silently
"all roles"), and every role a profile names must exist on that coordinator's
signed card. An explicit `AGENT_*` environment variable always wins over a
profile's control default, so operators can tighten (or, with care, relax) a
pack without editing code.

### FinOps & Banking controls

- **Transaction-limit gate** — `AGENT_MAX_TRANSACTION_AMOUNT` is a hard
  execution-time ceiling. A governed transaction above it is DENIED before a
  human review; no approval can authorize a larger sum. `AGENT_TRANSACTION_CURRENCY`
  pins the only accepted currency (no silent conversion).
- **Amount binding** — the approval request records the exact amount and
  currency. Re-dispatching with a different sum or currency is DENIED even if
  both are individually within policy.
- **Dual-approver HITL** — `AGENT_APPROVAL_QUORUM=2` requires two **distinct
  verified humans**. A first decision leaves the record `PENDING`; a duplicate
  approver is rejected; the execution gate re-checks quorum and every individual
  credential/tier. A partial quorum never spends the single-use nonce and its
  HOLD is never cached as a terminal verdict. The finance demo ends in:
  `Anomalous wire pattern -> FREEZE merchant-account-884 -> HOLD for Risk Officer`.

### Clinical & Healthcare controls

- **PII/PHI taint on every connector** — with `AGENT_PHI_DETECTION_ENABLED=true`,
  every record is scanned for patient/health identifiers. A positive label raises
  classification to `RESTRICTED`, sets monotone taint, and carries `sensitive_labels`
  through correlation, the proposal, the approval and the evidence chain.
  Restricted work requires a `mission_id`; a clean approval cannot authorize a
  tainted chain.
- **Signed external egress** — `AGENT_BLOCK_TAINTED_EGRESS=true` blocks publishing
  tainted/restricted decisions (for example to the Atlassian bridge) unless a
  verified detached or OIDC sign-off binds to both the **exact destination**
  (`egress_target`) and a **digest of the exact decision payload**
  (`egress_payload_digest`). Both fields are covered by the signed approval record
  and the human's credential, so a sign-off for one sink or payload cannot be
  replayed for another. A governed-action target such as `sandbox/<noun>` is not
  a sink binding. Use `python -m agents publish-decision <id> --signoff <approved-id>`.
  The healthcare demo ends in:
  `Conflicting medication/lab feed -> PAUSE automated-dispense-queue -> HOLD for Attending Clinician`.

### Compliance exports

The canonical store stays append-only JSONL. `python -m agents export` renders
read-only OEKP/BENGAL views over the verified chain
(`jsonl`, `oekp`, `bengal`, `oekp_bengal`), failing closed if the chain is not
verifiable. The FinOps and Clinical packs enable OEKP/BENGAL formats by default.
Because the in-memory bus uses an ephemeral signing key, set a stable
`AGENT_SHARED_SECRET` when evidence is generated by one process and exported by
another; otherwise MAC verification correctly fails.

## Governance, not vibes

USOC's rule is that **an AI recommendation is not execution authority**, pinned
in [toolbox/CONSTITUTION.md](toolbox/CONSTITUTION.md). The governed workflow has
twelve steps (see [toolbox/PLAYBOOK.md](toolbox/PLAYBOOK.md) and
[§2 of the architecture](docs/architecture.md#2-the-operational-workflow)):

```
observation -> intelligence -> mission interpretation -> security analysis
-> risk and policy evaluation -> simulation -> independent assurance
-> human authorization -> controlled execution -> independent validation
-> evidence preservation -> controlled improvement
```

This skeleton implements the backbone: observation (`acie`), intelligence
(`aicee`), policy evaluation (`seraphim`), simulation (`csssf`), independent
assurance (`bengal`), human authorization (`hitl`), evidence (`oekp`) and
controlled improvement proposals (`aicee`). Security analysis (`cyber_defense`)
and mission interpretation (`cohesion`) are available and routable. The
orchestrator intentionally does not auto-chain all twelve steps; it plans the
steps needed for the goal, so a read-only analysis does not create a human
approval queue.

Every consequential task (`execute`, `contain`) passes a deterministic policy
gate before any model call. The policy engine is plain Python — no prompt can
override its DENY.

### Decision matrix

| condition | decision |
|---|---|
| `read_only` / `recommend` / `simulate` | **ALLOW** — no approval needed |
| governed action without an explicit target | **DENY** |
| target outside the allowlist (`sandbox/*`, `staging/*` by default) | **DENY** |
| `restricted` data without a `mission_id` | **DENY** |
| governed action, no approval reference | **HOLD** — an approval request is created |
| governed action with tainted upstream provenance | **HOLD** with taint disclosed; a clean approval cannot authorize it |
| governed transaction above `AGENT_MAX_TRANSACTION_AMOUNT` | **DENY** at execution time — an approval cannot raise the ceiling |
| governed transaction in a currency other than `AGENT_TRANSACTION_CURRENCY` | **DENY** — no silent conversion |
| approval bound to a different amount or currency | **DENY** — exact transaction binding |
| dual-approver quorum not met (fewer than `AGENT_APPROVAL_QUORUM` distinct verified humans) | **HOLD** while pending, **DENY** if a signed record lacks the distinct decisions |
| approval is still pending | **HOLD** |
| approval was denied | **DENY** |
| approval has expired since it was decided | **DENY** |
| approval does not cover this action, target and mission | **DENY** |
| approval is approved and covers the action, target and mission | **ALLOW** + scoped authorization ref (TTL 900 s) |
| CYBER DEFENSE task matching prohibited offensive intent | **DENY** before the model runs |
| tainted/restricted data egress without a verified sign-off bound to the exact destination and payload digest | **DENY** (Clinical pack) — no external publication |
| `AGENT_SHADOW_MODE=true` and the policy would ALLOW | **OBSERVE** — the real ALLOW is recorded as `shadow.decision`, but the handler is never called; no tool, target or sink is touched |

Runtime behaviour is consistent: `HOLD` returns a typed `Handoff`, `DENY` returns
a typed `Failure`, `ALLOW` attaches `policy_decision_ref`, `authorization_ref`
and `evidence_ref` to the result.

Taint is monotone across the DAG. `_run_step` unions the provenance and taint of
every dependency into the outbound `TaskSpec`; the runtime copies it onto the
`TaskResult` even when a handler returns a default-clean result. A tainted
upstream result therefore stays tainted through any number of clean-looking
intermediaries, and SERAPHIM refuses to reuse an approval that was issued
without the same taint disclosure.

### Human approval walkthrough

A governed task returns a handoff instead of executing:

```text
handoff | Approval required: apr-89d9db2cba.
          Approve with: python -m agents approve apr-89d9db2cba
```

A human decides, out of band:

```powershell
python -m agents approvals
python -m agents approve apr-89d9db2cba --by alice --note "change window CHG-1042"
python -m agents deny apr-0000000000 --by alice
```

The approved task is then re-dispatched with `approval_ref="apr-..."`; the policy
engine re-evaluates it, checks that the approval covers the action, target and
mission, and issues a short-lived authorization. An approval for
`sandbox/node-1` cannot be replayed against `prod/db-primary`, and a wildcard
target does not authorize concrete hosts. An approval also expires
`AGENT_APPROVAL_TTL_S` after it was decided, so a one-off human decision is not a
permanent grant.

The approver must be named in `AGENT_APPROVERS` when the allowlist is required,
and cannot be the requester. With the memory bus the signing secret is ephemeral
per process, so set `AGENT_SHARED_SECRET` if `approve` runs in a different
process from the mesh; with Redis an explicit secret is mandatory. In
`AGENT_STRICT_PROD=1` mode the plain allowlist is replaced by a signed registry
and every decision must carry a cryptographic credential — see
[Production trust mode](#production-trust-mode) below.

### Evidence

`agents/evidence.py` writes an append-only JSONL chain. Each record hashes the
previous record, so modifying or deleting an entry breaks verification. OEKP
appends; BENGAL independently recomputes and reports the failure. Governed
execution results are recorded automatically by the runtime gate. Appends find
the chain tail by scanning backwards from EOF, so append cost stays flat as the
chain grows, and cross-process locks are acquired off the event loop so file
contention cannot stall unrelated async work.

### Wave failure and compensation

A wave is every step whose dependencies are satisfied; independent steps run in
one `asyncio.gather`. The wave runs to completion, then the orchestrator checks
results in plan order. If a step fails, the goal fails — but the report includes
**every** step that ran in that wave, not just the ones before the failure. A
`goal.failed` event is published alongside the typed `GoalResult`.

Because a wave runs to completion even when a sibling raises, **at most one
mutating step (`execute`/`contain`) may be ready in a wave**. `validate_plan`
assigns each step a topological layer and rejects a plan with two governed steps
in the same layer; `_execute` re-checks defensively before dispatching anything.
Serialization is explicit: a second governed step must depend on an earlier one.
Non-mutating siblings still run concurrently.

There is no automatic, model-invented undo. A governed step that changes the
world may declare `compensate` (agent, objective, action class, target, risk and
optionally an approval id). On failure the orchestrator walks successful
governed steps in reverse and dispatches each declared compensation through the
**same** runtime policy gate, approval store and evidence chain as the original
work:

| compensation outcome | meaning |
|---|---|
| `done` | policy ALLOW, undo executed, governance refs recorded |
| `hold` | a human decision is required; the approval id is returned |
| `denied` | policy or sender scope refused the undo; no execution |
| `failed` | handler error, timeout or an `ok=False` result |

Successful governed steps with no declared undo are listed in
`GoalResult.uncompensated`. That is deliberate: a partial wave is reported as
partial, never as a clean rollback. A governed step can carry `approval_ref`,
so an already-decided human approval can be re-dispatched by the planner
without inventing a new id.

## Solving fragmentation: read, correlate, govern

### Local operations dashboard

With the Docker mesh running, start the read-only local dashboard from the
project directory with `python dashboard/server.py`, then visit
`http://127.0.0.1:8090`. It reads `secrets/health_token.txt` on the server
and polls the existing health endpoints; the token is not sent to the browser.
Set `AGENT_HEALTH_TOKEN_FILE` to use a different token file, or
`AGENT_HEALTH_TOKEN` for an inline token. Host and port come from
`AGENT_HEALTH_HOST` / `AGENT_HEALTH_PORT` (environment or `.env`), so a moved
health endpoint does not appear as OFFLINE. Stop it with Ctrl+C. The dashboard
is a local prototype: it has no login and anyone with access to the local port
can see the status. Do not expose it to a network. Auth, timeout and transport
failures are labelled separately, and a transient outage keeps the last known
good values marked STALE instead of presenting guesses as live data. Connector
counts indicate configuration, not successful ingestion. Incident, evidence,
and metrics panels are placeholders, not live feeds; Prometheus is the proposed
next source and is not yet installed by this dashboard. The console follows the
UI/UX Pro Max dark operations-console direction: visible keyboard focus, 44px
tap targets, inline SVG icons, reduced-motion support, and no external font or
asset requests under its content-security policy. Live polling can be paused
and resumed or refreshed on demand; hidden tabs stop background work and keep
their earned retry backoff.

### Jira Cloud (read-only)

`connectors.yaml` is configured for `lyfe3493.atlassian.net`. It uses
Jira Cloud's GET-only enhanced issue search for issues updated in the last 30
days, and reads only the fields requested
in the URL. It maps each issue key as its entity; this does not automatically
associate tickets with infrastructure assets. It fetches only the first page
(up to 100 issues), and reports truncation when Jira supplies a next-page token.
Ingestion is on demand; the running health service does not poll periodically.

Create an Atlassian API token for an account with only the Jira access needed,
then set `JIRA_EMAIL` and `JIRA_API_TOKEN` in your PowerShell session. Do not
put the token in this file or in chat. With Docker Desktop running:

```powershell
docker compose --env-file .env.docker -f docker-compose.yml -f docker-compose.jira.example.yml up -d --build
docker compose --env-file .env.docker -f docker-compose.yml -f docker-compose.jira.example.yml exec mesh python -m agents ingest --connectors /app/connectors.yaml
```

The override passes credentials as container environment variables, which are
visible to Docker administrators. Restrict Docker access and use a dedicated,
least-privileged account. Check the ingest output's `errors` and `truncated`
fields; a healthy mesh does not establish that Jira authentication succeeded.

### Historical public-data exercise

Run `python -m agents.public_data --limit 100 --examples 5` to analyze recent
Washington State breach notifications and their related personal-information
breakdown, both listed on Data.gov. The command fetches at most 100
notifications and 5,000 detail rows from `data.wa.gov` over HTTPS, then joins
them using the publisher's notification ID. Each information type is counted
once per notification. Output flags sample and detail limits; the results are
not full-population statistics.

The tables are related views of the same collection, not independent sources.
These are historical public reports, not current incidents or managed assets.
The exercise is a separate read-only process: it does not invoke the mesh,
generate containment proposals, or change the Jira configuration. The optional
`connectors.public-data.example.yaml` demonstrates normalization of the main
table; run it in a separate workspace and do not propose actions on this data.

The mesh does not replace the incumbent tools. It reads from them, produces one
ranked operational picture, and routes any consequential action through the same
policy, approval and evidence chain.

```
observability --+
cloud cost -----+
vulnerability --+   read-only    +-------------+   deterministic   +------------+
SOC ------------+-- connectors -->| normalized  |-- correlation --->| ranked     |
identity -------+   (GET/file)    | Signal      |   entity + time   | incidents  |
network --------+                 +-------------+                   +-----+------+
...             +                                                       |
                                              proposal: CONTAIN sandbox/<entity>
                                                                        |
                                              policy -> HOLD -> human -> ALLOW
                                                                        |
                                              evidence (hash chain + MAC)
```

What it does:

- ingests each incumbent source through a read-only connector
- normalizes every record to one `Signal` schema
- resolves aliases (host, instance id, service account) with union-find
- clusters per entity inside a time window and scores risk from severity,
  source diversity, category diversity and attack/change patterns
- proposes one explicit containment target, then asks policy
- never executes containment without `ALLOW`; an AI recommendation is not authority

Run it offline:

```powershell
python -m agents ingest --fixtures fixtures/fragmentation
python -m agents demo-fragmentation --fixtures fixtures/fragmentation --mission demo-1
# HOLD: approve as a human in another process
$env:AGENT_SHARED_SECRET="<the same 32+ char secret>"
python -m agents approve apr-... --by alice
python -m agents demo-fragmentation --fixtures fixtures/fragmentation --mission demo-1 --approval apr-...
```

The fixture scenario merges `edge-02`, `i-0abc123` and `svc-edge-02` across ten
source types into one critical incident and proposes `CONTAIN sandbox/edge-02`.
Single-source distractors stay out of the incident.

Connector contract (enforced in `agents/connectors.py`):

- JSONL reads are confined to the connector root.
- HTTP is GET-only, HTTPS by default, host-allowlisted, redirect-refusing,
  size- and time-bounded.
- Tokens come from the environment, never YAML or evidence.
- Vendor payloads are untrusted data, never instructions.
- Secrets in attributes are redacted before storage or audit.

Point it at real tools by copying `connectors.example.yaml` to `connectors.yaml`
(or setting `AGENT_CONNECTORS_FILE`). Adding a source means adding a mapping, not
a new agent.

## How agents talk

One bus, one envelope type, four verbs:

| verb | message | semantics |
|---|---|---|
| `delegate()` | `TaskSpec` -> `TaskResult` | request/response on a correlation id |
| `ask()` | `Query` -> `QueryReply` | cheap side question |
| `emit()` | `Event` | broadcast, nobody waits |
| failure | `Failure` / `Handoff` | typed error or "needs a human" |

Direct messages go to `inbox.<agent>`; broadcasts go to `topic.<name>`.
Everything is validated by pydantic at both ends.

The envelope carries the USOC governance fields required by the in-repo
governance contract ([toolbox/CONSTITUTION.md](toolbox/CONSTITUTION.md),
[§3 of the architecture](docs/architecture.md#3-message-lifecycle)):
`mission_id`, `tenant_id`, `classification`, `policy_decision_ref`,
`authorization_ref`, `evidence_ref`, alongside `schema_version`, `message_id`,
`correlation_id`, `causation_id`, timestamps, sender/recipient, topic, hop,
attempt, deadline and integrity-relevant payload bounds.

A delegation looks like this in a subsystem you own:

```python
class MySubsystemAgent(SubsystemAgent):
    async def handle_task(self, spec, msg):
        telemetry = await self.delegate("acie", "Collect edge telemetry", inputs=spec.inputs)
        decision = await self.delegate(
            "seraphim",
            "Evaluate this containment action",
            target="sandbox/edge-01",
            action_class=ActionClass.CONTAIN,
            risk=RiskLevel.HIGH,
        )
        return TaskResult(ok=True, output=decision.output, data=telemetry.data)
```

No imports of other agents. No shared globals. Any coordinator can be restarted,
scaled or moved to another machine and the call still works.

## Plug in a real model

Point the mesh at any OpenAI-compatible endpoint — OpenAI, OpenRouter, vLLM,
Ollama, LiteLLM. Nothing else changes.

```powershell
$env:AGENT_LLM_BASE_URL="https://api.openai.com/v1"
$env:AGENT_LLM_API_KEY="sk-..."
$env:AGENT_MODEL="gpt-4.1-mini"        # analysis, coordination, assurance
$env:AGENT_MODEL_FAST="gpt-4.1-nano"   # light coordinators
python -m agents demo
```

With a real endpoint the orchestrator can use `LLMPlanner`, which plans a DAG
against the same capability cards. Without one it uses the deterministic
`RouterPlanner`.

### Live LLM rehearsal (staged rollout)

Before pointing the mesh at a live model, rehearse it. The harness sends
labeled prompts to the model, screens the *untrusted* output with the real
deterministic policy, and measures latency, tokens, prompt-injection hits and
HOLD/DENY accuracy — without executing anything:

```powershell
python -m agents llm-rehearsal                    # offline EchoLLM, zero network
python -m agents llm-rehearsal --live             # opt into AGENT_LLM_BASE_URL model egress
python -m agents llm-rehearsal --output exports/ # also write an oekp_bengal evidence export
```

The default path uses `EchoLLM` and makes no network call; `--live` is the only
way to reach `AGENT_LLM_BASE_URL`, and it fails closed if no base URL is set.
Rehearsal has **no tools, handlers, bus traffic, approval decisions, approval
consumption, egress guard calls or external writes** — it never constructs a
`Mesh` or calls a task handler. Cases live in
`fixtures/llm_rehearsal/cases.jsonl` (one labeled JSON object per line; pass
`--cases` to use your own).

Every observation is appended to a hash-chained evidence file
(`evidence/llm-rehearsal.jsonl` in the isolated shadow workspace) signed by the
same `build_signer(settings)` trust root as the mesh — HMAC or Ed25519 per
`AGENT_SIGNING_MODE`. Each record is hard-coded `rehearsal_only=true`,
`shadow=true` and `tainted=true`, with `llm-rehearsal` /
`untrusted-model-output` provenance, so BENGAL withholds
`trusted_for_execution`. A fresh run id and a per-record nonce sit inside the
signed payload, alongside the SHA-256 prompt/response digests, so a prior run
cannot be replayed as a new one. API keys and endpoint credentials are never
logged; URLs are redacted.

The policy screen (`PolicyEngine.screen_text`) is NFKC + casefold substring
matching against a defensive-only pattern list — it is a speed bump, not a
jailbreak detector. The `jailbreak-instruction` fixture deliberately expects no
screen hit to document this known limitation; regex/semantic detection is out
of scope here.

Governance-relevant environment settings:

```powershell
$env:AGENT_ALLOWED_TARGETS="sandbox/*,staging/*"   # policy allowlist
$env:AGENT_MISSION_ID="mission-2026-11-14"         # default mission contract
$env:AGENT_ROLE_PROFILE="finops_banking"           # active Starter Pack role view
$env:AGENT_MAX_TRANSACTION_AMOUNT="5000.00"        # hard per-transaction ceiling
$env:AGENT_TRANSACTION_CURRENCY="USD"
$env:AGENT_APPROVAL_QUORUM="2"                     # distinct verified humans
$env:AGENT_PHI_DETECTION_ENABLED="true"            # PII/PHI taint on every connector
$env:AGENT_BLOCK_TAINTED_EGRESS="true"             # signed sign-off for external egress
$env:AGENT_EVIDENCE_EXPORT_FORMATS="jsonl,oekp,bengal"
```

An explicit `AGENT_*` value overrides the active profile's control default;
`AGENT_ROLE_PROFILE=full_usoc` keeps all 93 roles. See `.env.example`.

## Security by default

The mesh is designed to be exposed to a CLI and a container orchestrator, not
just a laptop. The full threat model and deployment checklist are in
[SECURITY.md](SECURITY.md); the controls are:

| control | behaviour |
|---|---|
| message authentication | every message is signed and sender-bound (HMAC-SHA256 in dev, per-coordinator Ed25519 in production); tampered messages go to the DLQ and are never handled |
| fail-closed transport | `AGENT_BUS=redis` requires `AGENT_SHARED_SECRET` or `AGENT_SHARED_SECRET_FILE` at startup |
| approval identity | `AGENT_APPROVERS` allowlist (dev) or a signed registry bound to a key/`sub` and a `max_tier` (production); requester != approver, pending/decided TTL, mission scope |
| approval integrity | approval records are signed; unsigned or edited records are dropped |
| human credential | production approvals carry a detached Ed25519 signature or an Okta/Entra `id_token`, verified by HITL and logged into OEKP |
| cross-process approvals | the file store re-reads on change and writes under a lock for local dev; production uses tenant-partitioned Postgres with row-locked read-modify-write, so replicas cannot double-spend a nonce |
| persistent signing key | HMAC clusters fail startup without `AGENT_SHARED_SECRET(_FILE)` outside local dev; Ed25519/KMS modes use persistent asymmetric keys |
| tenant-partitioned Postgres | approvals, OEKP evidence and the task ledger are scoped by `tenant_id`; advisory locks assign DB sequence numbers and `SELECT ... FOR UPDATE` spans nonce spends |
| Redis hot cache | approvals are cached only for `AGENT_APPROVAL_CACHE_TTL_S`; the signed Postgres row remains the trust boundary |
| WORM evidence archive | signed, redacted ledger segments are written to S3 Object Lock with SSE and a future retention date; tenant chains and object keys are isolated |
| evidence integrity | hash-chained records plus a keyed MAC; recomputing a hash without the secret still fails |
| secret hygiene | file-based secrets, bearer/Basic/URL/query redaction in logs, masked Redis URLs in `doctor` |
| model transport | remote LLM endpoints must use TLS; loopback HTTP is allowed for local models |
| cache isolation | idempotency keys are scoped by agent, sender, tenant and mission |
| least privilege | workspace delete off by default; container runs non-root, read-only, with all capabilities dropped |
| capability-card integrity | startup SHA-256/HMAC pin over `subsystems.yaml`; fail closed when `AGENT_REQUIRE_SUBSYSTEMS_INTEGRITY=true` |
| topic ACLs | exact inbox topics for domain agents; wildcard publish only for `orchestrator`; wildcard subscribe only for the authenticated `oekp` audit sink |
| read-only service | `/health` and `/ready` only, counts-only and redacted; `/diagnostics` is admin-only and hidden without `AGENT_ADMIN_TOKEN` |
| role profiles | four Starter Packs filter capability-card role views only; all nine coordinators, ACLs, tiers and signed cards stay intact; unknown profile fails closed |
| transaction ceiling | `AGENT_MAX_TRANSACTION_AMOUNT` is a hard execution-time ceiling in the FinOps pack; approvals bind the exact amount/currency and cannot raise the ceiling |
| approval quorum | dual-approver HITL requires distinct verified humans; a partial quorum stays `PENDING`, cannot spend the nonce or be cached as an ALLOW, and the execution gate re-checks every decision |
| PII/PHI taint | every connector can classify health/personal data, raising it to `RESTRICTED` with monotone taint that survives correlation, approval and evidence |
| signed egress guard | tainted/restricted data cannot be published externally without a verified detached/OIDC sign-off bound to the exact destination and payload digest (Clinical pack) |
| shadow mode | `AGENT_SHADOW_MODE=true` runs real inputs through policy/HITL/evidence but never executes, never writes and never egresses; isolated workspace/approvals, distinct `shadow` evidence, BENGAL withholds `trusted_for_execution` |

```powershell
# Generate the cluster secret and health token.
python -c "import secrets; print(secrets.token_urlsafe(48))"

$env:AGENT_APPROVERS="alice,bob"
$env:AGENT_REQUIRE_APPROVER_ALLOWLIST="true"
$env:AGENT_BUS="redis"
$env:AGENT_SHARED_SECRET="<the generated secret>"
python -m agents serve --host 127.0.0.1 --port 8080
python -m agents probe --url http://127.0.0.1:8080/ready

# Pin the capability cards before production startup.
python -m agents integrity
$env:AGENT_SUBSYSTEMS_MANIFEST_HASH="<sha256 from integrity>"
$env:AGENT_REQUIRE_SUBSYSTEMS_INTEGRITY="true"
```

`AGENT_MESSAGE_AUTH=false` exists only for local debugging. Leave it on.

### Production trust mode

`AGENT_STRICT_PROD=1` removes every development fallback. `agents doctor` then
**fails closed** unless all of the following are mounted from a secret manager
(Secrets Manager, Vault, or a KMS sidecar) — inline JSON values and inline
signing keys are rejected:

* `AGENT_SIGNING_MODE=ed25519` with a public trust bundle
  (`AGENT_ED25519_PUBLIC_KEYS_FILE`) and a private key file or KMS signer for
  cluster-level approval/evidence records.
* `AGENT_BUS_PUBLIC_KEYS_FILE` — a `{agent_id: {kid: public_key}}` bundle
  mounted on every node. Only the node acting as an identity mounts that
  identity's private key (`AGENT_BUS_SIGNING_KEY_FILE`) or a KMS signer. A
  compromised low-privilege connector worker cannot forge bus messages as
  `seraphim`, `hitl`, or any other coordinator.
* `AGENT_APPROVER_REGISTRY_FILE`, its detached signature
  (`AGENT_APPROVER_REGISTRY_SIGNATURE_FILE`), and the trust key
  (`AGENT_APPROVER_REGISTRY_PUBLIC_KEY_FILE`, or the multi-key bundle file).
  The JSON maps `approver_id -> {"role": ..., "public_key": ..., "max_tier":
  "low|medium|high|critical"}`; `max_tier` is rechecked at execution time.

Generation and signing are offline steps:

```powershell
# 1. Registry signing key (never mounted on runtime nodes).
python -m agents keygen --private-key-file secrets/registry_private.pem --public-key-file trust/registry_public.hex --key-id registry-2026-11

# 2. Write trust/approvers.json: {"alice": {"role": "commander",
#      "public_key": "<alice Ed25519 public key hex>", "max_tier": "high"}}
# 3. Sign the exact registry bytes.
python -m agents sign-approvers --registry-file trust/approvers.json --key-file secrets/registry_private.pem

# 4. One Ed25519 keypair per coordinator; publish only the public halves in
#    trust/bus_public_keys.json and mount only the owning node's private key.
python -m agents keygen --private-key-file secrets/seraphim.pem --public-key-file trust/seraphim.hex --key-id seraphim-1
```

Every decision must carry a credential. Get the exact bytes to sign, sign them
offline with the approver's Ed25519 key, then submit the detached signature; or
pass an Okta/Entra `id_token` whose `sub` matches the registry id:

```powershell
python -m agents approval-payload apr-89d9db2cba --by alice --approve
python -m agents approve apr-89d9db2cba --by alice --signature-file /run/secrets/alice.sig
# OIDC alternative: get the per-approval nonce, put it in the login request,
# then submit the token the provider returns:
python -m agents approval-payload apr-89d9db2cba --by alice --approve --oidc-binding
python -m agents approve apr-89d9db2cba --by alice --id-token-file /run/secrets/alice.idtoken
```

HITL verifies the credential against the signed registry (or the configured
JWKS) and writes an `approval.verification` record to OEKP; failed attempts are
recorded with `verified: false`. An OIDC token must carry the per-approval
binding digest in its `nonce` claim (override the claim name with
`AGENT_APPROVAL_OIDC_BINDING_CLAIM`); a token for a different approval, target,
amount or decision is rejected. Configure OIDC with
`AGENT_APPROVAL_OIDC_ISSUER`, `AGENT_APPROVAL_OIDC_AUDIENCE`,
`AGENT_APPROVAL_OIDC_JWKS_URL` and optionally `AGENT_APPROVAL_OIDC_ROLE_CLAIM`.
See [SECURITY.md](SECURITY.md#production-trust-mode-agent_strict_prod) for the
full trust-bundle format, key custody, rotation and checklist.

### Shadow mode (observe-only deployment)

Shadow mode lets the mesh sit beside a live USOC process and consume the **same
real inputs**, running the full policy/HITL/evidence path for comparison —
without being able to change anything. Turn it on with `AGENT_SHADOW_MODE=true`
or use the dedicated command:

```powershell
python -m agents --workspace ./shadow-workspace shadow "Collect edge telemetry and evaluate a containment action"
```

Guarantees, enforced in code (not by convention):

* **No execution.** A policy `ALLOW` still produces its decision and evidence,
  but the agent handler is never called. The result carries
  `data.shadow=true` and `data.would_have=ALLOW`.
* **No external writes.** The Atlassian bridge is refused and `EgressGuard`
  denies every egress attempt unconditionally — even a perfectly signed,
  digest-bound sign-off cannot open the gate in shadow.
* **No state bleed.** The workspace is isolated under `<workspace>/shadow`, so
  shadow approvals and evidence can never be confused with — or spend — live
  approvals. Held actions still create real approval requests in that isolated
  store; `agents approve` is refused against a shadow workspace.
* **Mutating tools fail closed.** `workspace.write`, `workspace.delete` and
  `evidence.append` stay registered (registry validation requires it) but their
  handlers refuse every call. Read-only tools and read-only steps still work.
* **Distinct evidence.** Every record is marked `shadow: true` (covered by the
  hash/MAC). OEKP exports the flag; BENGAL reports `shadow_only` and withholds
  `trusted_for_execution`, so a shadow run can never be presented as proof of a
  real action.

The policy engine, approval rules, egress bindings and evidence signing are
unchanged — shadow only adds denials and a marker. Verify a run by checking that
`<workspace>/shadow/evidence/chain.jsonl` verifies and every record has
`"shadow": true`.

## Why this holds up

| risk | mechanism |
|---|---|
| unauthorized change | deterministic policy gate + human approval + target allowlist |
| AI overriding a DENY | policy decisions are code, not model output |
| hidden LLM in a deterministic coordinator | startup card/class check plus `BaseAgent` no-LLM guard; no model call is possible |
| sandbox rehearsal overwriting live artifacts | CSSSF `workspace.read`/`write` chrooted to `sandbox/` at the tool-runtime layer, with traversal and symlink escapes rejected |
| forged or edited bus messages | sender-bound HMAC in dev; per-coordinator Ed25519 in production, so no worker can sign as another identity; failures are quarantined in the DLQ |
| approval replay against another target or mission | approval must match action, target and mission |
| self-approval or an unknown approver | allowlist + requester != approver; in strict mode the signed registry is authoritative and a detached signature or `id_token` must bind the approver |
| approver exceeding their authority | signed registry `max_tier` is rechecked against the action risk at execution time |
| stale approval used later | pending approvals expire; policy denies an expired record |
| tampered approval file | signed records; invalid signatures are dropped on load |
| evidence tampering | hash chain + keyed MAC, independently verified |
| secret leakage in logs | bearer, Basic, URL and query credential redaction |
| offensive use of CYBER DEFENSE | prohibited-intent screen before the model call |
| redirect loops A->B->A | `hop` counter, capped at 8, enforced by the contract |
| stuck work | per-message deadline + timeout on every handler |
| broker redelivery | `idempotency_key` + result cache, so side effects happen once |
| transient provider failure | bounded exponential backoff before requeue (`AGENT_RETRY_BACKOFF_BASE_S`/`_MAX_S`) |
| partial wave failure | at most one mutating step per wave; whole wave reported, declared undos dispatched in reverse through policy/HITL, undeclared changes listed as `uncompensated` |
| indirect prompt injection through telemetry | monotone taint/provenance across every DAG hop; tainted actions need an approval that discloses the same chain |
| finance transaction beyond the mandate | hard per-transaction ceiling rechecked at execution time; amount and currency bound into the approval; no silent conversion or sum drift |
| one human approving twice / collusion | quorum counts distinct verified humans only; duplicate approvers rejected and each credential/tier rechecked at execution |
| PII/PHI leaking through a connector | detection on every connector raises classification to `RESTRICTED` and sets taint; label flows through correlation, proposal, approval and evidence as one monotone chain |
| tainted data exported externally | egress guard blocks bridge publication unless a verified detached/OIDC sign-off binds to the exact destination and payload digest; a name, unverified credential, mismatched sink or different payload never clears it |
| buyer pack widening privileges | profiles only filter role views; ACLs, tool scopes and tiers come from the signed cards and are identical in every pack |
| over-broad peer delegation | generated topic ACLs + mutually consistent sender/recipient and action/target scopes on every card |
| one slow agent | bounded per-agent queue and `max_concurrency` |
| runaway spend | per-step token budget, fast model tier for light agents |
| silent failure | typed `Failure`, dead-letter list, one trace id |
| bad plan | owners and dependencies validated before any step runs |
| long serial chains | independent **non-mutating** steps run in one `asyncio.gather` wave; governed steps serialize |

## Go durable

The in-memory bus is for one process. For anything real, use the Compose stack:

```powershell
Copy-Item .env.docker.example .env.docker
# Edit .env.docker: set AGENT_APPROVERS and a URL-safe REDIS_PASSWORD.

New-Item -ItemType Directory -Force secrets | Out-Null
python -c "import secrets; print(secrets.token_urlsafe(48))" | Set-Content -NoNewline secrets/agent_shared_secret.txt
python -c "import secrets; print(secrets.token_urlsafe(32))" | Set-Content -NoNewline secrets/health_token.txt

docker compose --env-file .env.docker up -d --build
docker compose --env-file .env.docker ps
python -m agents probe --url http://127.0.0.1:8080/ready --token (Get-Content secrets/health_token.txt -Raw)
```

The image runs as a non-root user with a read-only root filesystem, dropped
capabilities and `no-new-privileges`. Redis has a required password and lives on
an internal network; only the read-only health port is published, bound to
loopback. `/data` holds approvals and evidence on a named volume.

For a clustered deployment, see [`deploy/kubernetes/README.md`](deploy/kubernetes/README.md).
It provides hardened manifests (restricted Pod Security, read-only rootfs,
exec probes that read the health token from a secret file, default-deny
NetworkPolicies, a server-side dashboard proxy and HPAs for both the control
plane and workers). The production topology is fully stateless: approvals, OEKP
evidence and the unbounded task ledger are tenant-partitioned in Postgres;
Redis is a short-lived approval hot cache; and the signed, redacted ledger chain
is archived to S3 Object Lock (WORM). There is no `ReadWriteMany` volume and no
single-writer control-plane pod. Install the drivers with
`pip install -e '.[postgres,s3,redis]'`. An Atlassian egress proxy and a Helm
chart remain out of scope.

`AGENT_ENV=production` makes HMAC clusters fail startup without a persistent
shared signing key before the health port opens; `AGENT_STRICT_PROD=1` remains
the opt-in full Ed25519/registry mode. The one-off `usoc-doctor-preflight` Job
verifies Postgres, Redis and WORM connectivity and credentials before traffic is
ramped. The HTTP surface is still read-only: `/health`, `/ready` and
admin-only `/diagnostics`. Load tests for that surface and for tenant/nonce
contention live in [`tests/loadtest/`](tests/loadtest/README.md); no dispatch
endpoint is exposed to browsers or k6.

To use the fragmentation layer in the container, copy `connectors.example.yaml`
to `connectors.yaml`, review the mappings, uncomment the two read-only mounts in
`docker-compose.yml`, and set `AGENT_CONNECTORS_FILE=/app/connectors.yaml`.
Connector tokens still come from the environment or mounted secret files, never
from the YAML. Without that mount the mesh runs normally and reports
`fragmentation: false` on `/health`.

`RedisBus` uses one stream per topic and one consumer group per agent, so several
workers can share an agent id, unacked messages survive a crash, and
`reclaim_stale()` re-publishes a dead worker's pending work instead of only
counting it. `serve` runs that recovery loop, handles SIGINT/SIGTERM, and exposes
`/health` and `/ready`.

To run without Docker, install a local Redis with a password, set
`AGENT_BUS=redis`, `AGENT_REDIS_URL=redis://:PASSWORD@localhost:6379/0` and
`AGENT_SHARED_SECRET`, then `python -m agents serve`.

## Horizontal scaling

The mesh scales across processes by sharing Redis and one workspace. Nothing is
shared in memory.

```powershell
# control plane: all nine coordinators + the orchestrator
python -m agents serve --host 0.0.0.0 --port 8080

# workers: only the subsystems you want more of, no orchestrator
python -m agents worker --agents oekp --port 8091
python -m agents worker --agents oekp --port 8092
python -m agents worker --agents bengal --port 8093
```

Start multiple workers with the same `--agents` and different ports; the bus
delivers each message to exactly one replica via the per-agent consumer group.
Worker processes do not plan work: they consume, apply the policy gate, ask
peers, write evidence, and get out.

* **Idempotency** — `RedisStore` is shared across replicas, so a redelivered
  task produces one handler execution even with several workers on the same
  agent.
* **Evidence** — the append protocol re-reads the chain tail under the file
  lock before writing, so concurrent appenders on a shared volume cannot fork
  the chain (`test_two_processes_appending_to_the_same_chain_do_not_fork`).
* **Approvals** — `FileApprovalStore` serializes decisions through the same
  file lock, so two replicas cannot both approve the same request.
* **Cleanup** — `serve` and `worker` both run `reclaim_stale()`, recover a
  dead worker's pending messages, handle SIGINT/SIGTERM, and expose `/health`
  and `/ready` on their own port.

### Scaling on demand

`scale-advice` reads the live Redis backlog per agent (pending entries per
consumer group) and prints the desired replica count — clamped between
`AGENT_SCALE_MIN_REPLICAS` (default 1) and `AGENT_SCALE_MAX_REPLICAS`
(default 4), one replica per `AGENT_SCALE_MESSAGES_PER_REPLICA` pending
messages:

```powershell
python -m agents scale-advice             # human readable
python -m agents scale-advice --json --agents oekp,bengal
```

```text
oekp        pending=17   desired=3  (backlog 17 >= 8 per replica)
bengal      pending=0    desired=1  (steady state)
```

Workers publish no host ports; scaling them is `docker compose ... up -d
--scale oekp-worker=3` (or wire `scale-advice --json` into an HPA custom
metric). The loop reads real backlog, not a guess.

`docker-compose.workers.example.yml` shows the shape with a control plane and
scale-on-demand workers. Shared state lives on the `mesh-data` volume; Redis
streams split the load; unknown subsystem ids fail closed in `worker`.

Still single-host by design: approvals are a locked JSON file and evidence is
a JSONL chain on one volume. Moving to multiple machines means a transactional
approval store and immutable evidence storage — see
[PLAYBOOK](toolbox/PLAYBOOK.md) and the "Scaling out" notes in
[docs/architecture.md](docs/architecture.md).

## Layout

```
agents/
  contracts.py     Message union, governance envelope, plans, limits
  bus.py           Bus protocol, InMemoryBus, RedisBus
  runtime.py       BaseAgent: mailbox, governance gate, delegate/ask
  governance.py    deterministic policy engine, approvals, transaction/quorum gates
  evidence.py      append-only hash-chained, MAC-protected evidence, OEKP/BENGAL exports
  security.py      HMAC signer, secret loading, redaction, file locks, PII/PHI detection
  profiles.py      four Industry Starter Packs + control-default overrides
  storyboards.py   cross-vertical 3-minute Money Shot storyboards
  egress.py        signed egress guard for tainted/restricted data
  trust.py         production trust mode + detached/OIDC verification helpers
  oidc.py          OIDC token verification (JWKS, issuer, audience)
  service.py       read-only /health and /ready server
  usoc_agents.py   SERAPHIM/OEKP/BENGAL/HITL deterministic handlers
  shell.py         SHELL health, readiness, discovery and diagnostics
  orchestrator.py  planners + DAG execution
  registry.py      capability cards + deterministic routing
  llm.py           OpenAI-compatible + offline clients
  tools.py         sandboxed workspace tools + evidence tools
  store.py         idempotency store
  mesh.py          composition root
  __main__.py      CLI (demo, list, profiles, storyboard, export, doctor, integrity, serve, ...)
docs/architecture.md
subsystems.yaml
fixtures/
  fragmentation/  cyber/infra demo signals (Malicious IP -> CONTAIN prod-db-01)
  finance/        wire/ledger/merchant signals (FREEZE merchant-account-884)
  healthcare/     medication/lab/dispense signals (PAUSE automated-dispense-queue)
Dockerfile
docker-compose.yml
docker-compose.workers.example.yml
SECURITY.md
toolbox/           PLAYBOOK, CONSTITUTION (SpecKit-style SDLC), templates, scripts, docs index
tests/
```

See [docs/architecture.md](docs/architecture.md) for the message lifecycle,
governance sequence, failure matrix, scaling notes and implementation roadmap.

## Roles vs. runtime workers

The architecture defines 93 subsystem roles. This implementation runs **one
coordinator agent per subsystem** (9 runtime agents), each owning all roles for
its domain. That is intentional for a skeleton: fewer moving parts, one context
per subsystem, and role boundaries expressed in the capability card.

The open design decision is how many roles should become separate runtime
workers. The likely split is:

* **Separate workers** where isolation or load demands it — OEKP writers, HITL
  approval routing, CYBER DEFENSE detection jobs.
* **Capabilities inside the coordinator** where the work is a single reasoning
  pass — AICEE analysis, COHESION planning, BENGAL reporting.

The bus contract already supports either choice; only `subsystems.yaml` and the
worker entry point change.

## License

This repository is dual-licensed for selection: **Business Source License 1.1**
(see `LICENSE`) or **Elastic License 2.0** (see `LICENSE.ELASTIC-2.0`).
Choose one. Under BSL 1.1 the code becomes Apache 2.0 on 2030-11-15.

## Known limits

- `EchoLLM` performs no reasoning. Its output says so. Real work needs a real
  model endpoint.
- The approval flow is explicit: a held task is re-dispatched with its
  `approval_ref`. There is no automatic resume queue yet.
- Tool execution is a bounded two-round loop, not a full Reason+Act agent.
- `RedisBus` is exercised against a real Redis manually; unit tests use the
  in-memory adapter.
- Memory-bus mode is single process by design.
- Workspace tools are a sandboxed demo surface. Replace them with real connectors
  and keep the per-agent tool allowlist: that allowlist is the security boundary.
- The evidence chain is a local JSONL file. For production, ship it to immutable
  storage and monitor verification failures.
- The cluster secret is a long-lived trust root. Rotating it invalidates existing
  approval signatures and evidence MACs; [SECURITY.md](SECURITY.md) describes the
  migration procedure.
- Approval state is a local file by default. Multi-host deployments need shared
  storage that preserves atomic replace and locking, or a transactional store.
- The Redis password is passed in `AGENT_REDIS_URL` (environment), not a Docker
  secret. Keep Redis private and enable TLS for untrusted networks.
- The health endpoint has no rate limiting; bind it to loopback or put it behind
  a proxy.
- PII/PHI detection is heuristic (key and value patterns), not a clinical-grade
  classifier: it is a *classification* signal layered on top of field redaction,
  not a redaction substitute. Tune the patterns for your data and keep raw
  identifiers out of connector payloads where possible.
- The egress guard applies to bridge/decision publication. Other egress paths
  (operator-initiated network calls, logs) are outside its scope; keep the mesh
  network-segmented and review anything that can read the workspace.
- The transaction ceiling and quorum are profile defaults that an operator can
  override with explicit `AGENT_*` values. Treat those variables as governed
  configuration: the hard ceiling cannot be relaxed by an approval, but it can
  be raised by whoever controls the process environment.
