# USOC Agent Mesh

A working skeleton of the **Unified System Operations Center** agent architecture:
nine governed subsystem coordinators that communicate over one typed message bus,
wrapped in the deterministic controls USOC requires — a policy decision point,
human approvals, and an append-only evidence chain.

The master architecture calls for **93 subsystem roles plus 7 SHELL roles = 100
logical agents**. This repository implements the **9 subsystem coordinators** and
the SHELL as platform infrastructure, and declares all 93 roles on the capability
cards so the full surface is visible and routable. See
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

## Quickstart

```powershell
pip install -e ".[dev]"
python -m agents doctor          # config, registry, bus, model, security
python -m agents list            # nine cards and all 93 roles
python -m agents demo            # one governed goal end to end
python -m agents health          # SHELL health + diagnostics
python -m agents ingest --fixtures fixtures/fragmentation
python -m agents demo-fragmentation --fixtures fixtures/fragmentation
python -m pytest -q              # 177 tests, no network
```

The demo runs fully offline with a deterministic echo model, so the whole message
flow is visible before you wire a provider. It seeds
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
| 0:00–0:30 | `git log --oneline -3` and `python -m pytest -q` | Three commits: offline Ed25519 keys, multi-key trust bundle, approval-gated Atlassian bridge. Clean remote, 177 tests passing. |
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

The build-to-demo order, the non-negotiable rules, and what "done" means are
pinned in [toolbox/PLAYBOOK.md](toolbox/PLAYBOOK.md). The delivery
constitution and reusable scripts/templates live in [toolbox/](toolbox/README.md).

## The nine subsystems

| id | roles | job |
|---|---|---|
| `aicee` | 14 | Operational intelligence: anomalies, forecasts, root cause, recommendations. Advises only. |
| `acie` | 10 | Edge telemetry, network state, digital twin, connectivity and edge integrity. |
| `seraphim` | 12 | Policy decision point: identity, scope, risk, compliance, ALLOW/HOLD/DENY/CONTAIN. |
| `cohesion` | 9 | Mission intent, requirements, dependencies, priorities and cross-subsystem plans. |
| `bengal` | 9 | Independent assurance and validation against evidence. |
| `csssf` | 10 | Controlled sandboxes, change rehearsal, fault injection, simulation results. |
| `oekp` | 8 | Evidence, provenance, integrity hashes, audit trail, decision lineage. |
| `cyber_defense` | 11 | Defensive security: vulnerability assessment, triage, detection, containment planning. |
| `hitl` | 10 | Human governance: decision presentation, approval routing, escalation, oversight. |

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
quality and least-privilege tool access come from that file.

## Governance, not vibes

USOC's rule is that **an AI recommendation is not execution authority**. The
master workflow has twelve steps:

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
| approval is still pending | **HOLD** |
| approval was denied | **DENY** |
| approval has expired since it was decided | **DENY** |
| approval does not cover this action, target and mission | **DENY** |
| approval is approved and covers the action, target and mission | **ALLOW** + scoped authorization ref (TTL 900 s) |
| CYBER DEFENSE task matching prohibited offensive intent | **DENY** before the model runs |

Runtime behaviour is consistent: `HOLD` returns a typed `Handoff`, `DENY` returns
a typed `Failure`, `ALLOW` attaches `policy_decision_ref`, `authorization_ref`
and `evidence_ref` to the result.

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
process from the mesh; with Redis an explicit secret is mandatory.

### Evidence

`agents/evidence.py` writes an append-only JSONL chain. Each record hashes the
previous record, so modifying or deleting an entry breaks verification. OEKP
appends; BENGAL independently recomputes and reports the failure. Governed
execution results are recorded automatically by the runtime gate.

## Solving fragmentation: read, correlate, govern

### Local operations dashboard

With the Docker mesh running, start the read-only local dashboard from the
project directory with `python dashboard/server.py`, then visit
`http://127.0.0.1:8090`. It reads `secrets/health_token.txt` on the server
and polls the existing health endpoints; the token is not sent to the browser.
Set `AGENT_HEALTH_TOKEN_FILE` to use a different token file. Stop it with
Ctrl+C. The dashboard is a local prototype: it has no login and anyone with
access to the local port can see the status. Do not expose it to a network.
Connector counts indicate configuration, not successful ingestion. Incident,
evidence, and metrics panels are placeholders, not live feeds; Prometheus is
the proposed next source and is not yet installed by this dashboard.

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

The envelope carries the USOC governance fields required by the master prompt:
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

Governance-relevant environment settings:

```powershell
$env:AGENT_ALLOWED_TARGETS="sandbox/*,staging/*"   # policy allowlist
$env:AGENT_MISSION_ID="mission-2026-11-14"         # default mission contract
```

## Security by default

The mesh is designed to be exposed to a CLI and a container orchestrator, not
just a laptop. The full threat model and deployment checklist are in
[SECURITY.md](SECURITY.md); the controls are:

| control | behaviour |
|---|---|
| message authentication | every message is HMAC-SHA256 signed and sender-bound; tampered messages go to the DLQ and are never handled |
| fail-closed transport | `AGENT_BUS=redis` requires `AGENT_SHARED_SECRET` or `AGENT_SHARED_SECRET_FILE` at startup |
| approval identity | `AGENT_APPROVERS` allowlist, requester != approver, pending/decided TTL, mission scope |
| approval integrity | approval records are signed; unsigned or edited records are dropped |
| cross-process approvals | the file store re-reads on change and writes under a lock, so CLI approvals reach a running `serve` |
| evidence integrity | hash-chained records plus a keyed MAC; recomputing a hash without the secret still fails |
| secret hygiene | file-based secrets, bearer/Basic/URL/query redaction in logs, masked Redis URLs in `doctor` |
| model transport | remote LLM endpoints must use TLS; loopback HTTP is allowed for local models |
| cache isolation | idempotency keys are scoped by agent, sender, tenant and mission |
| least privilege | workspace delete off by default; container runs non-root, read-only, with all capabilities dropped |
| capability-card integrity | startup SHA-256/HMAC pin over `subsystems.yaml`; fail closed when `AGENT_REQUIRE_SUBSYSTEMS_INTEGRITY=true` |
| topic ACLs | exact inbox topics for domain agents; wildcard publish only for `orchestrator`; wildcard subscribe only for the authenticated `oekp` audit sink |
| read-only service | `/health` and `/ready` only, counts-only and redacted; `/diagnostics` is admin-only and hidden without `AGENT_ADMIN_TOKEN` |

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

## Why this holds up

| risk | mechanism |
|---|---|
| unauthorized change | deterministic policy gate + human approval + target allowlist |
| AI overriding a DENY | policy decisions are code, not model output |
| forged or edited bus messages | sender-bound HMAC; failures are quarantined in the DLQ |
| approval replay against another target or mission | approval must match action, target and mission |
| self-approval or an unknown approver | allowlist + requester != approver |
| stale approval used later | pending approvals expire; policy denies an expired record |
| tampered approval file | signed records; invalid signatures are dropped on load |
| evidence tampering | hash chain + keyed MAC, independently verified |
| secret leakage in logs | bearer, Basic, URL and query credential redaction |
| offensive use of CYBER DEFENSE | prohibited-intent screen before the model call |
| redirect loops A->B->A | `hop` counter, capped at 8, enforced by the contract |
| stuck work | per-message deadline + timeout on every handler |
| broker redelivery | `idempotency_key` + result cache, so side effects happen once |
| one slow agent | bounded per-agent queue and `max_concurrency` |
| runaway spend | per-step token budget, fast model tier for light agents |
| silent failure | typed `Failure`, dead-letter list, one trace id |
| bad plan | owners and dependencies validated before any step runs |
| long serial chains | independent steps run in one `asyncio.gather` wave |

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

## Layout

```
agents/
  contracts.py     Message union, governance envelope, plans, limits
  bus.py           Bus protocol, InMemoryBus, RedisBus
  runtime.py       BaseAgent: mailbox, governance gate, delegate/ask
  governance.py    deterministic policy engine, approvals
  evidence.py      append-only hash-chained, MAC-protected evidence
  security.py      HMAC signer, secret loading, redaction, file locks
  service.py       read-only /health and /ready server
  usoc_agents.py   SERAPHIM/OEKP/BENGAL/HITL deterministic handlers
  shell.py         SHELL health, readiness, discovery and diagnostics
  orchestrator.py  planners + DAG execution
  registry.py      capability cards + deterministic routing
  llm.py           OpenAI-compatible + offline clients
  tools.py         sandboxed workspace tools + evidence tools
  store.py         idempotency store
  mesh.py          composition root
  __main__.py      CLI (demo, list, doctor, integrity, serve, probe, health, approvals)
docs/architecture.md
subsystems.yaml
Dockerfile
docker-compose.yml
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
