# Security model and deployment guide

USOC is built so that an AI recommendation is never execution authority. This
document describes the controls that enforce that rule, how to deploy the mesh
safely, and the risks that remain.

## Trust boundaries

| boundary | trust |
|---|---|
| CLI operator | trusted; runs as the same OS user as the mesh when using the file approval store |
| subsystem agents | semi-trusted; they may be wrong or compromised, so every consequential action is gated |
| LLM endpoint | untrusted output; it never decides a policy outcome |
| bus | authenticated, not encrypted by default; run Redis on a private network or with TLS |
| workspace tools | sandboxed to `AGENT_WORKSPACE`; destructive delete is disabled by default |
| health endpoint | read-only and optionally bearer-protected; it accepts no work |

## Controls

### Message authentication

Every published message is signed with HMAC-SHA256 over a canonical JSON form
of the envelope, keyed by the cluster secret **and the sender identity**. A
message therefore cannot be edited, replayed from another sender, or forged
without the secret.

* `AGENT_MESSAGE_AUTH=true` by default.
* Memory bus: an ephemeral per-process secret is generated, so tests and demos
  are authenticated but nothing survives a restart.
* Redis bus: `AGENT_SHARED_SECRET` or `AGENT_SHARED_SECRET_FILE` is **required**;
  the process fails at startup rather than run unauthenticated.
* Messages that fail verification are acknowledged and quarantined in the DLQ
  (`mesh:dlq` on Redis, `bus.dlq` in memory). They are never handed to an agent.
* `AGENT_MAX_MESSAGE_AGE_S` optionally rejects old messages. It is off by
  default because at-least-once delivery can legitimately redeliver a message.

Set `AGENT_MESSAGE_AUTH=false` only for local debugging.

### Asymmetric signing (Ed25519)

`AGENT_SIGNING_MODE=ed25519` replaces the symmetric HMAC signer with Ed25519 for
messages, approvals and evidence records. The private key is kept offline in
CI/CD or inside a KMS; runtime nodes are intended to hold only the public
verification key.

Key custody:

* CI/CD or a KMS holds the private key. Runtime nodes mount public keys only,
  either as `AGENT_ED25519_PUBLIC_KEY(_FILE)` or, preferably, as a **trust
  bundle** in `AGENT_ED25519_PUBLIC_KEYS` / `AGENT_ED25519_PUBLIC_KEYS_FILE`.
* `python -m agents keygen` generates a PKCS#8 private key (`secrets/`) and a raw
  hex public key (`trust/`). Use `--key-id` and `--keyset-file` to write a
  `{kid: public_key}` bundle directly. `AGENT_ED25519_KEY_ID` selects the active
  signing key and labels it in logs and rotation records.
* With only a public key, the runtime is **verification-only**: it validates
  messages, approvals and evidence but refuses to sign, so an audit/read-only
  node cannot mint records.
* An active runtime signs through a KMS or signing sidecar by setting
  `AGENT_KMS_SIGN_URL` (and optionally `AGENT_KMS_SIGN_TOKEN_FILE`). The private
  key never enters the mesh process. The endpoint receives a `POST` containing
  the exact bytes to raw-sign with Ed25519 and returns
  `{"signature": "<hex or base64>"}`.
* A local private key (`AGENT_ED25519_PRIVATE_KEY_FILE`) is supported for CI
  signing jobs and development, and must not be mounted on runtime nodes.

Capability cards use a detached signature produced in CI:

```bash
python -m agents keygen --private-key-file secrets/ed25519_private.pem \
  --public-key-file trust/ed25519_public.hex \
  --key-id usoc-2026-11 --keyset-file trust/ed25519_keys.json
python -m agents sign-config --key-file secrets/ed25519_private.pem
# runtime:
AGENT_SIGNING_MODE=ed25519
AGENT_ED25519_PUBLIC_KEYS_FILE=/etc/usoc/ed25519_keys.json
AGENT_ED25519_KEY_ID=usoc-2026-11
AGENT_SUBSYSTEMS_SIGNATURE_FILE=/etc/usoc/subsystems.yaml.sig
AGENT_REQUIRE_SUBSYSTEMS_INTEGRITY=true
```

The bundle is a JSON object mapping key ids to hex (or PEM) public keys:

```json
{
  "usoc-2025-06": "3b4c...",
  "usoc-2026-11": "9f21..."
}
```

Startup verifies the exact file bytes against the detached signature before
parsing any capability card. Ed25519 signatures cover a domain-separated
envelope (`scope`, `identity`, canonical body), so a signature cannot be
replayed from one purpose or sender into another.

#### Zero-downtime rotation with a trust bundle

Every node verifies against **all** keys in the bundle, not just the active one.
Signatures do not carry a key id, so the verifier tries each trusted key until
one matches. That keeps in-flight waves and historical OEKP evidence valid
while a retired key remains in the bundle.

1. Generate the new keypair offline with a fresh `--key-id`.
2. Add the new public key to `ed25519_keys.json` (keep the old one). Deploy the
   updated bundle to every runtime node and confirm they are healthy. Both keys
   are now trusted, so records signed by either verify.
3. Switch the signer: set `AGENT_ED25519_KEY_ID` to the new kid and point the
   KMS/signing job at the new private key. New records use the new key while
   older records still verify.
4. After all in-flight waves have drained and no stored evidence, approvals, or
   capability-card signatures need the old key, remove it from the bundle and
   redeploy. Removing it too early breaks verification of those records.

A signing node fails closed if `AGENT_ED25519_KEY_ID` is absent from the bundle,
if a local private key does not match its public entry, or if the KMS returns a
`key_id` that is not trusted. HMAC-signed records are not valid in Ed25519 mode
(and vice versa), so switching *modes* still needs a maintenance window.

### Approval integrity

Consequential actions (`execute`, `contain`) require a human approval. The
approval store enforces:

* **Allowlist** — `AGENT_APPROVERS` names the humans who may decide. Set
  `AGENT_REQUIRE_APPROVER_ALLOWLIST=true` in production so an empty allowlist is
  a hard failure instead of "any name can approve".
* **Four eyes** — the requester can never approve their own request.
* **Expiry** — pending approvals older than `AGENT_APPROVAL_TTL_S` are denied,
  both when deciding and when the policy engine re-evaluates them. An approval
  that was granted also expires `AGENT_APPROVAL_TTL_S` after it was decided, so
  it is not a permanent grant.
* **Mission scope** — an approval issued for one mission cannot authorize
  another; an approval with no mission cannot authorize mission work.
* **Action and exact target binding** — an approval for `sandbox/node-1` cannot
  be replayed against `prod/db-primary`, and a wildcard target does not
  authorize concrete hosts.
* **Signatures** — records are signed with the cluster secret. Unsigned or
  tampered records are dropped when loaded; they never become an ALLOW.
* **Cross-process safety** — `FileApprovalStore` re-reads when the file changes
  and writes under a cross-process lock with an atomic replace, so a CLI
  approval is visible to a long-running `serve` without a restart.

The HITL agent routes approvals; it has no code path that decides them. An agent
identity is never a valid approver.

### Evidence

OEKP writes an append-only JSONL chain. Each record hashes the previous record
and carries a keyed MAC over its content. Editing a record, deleting one, or
recomputing the hash without the cluster secret all fail `evidence.verify()`.
BENGAL independently verifies the chain.

### Atlassian publishing bridge (opt-in)

`agents/atlassian_bridge.py` is the only outward publishing path for governed
decisions. It is **disabled by default** (`AGENT_ATLASSIAN_BRIDGE_ENABLED=false`). When
enabled, `agents approve` / `agents deny` publish *after* the decision is
persisted and appended to evidence:

* A Confluence page holds a signed publication envelope covering the exact
  approval record, evidence chain head and rendered ADR text. The signature
  uses the mesh signer under the `atlassian-publication` scope, so a reader can
  prove the ADR is the one the mesh decided. Taint/provenance disclosure is
  included for tainted chains.
* Optionally, a JSM request records the same decision and links back to the ADR.
* Publications are idempotent: the signature digest is recorded in
  `AGENT_ATLASSIAN_PUBLISH_STATE_FILE`, so a retry never creates a duplicate
  page or ticket. Use `python -m agents publish-decision <id>` to retry after a
  network failure; the mesh decision itself is unaffected by a publish error.

Configuration (a Bearer service-account key is recommended over a personal
token; the value always comes from env or a mounted file, never from config):

```bash
AGENT_ATLASSIAN_BRIDGE_ENABLED=true
AGENT_ATLASSIAN_BASE_URL=https://testing-bay.atlassian.net
AGENT_ATLASSIAN_API_KEY_FILE=/run/secrets/atlassian_api_key
AGENT_ATLASSIAN_CONFLUENCE_SPACE_KEY=SD
AGENT_ATLASSIAN_JSM_ENABLED=true          # requires a JSM project on the site
AGENT_ATLASSIAN_JSM_SERVICE_DESK_ID=...
AGENT_ATLASSIAN_JSM_REQUEST_TYPE_ID=...
```

Fail-closed rules: an incomplete config, a missing signer, a pending approval,
a corrupt state file or a non-2xx Atlassian response all raise `SecurityError`.
No AI recommendation can publish — publication requires an already-decided
approval with an approver identity and timestamp. The publishing tests use an
injected HTTP transport, so no live Atlassian writes occur in CI.

#### Verified write-gate and outbound-request properties

* **Write gate.** `publish-decision` loads the approval through
  `FileApprovalStore`, which verifies the signature of every persisted record
  on load. An attacker who edits the approval JSON on disk has that record
  dropped rather than published. The `approve`/`deny` path likewise publishes
  only a freshly signed, already-decided record. This guarantee requires
  signing to be enabled: `AGENT_MESSAGE_AUTH=false` makes `build_signer()`
  return `None`, in which case `FileApprovalStore` skips verification. Keep
  signing on in every environment that has the bridge enabled.
* **Outbound requests.** `AGENT_ATLASSIAN_BASE_URL` must use `https://`; every
  API path is a fixed string literal (`/wiki/rest/api/content`,
  `/rest/servicedeskapi/request`). The only dynamic path segment is a page id
  returned by Atlassian itself, never approval data. Approval-controlled
  values stay inside JSON payloads, and ADR markdown plus the serialized
  envelope are HTML-escaped before entering Confluence `<pre>` storage blocks,
  so neither path traversal nor stored XSS is reachable from an approval
  record. `httpx.request` does not follow redirects by default.
* **Trust boundary.** The base URL is operator-controlled configuration, not
  untrusted input; there is no separate host allowlist. Treat
  `AGENT_ATLASSIAN_BASE_URL` and the mounted API key as sensitive deployment
  configuration.

### Secrets

* Prefer `AGENT_SHARED_SECRET_FILE` and `AGENT_HEALTH_TOKEN_FILE` over inline
  environment variables; the Docker image uses mounted secrets.
* With the memory bus the signing secret is ephemeral per process. Set
  `AGENT_SHARED_SECRET` if `agents approve` must verify approvals written by a
  different process; with Redis an explicit secret is mandatory.
* `redact_text` and `redact_fields` strip bearer/Basic tokens, URL credentials
  and query-string secrets from structured logs.
* `python -m agents doctor` prints Redis URLs with the password masked.
* Never put a secret in `docker-compose.yml`, `.env.docker`, an image layer, a
  prompt, or an evidence record.

Generate secrets with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

```bash
python -c 'import secrets; print(secrets.token_urlsafe(48))'
```

### Model endpoint

A remote `AGENT_LLM_BASE_URL` must use `https://` so the API key is not sent in
clear text. Plain `http://` is accepted only for loopback (`localhost`,
`127.0.0.1`, `::1`), which covers local Ollama and vLLM. Set
`AGENT_ALLOW_INSECURE_LLM=true` only for a trusted local network such as
`host.docker.internal`.

### Idempotency cache

At-least-once delivery means agents deduplicate side effects with
`TaskSpec.idempotency_key`. The cache key is scoped by agent id, sender, tenant
and mission, so a shared store cannot return one agent's or tenant's result to
another.

### Filesystem and container

* Approvals and evidence files are created `0600`; their directory is `0700` on
  POSIX. Windows relies on the user profile ACL.
* `workspace.delete` is not registered unless `AGENT_ALLOW_WORKSPACE_DELETE=true`.
* The image runs as UID/GID `10001`, drops all Linux capabilities, sets
  `no-new-privileges`, and supports a read-only root filesystem. Only `/data`
  (volume) and `/tmp` (tmpfs) are writable.
* Redis is on an internal Compose network; only the health port is published,
  and it binds to `127.0.0.1` by default.

### Health and diagnostics endpoints

`GET /health` (liveness) and `GET /ready` (readiness) are the public-safe HTTP
routes. There is no work submission over HTTP. When `AGENT_HEALTH_TOKEN` or
`AGENT_HEALTH_TOKEN_FILE` is set, both routes require
`Authorization: Bearer <token>`; comparisons are constant-time.

Public responses are deliberately minimal: counts and status flags only. They
never include agent ids, internal bus endpoints, topology, configuration error
text, or secret values.

`GET /diagnostics` is a separate administrative surface. It returns topology,
per-agent detail and issue text, so it is only served when
`AGENT_ADMIN_TOKEN`/`AGENT_ADMIN_TOKEN_FILE` is configured; without an admin
token the route returns `404`. It requires its own `Authorization: Bearer`
token, and startup refuses a configuration where the admin token equals the
health token. Every diagnostics payload is passed through the redaction helpers,
so connection strings such as `redis://user:password@host` are masked even on
the authenticated route.

### Capability card integrity

`subsystems.yaml` is the IAM policy store for the mesh: it decides which tools,
recipients, senders, action classes and topics each subsystem may use. A runtime
edit is a privilege escalation, so startup verifies the file before parsing it
(`config.verify_subsystems_file`, called by `load_registry`).

Pin the exact bytes with one or more of:

* `AGENT_SUBSYSTEMS_MANIFEST_HASH` — SHA-256 of the file.
* `AGENT_SUBSYSTEMS_SIGNATURE` — HMAC-SHA256 over the file bytes keyed with
  `AGENT_SHARED_SECRET`.
* `AGENT_SUBSYSTEMS_SIGNATURE_ED25519` or `AGENT_SUBSYSTEMS_SIGNATURE_FILE` —
  detached Ed25519 signature produced offline in CI/CD. Runtime verifies it
  with the trusted key bundle (`AGENT_ED25519_PUBLIC_KEYS(_FILE)`) or a single
  `AGENT_ED25519_PUBLIC_KEY(_FILE)`, and never needs the private key. A card
  signed by a retired key keeps verifying while that key remains in the bundle.

Generate the values with `python -m agents integrity` (HMAC) or
`python -m agents sign-config` (Ed25519), or verify a deployment with
`python -m agents integrity --check`. Set
`AGENT_REQUIRE_SUBSYSTEMS_INTEGRITY=true` in production so a missing pin fails
closed instead of trusting the file on disk.

### SHELL infrastructure boundary

The seven SHELL roles are platform infrastructure, not domain agents. Because
they sit beneath the bus, a SHELL compromise bypasses SERAPHIM and HITL. Treat
every SHELL process as a privileged boundary:

* Run SHELL components in separate, minimal containers with `read_only: true`,
  `cap_drop: ALL`, `no-new-privileges`, and no shared PID namespace.
* Pin base and dependency images by digest; rebuild immutably and sign images
  (cosign/Sigstore) so a drifted SHELL image is rejected at admission.
* Keep signing and evidence keys outside the agent runtime: use an HSM/KMS or
  hardware-backed keystore, never a file readable by the mesh container.
* Deny SHELL containers direct Redis or agent-bus credentials; give them a
  dedicated, least-privilege control channel.
* Audit and alert on any SHELL restart, image change, or exec into a SHELL
  container.

### Confused-deputy / provenance taint

`TaskSpec` carries `provenance` (upstream subsystems) and `tainted` (any
untrusted telemetry or vendor payload). A governed action derived from tainted
provenance is not authorized by agent identity alone: SERAPHIM holds it for
explicit human approval and records the provenance and taint flag in the
evidence chain. This prevents poisoned ACIE telemetry -> AICEE recommendation ->
COHESION plan from becoming an executable action without a human seeing the
tainted chain.

### Capability scoping (least privilege)

Each subsystem declares an authorization matrix in `subsystems.yaml`:

* `allowed_recipients` — agents it may delegate to (`None` = any known agent).
* `allowed_senders` — agents that may task it (`None` = any sender).
* `allowed_action_classes` — action classes it may propose (`None` = any).
* `allowed_targets` — target patterns it may act on (`None` = any).

These are enforced at runtime in `BaseAgent` (`_require_delegation_allowed`,
`_require_recipient_allowed`, `_on_task`, `_authorize`) and fail closed: an
undeclared recipient, action class or target raises `AgentError` / returns a
policy DENY before any work runs. With no matrix declared (the default for
existing cards) behaviour is unchanged, so scoping is opt-in and backward
compatible.

### Topic ACLs and wildcards

The mesh derives bus ACLs from the capability cards at startup. A domain agent
may publish only to the exact `inbox.<recipient>` topics it is authorized for
(declared recipients plus the control plane), and may subscribe only to the
exact topics on its card. Wildcards are control-plane conveniences:

* Only `orchestrator` may use a wildcard **publish** rule.
* Only the audit sink (`oekp`) may subscribe to a wildcard, and only under
  `topic.*`.
* A wildcard audit subscription requires message authentication; an
  unauthenticated sink cannot be configured to observe every broadcast.
* Publishing to a wildcard topic (for example `topic.*`) is rejected.

`bus.validate_topic_acls` enforces these rules at construction time, and the
subscribe/publish paths re-check wildcard requests at runtime.

### Read-only connectors and correlation

The fragmentation layer ingests incumbent tools without giving the mesh write
access to them:

* Connectors are GET-only or file-read-only. There is no write path.
* `jsonl` paths are resolved under the connectors file's directory and may not
  escape it; symlinks and absolute paths outside the root are refused.
* `http_json` requires `https://` (plain HTTP only for loopback), a host
  allowlist (`allowed_hosts` or `AGENT_CONNECTOR_ALLOWED_HOSTS`), refuses
  redirects, caps response bytes and enforces a timeout.
* API tokens are read from the environment variable named by `token_env`. They
  are never stored in YAML, a signal or an evidence record.
* Vendor payloads are untrusted data. Sensitive attribute keys are redacted, and
  size/record limits bound memory and evidence growth.
* Correlation is deterministic platform code. A model may summarize its output,
  but it cannot change a score, merge entities or authorize an action.
* A containment proposal is still a governed `contain` action: policy first,
  human approval second, evidence third. A missing policy engine fails closed.

## Docker quickstart

```powershell
Copy-Item .env.docker.example .env.docker
# Edit .env.docker: set AGENT_APPROVERS and a URL-safe REDIS_PASSWORD.
#   python -c "import secrets; print(secrets.token_urlsafe(32))"

New-Item -ItemType Directory -Force secrets | Out-Null
python -c "import secrets; print(secrets.token_urlsafe(48))" | Set-Content -NoNewline secrets/agent_shared_secret.txt
python -c "import secrets; print(secrets.token_urlsafe(32))" | Set-Content -NoNewline secrets/health_token.txt

docker compose --env-file .env.docker up -d --build
docker compose --env-file .env.docker ps
docker compose --env-file .env.docker logs -f mesh
```

Verify readiness from the host (the token is read from the same settings file):

```powershell
$env:AGENT_HEALTH_TOKEN_FILE=".\secrets\health_token.txt"
python -m agents probe --url http://127.0.0.1:8080/ready
```

Stop without deleting state:

```powershell
docker compose --env-file .env.docker down
```

## Deployment checklist

- [ ] `AGENT_BUS=redis` and a password-protected Redis URL.
- [ ] `AGENT_SHARED_SECRET_FILE` points at a mounted secret of at least 32 chars.
- [ ] `AGENT_REQUIRE_APPROVER_ALLOWLIST=true` and `AGENT_APPROVERS` names real humans.
- [ ] `AGENT_SUBSYSTEMS_MANIFEST_HASH` or `AGENT_SUBSYSTEMS_SIGNATURE` is pinned and
      `AGENT_REQUIRE_SUBSYSTEMS_INTEGRITY=true`.
- [ ] `AGENT_ADMIN_TOKEN_FILE` is mounted if `/diagnostics` is needed, and it is
      distinct from the health token.
- [ ] `AGENT_ALLOWED_TARGETS` is as narrow as the mission allows.
- [ ] `AGENT_CONNECTOR_ALLOWED_HOSTS` lists only the incumbent APIs in use, and
      `AGENT_CONNECTORS_FILE` points at a reviewed mapping.
- [ ] Connector tokens live in environment/secret stores, never in YAML.
- [ ] `AGENT_ALLOW_WORKSPACE_DELETE` stays unset unless a workflow needs it.
- [ ] Health port is bound to loopback or a private network, with a token.
- [ ] `/data` is a persistent volume; evidence and approvals are backed up.
- [ ] Redis is private, or TLS is enabled and the URL uses `rediss://`.
- [ ] Logs are shipped somewhere tamper-resistant; `AGENT_LOG_JSON=true`.
- [ ] `python -m agents doctor` passes in the deployed environment.
- [ ] Approvals and evidence are tested end to end after any secret change.

## Secret rotation

The cluster secret is the trust root for messages, approvals and evidence MACs.
Rotating it invalidates signatures on existing approval records and makes older
evidence records fail MAC verification. Treat rotation as a migration:

1. Stop work submission and drain the bus.
2. Archive the current evidence file and approval store.
3. Start a new evidence chain and approval store under the new secret.
4. Record the rotation itself as the first evidence entry in the new chain.

Key-id based rotation (verifying with a previous key while signing with the
current one) is the next step if long-lived evidence must survive rotation.

## Residual risks

* The Redis password appears in the mesh container's environment. Docker secrets
  protect the shared secret and health token, but Redis URL credentials are still
  env-based. Use TLS and a private network, or a Redis ACL/credential provider.
* Approval state is a local file by default. In a multi-host deployment, put it on
  shared storage that preserves atomic replace and locking, or replace it with a
  transactional database store.
* There is no role-based authorization beyond the approver allowlist. Any process
  with the shared secret can sign as any agent; keep the secret to the mesh.
* The in-memory bus is single-process and provides no isolation between agents.
* The health endpoint has no rate limiting. Keep it on loopback or behind a proxy.
* `EchoLLM` is not a security boundary. Real model endpoints are untrusted and
  must remain outside the policy decision path.
* The evidence chain is local JSONL. For production, ship the head to immutable
  storage and monitor verification failures.
* Connector data is untrusted and may be adversarial. Correlation limits the
  blast radius (bounded fields, redaction, no writes), but a compromised source
  can still create false incidents. Treat proposals as recommendations and keep
  the human approver independent of the source system.
* The HTTP connector validates the URL host, not the resolved IP. Deploy it with
  egress controls or a proxy if the allowlisted host can resolve internally.
