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

Set `AGENT_MESSAGE_AUTH=false` only for local debugging. For production,
`AGENT_STRICT_PROD=1` replaces the symmetric cluster secret with
**per-coordinator Ed25519 keys**, so a node that can verify messages cannot
forge them as another identity; see
[Production trust mode](#production-trust-mode-agent_strict_prod).

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
  `AGENT_REQUIRE_APPROVER_ALLOWLIST=true` so an empty allowlist is a hard failure
  instead of "any name can approve". In `AGENT_STRICT_PROD=1` this is superseded
  by the [signed approver registry](#signed-approver-registry), where each name
  is bound to a public key (or OIDC `sub`) and a maximum risk tier.
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
* **Risk ceiling** — a HIGH approval may cover a LOW action of the same scope,
  but a LOW approval can never be escalated to HIGH or CRITICAL.
* **Single use** — every approval carries a `nonce` that is atomically spent on
  the first ALLOW. The runtime checks its idempotency cache *before* the policy
  gate so a redelivery cannot spend it again, and OEKP records the spent nonce
  as `approval.consumed` evidence so consumption is auditable.
* **Taint disclosure hash** — the approval commits to the provenance labels and
  taint flag the human reviewed. Relabelling a poisoned payload with a trusted
  source invalidates the approval.
* **Signatures** — records are signed with the cluster secret. Unsigned or
  tampered records are dropped when loaded; they never become an ALLOW.
* **Cross-process safety** — `FileApprovalStore` re-reads when the file changes
  and writes under a cross-process lock with an atomic replace, so a CLI
  approval is visible to a long-running `serve` without a restart.

The HITL agent routes approvals; it has no code path that decides them. An agent
identity is never a valid approver.

### Production trust mode (`AGENT_STRICT_PROD=1`)

The HMAC signer and the plain `AGENT_APPROVERS` allowlist are development
conveniences: anyone who can read the cluster secret can sign as **any**
coordinator, and a bare name is not proof that a human authorised anything.
Setting `AGENT_STRICT_PROD=1` removes those fallbacks. `agents doctor` then exits
non-zero unless the complete trust chain is configured from mounted files or a
KMS-backed signer; inline JSON keys, inline approver registries and inline shared
secrets are all refused. No cloud SDK is needed: the secret manager (AWS Secrets
Manager, Vault, a KMS sidecar) injects files or exposes a signing endpoint.

`validate_strict_prod()` checks, and `doctor` fails closed on:

* `AGENT_MESSAGE_AUTH` enabled and no ephemeral secret (a random in-memory key
  is never acceptable).
* `AGENT_SIGNING_MODE=ed25519` for cluster-level approval/evidence records.
* Managed key material — mounted public/private key files or a KMS signer, no
  inline key values.
* `AGENT_BUS_PUBLIC_KEYS_FILE` (mounted, not inline) with per-coordinator
  Ed25519 identities.
* `AGENT_APPROVER_REGISTRY_FILE`, its detached signature file and a mounted
  registry trust-key file.
* At least one approver in the signed registry with a valid `role`, public key
  and `max_tier`.

#### Per-coordinator bus identities

Every node mounts the same trust bundle
`AGENT_BUS_PUBLIC_KEYS_FILE` — a JSON object of the form:

```json
{
  "seraphim": {"seraphim-1": "<hex or PEM public key>"},
  "hitl":     {"hitl-1":     "<hex or PEM public key>"},
  "bengal":   {"bengal-1":   "<hex or PEM public key>"}
}
```

Only the node acting as a given coordinator mounts *that* identity's private
key (`AGENT_BUS_SIGNING_KEY_FILE`) or is allowed to call its KMS key
(`AGENT_BUS_KMS_SIGN_URL`). It declares which identity it is with
`AGENT_BUS_SIGNING_AGENT` and which key with `AGENT_BUS_SIGNING_KID`. The bus
signer/verifier interface is unchanged: messages are still signed by
`sign_message()` and checked by `verify_message()`, but the key is selected by
the `sender` field and the claimed `kid`.

The verifier fails closed when the sender is unknown, the `kid` is not in that
sender's bundle, `signature_alg` is not `ed25519`, the signature does not verify,
or (when `AGENT_MAX_MESSAGE_AGE_S` is set) the message is stale. The `alg` and
`kid` fields are set *before* signing and are part of the signed canonical
message, so an attacker cannot relabel a valid message with another identity's
key id or algorithm. A compromised low-privilege connector worker that mounts
only its own key therefore cannot forge a message as `seraphim`, `hitl`, or any
other coordinator — it has no signing slot for those senders.

Cluster-level records (approvals, evidence, ADRs, capability-card signatures)
continue to use `AGENT_SIGNING_MODE=ed25519` with the shared trust bundle from
the previous section; that key is independent of the per-coordinator bus keys.
Mount only the public halves on read-only nodes. A runtime that signs through a
KMS sidecar sends a `POST` of the exact canonical bytes with an optional
`Authorization: Bearer` token (`AGENT_BUS_KMS_SIGN_TOKEN_FILE`) and expects
`{"signature": "<hex or base64>", "key_id": "<kid>"}`. The mesh rejects a
response whose `key_id` is not in the trusted bundle or whose signature is not a
64-byte Ed25519 value. For cluster-level signing the equivalent settings are
`AGENT_KMS_SIGN_URL` / `AGENT_KMS_SIGN_TOKEN_FILE`.

Generate one keypair per coordinator offline and publish only the public halves:

```bash
python -m agents keygen \
  --private-key-file secrets/seraphim.pem \
  --public-key-file trust/seraphim.hex \
  --key-id seraphim-1
```

Rotation follows the bundle model already described: add the new public key to
the bundle on every node while keeping the old one, switch
`AGENT_BUS_SIGNING_KID` (and the KMS key), let in-flight messages drain, then
remove the retired key.

#### Signed approver registry

Replace plain names with a signed JSON document:

```json
{
  "alice": {
    "role": "commander",
    "public_keys": {"alice-1": "<hex or PEM public key>"},
    "max_tier": "high"
  },
  "bob": {"role": "operator", "public_key": "<hex key>", "max_tier": "medium"}
}
```

`public_key` (single) and `public_keys` (`{kid: key}`) are both accepted; both
support key rotation. `max_tier` uses the `RiskLevel` vocabulary
`low`/`medium`/`high`/`critical`. Sign the exact file bytes offline with a key
that is distinct from the bus keys:

```bash
python -m agents sign-approvers \
  --registry-file trust/approvers.json \
  --key-file secrets/registry_private.pem
# writes trust/approvers.json.sig
```

At startup the mesh verifies the signature over the raw bytes *before* parsing
any entry; a one-byte tamper fails closed. When a registry is configured it is
authoritative: configured plain names are intersected with registry ids, and an
unknown name can never approve. The registry trust key is a separate anchor, so
a worker that compromises its own bus key cannot add an approver.

`max_tier` is not just advisory: `PolicyEngine.evaluate` rechecks the approver's
ceiling against the action's risk at execution time. An approver whose registry
entry allows `high` cannot authorise a `critical` action even with an otherwise
valid decision record.

#### Human credentials

Strict mode requires every `approve`/`deny` decision to carry a credential. Two
forms are supported, selected by `AGENT_APPROVAL_CREDENTIAL_MODE`
(`detached`, `oidc`, or `either`):

* **Detached Ed25519 signature.** The human signs a canonical payload bound to
  the approval id, action, target, risk, mission, requester, decided-by identity
  and approve/deny decision. Print the exact bytes with
  `python -m agents approval-payload <id> --by alice --approve`, sign them with
  the approver's private key, and submit with
  `python -m agents approve <id> --by alice --signature-file /run/secrets/alice.sig`
  (or `--signature <hex>`). HITL verifies against the public key in the signed
  registry. A credential for a different approval, target, mission or decision
  does not verify.
* **OIDC / SSO id_token.** Set `AGENT_APPROVAL_OIDC_ISSUER`,
  `AGENT_APPROVAL_OIDC_AUDIENCE` and `AGENT_APPROVAL_OIDC_JWKS_URL` (Okta or
  Entra ID), then pass `--id-token-file` (or `--id-token`). The verifier checks
  the JOSE header (`RS256`/`ES256`), `kid`, signature, issuer, audience, `exp`
  and `nbf`, and binds the configured `sub` claim (default `sub`, override with
  `AGENT_APPROVAL_OIDC_SUB_CLAIM`) to the registry id. If
  `AGENT_APPROVAL_OIDC_ROLE_CLAIM` is set, the token must also contain the entry's
  `role`. JWKS responses are cached briefly; no JWT library is added.

HITL writes an `approval.verification` record to OEKP for every verified
credential, including the method, key id/fingerprint or token subject, role and
max tier. Rejected attempts are recorded with `verified: false`. The verification
result is stored on the signed approval record and included in the
`approval.decided` evidence, so an auditor can see exactly how identity was
established without access to the raw credential.

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
* In `AGENT_STRICT_PROD=1` the only acceptable inputs are mounted key/registry
  files or a KMS signing endpoint. Inline JSON keys, inline approver registries
  and inline shared secrets are rejected so nothing sensitive leaks into env
  files, process listings or logs.
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

### Capability-card authorization matrix

The pins above protect the bytes; the fields inside the cards decide privileges.
Every shipped card declares `allowed_recipients`, `allowed_senders`,
`allowed_action_classes` and `allowed_targets`; `None` means unrestricted and is
not used in the shipped file. `acls_from_specs` turns recipients and
`subscribes` into exact topic rules, while `BaseAgent._require_delegation_allowed`
and `_authorize` enforce the matrix at dispatch time. The shipped cards are
mutually consistent: if A may delegate to B, B must name A in
`allowed_senders`, and a test fails the build if that invariant breaks.

Only CSSSF (`execute`, `sandbox/*`) and CYBER DEFENSE (`contain`, `sandbox/*`
and `staging/*`) can accept governed actions. Every other coordinator is
limited to read-only or recommend work. Treat a new card as an IAM policy, not
as documentation: widening `allowed_recipients` or `allowed_action_classes` is
a privilege change and needs a signature refresh.

### Deterministic tiers are implementation facts

`model_tier: deterministic` is not a cost label. It asserts that the subsystem
has no LLM path at all. `Mesh.start` checks that each deterministic card maps to
a Python class declaring `deterministic = True` (and the reverse), so a card
cannot quietly claim determinism while using the generic handler. At runtime,
`BaseAgent.handle_task`, `handle_query`, `_run_tool` and the model-selection path
refuse deterministic specs before any provider call. SERAPHIM, BENGAL, OEKP and
HITL are shipped this way; no model, even an offline echo model, is in the loop.

### CSSSF tool confinement

CSSSF remains an LLM-backed coordinator, but its capability card declares
`tool_scopes` for `workspace.read` and `workspace.write` as `sandbox/`. The mesh
builds CSSSF a separate `ToolRegistry` whose path arguments are normalized and
anchored at `workspace/sandbox/`:

* `foo` and `sandbox/foo` both resolve under the sandbox, so prompts do not need
  to know the real workspace layout.
* Absolute paths and `..` are rejected before the base handler runs. A path
  such as `evidence/chain.jsonl` is interpreted as
  `sandbox/evidence/chain.jsonl`; it can never address the live prefix.
* The final path is resolved after joining, so a symlink under `sandbox/` that
  points to a live artifact is rejected as an escape.
* `workspace.list` defaults to the sandbox root instead of the workspace root;
  an omitted argument cannot widen the search.

Other agents keep the unscoped registry. This is deliberately enforced in the
tool runtime, not by system-prompt wording or by the policy target allowlist: a
successful sandbox rehearsal cannot overwrite the evidence and telemetry that
BENGAL and OEKP later read.

### Mutating steps are serialized

`asyncio.gather(..., return_exceptions=True)` deliberately lets a whole wave run
to completion. That is good for honest failure reporting but dangerous for
side effects: if two governed steps shared a wave, one could commit while the
other failed, leaving split state before the fail-fast boundary. `validate_plan`
therefore computes each step's topological layer and rejects a plan with more
than one `execute`/`contain` step in a layer. `Orchestrator._execute` repeats the
check before dispatch so an injected or post-plan mutation cannot reintroduce
the hazard. A second mutating step must name an earlier step in `depends_on`;
read-only siblings still run concurrently.

### Compensation is governed work

An undo is never inferred from model prose. A governed step must declare a
structured `compensate` with its own agent, objective, action class, target and
optional human approval. On a wave failure the orchestrator walks successful
governed steps in reverse and dispatches each declared undo as an ordinary task,
so it passes through the same sender check, policy decision point, approval
store, provenance tracking and evidence chain as the original action.

A compensation that needs a human returns `HOLD` with the new approval id; it
is reported as pending, never silently skipped or self-approved. A compensation
that policy refuses is `denied` without a model call. Successful governed steps
with no declared undo are listed in `GoalResult.uncompensated`, so a partial
wave is never presented as a clean rollback. `goal.failed` and `goal.compensated`
events make the outcome observable to audit consumers.

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

Propagation is monotone, not best-effort. `Orchestrator._run_step` unions the
provenance and taint of every dependency into the downstream `TaskSpec`, and
`BaseAgent` copies that context onto the returned `TaskResult` even when a
handler emits a default-clean result. An intermediary cannot launder poisoned
input by re-delegating under a different agent identity: the governed task
still carries the original connector provenance and `tainted=True`. A clean
approval is rejected with a `taint disclosure` denial; only a fresh approval
issued for the same tainted chain can authorize the action. Failed results and
step records carry the same metadata so compensation and audit stay honest.
Idempotency keys are also scoped by taint and provenance, so a clean cache entry
cannot be replayed for a tainted re-dispatch of the same objective.

### Industry Starter Profiles

Four buyer-facing packs ship with the mesh: `core` (12 roles),
`finops_banking` (24), `clinical_healthcare` (22) and `full_usoc` (93, the
default). A profile is a **view filter**, not an execution boundary: all nine
coordinators keep running with their signed capability cards, topic ACLs, tool
scopes and risk tiers. `apply_role_profile()` narrows only each card's `roles`
list; it never widens a topic, adds a tool or changes a tier. This means a profile
cannot grant a privilege the full mesh does not already have.

Selection is fail-closed. `get_profile()` and `apply_role_profile()` reject an
unknown profile id with `RegistryError` rather than silently falling back to
"all roles", and every named role is validated against the signed card at import
and at startup. Profile control defaults (transaction ceiling, quorum, PII/PHI
detection, egress blocking, export formats) are applied only when the matching
explicit `AGENT_*` variable is unset, so an operator's setting always wins.
Treat those environment variables as governed configuration.

### Transaction ceilings and dual-approver quorum

The FinOps & Banking profile adds two hard controls:

* `AGENT_MAX_TRANSACTION_AMOUNT` is a **hard execution-time ceiling**, not a
  recommendation. `PolicyEngine.evaluate()` parses the transaction amount with
  `parse_money()` (strict finite, non-negative, at most four decimal places) and
  DENIES anything above the ceiling **before** an approval is consulted. A human
  approval can never authorize a larger sum. `AGENT_TRANSACTION_CURRENCY` pins
  the only accepted currency, so a foreign-currency amount is DENIED instead of
  silently converted.
* The approval request records the exact amount and currency. Re-dispatching the
  same approval against a different sum or currency is DENIED by the binding
  check even if both values are individually within policy.
* `AGENT_APPROVAL_QUORUM=2` requires two **distinct verified humans**. A single
  decision leaves the record `PENDING`, so evaluation still HOLDs; a duplicate
  approver is rejected by `ApprovalStore.decide()`. The execution-time check
  re-verifies every individual decision (credential, `max_tier` risk ceiling,
  nonce, TTL and scope) before ALLOW, so a partially-approved or stale quorum
  cannot slip through. The existing single-approver fallback remains the default
  for other profiles.
* A partial quorum is not a consumable verdict. `ApprovalStore.consume()` refuses
  any record that is not `APPROVED` with the required number of distinct signed
  decisions, so the first human's signature cannot spend the single-use nonce.
  The runtime also publishes a `Handoff` for a HOLD and never writes that HOLD to
  the idempotency cache, so a redelivery re-evaluates the current quorum instead
  of replaying a stale terminal answer.

### PII/PHI classification on every connector

The Clinical & Healthcare profile enables `AGENT_PHI_DETECTION_ENABLED`. Each
connector record is scanned by `detect_sensitive_data()` for health and personal
identifier keys/values (for example patient id, diagnosis, MRN, SSN, email). A
positive label raises classification to `RESTRICTED`, sets `tainted=True`, and
attaches `sensitive_labels`. This is a **classification** signal layered on top
of existing field redaction, not a redaction substitute.

The label is monotone: provenance and sensitive labels survive correlation, the
proposal, the approval request (`taint_hash` disclosure) and the evidence chain.
Restricted work requires a `mission_id`, and a clean approval cannot authorize a
tainted chain. The detector is heuristic (pattern based), not a clinical-grade
classifier; tune it for your data and keep raw identifiers out of payloads where
possible.

### Signed egress guard

Connectors are read-only, but publishing a decision to the Atlassian bridge (or
another external sink) moves governed data outside the mesh. With
`AGENT_BLOCK_TAINTED_EGRESS=true`, `EgressGuard.assert_allowed()` blocks any
tainted or `RESTRICTED` publication unless a sign-off satisfies **all** of:

* the approval record's status is `APPROVED` (not `PENDING`/`DENIED`);
* its `egress_target` equals the exact destination endpoint (for example
  `atlassian:https://example.atlassian.net`);
* its `egress_payload_digest` equals the digest of the exact decision payload
  being published; and
* it carries a verification with `verified=True` whose method is `detached`
  (Ed25519) or `oidc`.

Both binding fields are set when the policy engine creates the approval and are
covered by the signed approval record and by `approval_credential_payload()`, the
bytes the human signs. `decision_payload_digest()` includes only immutable
request-time fields (scope, target, mission, provenance, taint disclosure, amount
and currency), so the digest is stable between request and publication. A
governed-action target such as `sandbox/<noun>` in `also_targets` does **not**
satisfy the egress binding: an approval for one internal action cannot be reused
to publish to a different external sink. A bare approver name, an unverified
credential, a mismatched destination, a different payload or a pending record
never clears the gate. Use
`python -m agents publish-decision <id> --signoff <approved-id>`. The guard is
wired into decision publication/bridge publication; other network paths are
outside its scope, so keep the mesh network-segmented.

### Shadow mode (observe-only)

`AGENT_SHADOW_MODE=true` (or `python -m agents shadow`) is a deployment-level
kill switch for *all* consequential side effects while preserving decision
fidelity. It is designed for running the mesh alongside a live USOC process on
real inputs. Shadow is strictly weaker than live — it can only add refusals:

* **Execution:** `BaseAgent._on_task_body` still evaluates policy and still
  emits `shadow.task`, `policy.decision` and `shadow.decision` evidence, but on
  an `ALLOW` it returns a `TaskResult` with `data.shadow=true` **before**
  `handle_task`; no tool, target or downstream sink is touched. `HOLD` and
  `DENY` behave exactly as in live mode.
* **State isolation:** `Mesh` resolves its workspace to `<workspace>/shadow`,
  so approvals, evidence and publish state are physically separate. A shadow
  approval store cannot spend a live nonce. `agents approve`/`deny` and
  `publish-decision` are refused against a shadow configuration.
* **Mutating tools:** `build_default_tools(..., allow_write=False)` keeps
  `workspace.write`, `workspace.delete` and `evidence.append` registered but
  makes their handlers raise `ToolError`; `BaseAgent._run_tool` independently
  blocks the same names. Read-only tools remain available.
* **Egress and bridge:** `EgressGuard(shadow=True)` raises before any signoff
  check, so no payload leaves the process. `build_bridge()` returns `None` and
  `AtlassianBridge.__init__` raises even when the bridge is otherwise fully
  configured — no HTTP call, no Confluence page, no JSM request.
* **Evidence:** each `EvidenceRecord` carries `shadow: bool` (hashed and MAC'd).
  OEKP exports the flag, BENGAL totals `shadow_only`, and BENGAL withholds
  `trusted_for_execution` for any chain containing shadow records — exactly as
  it does for rehearsals and unmarked sandbox-origin records.

Shadow mode does **not** relax policy, quorum, target/digest binding or signing.
The negative guarantees are covered by `tests/test_shadow_mode.py`.

### Compliance exports

The canonical store remains an append-only, hash/MAC-chained JSONL file.
`render_export()` produces read-only views in `jsonl`, `oekp`, `bengal` and
`oekp_bengal` formats and fails closed if the chain is not verifiable (`bengal`
sets `assurance=FAIL` when verification fails). The FinOps & Banking and Clinical
& Healthcare profiles enable OEKP/BENGAL export formats by default; an explicit
`AGENT_EVIDENCE_EXPORT_FORMATS` or `agents export --format ...` overrides it.

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

In addition to the topic patterns above, two control-plane broadcasts are
pinned to a single identity: `policy.verdict` may only be published by
`seraphim`, and `approval.granted` only by `hitl`. The rules are derived from
the mounted message authority; in strict production they also pin the exact
signing `kid`, and `agents doctor` fails closed if either topic has no managed
kid. The check runs *after* signing on the trusted `signing_kid`, in both buses,
and Redis re-applies it on receive so a direct stream injection is quarantined
to `mesh:dlq` instead of being delivered.

### Governance red team

`tests/test_governance_redteam.py` covers the four adversarial paths that matter
once work is spread across workers. Every case is expected to fail closed; the
suite runs in normal CI alongside the rest of the tests.

#### Approval replay and scope creep

An approval is a signed, single-use credential, not a bearer token. On the
first ALLOW the policy engine atomically spends its `nonce` through
`ApprovalStore.consume()`; a second evaluation is DENIED with
`already consumed`. Every ALLOW also appends an `approval.consumed` record to
the evidence chain through OEKP with the approval id, nonce, action, target,
risk and taint disclosure, so consumption is auditable rather than
process-local.

Before anything is consumed, the engine rechecks the signed scope at execution
time: action and target, mission, risk ceiling, TTL (from decision time) and
taint disclosure hash. A low-risk approval cannot be escalated to critical; a
higher-risk approval may cover a lower-risk variant of the same scope. The
`taint_hash` commits to the set of provenance labels and the taint flag shown
to the human, so swapping a poisoned source for a "trusted" label invalidates
the approval. Failed scope-creep attempts do not spend the nonce: the correct
scope still succeeds afterwards.

#### Taint laundering

Taint is a gate, not a label. A tainted `read_only`, `recommend` or `simulate`
step is held for HITL just like `execute`/`contain`: a poisoned connector
payload cannot be summarised into a clean-looking step that seeds a later
mutating step. `PolicyEngine` forces HOLD, the HITL request records the full
provenance and taint hash, and the runtime fails closed when a tainted task
reaches an agent with no policy engine. Taint and provenance survive
`TaskResult` and are folded into idempotency keys, so a clean cached result
cannot be replayed for a tainted re-dispatch of the same objective.

#### Sandbox spoofing

Evidence records carry `origin` (derived from the authenticated message
sender, never from task inputs), `provenance`, `tainted` and `rehearsal_only`,
all covered by the hash/MAC chain. OEKP rejects any sandbox-origin record that
is not explicitly marked `rehearsal_only` with
`Failure(code="rehearsal_only")`. BENGAL counts rehearsal-only and unmarked
sandbox records and sets `trusted_for_execution=false` when either is present,
even when the structural chain verifies. Rehearsals are visible to auditors but
can never be presented as production execution proof.

#### Cross-worker impersonation

`policy.verdict` and `approval.granted` are pinned to `seraphim` and `hitl`
respectively, including the signing `kid` in strict production. Publish checks
run after signing in both the memory and Redis buses; the runtime also fails
early in `_publish()`. Redis rechecks on receive and quarantines a forged
stream entry, closing the bypass where a sibling worker writes directly to the
stream with its own valid key. A worker that mounts only its own coordinator
key therefore cannot emit a verdict or grant as another identity.

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
- [ ] `AGENT_SHARED_SECRET_FILE` points at a mounted secret of at least 32 chars
      (dev/HMAC only; strict mode uses Ed25519 instead).
- [ ] `AGENT_REQUIRE_APPROVER_ALLOWLIST=true` and `AGENT_APPROVERS` names real humans
      (dev/HMAC only; strict mode uses the signed registry below).
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
- [ ] For shadow deployments: `AGENT_SHADOW_MODE=true`, a dedicated
      `<workspace>/shadow` path, bridge disabled, and egress denied end to end;
      verify every chain record is `shadow: true` and BENGAL reports
      `trusted_for_execution=false`.
- [ ] `/data` is a persistent volume; evidence and approvals are backed up.
- [ ] Redis is private, or TLS is enabled and the URL uses `rediss://`.
- [ ] Logs are shipped somewhere tamper-resistant; `AGENT_LOG_JSON=true`.
- [ ] `python -m agents doctor` passes in the deployed environment.
- [ ] Approvals and evidence are tested end to end after any secret change.

For `AGENT_STRICT_PROD=1`, additionally:

- [ ] `AGENT_SIGNING_MODE=ed25519` with a mounted `AGENT_ED25519_PUBLIC_KEYS_FILE`
      and a private key file or KMS signer for cluster-level records.
- [ ] `AGENT_BUS_PUBLIC_KEYS_FILE` is mounted on every node; each node mounts
      only the private key (or KMS key id) for its own `AGENT_BUS_SIGNING_AGENT`.
- [ ] `AGENT_MAX_MESSAGE_AGE_S` is set to a small replay window compatible with
      your at-least-once delivery.
- [ ] `AGENT_APPROVER_REGISTRY_FILE`, `AGENT_APPROVER_REGISTRY_SIGNATURE_FILE`
      and a mounted registry trust-key file are present; every approver has a
      reviewed `role`, public key and `max_tier`.
- [ ] `AGENT_APPROVAL_CREDENTIAL_MODE` is `detached`, `oidc` or `either`, and
      production decision flows supply `--signature(-file)` or
      `--id-token(-file)`. OIDC mode has issuer, audience and JWKS URL configured
      with role-claim mapping if roles are enforced.
- [ ] `python -m agents doctor` reports `strict production ... managed keys,
      signed approvers and per-coordinator signatures` and exits 0.

## Secret rotation

The cluster secret is the trust root for messages, approvals and evidence MACs.
Rotating it invalidates signatures on existing approval records and makes older
evidence records fail MAC verification. Treat rotation as a migration:

1. Stop work submission and drain the bus.
2. Archive the current evidence file and approval store.
3. Start a new evidence chain and approval store under the new secret.
4. Record the rotation itself as the first evidence entry in the new chain.

With `AGENT_SIGNING_MODE=ed25519` and `AGENT_STRICT_PROD=1`, key-id based
rotation is supported for both cluster-level records and per-coordinator bus
keys: keep the old public key in the trust bundle while signing with the new
`AGENT_ED25519_KEY_ID` / `AGENT_BUS_SIGNING_KID`, let in-flight waves and stored
records drain, then remove the retired key from the bundle. See the rotation
steps in the sections above.

## Residual risks

* The Redis password appears in the mesh container's environment. Docker secrets
  protect the shared secret and health token, but Redis URL credentials are still
  env-based. Use TLS and a private network, or a Redis ACL/credential provider.
* Approval state is a local file by default. In a multi-host deployment, put it on
  shared storage that preserves atomic replace and locking, or replace it with a
  transactional database store.
* In HMAC/dev mode there is no role-based authorization beyond the approver
  allowlist, and any process with the shared secret can sign as any agent; keep
  the secret to the mesh. `AGENT_STRICT_PROD=1` addresses both: per-coordinator
  Ed25519 keys stop a worker signing as another identity, the signed registry
  binds an approver to a key/`sub` and `max_tier`, and every decision must carry
  a verified detached signature or id_token.
* The in-memory bus is single-process and provides no isolation between agents.
* The health endpoint has no rate limiting. Keep it on loopback or behind a proxy.
* `EchoLLM` is not a security boundary. Real model endpoints are untrusted and
  must remain outside the policy decision path.
* The evidence chain is local JSONL. For production, ship the head to immutable
  storage and monitor verification failures.
* `taint_hash` commits to provenance labels and the taint flag, not to the
  payload bytes. Two different payloads carrying the same labels are not
  distinguishable at approval time; keep upstream provenance labels precise.
* Restricted-topic `kid` pinning depends on per-coordinator managed keys. In
  dev/HMAC mode the sender check still applies, but that mode is not a
  production trust boundary.
* Approval consumption is atomic only against the configured store.
  `FileApprovalStore` relies on cross-process file locking, so shared storage
  must preserve it; use a transactional store for multi-host deployment.
* BENGAL's verification is structural. It reports rehearsal and sandbox-origin
  metadata and withholds `trusted_for_execution`, but it does not semantically
  prove that a governed action actually happened. Keep external execution
  audit independent of the evidence chain.
* Shadow mode suppresses execution, mutating tools and egress in-process; it is
  not a network-level sandbox. A compromised dependency that bypasses the agent
  runtime entirely could still make outbound connections. Deploy shadow nodes
  in a network-segmented zone with no egress route as defence in depth.
* Connector data is untrusted and may be adversarial. Correlation limits the
  blast radius (bounded fields, redaction, no writes), but a compromised source
  can still create false incidents. Treat proposals as recommendations and keep
  the human approver independent of the source system.
* The HTTP connector validates the URL host, not the resolved IP. Deploy it with
  egress controls or a proxy if the allowlisted host can resolve internally.
* PII/PHI detection is heuristic pattern matching over keys and values. It is a
  classification signal, not a clinical-grade classifier or a redaction
  substitute; tune the patterns for your domain and keep raw identifiers out of
  connector payloads. An unrecognized label will not raise classification.
* The egress guard covers decision/bridge publication only. It does not inspect
  arbitrary network calls, logs or operator-initiated exports; keep the mesh
  network-segmented and review any component that can read the workspace.
* Profile control defaults can be overridden by explicit `AGENT_*` environment
  variables. The transaction ceiling cannot be relaxed by an approval, but it
  can be raised by whoever controls the process environment, so protect those
  variables as governed configuration. A role profile filters role views only;
  it does not reduce the runtime privileges of the nine coordinators.
