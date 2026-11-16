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

### Health endpoint

`GET /health` (liveness) and `GET /ready` (readiness) are the only HTTP routes.
There is no work submission over HTTP. When `AGENT_HEALTH_TOKEN` or
`AGENT_HEALTH_TOKEN_FILE` is set, both routes require
`Authorization: Bearer <token>`; comparisons are constant-time. Responses
contain counts and status flags only.

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
