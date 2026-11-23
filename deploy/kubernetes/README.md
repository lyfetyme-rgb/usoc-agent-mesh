# USOC Mesh — Kubernetes production manifests

These manifests deploy a **stateless, autoscalable control plane**. They replace
the earlier single-writer scaffold: approvals, OEKP evidence and the task ledger
are tenant-partitioned in Postgres, Redis is a short-lived hot cache, and the
signed redacted ledger chain is archived to S3 Object Lock. No `ReadWriteMany`
volume and no `/data` mount remain.

| Invariant | How it is preserved here |
|---|---|
| non-root | `runAsNonRoot: true`, uid/gid 10001, `fsGroup: 10001`, `RuntimeDefault` seccomp |
| read-only rootfs | `readOnlyRootFilesystem: true` everywhere; only `/tmp` is writable (`emptyDir`) |
| dropped privileges | `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, no service-account token mounted |
| zero browser token exposure | health/admin tokens are mounted as read-only files; only the server-side proxy adds `Authorization`. `/diagnostics` needs a separate admin token and stays unreachable from the proxy |
| strict egress boundaries | default-deny ingress **and** egress, DNS + Redis/Postgres/S3 VPC endpoints only; no direct Atlassian/gateway/h-lift/model egress |
| multi-replica safety | Postgres row locks span decision/nonce transactions; the evidence head is row-locked and reload-verified; Redis is cache-only |
| immutable evidence | S3 Object Lock in `COMPLIANCE` mode with AES256 SSE and a dedicated chain-secret file |

## Backends

The image must include the optional drivers:

```dockerfile
RUN pip install --no-cache-dir -e '.[postgres,s3,redis]'
```

The correct variable names are `AGENT_*` (`Settings` uses `env_prefix="AGENT_"`).
The old blueprint names `DATABASE_URL`, `REDIS_URL` and `EVIDENCE_S3_BUCKET` are
not USOC settings and are absent from these manifests.

Required production values in `02-configmap.yaml`:

* `AGENT_APPROVAL_BACKEND=postgres`
* `AGENT_EVIDENCE_BACKEND=postgres`
* `AGENT_LEDGER_BACKEND=postgres`
* `AGENT_ARCHIVE_BACKEND=s3`
* `AGENT_ARCHIVE_BUCKET`, `AGENT_ARCHIVE_REGION`, `AGENT_ARCHIVE_LOCK_MODE=COMPLIANCE`

Required values from `usoc-mesh-secrets`:

* `AGENT_POSTGRES_DSN` — managed, private TLS DSN; backup and PITR are mandatory.
* `AGENT_REDIS_URL` — TLS/AUTH endpoint; used for the bus and approval hot cache.
* `AGENT_SHARED_SECRET_FILE` — mandatory for HMAC clusters; Ed25519/KMS clusters
  use persistent asymmetric keys instead.
* `AGENT_ARCHIVE_SECRET_FILE` — dedicated WORM chain key. HMAC clusters may reuse
  the shared secret; Ed25519/KMS clusters must set this explicitly.
* `AGENT_HEALTH_TOKEN_FILE` and `AGENT_ADMIN_TOKEN_FILE` — distinct values.

`01-secrets.example.yaml.example` is a template only. Prefer External Secrets
Operator or Secrets Store CSI so no usable Secret exists in Git or shell history.

## What is still out of scope

* **No managed Redis/Postgres/S3 deployment.** The manifests assume managed,
  external endpoints and explicit CIDRs in the NetworkPolicies.
* **No Atlassian egress-proxy image.** The opt-in bridge is denied egress by
  default; add a narrow NetworkPolicy and proxy if you enable it.
* **No Helm chart.** Plain manifests keep the audit surface small; a chart can
  wrap these later without changing the app.

## Apply

```powershell
# 0. Build and push both images (with the optional drivers installed).
docker build -t ghcr.io/<org>/usoc-mesh:0.2.0 .
docker build -f Dockerfile.dashboard -t ghcr.io/<org>/usoc-dashboard:0.2.0 .
# Update the `image:` fields in 10-control-plane.yaml and 11-workers.yaml.

# 1. Create the secret from files (or let an external secret operator do it).
python -c "import secrets; print(secrets.token_urlsafe(48))" | Set-Content -NoNewline secrets/agent_shared_secret.txt
python -c "import secrets; print(secrets.token_urlsafe(48))" | Set-Content -NoNewline secrets/archive_secret.txt
python -c "import secrets; print(secrets.token_urlsafe(32))" | Set-Content -NoNewline secrets/health_token.txt
python -c "import secrets; print(secrets.token_urlsafe(32))" | Set-Content -NoNewline secrets/admin_token.txt
kubectl -n usoc-prod create secret generic usoc-mesh-secrets `
  --from-file=agent-shared-secret=./secrets/agent_shared_secret.txt `
  --from-file=archive-secret=./secrets/archive_secret.txt `
  --from-file=health-token=./secrets/health_token.txt `
  --from-file=admin-token=./secrets/admin_token.txt `
  --from-literal=redis-url='rediss://user:password@redis.internal:6379/0' `
  --from-literal=postgres-dsn='postgresql://user:password@postgres.internal:5432/usoc'

# 2. Edit placeholders: 20-network-policies.yaml (real Redis/Postgres/S3 CIDRs
#    and authenticating ingress namespace), 02-configmap.yaml (bucket, region,
#    approvers), image references.

# 3. Apply in order. `kubectl apply -f deploy/kubernetes/` applies every *.yaml
#    in the directory; the .example templates are deliberately excluded.
kubectl apply -f deploy/kubernetes/00-namespace.yaml
kubectl apply -f deploy/kubernetes/02-configmap.yaml
kubectl apply -f deploy/kubernetes/03-storage.yaml
kubectl apply -f deploy/kubernetes/10-control-plane.yaml
kubectl apply -f deploy/kubernetes/11-workers.yaml
kubectl apply -f deploy/kubernetes/20-network-policies.yaml
kubectl apply -f deploy/kubernetes/30-dashboard-proxy.yaml
```

Do **not** apply `31-ingress.yaml.example` until an authenticating ingress is
configured. The dashboard proxy has no login; the Service is ClusterIP so it is
not exposed by default.

## Verification

```powershell
kubectl -n usoc-prod get pods
kubectl -n usoc-prod get hpa
kubectl -n usoc-prod exec deploy/usoc-mesh -- python -m agents probe --url http://127.0.0.1:8080/ready
kubectl -n usoc-prod exec deploy/usoc-mesh -- python -m agents doctor
kubectl -n usoc-prod port-forward svc/usoc-dashboard 8090:80
# browse http://127.0.0.1:8090 -- the browser never sees a token
```

`exec` probes reuse `python -m agents probe`, which reads the health token from
`AGENT_HEALTH_TOKEN_FILE`. No bearer token appears in any manifest, pod env, or
browser request. The dashboard also uses loopback exec probes because kubelet
`httpGet` probes carry a pod-IP Host header that the proxy's DNS-rebinding
allowlist correctly rejects. If your CNI applies NetworkPolicy to `kubectl
port-forward`, temporarily allow your admin namespace in
`allow-dashboard-ingress`.

## Scaling

Both the control plane and the example worker deployments have HPAs. The CPU
targets are a bootstrap signal; USOC's authoritative demand signal is **Redis
backlog**:

```powershell
python -m agents scale-advice --json --agents oekp,bengal
```

Wire that output into a custom metric or a scheduled job that patches the
Deployments if you need backlog-driven scaling. `scale-advice` defaults are 1–4
replicas and 8 pending messages per replica; align them with the HPA bounds
before enabling both. The control-plane HPA has `minReplicas: 2` because the old
single-writer constraint no longer exists.

## Hardening follow-ups (not enabled by default)

Uncomment the corresponding block in `02-configmap.yaml` only after the
supporting files exist and `python -m agents doctor` passes in strict mode:

* `AGENT_STRICT_PROD=1` with per-coordinator Ed25519 bus keys,
  `AGENT_BUS_PUBLIC_KEYS_FILE`, a KMS signing URL for the control plane, and a
  signed approver registry (`AGENT_APPROVER_REGISTRY_*`). Strict mode now also
  requires the Postgres/S3 backends above and `AGENT_ARCHIVE_SECRET_FILE`.
* `AGENT_REQUIRE_SUBSYSTEMS_INTEGRITY=true` plus the SHA-256/HMAC/Ed25519 pin
  generated by `python -m agents integrity` (the capability cards are the IAM
  policy store, so a runtime edit is privilege escalation).
* `AGENT_ED25519_PUBLIC_KEYS_FILE` for cluster-level approval/evidence signing;
  the private key stays in CI/KMS, never in the image.

Secrets should come from a KMS-backed secret store rather than the example
`Secret` manifest. Restrict `get secrets` with RBAC: `AGENT_REDIS_URL` and
`AGENT_POSTGRES_DSN` are credentials exposed as pod env because `Settings` has
no file variant for them. Use TLS and private CIDRs for both.
