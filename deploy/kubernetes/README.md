# USOC Mesh — Kubernetes production manifests

These manifests replace the single-host `docker-compose.yml` topology with a
container orchestration layout while preserving the Section 6 invariants that
matter to the governance core:

| Invariant | How it is preserved here |
|---|---|
| non-root | `runAsNonRoot: true`, uid/gid 10001, `fsGroup: 10001`, `RuntimeDefault` seccomp |
| read-only rootfs | `readOnlyRootFilesystem: true` everywhere; only `/tmp` is writable (`emptyDir`), plus the shared `/data` mount |
| dropped privileges | `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, no service-account token mounted |
| zero browser token exposure | health/admin tokens are mounted as read-only files; only the server-side proxy adds `Authorization`. `/diagnostics` needs a separate admin token and stays unreachable from the proxy |
| strict egress boundaries | default-deny ingress **and** egress, DNS + Redis only; no direct Atlassian/gateway/h-lift/model egress |

## What this is — and what it is not

This is a **corrected manifest scaffold for the code that actually exists**.
Several ideas in the source blueprint do not exist in USOC Mesh and were
deliberately **not** implemented:

- **No Postgres approval backend.** Approvals are a signed, atomically replaced
  file (`FileApprovalStore`) guarded by cross-process locks, nonce atomicity,
  OIDC/detached credential checks, shadow fail-closed and OEKP evidence. There
  is no Postgres driver or `governance_approvals` table. `DATABASE_URL` is not
  a USOC setting and is absent from these manifests.
- **No S3/GCS Object Lock (WORM) evidence backend.** Evidence is a signed local
  JSONL hash chain; the durable cold archive is `SignedArchiveSink`, which
  writes to a local path. `EVIDENCE_S3_BUCKET` is not a USOC setting.
- **No managed Redis deployment.** The manifests assume an external
  Redis/Valkey endpoint with TLS + AUTH; supply its CIDR and URL.
- **No Atlassian egress-proxy image.** The opt-in bridge is therefore denied
  egress by default. Add a narrow NetworkPolicy and a proxy if you enable it.
- **No Helm chart.** Plain manifests keep the audit surface small; a chart can
  wrap these later without changing the app.
- **The control plane is deliberately 1 replica.** HPA scales only workers.
  The approval queue and evidence chain are file-backed with OS locks and must
  have a single authoritative mount; see the RWX note below.

The blueprint's `REDIS_URL` would also have been ignored: `Settings` uses
`env_prefix="AGENT_"`, so the correct variable is `AGENT_REDIS_URL`.

## Shared storage requirement

The control plane and every worker instantiate `FileApprovalStore` and
`EvidenceChain` under `AGENT_WORKSPACE=/data/workspace`. A per-pod `emptyDir`
there would fork the approval queue and the signed hash chain — HPA would
silently split brain. `03-storage.yaml` therefore requests a **ReadWriteMany**
PVC (EFS CSI on EKS, Filestore/NFS CSI on GKE, Azure Files on AKS). The CSI
driver must support `flock`/`fcntl` semantics for `async_exclusive_lock`.

This is the honest Kubernetes equivalent of Compose's `mesh-data` named
volume, not a distributed WORM store. Truly multi-writer, immutable evidence
needs a new backend with its own invariants and T&E — out of scope here.

## Apply

```powershell
# 0. Build and push both images (no new runtime dependencies).
docker build -t ghcr.io/<org>/usoc-mesh:0.2.0 .
docker build -f Dockerfile.dashboard -t ghcr.io/<org>/usoc-dashboard:0.2.0 .
# Update the `image:` fields in 10-control-plane.yaml and 11-workers.yaml.

# 1. Create the secret from files (or let an external secret operator do it).
python -c "import secrets; print(secrets.token_urlsafe(48))" | Set-Content -NoNewline secrets/agent_shared_secret.txt
python -c "import secrets; print(secrets.token_urlsafe(32))" | Set-Content -NoNewline secrets/health_token.txt
python -c "import secrets; print(secrets.token_urlsafe(32))" | Set-Content -NoNewline secrets/admin_token.txt
kubectl -n usoc-prod create secret generic usoc-mesh-secrets `
  --from-file=agent-shared-secret=./secrets/agent_shared_secret.txt `
  --from-file=health-token=./secrets/health_token.txt `
  --from-file=admin-token=./secrets/admin_token.txt `
  --from-literal=redis-url='rediss://user:password@redis.internal:6379/0'

# 2. Edit placeholders: 03-storage.yaml (RWX class), 20-network-policies.yaml
#    (Redis CIDR + authenticating ingress namespace), 02-configmap.yaml
#    (approvers), image references.

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
configured. The dashboard proxy has no login; the Service is ClusterIP so it
is not exposed by default.

## Verification

```powershell
kubectl -n usoc-prod get pods
kubectl -n usoc-prod exec deploy/usoc-mesh -- python -m agents probe --url http://127.0.0.1:8080/ready
kubectl -n usoc-prod exec deploy/usoc-mesh -- python -m agents doctor
kubectl -n usoc-prod port-forward svc/usoc-dashboard 8090:80
# browse http://127.0.0.1:8090 -- the browser never sees a token
```

`exec` probes reuse `python -m agents probe`, which reads the health token
from `AGENT_HEALTH_TOKEN_FILE`. No bearer token appears in any manifest,
pod env, or browser request. The dashboard also uses loopback exec probes
because kubelet `httpGet` probes carry a pod-IP Host header that the proxy's
DNS-rebinding allowlist correctly rejects. If your CNI applies NetworkPolicy
to `kubectl port-forward`, temporarily allow your admin namespace in
`allow-dashboard-ingress`.

## Scaling

The shipped HPAs use CPU as a bootstrap signal. USOC's authoritative demand
signal is **Redis backlog**, not CPU:

```powershell
python -m agents scale-advice --json --agents oekp,bengal
```

Wire that output into a custom metric or a scheduled job that patches the
worker Deployments if you need backlog-driven scaling. Keep control-plane
replicas at 1. `scale-advice` defaults are 1–4 replicas and 8 pending messages
per replica; align them with the HPA bounds before enabling both.

## Hardening follow-ups (not enabled by default)

Uncomment the corresponding block in `02-configmap.yaml` only after the
supporting files exist and `python -m agents doctor` passes in strict mode:

- `AGENT_STRICT_PROD=1` with per-coordinator Ed25519 bus keys,
  `AGENT_BUS_PUBLIC_KEYS_FILE`, a KMS signing URL for the control plane, and a
  signed approver registry (`AGENT_APPROVER_REGISTRY_*`).
- `AGENT_REQUIRE_SUBSYSTEMS_INTEGRITY=true` plus the SHA-256/HMAC/Ed25519 pin
  generated by `python -m agents integrity` (the capability cards are the IAM
  policy store, so a runtime edit is privilege escalation).
- `AGENT_ED25519_PUBLIC_KEYS_FILE` for cluster-level approval/evidence signing;
  the private key stays in CI/KMS, never in the image.

Secrets should come from a KMS-backed secret store rather than the example
`Secret` manifest. Restrict `get secrets` with RBAC: `AGENT_REDIS_URL` is the
one credential exposed as pod env because `Settings` has no file variant.
