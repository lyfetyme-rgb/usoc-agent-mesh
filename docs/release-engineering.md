# USOC Mesh release engineering

This document defines the repository lifecycle after Phase 0. It complements [`docs/requirements/README.md`](requirements/README.md), which owns the requirement-to-evidence catalog.

## Branch strategy

| Branch | Purpose | Protection |
|---|---|---|
| `main` | Stable release baseline. Only squash merges from PRs. | Required `pytest`, `security` and `traceability` checks; admins enforced; no force push or deletion. |
| `dev` | Integration branch for `feature/*` work. | Same required checks as `main`. |
| `production` | Promotion target for released commits. Same commit or fast-forward from `main`. | Same required checks; deployment requires a separate GitHub Environment approval. |
| `feature/*`, `work/*` | Short-lived work branches. Open a PR into `dev`; reference the `REQ-*` / `ENG-*` issue. | Unprotected. |
| `release/*` | Optional stabilization branch for a planned tag. PR into `main`. | Unprotected until merged. |

Tags follow `vMAJOR.MINOR.PATCH[-suffix]` and are created on the squash-merge commit on `main`. Annotated tags are pushed to `origin`.

Verify protection with:

```powershell
gh api repos/lyfetyme-rgb/usoc-agent-mesh/branches/main/protection --jq '.required_status_checks.contexts'
gh api repos/lyfetyme-rgb/usoc-agent-mesh/branches/dev/protection --jq '.required_pull_request_reviews.required_approving_review_count'
gh api repos/lyfetyme-rgb/usoc-agent-mesh/branches/production/protection --jq '.enforce_admins.enabled'
```

`.github/CODEOWNERS` assigns `@lyfetyme-rgb` as the default reviewer. The repository currently has one collaborator, and GitHub does not allow self-approval, so `required_approving_review_count` remains `0` on all three branches. The target policy is one CODEOWNERS approval per PR; enable it as soon as a second maintainer is added. Until then, the enforced gate is the three required status checks plus environment approval on deploy.

## CI

`.github/workflows/ci.yml` runs on pushes and PRs to `main`, `dev` and `production`:

- `pytest` job: full offline suite, doctor, storyboards, LLM rehearsal, submodule drift check, and `python toolbox/scripts/traceability_check.py`.
- `security` job: `pip-audit .`, Bandit with the documented B608 exclusion, Gitleaks secret scan, and Trivy filesystem scan. High/critical findings fail the job.

Required status check names are `pytest`, `security` and `traceability`. A PR cannot merge until all three pass.

## Release and supply chain

`.github/workflows/release.yml` runs on `main`, on version tags, and by manual dispatch. It:

1. Builds `usoc-mesh` and `usoc-dashboard` images from the pinned Dockerfiles.
2. Publishes both images to GHCR by immutable digest.
3. Generates SPDX and CycloneDX SBOMs with Syft for source and images.
4. Signs images with cosign keyless OIDC/Sigstore.
5. Attaches build provenance and uploads all evidence as workflow artifacts.

Required token permissions are `contents: read`, `packages: write` and `id-token: write`. No long-lived registry credential is stored in the repository.

## Environments and deployment gates

Two GitHub Environments are configured. `prevent_self_review` is currently `false` because the repository has one maintainer; set it to `true` when a second approver is available.

| Environment | Purpose | Gate |
|---|---|---|
| `staging` | Pre-production validation of a release digest. | Required reviewer, `pytest`/`security`/`traceability` checks. |
| `production` | Customer-facing promotion of the exact staging-approved digest. | Required reviewer; same checks; cosign verification must pass; deployment limited to protected branches. |

`.github/workflows/deploy.yml` is manually dispatched with `environment`, `mesh_digest` and `dashboard_digest` inputs. It:

1. Verifies the cosign signature and SLSA provenance attestation for both digests.
2. Renders the selected Kustomize overlay (`staging` or `production`) with `toolbox/scripts/render_overlay.py`, pinning every workload — including the doctor Job — to the verified digests before apply. A tag is never deployed and `kubectl set image` is never used after apply.
3. Deletes any prior doctor Job and applies the pinned manifest to `usoc-staging` or `usoc-prod` with `kubectl apply -f rendered.yaml`.
4. Waits for rollout completion, then runs the doctor Job and checks its logs.
5. Probes `/ready` through the server-side proxy and uploads `rendered.yaml`, `doctor.log` and `smoke.log` as operational validation evidence.

Required repository secrets: `KUBE_CONFIG_STAGING`, `KUBE_CONFIG_PRODUCTION`, `AGENT_HEALTH_TOKEN` and `AGENT_ADMIN_TOKEN`. Kubeconfigs must be scoped to the target namespace, and tokens must never be written into manifests or browser bundles.

## Infrastructure overlays

`deploy/kubernetes/base/` holds the plain manifests and `deploy/kubernetes/kustomization.yaml` is the direct production entry point. Environment-specific overlays are:

- `deploy/kubernetes/overlays/staging/kustomization.yaml` → namespace `usoc-staging`
- `deploy/kubernetes/overlays/production/kustomization.yaml` → namespace `usoc-prod`

The staging overlay also rewrites the dashboard DNS-rebinding allowlist to the staging service name; Kustomize's namespace transformer changes `metadata.namespace` but not embedded hostname strings.

Do not create Secrets in git. The `.example` templates remain the only secret shapes in the repository; Secrets Store CSI or an external secrets controller supplies the real values.

## Production readiness gates

A release is production-eligible only when all of the following are true:

- The PR traceability block names a `REQ-*` / `ENG-*` issue and the CI evidence URLs.
- `pytest`, `security` and `traceability` checks pass on the merge commit.
- The image digest is signed, attested and copied to the release workflow evidence bundle.
- The staging environment approval is recorded on that exact digest.
- The doctor Job, health probe and load-test evidence succeed in staging.
- The production environment approval is recorded on the same digest.

Threat model, pentest evidence, IR runbooks, recovery drills and vulnerability disclosure remain tracked under `REQ-010` until their artifacts exist.
