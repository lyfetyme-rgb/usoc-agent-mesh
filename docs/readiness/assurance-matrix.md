# Section 6 assurance matrix

This matrix is generated and checked offline by
`toolbox/scripts/readiness_check.py`. Each invariant is mapped to an automated
test in `tests/`. A missing mapping, missing test file or missing marker fails
the readiness gate. No production system is contacted. Automated test evidence
is the only accepted proof for a control in this matrix.

| Section 6 invariant | Automated test evidence | Enforcement summary |
| --- | --- | --- |
| non-root | `tests/test_kubernetes_manifests.py` | Pod `runAsNonRoot`, `runAsUser`, no `hostNetwork`, no `hostPath`. |
| read-only rootfs | `tests/test_kubernetes_manifests.py` | `readOnlyRootFilesystem: true` plus a writable `/tmp` scratch mount. |
| zero browser token exposure | `tests/test_dashboard_server.py` | Server-side token only; loopback/Host allowlist, `no-store`, CSP and no diagnostics in the browser surface. |
| strict egress | `tests/test_kubernetes_manifests.py` | Namespace default-deny ingress/egress and no `0.0.0.0/0` egress; connector/egress tests cover signed target+digest binding. |
| Ed25519 signatures | `tests/test_security.py`, `tests/test_production_trust.py`, `tests/test_production_signing.py` | Sender-bound signing, public-key verification, KMS mode, freshness and key rotation/keysets. |
| single-use nonce atomicity | `tests/test_security.py`, `tests/test_production_trust.py` | Tenant-partitioned approvals, locked read-modify-write, consumed-nonce evidence and cross-tenant replay denial. |
| OIDC/detached credential checks | `tests/test_production_trust.py`, `tests/test_seraphim.py` | Issuer/audience/expiry/JWKS checks, exact approval binding, detached signature verification, trusted injected verifier and replay refusal. |
| shadow fail-closed | `tests/test_shadow_mode.py` | Shadow only adds refusals; no tools, bridge, sink or live nonce; egress denies before signoff. |
| immutable OEKP evidence | `tests/test_security.py`, `tests/test_production_trust.py` | Hash-chained, signed records; recomputed hashes without MAC fail; concurrent appenders cannot fork the chain. |
| no raw payloads in ledger/evidence/health | `tests/test_observability_hardening.py` | Opaque reason fingerprints, redacted logs, minimal health/ready views and drops of unknown fields. |

## Operational evidence

- `docs/readiness/threat-model.md`: trust boundaries and adversary model.
- `docs/readiness/vulnerability-disclosure.md`: coordinated report and disclosure process.
- `docs/readiness/incident-response.md`: containment, evidence and recovery workflow.
- `docs/readiness/penetration-test.md`: scoped offline assessment procedure and checklist.
- `docs/readiness/recovery-drill.md`: offline simulation procedure with RTO/RPO targets.

Release and deployment remain gated by the existing signed digest, SBOM,
provenance and GitHub Environment approvals in `.github/workflows/`.
