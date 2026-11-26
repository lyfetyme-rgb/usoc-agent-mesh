# Threat model

Scope: the USOC-owned `agents/`, `dashboard/`, `tests/`, mesh fixtures and
deployment manifests. The adjacent `gateway-cloud-functions/`, `h-lift/` and
`atlas/` trees are out of scope for this repository's control changes. Each
trust boundary below is enforced in code or manifests, not by prompt text.

## Assets and trust boundaries

- **Governed decision authority**: policy engine, approval store and message
  verifier. Only signed, fresh, sender-bound messages cross the bus boundary.
- **Evidence authority**: OEKP hash chain and WORM archive. Evidence is append
  only, signed/MACed and redacted before storage.
- **Execution boundary**: a HOLD becomes a human handoff, never execution; a
  DENY returns a failure with no model call. Compensations are governed tasks.
- **Browser boundary**: the dashboard proxy holds the health token server-side.
  Browsers receive counts and status flags only, with `no-store` and CSP.
- **Ingestion boundary**: connectors use allowlisted HTTPS, bounded responses,
  redaction and captured fingerprints; unknown fields are quarantined without
  retaining the value.

## Adversary model

The adversary may replay signed messages, forge a sender or `kid`, submit
oversized or tainted inputs, replay an approval nonce, tamper with evidence,
attempt cross-tenant approval spend, or send malicious Host headers to the
dashboard. It may also exploit a container to reach the cluster network.

## Controls

Ed25519/KMS signing and freshness checks address identity forgery and replay.
Tenant-partitioned, locked approval consumption addresses nonce replay and
cross-tenant spend. Default-deny NetworkPolicies and Seraphim containment limit
lateral movement. Read-only rootfs, non-root execution, dropped capabilities and
pinned digests limit container escape. Redaction and strict field allowlists
prevent raw record bodies from reaching ledger, evidence or health surfaces.

Residual risk: without a second maintainer, self-review cannot be enforced by
GitHub; this is recorded in release engineering docs and compensated by
checks-only branch protection and environment reviewers.
