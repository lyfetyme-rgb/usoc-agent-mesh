# Incident response runbook

This runbook covers suspected token exposure, forged messages, approval replay,
unapproved egress, evidence tampering and compromised workload behavior.

## Phase 1 — detect and classify

Use `/health` and `/ready` counts and reason codes only. Do not publish
`/diagnostics`. Record the incident class, tenant scope, affected digest and
first-seen time in a redacted incident note.

## Phase 2 — containment

For unapproved egress or a known-exploited vulnerability, apply a Seraphim
`CONTAIN` decision with a default-deny quarantine NetworkPolicy. Do not run
remediation from an advisory or rehearsal result. Rotate the affected signing
or health credential through the mounted secret workflow, never by placing it
in a manifest or browser store.

## Phase 3 — evidence preservation

Append only redacted, fingerprinted facts to the OEKP chain. Keep WORM archive
segments intact; do not rewrite the chain to "clean up" an incident. Verify the
chain head and signature before export.

## Phase 4 — recovery and review

Restore from the last verified immutable artifact, verify signatures and
provenance, and rerun doctor plus the readiness checker. Perform a blameless
review, map any new finding to a regression test, and update the assurance
matrix before closing the incident. Recovery targets are defined in
`recovery-drill.md`.
