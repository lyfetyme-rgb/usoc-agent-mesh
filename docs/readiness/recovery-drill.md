# Recovery drill procedure

Status: **procedure and checklist**, not a completed drill report. An observed
result with date, operator, commit and sign-off must be recorded externally
before this document is cited as completed evidence.

Type: **offline simulation**. There is **no live production** system, credential
or network involved in this repository's procedure.

## Objective

Verify that a stateless control plane can be restored from a signed, immutable
artifact and that governance trust is re-established before workload traffic
resumes.

## Targets

- **RTO**: 60 minutes for control-plane restoration in the drill.
- **RPO**: last verified OEKP chain head and signed WORM segment; zero loss of
  accepted evidence because writes are append-only and verified before export.

## Drill steps

1. Start from a clean workspace with only mounted trust inputs.
2. Verify the image digest, SBOM, SLSA provenance and cosign signature.
3. Restore the OEKP chain head from the immutable archive and verify its MAC.
4. Run `python -m agents doctor` and `python toolbox/scripts/readiness_check.py`.
5. Confirm health/ready expose counts and flags only.
6. Replay a bounded approval fixture and confirm single-use consumption.
7. Record the observed RTO/RPO, any gaps and the remediation owner.

## Result record (not yet performed)

| Field | Value |
|---|---|
| Commit | not yet recorded |
| Date / operator | not yet performed |
| Observed RTO | not yet performed |
| Observed RPO | not yet performed |
| Sign-off | pending |

Any deviation from the RTO/RPO target must be recorded as an incident follow-up
in `incident-response.md`. No unredacted record bodies may be written into the
drill note or evidence export.
