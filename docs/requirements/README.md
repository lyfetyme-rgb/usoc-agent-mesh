# USOC Mesh requirements traceability

This directory is the authoritative, machine-readable traceability surface for the USOC Mesh roadmap. GitHub Issues are the engineering-issue tracker of record.

## Traceability chain

Every catalog entry carries one field for each step of the required chain:

`Mission Requirement → Capability → Operational Function → System Requirement → Engineering Issue → Code/Commit/PR → Automated Test Evidence → Build Artifact → Deployment Approval → Operational Validation`

| Chain step | Catalog field | Notes |
|---|---|---|
| Mission Requirement | `mission_requirement` | Stable `MR-*` identifier from the roadmap. |
| Capability | `capability` | Stable `CAP-*` identifier. |
| Operational Function | `operational_function` | Stable `OF-*` identifier. |
| System Requirement | `system_requirement` | Stable `SR-*` identifier. |
| Engineering Issue | `issue`, `issue_url` | GitHub issue number and canonical URL. |
| Code / Commit / PR | `code` | Paths that implement the requirement; commit/PR linkage comes from the PR template. |
| Automated Test Evidence | `tests` | Test paths that must exist and run in CI. |
| Build Artifact | `artifacts` | Workflow/manifest paths that define immutable release evidence. Required for `implemented` items. |
| Deployment Approval | `deployment_approval` | GitHub Environment or explicit gate description. |
| Operational Validation | `operational_validation` | Doctor job, smoke probe, load artifact, or drill record. |

## Issue conventions

- `REQ-*` issues are top-level roadmap requirements, one per mission area.
- `ENG-*` issues are engineering work items and declare a `parent: REQ-*`.
- Labels: `requirement`, `phase-0` … `phase-4`, plus domain labels such as `aicee`, `waste-optimization`, `seraphim`, `acie`, `cyber-defense-range`, `ui-product`, `performance`, `production-readiness`, `supply-chain` and `traceability`.
- Every PR must fill in the `.github/pull_request_template.md` traceability block with the requirement ID, issue link, test evidence and artifact digest or workflow run URL.

## Validation

The catalog is validated offline and in CI:

```powershell
python toolbox/scripts/traceability_check.py
python -m pytest -q tests/test_traceability.py
```

The validator fails when a requirement is missing a chain field, points at a non-existent code/test/artifact path, duplicates an issue, links the wrong issue URL, or declares `implemented` without build evidence.

## Updating the catalog

1. Create or update the GitHub issue first; record its number.
2. Add or update the catalog entry with all ten chain fields.
3. Add code and test paths that already exist — the checker is intentionally strict about this.
4. Run `python toolbox/scripts/traceability_check.py` locally before opening the PR.
5. Paste the validator output into the PR's automated test evidence block.
