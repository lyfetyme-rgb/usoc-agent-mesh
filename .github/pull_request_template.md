## Traceability

- Requirement ID(s): <!-- REQ-xxx / ENG-xxx -->
- Engineering issue(s): <!-- https://github.com/lyfetyme-rgb/usoc-agent-mesh/issues/N -->
- Capability / Operational Function / System Requirement: <!-- from docs/requirements/catalog.yaml -->

## Change

<!-- What changed and why. Keep the Section 6 invariants explicit when touching agents/, dashboard/ or deploy/. -->

## Automated test evidence

- `python -m pytest -q`: <!-- paste summary -->
- `python toolbox/scripts/traceability_check.py`: <!-- paste output -->
- CI run URL: <!-- paste URL -->

## Build artifact / deployment approval / operational validation

- Image digest or workflow artifact: <!-- digest or run URL -->
- Deployment environment and approval: <!-- staging / production, approver -->
- Doctor job, probe or load-test evidence: <!-- command + result -->

## Checklist

- [ ] `python toolbox/scripts/traceability_check.py` passes.
- [ ] No changes to `gateway-cloud-functions/`, `h-lift/` or `atlas/`.
- [ ] `SECURITY.md` shadow wording is unchanged when that file is touched.
- [ ] No browser-visible token, raw payload or privileged container was introduced.
