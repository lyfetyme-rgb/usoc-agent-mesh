# USOC Mesh Toolbox

Canonical home for USOC delivery artifacts: the playbook that governs each
release, the constitution that governs how changes are made, and the scripts,
templates and notes that are safe to reuse. If a file is approved for demo,
partner or production use, it lives here.

## What lives here

| Path | Purpose |
|---|---|
| `PLAYBOOK.md` | Goal → ordered steps → rules → done definition, from first hardening to demo. |
| `CONSTITUTION.md` | SpecKit-style SDLC rule for this repo. Read it before touching code. |
| `templates/decision-record.md` | Fill-in template for Confluence ADR pages from `testing-bay`. |
| `templates/sign-off.md` | One-paragraph sign-off/decision record for human approvers. |
| `scripts/live_smoke.ps1` | Read-only local smoke: install check, test suite, doctor, integrity. No network, no writes. |
| `scripts/doc_consistency.ps1` | Greps README/SECURITY/docs for the current test count and env var names, fails on drift. |
| `docs/INDEX.md` | Where the truth lives: canonical repo files, Confluence ADR, Jira board, security boundaries. |

## Rules of the toolbox

1. Nothing enters the toolbox without the same bar as code: tests pass, docs
   match, and it is safe to hand to a design partner.
2. Scripts are read-only unless a script explicitly says otherwise and is
   reviewed like a security change.
3. Templates carry the same controls as the product — no
   "just show it working" shortcuts.
4. Anything a human must decide is printed as a checklist, never implied.
5. The toolbox follows `CONSTITUTION.md`; the constitution is the arbiter when
   the two disagree.
