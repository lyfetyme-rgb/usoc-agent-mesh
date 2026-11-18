# Canonical pointers

One source per claim. If two disagree, this list decides which is truth.

| Claim | Canonical source |
|---|---|
| Goal, steps, done definition | `toolbox/PLAYBOOK.md` |
| How changes are made | `toolbox/CONSTITUTION.md` |
| Capability baseline and governance rules (self-contained in git) | `toolbox/CONSTITUTION.md` + `subsystems.yaml` |
| Repo layout | `README.md` |
| Threat model, controls, bridge, rotation, audit | `SECURITY.md` |
| Message lifecycle, governance gate, failure matrix | `docs/architecture.md` |
| Subsystem roles and routing | `subsystems.yaml` |
| Decision record for Ed25519 | Confluence `testing-bay`, space SD, page 786434 |
| Follow-up work | Jira `testing-bay`, project KAN (KAN-1…4) |
| Tests | `python -m pytest -q` |

Advice to future editors: edit the canonical file, then this index only if the
pointer itself moved. Never copy a claim into a second file as a quote — link
it.
