# USOC Mesh Constitution — SpecKit-style SDLC

This is the rule for every change to the mesh, in the spirit of GitHub
spec-kit's constitution → specify → plan → tasks → implement pipeline. It is not
negotiable because "the demo is on Friday" and it is enforced at review.

## 0. The constitution (non-negotiable)

1. **No AI recommendation is execution authority.** Consequential actions pass
   the deterministic policy gate and, when required, a human decision.
2. **Fail closed.** Missing config, bad signature, expired approval, corrupt
   state → refuse; never guess, never best-effort.
3. **Least privilege is the default.** Every tool, token, topic and secret is
   scoped to exactly what is needed — no wildcard grants.
4. **Evidence or it didn't happen.** Every governed decision is signed and
   appended to the chain; BENGAL can re-verify.
5. **No secret in config, chat, YAML or evidence.** Mounted files and env
   substitution only.
6. **No live writes in CI.** Tests inject transports; only an explicitly
   enabled, approval-gated publish may touch a real site.
7. **Shadow execution is impossible.** `AGENT_SHADOW_MODE` keeps policy/HITL/
   evidence fidelity on real inputs but handlers, mutating tools, egress and
   external bridges fail closed; state is isolated and shadow evidence is never
   trusted as execution proof.
8. **Docs are part of the change.** README, SECURITY and docs move with the
   code or the change does not ship.

## 1. Specify

Every change starts as a problem statement with **measurable success criteria**
and **failure modes** written down before any code is drafted. Security and
governance work additionally states the threat and the boundary being closed.

Sample gate (all answers required):

- What is the user/operator problem?
- What does success look like, measurably?
- What is the worst failure mode, and is it silent or loud?
- What data/keys/tokens does it touch, and who can forge them?

## 2. Plan

The plan lists affected components, trust boundaries, failure modes, rollback,
and which controls the change relies on (policy, approvals, signature, evidence).
Architecture changes update `docs/architecture.md`; control changes update
`SECURITY.md` before or with the code.

## 3. Tasks

The plan becomes a checklist with a verification step each: unit test, integration
test, live read-only check, or document. No task is complete until its
verification step passes. For signing and approval work, at least one
*negative* test (tampered input must fail) is mandatory.

## 4. Implement

Smallest safe change that passes the tasks. Security and signing paths get tests
first. No unrelated refactors ride along. Commit messages say *why*, name the
boundary being closed, and reference the Jira issue when one exists.

## 5. Verify

- `python -m pytest -q` — everything passes, no network.
- `python -m agents doctor` — clean on a configured environment.
- Docs consistency — counts, env names, and controls match the code.
- For anything touching the bridge or signing: run the *risky path*, not the
  preview (see `scripts/live_smoke.ps1` for the offline half).

## 6. Ship

- Commit, push, verify `git diff` against `origin/main` is empty.
- Update `toolbox/docs/INDEX.md` if any canonical pointer moved.
- Update the ADR page and Jira if the change crosses a decision boundary.

## 7. Done means

Measurable criteria from the spec are met, the negative tests fail correctly,
the remote is clean, and the docs were not forgotten. A change that cannot be
explained in two sentences to a design partner is not done.
