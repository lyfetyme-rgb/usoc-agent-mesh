# USOC Mesh — Shipping Playbook

**Goal.** Take the USOC agent mesh from a hardened skeleton to a demonstrable,
evidence-backed prototype that proves one thing on stage: *no AI recommendation
can execute a consequential action without a human decision, and every decision
is signed, scoped and kept forever.* That is the claim design partners and seed
investors are buying.

Stop adding features once the demo is recorded. From that point the only
high-ROI work is showing the demo.

## The order that actually mattered

Each step below is complete unless marked **OPEN**.

1. **Security foundation** — least-privilege bus ACLs (no wildcard publish for
   domain agents), sender-bound HMAC, fail-closed transport (`AGENT_BUS=redis`
   refuses to start without a secret), taint/provenance across ACIE → AICEE →
   COHESION, `cyber_strike` renamed to `cyber_defense`, SHELL boundary
   documented, signed capability cards, diagnostics redacted behind an admin
   token.
2. **Asymmetric signing** — Ed25519 with the private key offline in CI/CD or a
   KMS. Runtime nodes hold public keys only; a public-key-only node can verify
   but cannot forge. Detached capability-card signatures are checked at
   startup. KMS signers receive the exact bytes to raw-sign.
3. **Zero-downtime rotation** — `PublicKeySet` maps `kid → public key`;
   verification tries every trusted key, so signing keys rotate without
   breaking in-flight waves, approvals or historical OEKP evidence. Missing
   active kid or an untrusted KMS `key_id` fails closed. KAN-2 is **Done**.
4. **Approval-gated outward writes** — the Atlassian bridge publishes only an
   *already-decided* approval: a mesh-signed ADR page in Confluence and, when a
   JSM desk exists, a JSM request linking back to it. Idempotent, opt-in
   (`AGENT_ATLASSIAN_BRIDGE_ENABLED=true`), no live writes in CI.
5. **Write-gate / SSRF audit documented** — see `SECURITY.md` ("Verified
   write-gate and outbound-request properties").
6. **Live smoke test** — `testing-bay.atlassian.net`, read-only PASS: ADR page
   `786434`, KAN-2 Done. No writes were performed.
7. **Risky path tested live** — real Redis container, real cross-process
   approvals/denies, real evidence chain, tamper tests. It caught and fixed two
   defects (a crash in `publish-decision`, a wrong env var name that would have
   silently disabled the bridge for anyone following the docs).
8. **Demo recorded and pinned** — `README.md` carries the 3-minute storyboard;
   it is the artifact you show.

## The rules, non-negotiable

- **No consequential action without a human.** `execute` and `contain` return
  HOLD → `Handoff` and wait. Policy is plain Python; no model output flips a
  DENY.
- **Fail closed.** Unknown world, missing config, bad signature, expired
  approval, corrupt file → refuse, never guess, never "best effort".
- **AI is untrusted input.** Agent-to-agent messages are data, not
  instructions. Tool allowlist is the security boundary.
- **Nothing ships without tests and docs.** No merge without an updated README
  or `SECURITY.md`. If a control changes, the docs say so.
- **No secrets in config, chat or evidence.** File-based secrets, redaction in
  logs. Credentials are mounted, never pasted.
- **Env vars match pydantic field names.** `atlassian_bridge_enabled` →
  `AGENT_ATLASSIAN_BRIDGE_ENABLED`. Copy-paste the exact name.
- **No live writes in CI or from tests.** Tests use injected HTTP transports.
  The only approved live write is an approval-gated, explicitly-enabled publish
  to a site you own.
- **Stop at the demo.** Once tests pass and the storyboard is recorded, stop
  building. Resist "just one more feature."

## What "done" looks like

- `python -m pytest -q` → **186 passed**, no network.
- `git status` clean; local `HEAD` == `origin/main`; no unpushed hardening work.
- `python -m agents doctor` reports Redis reachable, approvers configured,
  allowlist required.
- Demo beat 2:20–3:00 runs end to end: HOLD → human `approve` → ALLOW → signed
  evidence, and `publish-decision` produces a signed ADR idempotently.
- README/SECURITY/docs all agree with the code (test count, env names, controls).
- Testing-bay shows the decision ADR at the expected version; KAN board reflects
  reality.

## Still open before production (do not demo as done)

- **KAN-1** — named human approver and recorded sign-off.
- **KAN-3** — private key in KMS/HSM; local key files retired.
- **KAN-4** — public key and detached signature deployed to runtime nodes with
  `AGENT_REQUIRE_SUBSYSTEMS_INTEGRITY=true`.
- JSM: no service desk exists on testing-bay; bridge publishes Confluence only
  until one is created and its IDs are provided.
- Zero-downtime evidence migration across an HMAC→Ed25519 mode switch.

If someone asks "is it production-ready?", the honest answer is: the governance
gate and the signing chain are production-shaped; the operational rollout steps
above are not done yet. Treat every demo artifact as a prototype receipt, not a
maturity claim.
