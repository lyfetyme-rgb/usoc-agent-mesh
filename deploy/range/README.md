# Isolated Cyber Defense Range (out-of-band scaffold)

This directory is a **proposal scaffold only**. The executable range must live
in a **separate repository** and a separate cloud account/cluster. It is never
joined to the production message bus, Redis, Postgres, S3 evidence bucket or
dashboard.

## Non-negotiable isolation

- **no production credentials**, no shared identity provider client, no mounted
  mesh secrets, and no network path to `usoc-prod`;
- **default-deny** ingress and egress, with every scenario run in a dedicated
  `usoc-range` namespace and a ResourceQuota;
- all workloads are non-root, read-only rootfs, capability-dropped and never
  privileged or host-networked. Committed images are non-deployable placeholders;
  the external range repository must pin real signed digests before execution;
- range output is untrusted, tainted evidence in the USOC contract. It cannot
  create execution authority, grant approvals or change policy outcomes;
- the retired `cyber_strike` term is not used. Use `cyber_defense`.

## Scenario library contract

The external range repository must implement and record evidence for:

1. compromised container;
2. lateral movement;
3. credential misuse;
4. KEV exploitation/remediation;
5. ransomware-like recovery;
6. network degradation;
7. DDoS telemetry flooding;
8. failed patch;
9. rollback;
10. backup destruction attempt.

Each scenario exports a signed, redacted summary: scenario id, image/config
digests, isolation proof, start/end time, observed control results and a hash
of the raw capture. Raw capture never enters USOC Mesh evidence.

## Validation

Run `python toolbox/scripts/validate_range_isolation.py` before moving this
scaffold to its own repository. It fails closed on production linkage,
privileged workloads, host networking, placeholder image digests, missing quota
or a missing default-deny policy.
