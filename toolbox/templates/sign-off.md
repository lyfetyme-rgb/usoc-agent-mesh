# Sign-off — <change / decision>

One paragraph, one signature, one commitment. File this with the evidence
record or the Jira issue; not in chat.

> I, <name> (<role>), approve <change/decision, ids> on <date>.
> I reviewed <artifacts: commit ids, ADR id, evidence head hash, test count>.
> I understand the failure mode is <worst credible failure> and that this
> action does not expire from authorization until <TTL> after decision.
> KMS/runtime key material: <custodian and location, or N/A>.
> Re-verification: <who will re-verify, when>.

Sign-off rule: the approver cannot be the requester; approvals must name the
action, target, mission and time window; approving delegates authority but not
accountability.
