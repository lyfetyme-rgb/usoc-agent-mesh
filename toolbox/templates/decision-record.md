# Decision record — <title>

Copy this to the `SD` Confluence space (or any space with a decisions parent).
Keep the shape from the USOC ADR on `testing-bay`: header table, background,
data, options, action items, outcome. Fill every field; do not invent people
(write `[approver — to be assigned]`).

| Field | Value |
|---|---|
| Status | NOT STARTED / IN PROGRESS / COMPLETE |
| Impact | HIGH / MEDIUM / LOW |
| Driver | @<account id> |
| Approver | @<account id> or [to be assigned] |
| Contributors | ... |
| Informed | ... |
| Due date | YYYY-MM-DD |
| Resources | <commit hash> · <doc link> · <Jira keys> |

## Background

Context, constraints, challenges.

## Relevant data

Measured facts only: test counts, commit ids, verified behavior, failure rates.

## Options considered

| | Option 1 | Option 2 | Option 3 |
|---|---|---|---|
| Description | ... | ... | ... |
| Pros and cons | ... | ... | ... |
| Estimated cost | LOW / MEDIUM / LARGE | | |

## Action items

- [ ] concrete task — owner — acceptance criteria

## Outcome

Decision, with a one-line reason. List what was explicitly rejected and why.

## Rollback

How to undo this decision and what breaks if you do.
