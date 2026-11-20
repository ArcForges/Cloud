# Remote outcome uncertain

Alert: `remote-outcome-uncertain` · route: `page`

## Preconditions

Use the restricted operation status workflow and match the original enrollment and command identity.

## Decisions

Check count, age and truncation. A sampled count at the cap can represent more uncertain operations.

## Steps

Check the original Node and its durable Run state. Use supported reconciliation on the original command when evidence is available. Preserve UNKNOWN across service loss.

## Verification

Confirm the exact result or hand off the remaining uncertainty while keeping the original command identity.

## Rollback and escalation

Escalate unresolved outcome evidence to the operations owner. A missing response does not authorize a replacement command.

Rehearsal status: not recorded here; OPS.03 owns runbook rehearsal.
