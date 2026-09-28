# Data-integrity alarm

Alert: `data-integrity-alarm` · dependency: `primary-database` · route: `page` · severity: `SEV0`

## Preconditions

Use read-only integrity alarm metadata and the existing security incident channel. Do not repair, replay, delete or overwrite affected data without incident authority.

## Decisions

Treat any validated integrity alarm as possible data loss and page immediately. Preserve the alarm's rule ID, bounded entity class, time window and verification evidence; never copy customer content.

## Steps

1. Confirm the alarm came from the validated integrity monitor and record the integrity rule/version.
2. Freeze only the relevant read-only evidence and compare the source/replica or manifest checks without mutating either side.
3. Notify the security/data owner and open the independent incident process; record the notification deadline decision.
4. Determine the affected capability groups and dependency from metadata; do not label unaffected capabilities down.

## Verification

Require the data owner to attest that integrity checks pass against the authoritative source and record the exact evidence reference before reopening affected writes.

## Rollback and escalation

Do not rollback database state or apply migrations from this runbook. Escalate immediately to the data-integrity and security incident owners; any restore uses the separately approved fresh-realm recovery procedure under incident authority.

Rehearsal status: not recorded here; OPS.03 owns runbook rehearsal and this file does not close WP-45.02.
