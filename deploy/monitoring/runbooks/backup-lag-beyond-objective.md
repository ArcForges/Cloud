# Backup lag beyond objective

Alert: `backup-lag-beyond-objective` · dependency: `object-storage` · route: `page`

## Preconditions

Use read-only backup freshness, object-inventory and D1 health evidence. Do not alter retention, delete objects or start an unapproved restore.

## Decisions

Confirm backup lag is over the one-hour internal objective. This is an internal recovery-readiness objective, not an external recovery promise. Attribute the event to backup/object storage separately from request availability.

## Steps

1. Confirm the backup watermark age and most recent completed verification using metadata only.
2. Compare object-storage health with the source database and upload/verification pipeline indicators.
3. Check whether the current backup generation is complete and whether the alert is isolated to one stage.
4. Page the backup/recovery owner with generation identifiers, age and verification status.

## Verification

Require a new completed backup watermark and its existing integrity/manifest verification before declaring recovery. A successful API request does not prove backup health.

## Rollback and escalation

Do not restart, delete or overwrite a backup generation. Any recovery or fresh-realm restore follows the separately approved backup/recovery procedure and its authority; use the approved [deployment recovery procedure](../../../docs/deployment.md#recovery) only for a candidate regression.

Rehearsal status: not recorded here; OPS.03 owns runbook rehearsal and this file does not close WP-45.02.
