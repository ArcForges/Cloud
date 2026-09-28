# Dead-letter growth

Alert: `dead-letter-growth` · dependency: `message-queue` · route: `page`

## Preconditions

Use read-only dead-letter counts and bounded reason codes. Never export payloads or log raw exception text.

## Decisions

Confirm more than ten new dead-lettered items in the fifteen-minute window. Distinguish a repeated systemic failure from one poison item; the threshold is count-based and payload-independent.

## Steps

1. Confirm the dead-letter growth delta and affected queue class.
2. Compare first-party capability SLIs and dependency health to isolate the failing consumer or dependency.
3. Check recent sealed-candidate changes and group failures by stable reason code.
4. Page the owning Cloud module/queue owner; preserve only counts, timestamps and redacted correlation references.

## Verification

Verify the growth rate returns to zero and newly accepted work completes through the authoritative state path. A reduced queue count alone is not evidence of successful completion.

## Rollback and escalation

Do not replay or purge dead letters without the owning module's explicit effect-certainty procedure. If a candidate regression is confirmed, follow the approved [deployment recovery procedure](../../../docs/deployment.md#recovery) before any replay decision.

Rehearsal status: not recorded here; OPS.03 owns runbook rehearsal and this file does not close WP-45.02.
