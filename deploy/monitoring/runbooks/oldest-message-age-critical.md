# Critical oldest-message age

Alert: `oldest-message-age-critical` · dependency: `message-queue` · route: `page`

## Preconditions

Use read-only queue age, delivery and capability views. Do not inspect or copy message payloads.

## Decisions

Confirm the oldest-message age exceeded five minutes and identify the bounded queue class. Separate delayed work from a user-facing API outage; queue age is its own dependency signal.

## Steps

1. Confirm the window and the oldest age from metadata only.
2. Compare queue age, active-worker capacity, retry counts and dead-letter growth.
3. Check whether the producing API capability remains healthy and whether only one queue class is affected.
4. Page the queue/Cloud owner with queue class, age and correlation references; never include message content.

## Verification

Observe the oldest-message age returning below the five-minute threshold and confirm the affected task or delivery reaches its authoritative terminal state. Realtime hints are not proof of completion.

## Rollback and escalation

Do not replay, delete or mutate queue messages from this runbook. If a recent sealed candidate is implicated, follow the approved [deployment recovery procedure](../../../docs/deployment.md#recovery); queue replay and effect-certainty decisions require the owning module's incident procedure.

Rehearsal status: not recorded here; OPS.03 owns runbook rehearsal and this file does not close WP-45.02.
