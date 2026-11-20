# Center pending source unavailable

Alert: `center-pending-source-unavailable` · route: `page`

## Preconditions

The runtime store accepts this build and the named durable queue is configured.

## Decisions

An unavailable sample leaves the queue count and age unknown. The source may have exceeded its deliberate read deadline.

## Steps

Check the fixed queue label and runtime pool contention. Use the restricted database operational workflow to diagnose load, plan or permission changes. Keep customer and operation details private.

## Verification

Confirm another sample is available and check its count, age and truncation.

## Rollback and escalation

Preserve records and escalate ongoing sampling failures. Widening the telemetry query budget requires review against the remaining workload.

Rehearsal status: not recorded here; OPS.03 owns runbook rehearsal.
