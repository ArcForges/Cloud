# Center watch admission refused

Alert: `center-watch-admission-refused` · route: `page`

## Preconditions

Use aggregate watcher refusals with fixed global, account and Node scope labels.

## Decisions

A full account or Node cap can refuse a watch while global occupancy is below its limit.

## Steps

Locate the rising scope. Correlate it with repeated subscriptions or abrupt reconnects. Keep account and Node identifiers in restricted incident records.

## Verification

Confirm excess subscriptions receive the expected bounded refusal and reserved watch slots release on deadline or cancellation.

## Rollback and escalation

Use the approved recovery procedure if authorized watches cannot recover. Preserve the admission controls during recovery.

Rehearsal status: not recorded here; OPS.03 owns runbook rehearsal.
