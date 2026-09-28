# Remote connection collapse

Alert: `remote-connection-collapse` · capability: `realtime` · route: `page`

## Preconditions

Use read-only realtime negotiation, reconnect and authoritative-polling indicators. Do not rely on a realtime event as the authoritative result.

## Decisions

Confirm the five-minute connection-loss rate exceeds 50% with at least 20 attempts. Compare the realtime capability and its transport dependency separately with API, identity and sync-control-plane objectives.

## Steps

1. Verify the signal is limited to realtime negotiation/reconnect attempts rather than successful HTTP reads.
2. Check connection loss, cursor-reset and authoritative-reconciliation counts without recording user content.
3. Confirm bounded polling/read recovery remains available and identify whether one transport dependency is affected.
4. Page the realtime/Cloud owner with the time window and redacted correlation references.

## Verification

Confirm clients can obtain the authoritative state through the documented read path and that realtime negotiation recovers below threshold. Reconcile cursors before claiming convergence.

## Rollback and escalation

Do not invent a second realtime transport or disable authoritative reads. If a sealed candidate caused the collapse, use the approved [deployment recovery procedure](../../../docs/deployment.md#recovery); escalate transport incidents to the dependency owner.

Rehearsal status: not recorded here; OPS.03 owns runbook rehearsal and this file does not close WP-45.02.
