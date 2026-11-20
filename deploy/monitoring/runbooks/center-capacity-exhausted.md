# Center capacity exhausted

Alert: `center-capacity-exhausted` · route: `page`

## Preconditions

Use the private Center metrics or structured pulse and scope the incident to one instance and resource.

## Decisions

Compare occupied reservations with the enforced limit. Confirm a sustained cap before paging.

## Steps

Inspect new channel refusals and client reconnect activity. Correlate full request pools with idle socket counts and full watch pools with slow or stuck clients. Let denied clients use their configured backoff.

## Verification

Confirm reservations fall below the configured cap and authorized work can be admitted again.

## Rollback and escalation

Preserve the cap while investigating. If capacity stays exhausted, shed unnecessary remote activity using the approved operation procedure. Local Sandbox and Run activity remains on the Node.

Rehearsal status: not recorded here; OPS.03 owns runbook rehearsal.
