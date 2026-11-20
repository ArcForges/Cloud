# Storage admission unavailable

Alert: `storage-admission-unavailable` · route: `page`

## Preconditions

Check runtime database and schema-admission series on the private listener or pulse.

## Decisions

Failed schema admission with a reachable database can reflect an incompatible migration or a still-isolated restoration.

## Steps

Check the expected migration identity and restore status using the administrator workflow. Keep restored targets isolated until the qualified admission procedure completes. Preserve the private archive and matching sidecar.

## Verification

Confirm both runtime checks recover and an authorized Node operation returns typed outcomes before accepting the restore as usable.

## Rollback and escalation

If validation fails, preserve the target for inspection and use the existing deployment recovery workflow with the original qualified source.

Rehearsal status: not recorded here; OPS.03 owns runbook rehearsal.
