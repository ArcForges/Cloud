# Primary database unavailable

Alert: `database-unavailable` · dependency: `primary-database` · route: `page`

## Preconditions

Use the existing on-call identity and read-only capability/dependency health views. Do not run ad-hoc D1 writes or destructive repair statements.

## Decisions

Confirm three consecutive dependency-health failures. Compare the database dependency objective with cloud API, identity and sync-control-plane SLIs so the event is attributed to the database rather than reported as undifferentiated platform downtime.

## Steps

1. Verify the alert's consecutive-failure evidence and the current dependency health view.
2. Check whether unrelated capabilities and non-database dependencies remain healthy.
3. Inspect the last sealed deployment and existing platform incident notices for a correlated change.
4. Page the database/Cloud on-call owner with the bounded failure window and affected capability groups.

## Verification

Use read-only capability probes until the dependency owner confirms recovery. Then verify a contract-valid read and the sync control-plane's committed-state read; do not infer recovery from process liveness alone.

## Rollback and escalation

Escalate suspected provider/region faults to the Cloudflare database owner. If a sealed candidate is implicated, use only the approved [deployment recovery procedure](../../../docs/deployment.md#recovery). Preserve database state; recovery or restore operations belong to the separately approved recovery runbook and incident authority.

Rehearsal status: not recorded here; OPS.03 owns runbook rehearsal and this file does not close WP-45.02.
