# Server error-rate spike

Alert: `server-error-rate-spike` · capability: `cloud-api` · route: `page`

## Preconditions

Use read-only telemetry and deployment views. Keep exception text, request bodies, credentials and user identifiers out of notes.

## Decisions

Confirm the five-minute server-error rate exceeded its threshold with at least 100 observations. A single unexpected exception is a defect signal, not a page; group errors by bounded reason code and capability.

## Steps

1. Confirm the alert window and sample count, then compare API, identity and sync-control-plane indicators.
2. Check whether the spike begins at a candidate promotion boundary and compare only the sealed candidate identities.
3. Review bounded reason codes and dependency attribution; do not export exception messages or raw URLs.
4. If the errors are isolated to an external dependency, page that dependency owner and keep its objective separate from first-party API availability.

## Verification

Issue a contract-valid read for the affected capability and verify the expected typed result. Confirm the error-rate signal stays below threshold through a full evaluation window.

## Rollback and escalation

For a confirmed candidate regression, follow the approved [deployment recovery procedure](../../../docs/deployment.md#recovery) using the last sealed candidate. Do not retry writes blindly or change production data. Route provider failures to the dependency owner.

Rehearsal status: not recorded here; OPS.03 owns runbook rehearsal and this file does not close WP-45.02.
