# Cloud API unavailable

Alert: `cloud-api-unavailable` · capability: `cloud-api` · route: `page`

## Preconditions

Use the existing on-call identity and read-only telemetry/deployment views. Do not copy user payloads, credentials, raw URLs or provider tokens into the incident record.

## Decisions

Confirm the alert's five-minute user-visible success window and minimum sample count. Compare the Cloud API capability with identity, sync, realtime and managed-AI indicators; there is deliberately no single platform-wide availability total.

## Steps

1. Confirm the page is not a stale evaluation and record the alert ID, evaluation window and redacted correlation references.
2. Compare the current sealed candidate and deployment status with the last known healthy candidate.
3. Check the `edge-ingress` and `primary-database` dependency indicators to distinguish ingress, storage and first-party API failures.
4. If only the API capability is affected, page the Cloud on-call owner and preserve the affected route-template and status-code counts.

## Verification

Use a bounded, contract-valid read request and confirm its expected result. Require the API SLI to recover above its internal objective for a complete evaluation window; check that other capability indicators remain separately visible.

## Rollback and escalation

If a newly promoted sealed candidate is implicated, use the documented [deployment recovery procedure](../../../docs/deployment.md#recovery) and the integration owner's approval. Do not rebuild or promote an unsealed image. Escalate dependency evidence to its owner; do not make database or edge configuration changes from this runbook.

Rehearsal status: not recorded here; OPS.03 owns runbook rehearsal and this file does not close WP-45.02.
