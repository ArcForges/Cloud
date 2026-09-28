# Payment provider webhook backlog

Alert: `payment-provider-webhook-backlog` · dependency: `payment-provider` · route: `page`

## Preconditions

Use webhook receipt and reconciliation metadata only. Do not handle cardholder data, signing secrets or payment payloads in monitoring or incident notes.

## Decisions

Confirm the oldest pending webhook is older than five minutes. Separate provider delivery delay from Cloud receipt, signature verification, deduplication and downstream processing.

## Steps

1. Check the bounded oldest-age and backlog counters plus signature-verification outcome codes.
2. Compare payment-provider health with Cloud API and database objectives; keep the provider objective distinct.
3. Check reconciliation status by opaque event reference and idempotency state; do not interpret missing provider search results as non-acceptance.
4. Page the payment integration owner and preserve only redacted provider event references.

## Verification

Verify the backlog drains through idempotent processing and each affected payment fact reaches the authoritative reconciled state. Do not replay a webhook manually.

## Rollback and escalation

Do not change financial records or suppress signature checks. Use the payment owner's approved reconciliation procedure for unknown outcomes; a deployment rollback follows the approved [deployment recovery procedure](../../../docs/deployment.md#recovery).

Rehearsal status: not recorded here; OPS.03 owns runbook rehearsal and this file does not close WP-45.02.
