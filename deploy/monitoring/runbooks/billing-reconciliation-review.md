# Billing reconciliation review

Alert: `billing-reconciliation-review` · route: `page`

## Preconditions

Use aggregate counts in operational telemetry and the restricted billing workflow for the individual verified provider record.

## Decisions

Review records are held for a decision and do not drain through routine retries.

## Steps

Check queue age and truncation. Match the original provider resource and normalized event. Keep raw webhook data and customer details out of the alert.

## Verification

Confirm authorized settlement clears the review and that the target ledger matches verified provider facts.

## Rollback and escalation

Escalate uncertain provider outcomes without editing financial or entitlement history. Preserve the checkout and original verified payment evidence.

Rehearsal status: not recorded here; OPS.03 owns runbook rehearsal.
