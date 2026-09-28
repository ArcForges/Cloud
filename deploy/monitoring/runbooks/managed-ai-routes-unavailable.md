# All managed-AI routes unavailable

Alert: `managed-ai-routes-unavailable` · capability: `managed-ai` · route: `page`

## Preconditions

Use aggregate route-availability and bounded typed failure categories. Never copy prompts, responses, model names supplied by users, BYOK values or provider credentials into evidence.

## Decisions

Confirm no managed-AI route was available during the five-minute window. Compare the managed-AI capability and managed-AI dependency objectives independently with Cloud API, identity, sync and realtime.

## Steps

1. Confirm route-availability evidence is an aggregate over the configured managed routes and not a single-route failure.
2. Check bounded provider failure categories and circuit/degradation state from the existing operations view.
3. Verify non-AI capabilities remain separately usable and do not classify a managed-AI outage as a total platform outage.
4. Page the managed-AI/Cloud owner with route count, time window and redacted correlation references only.

## Verification

Confirm at least one authorized managed route returns its contract-valid typed outcome, then require the managed-AI SLI to recover over a full window. A completed response does not authorize logging its content.

## Rollback and escalation

Do not switch providers, alter model policy or expose BYOK secrets from this runbook. Use the existing managed-AI outage and uncertain-supplier-reconciliation procedure; a candidate rollback uses only the approved [deployment recovery procedure](../../../docs/deployment.md#recovery).

Rehearsal status: not recorded here; OPS.03 owns runbook rehearsal and this file does not close WP-45.02.
