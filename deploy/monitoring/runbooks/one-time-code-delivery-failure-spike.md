# One-time-code delivery failure spike

Alert: `one-time-code-delivery-failure-spike` · dependency: `identity-delivery` · route: `page`

## Preconditions

Use delivery outcome and suppression metadata only. Never place a one-time code, email address, credential or message body in telemetry or the incident record.

## Decisions

Confirm the ten-minute failure rate exceeded 20% with at least 20 outcomes. Distinguish provider rejection, bounce/complaint suppression, rate limiting and an unknown send outcome; unknown is not a safe reason to retry through another provider.

## Steps

1. Compare accepted, delivered, bounced, complained and unknown outcome counts using bounded categories.
2. Check the notification purpose/stream and provider adapter's redacted status without exposing account data.
3. Confirm whether security-critical delivery has a prepared secondary path and whether its activation is authorized.
4. Page the identity-delivery owner; preserve provider request references only when they contain no secret material.

## Verification

Verify new test deliveries reach a terminal provider outcome through the authorized adapter and that suppression/rate-limit protections remain active. Do not treat an accepted send as proof that a user received or read a code.

## Rollback and escalation

Do not resend an unknown logical delivery or disable suppression. Provider failover is permitted only under the delivery adapter's documented acceptance/effect-certainty rules; escalate ambiguous delivery to the incident owner.

Rehearsal status: not recorded here; OPS.03 owns runbook rehearsal and this file does not close WP-45.02.
