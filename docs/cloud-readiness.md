# Failure isolation and readiness

This document describes the readiness surface of the Cloud Worker and host (CLOUD.08, WP-21.07). It states what each
check proves and what it does not. Nothing here adds a public production route, a contract field or a wire meaning.

## What readiness is

Readiness answers one question: can this deployment serve work right now. It is reported **per component**, never as one
flag, so a failing dependency never hides behind a healthy one and a healthy dependency never vouches for a failing one:

| Component       | Where it is judged                                                        | What a `ready` answer proves                                                                                                                                                                                       |
| --------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `ingress`       | Worker                                                                    | The declared ingress bindings are present with the expected shape (`SOURCE_REVISION`, the rate limiter, and in the proof environment the allowed origin). The Worker answered, so it is serving. Evidence `bound`. |
| `container`     | Worker, from the host's own reply                                         | The Container started and answered one signed private readiness call within the bounded wait, so it trusts this Worker's key and runs a host with the readiness route. Evidence `probed`.                          |
| `d1`            | Host (D1 reached through the real plan path), checked again by the Worker | The named readiness plan ran through the Worker's storage handler and returned schema version 1, the plan-manifest hashes of Worker and host are equal, and the recovery generations agree. Evidence `probed`.     |
| `durableObject` | Worker                                                                    | One read of an observation that nothing writes, on a Durable Object with a fixed name, answered. Evidence `probed`.                                                                                                |
| `r2`            | Worker                                                                    | A `head` of a key that holds nothing answered (absent is the healthy answer). No object is ever written. Evidence `probed`.                                                                                        |
| `queue`         | Worker                                                                    | The producer binding is present with a `send` method. A Queue producer has no read-only probe, and a send would enqueue work, so this is evidence `bound` only: it does **not** prove that messages are delivered. |

Not checked, because no such component exists yet: Vectorize, Workers AI, the Workflow, provider adapters. Each owning task
appends its declarations to `worker/readiness/bindings.ts` in its own section.

## States and reasons

Each component has one state and, when it is not ready, one reason from a closed list. Nothing else is ever reported: no
request, identifier, binding value, secret, SQL, error text or object key.

| State           | Meaning                                                                                                         | Retry helps                          |
| --------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| `ready`         | The check passed at its evidence level.                                                                         | n/a                                  |
| `starting`      | The dependency did not answer within the bounded wait, so a start may be in progress.                           | yes                                  |
| `unavailable`   | The dependency failed or could not be provided.                                                                 | yes                                  |
| `misconfigured` | A declared binding, key, plan manifest or recovery generation is missing or wrong.                              | no, until the deployment is repaired |
| `unknown`       | Not determined because the Container, which D1 is judged through, is not ready. It never counts as ready.       | follows the Container                |
| `not_required`  | The environment does not declare this component. The production Worker declares only `ingress` and `container`. | n/a                                  |

The whole is `ready` only when every component is `ready` or `not_required`. Otherwise its status is the first that applies
of `misconfigured`, `unavailable`, `starting`, and a lone `unknown` is `unavailable`. A test enumerates every combination of
component states and checks this rule.

| Reason                         | Component(s)                       | Cause                                                                                                                           |
| ------------------------------ | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `binding_missing`              | any                                | A required binding is absent or has the wrong shape. The report lists its name in `missing`.                                    |
| `key_missing`                  | `container`, `d1`                  | A signing key or the CSRF secret is absent or malformed. A half-configured previous key counts as malformed.                    |
| `key_mismatch`                 | `container`, `d1`                  | The host answered 401 (or the Worker refused the host's signature): the keys differ, or a clock is beyond the 60 second window. |
| `host_route_missing`           | `container`                        | The host answered 404: an older image without the route, or a host with the foundation module disabled.                         |
| `host_reply_invalid`           | `container`                        | The host answered 200 with a reply outside the closed shape, or one whose two statements disagree.                              |
| `host_error`                   | `container`                        | Any other status, or a 503 without the closed report.                                                                           |
| `no_instance_available`        | `container`                        | The Containers platform could not provide an instance: the instance limit is reached, or the application is still provisioning. |
| `start_failed`                 | `container`                        | The platform started the Container and it failed to come up.                                                                    |
| `rate_limited`                 | `container`                        | The platform rate limited the start.                                                                                            |
| `no_answer_in_wait`            | `container`, `durableObject`, `r2` | Nothing answered within the bounded wait. For the Container this includes a cold start that is still running.                   |
| `unreachable`                  | `container`, `durableObject`, `r2` | The call failed before an answer.                                                                                               |
| `container_not_ready`          | `d1`                               | D1 is judged through the Container and the Container is not ready.                                                              |
| `plan_hash_mismatch`           | `d1`                               | The Worker's generated plans and the host's compiled plans were built from different manifests.                                 |
| `schema_mismatch`              | `d1`                               | The readiness plan returned a schema version other than 1, or no row.                                                           |
| `recovery_generation_mismatch` | `d1`                               | The Worker's active recovery generation differs from the host's.                                                                |
| `d1_unavailable`               | `d1`                               | D1 could not be reached or answered with a failure.                                                                             |

## Surfaces

- **Operator readiness** `POST /proof/v1/readiness` with an empty JSON object and the operator signature, in the isolated proof
  environment only. It returns the closed report: `schema`, `status`, `ready`, `environment`, `workerRevision`, `components`,
  and, from the host's own valid reply, `manifestHash`, `schemaVersion` and `revision` (the names the deployed scenarios
  already read). Status 200 when ready; 503 otherwise, with `Retry-After: 2` only when `starting` or `unavailable`.
  Each call asks the Container once, reads the Durable Object and R2 once, and never retries, replays or writes.
- **Host readiness** `POST /internal/foundation/v1/readiness`, signed by the Worker, never public. 200 when D1 is ready, 503
  with the same closed report otherwise (a 503 is the host's own answer, so the Worker can tell a plan mismatch from an outage).
- **Production** serves no new route: the production Worker keeps the anonymous Hello method and `/api/healthz` only
  ([cloud-ingress](cloud-ingress.md)). The Container start-failure classification below applies there too.

## A Container that could not be started

The Containers library answers a request for an instance it could not start with a plain-text response of its own (503
`There is no Container instance available at this time.`, 500 `Failed to start container: ...`, or 429). Such a response
proves the request never reached the host. The Worker classifies it from the status, the plain-text media type and the
exact opening of the text, and answers with the fixed text `Cloud container is temporarily unavailable.`, HTTP 503 and
`Retry-After: 2`: the effect did not happen, so a retry is safe. The library's text is never passed on.

Any other non-200 status, a thrown error and an unreadable reply stay the same fixed 503 **without** retry guidance: the
call may have been forwarded, so its effect is not known and ordinary uncertainty recovery applies. The cold-start bound of
a stream (fifteen seconds) ends the same way, without guidance, because it also ends a call that reached a slow running Container. There is no retry or replay of an application call.

The opening texts come from the locked `@cloudflare/containers`. `tests/worker/readiness-container.test.ts` reads the
installed library and fails if an upgrade changes them, so the classification can never degrade silently; an unrecognized
response only loses its retry hint and is never treated as a success.

### Diagnosing a 503 from the proof origin

1. `GET /api/healthz` answers from the Hello instance. A 200 there says the Worker, its Durable Object and one Container
   instance work, and nothing about the foundation instance, which is a separate Durable Object instance of the same class.
2. `GET /session/v1/bootstrap` (anonymous) goes to the foundation instance. A 503 whose body begins with
   `There is no Container instance available at this time.` is the platform's answer that it could not provide an instance
   (after about thirty seconds: the library tries to acquire one for eight seconds and waits up to twenty for the port). It is
   neither the Worker's own refusal (empty body) nor the host's (JSON).
3. The operator readiness report names the same condition as `container: unavailable:no_instance_available`.
4. The pattern seen from outside on 2026-10-06 (CLOUD.71): with `max_instances` 2 only one of the two named instances ran
   at a time. While Hello answered, every foundation call ended in this 503 after about thirty seconds, for as long as Hello
   stayed active, and the reverse; the refused instance started within seconds after the other one's 60 second idle stop.
   The proof ceiling is therefore 4, a limit with headroom for the two names, not a minimum.
5. What a request cannot tell: whether a stopped or stopping instance still counts, only one location is usable, an older
   rollout left instances behind, or the application is still provisioning (about ten minutes after a deployment). The
   manual dispatch `proof=observe` (`npm run observe:proof`, read-only, [PRF.07 proof](prf-07-foundation-proof.md)) prints
   the provider's own view: the configured ceiling, every instance by state, version and location, the Durable Object each
   one serves, and the newest rollouts.

## The wait is bounded

The operator readiness call waits at most `readinessWaitMs` (eight seconds, Design D1 profile section 3) for each component
and aborts the Container call at the bound; a Container that is still starting is reported `starting` with `Retry-After: 2`,
and the next call finds it further along. launch-capacity.v1 (CLOUD.10) carries the same value as `readinessTimeoutMs`.

What is **not** bounded by this task: the library's own start wait inside the Durable Object (about eight seconds to acquire an
instance plus up to twenty for the port) when a public request or an operator operation other than readiness meets a cold
Container. A bounded start inside the Container class, which refuses before forwarding with an exact `didNotHappen` effect,
changes the Container class of the production Worker and belongs with the launch configuration.

## No-content logs

The operator readiness call writes one line: `event`, `status`, `environment` and one `state` or `state:reason` token per
component, all from the closed vocabulary above. No request, identifier, binding value, secret, duration or error text is
logged, and the report has none either. Tests check both against secret values placed in the environment.

## The first write after a restart: what `unknown_outcome` is and what is known

`unknown_outcome` is the answer for a **write** whose outcome the system cannot know. It has exactly two sources: the Worker's
storage handler when the write batch outlives its eight second deadline, and the host's `WorkerPlanExecutor` when its HTTP call
to the storage binding does not answer within ten seconds (the eight second default deadline plus two seconds of grace; a test
pins both numbers and the classification). A read in the same situation is `unavailable`, because it has no effect. A write is
never retried automatically, so the caller reconciles through the stored receipt.

The CLOUD.01 live run met it once: the first write after the foundation Container was stopped and restarted answered
`unknown_outcome` after about 11 seconds, a readiness read through the same path had answered under a second earlier, and the
identical scenario passed in 3.4 seconds on the same deployment in the next run. About 11 seconds fits the host's ten second
bound plus the call's overhead better than the Worker's own eight second deadline, which would point at the storage binding not
answering in time rather than at D1 failing; the overhead of the operator call is not measured, so this is an inference.

**Status of the lead.** It is explained, not reproduced. A read that succeeded shortly before proves the path worked then, not
that the next write cannot stall, and a stall on either the first use of the restarted instance's outbound interception or the
first D1 write after idle is consistent with the timing. Neither can be told apart from this repository: no provider logs or
metrics are readable with the access available, and a stall is not reproducible offline. Readiness does not turn it into a
guarantee: a probe that guarantees a first write would have to write, and the proof schema is not extended for that. What the
system does guarantee is the behavior, and the tests pin it: the bounds, the classification, no automatic retry and no
success reported. A deployed scenario that repeats stop, restart and first write several times (opt-in, under the
`RES-cloud-deployment` lease) is the way to measure how often it happens; it is a deferred live check, not part of this task.
