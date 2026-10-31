# Feature availability and entitlements on the center

AF-CTR-03 part B gives the Go center its answer to "may this account use this feature": the entitlement resolver (a Go port of the
C# module, [entitlement resolver](entitlement-resolver.md)), a store for its records and snapshots (migration `0003`), the plan
catalogue as configuration, the operator grant, the self-hosted default, and the feature gate in the center's authorization. It
sells nothing, charges nobody and activates nothing: the production catalogue is empty and stays empty until the owner decides
prices and limits (H-07).

The commerce path (a purchase becomes grants and terms) is AF-CTR-09, the operator's own service is AF-OPS-01, and the gated
operations themselves (task control, nodes, MCP, push) arrive with AF-CTR-04 and later. [What waits](#what-waits-for-later-tasks) lists
what this document does not describe because it does not exist yet.

## Evidence labels

Every test and every piece of evidence of this part is one of the two:

| Label      | What it is                                                                                                                                                                                                                                                                                                                                                                                        |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **REAL**   | The Go resolver replayed against every row the C# suites produce (recorded data, real logic); the store, the migration and the grants on a real PostgreSQL; the step-up evidence consumed by the real identity code; the audit chain; the real ingress pipeline and bearer verifier in front of the gate; the passkey ceremony of the page tests (a virtual authenticator, a real relying party). |
| **MOCKED** | The plan catalogue (the illustrative development fixture, or a document injected by a test), its prices (USD 5 and USD 15, illustrative and not approved); the test-only operations that stand for the gated operations no task serves yet; the step-up evidence stubbed in the rig that proves the gate after a grant.                                                                           |

## The catalogue

`ARCFORGES_CENTER_PLAN_CONFIGURATION` is the only source of a catalogue (DC-12). There is no environment variable that carries a
catalogue document, no file path and no production slot:

| Value                  | Result                                                                                                                                                                                                                                                                                                  |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| empty (production)     | No catalogue: every gated key is unavailable (`plan_configuration_missing`) and operator grants are refused (`no_catalogue`). This is the production state until H-07.                                                                                                                                  |
| `development-fixtures` | The embedded `center/internal/feature/fixtures/development.json` (marked `"fixture": true`, with the plans `fixture-all` at an illustrative USD 15 and `fixture-view` at USD 5). Official-hosted only; the acceptance environment sets it, production never does (`tests/worker/proof-deploy.test.ts`). |
| anything else          | The center does not start.                                                                                                                                                                                                                                                                              |

A catalogue is strict JSON of at most 64 KiB (no unknown or repeated field), with a version, the six gated keys as its
capabilities (exactly those, each once), and at most 16 plans of known keys. A price is allowed only in a fixture, as the
illustrative USD 5 or 15, and a fixture is allowed only under the development classification: a fixture under the production
classification, a price outside a fixture or any other violation makes the catalogue invalid, the start logs the rule that failed
(never a value), and every gated key is unavailable (`plan_configuration_invalid`). The classification of a running center is
development with the fixtures and production without a catalogue; a production-classified catalogue exists only injected into
`server.Options` by a test (`Catalogue`, `CatalogueClass`: tests only, and `TestTheCatalogueOfARunningCenterComesOnlyFromItsPlanConfiguration`
fails if `cmd/arcforges-center` ever sets them). The plans are configuration for AF-CTR-09, which turns a purchase of a plan into
grants of its features; this task issues grants of features, never of plans.

A change of the definitions version is a `definitions_activation` row and raises the entitlement version of an account once, at its
next read or write (`entitlement.WithActivation`); nothing rewrites history.

## Operator grants

An operator gives an account features for a bounded time, with a recorded reason. The logic is `entitlement.Operator` so that
AF-OPS-01's OperatorService can call it; the interim interface is [the operations page](#the-operations-page).

- **Who.** A HUMAN account session (scope `account`) whose user is a live operator: an `identity.operator` row that is neither revoked
  nor ended, or the owner who bootstrapped the center ([operator role](center-identity.md#operator-role)), **and whose account is
  active**: a restricted, suspended or deleted account reaches only security operations, so it is no operator here (it is audited as
  any other stranger below). The role is read when the request is checked and again in the grant's own transaction, after that
  transaction has locked the operator's `identity.user` row (`FOR UPDATE`). `grant-operator` and `revoke-operator` and the
  consumption of step-up evidence lock the same row, always first, so a revocation either committed before the grant's read (the grant
  is refused) or waits for the grant's transaction and follows it, and two `grant-operator` runs for one account leave one live row.
  Only the official hosted center has operator grants: a self-hosted
  center refuses them (`self_hosted`, its availability is the built-in default), and so does a center without a valid catalogue
  (`no_catalogue`).
- **The request.** The account (a uuid), the feature keys of the catalogue or the shorthand for every key (not both: `all` together
  with named keys is refused, `features: conflicts_with_all`, because one would silently replace the other), a reason of 1 to 512
  characters that is valid UTF-8 and has no control characters (an invalid byte sequence is refused, `reason: encoding`, like the
  justification and the source reference), an expiry, and a source reference of 1 to 96 characters (a ticket or incident). The expiry
  is required, lies in the future and is at most 90 days ahead under a production-classified configuration and 400 days otherwise.
  Under a production-classified configuration a grant of every key of the catalogue is refused (`catalogue_wide`). A grant to the
  operator's own account needs a justification of its own; it is stored with the reason (`<reason> | self-approval: <justification>`,
  512 characters together at most).
- **The step-up.** The step-up class is `center.operatorGrant` (`access.CenterOperations`), valid for five minutes, its target the
  SHA-256 of the canonical request (the operator, the account, the sorted keys, the reason, the expiry, the source reference and the
  justification), so evidence for one request cannot authorize another. It is single use and consumed in the grant's own
  transaction (`identity.ConsumeEvidenceFor`): a grant that refuses afterwards spends nothing.
- **One transaction.** The command receipt (`platform.Execute`, operation `center.operatorGrant`, keyed by the client's command ID),
  one `compensation` service term over the window, one `AdminGrant` capability grant per key (source reference
  `<reference>:<key>`), the refreshed snapshot and the audit event `entitlement.operator_grant.issued`, whose payload holds the
  account, the keys, the expiry, the ids and the digest and length of the reason, never the reason. A failed audit append refuses
  the grant. The same command again answers its stored result and writes nothing; the same command with another request is
  `CONFLICT/command_id_reused`; the same source reference again is `CONFLICT/already_exists`.
- **Refusals** are audited as `entitlement.operator_grant.refused` in a transaction of their own, with a closed reason
  (`not_operator`, `step_up_required`, `invalid_argument`, `account_not_found`, `already_granted`, and for a state refusal its
  reason: `no_catalogue`, `self_hosted`, `catalogue_wide`, `self_approval_required`, `account_state`, `clock`, `history`); a refusal
  whose audit cannot be written surfaces the store failure instead of staying silent. The payload never holds the operator's raw
  text: the feature keys are the normalized keys of the catalogue (a name it does not know is only counted), with their count and the
  SHA-256 of the submitted list, so a refused request cannot put free text, control characters or a megabyte into the audit chain.
- **A stranger's request.** An account that is no operator and asks for the page (`GET` or `POST`, any of the three routes), or whose
  grant is refused because it stopped being an operator after the page loaded, is answered 403 and its refusal is audited as
  `entitlement.operator_grant.refused` (reason `not_operator`, with the route asked for on the page) in a transaction of its own and
  **once per hour and account**: the first refusal of the window is audited, the others are counted and answered without a row, so
  an authenticated stranger cannot flood the audit chain. This is the pattern of the sign-in failures ([audit](center-identity.md#audit):
  the first failure of a window per bucket): `ratelimit.Limiter.Fail` reports the first failure of a window. The other refusals of an
  operator (a bad request, a missing step-up) are audited every time: they take a signed-in live operator, and each of
  them is a decision the owner may need to read.
- **Concurrency.** Two operators granting to one account at once both succeed: the account's revision row is locked
  (`SELECT ... FOR UPDATE`, pinned by `TestManyOperatorsGrantingToOneAccountAtOnceAllSucceed`), the history is loaded under the lock
  and the commit is fenced by the revision. A command that finds the revision changed re-derives and tries again, at most **four
  attempts**, immediately and without backoff (the lock makes the second attempt find the other writer's commit); when all four
  lose, nothing is written and the answer is `RESOURCE/overloaded` (the store's contention), after which the same command ID may be
  sent again. The same command running twice at once answers the same way (`ErrCommandInProgress`).

The records of a grant are the records the resolver reads (a grant is a fact; the snapshot is derived). A term, a status fact or a
feature release written by its owner admission must refresh the snapshot in the same unit (`Service.Refresh`), because only grants
and revocations are validity boundaries the snapshot's expiry covers; the owners of those records (commerce, trust and safety,
configuration) are later tasks and have no INSERT privilege on them yet.

## The operations page

The interim page is the `operations` surface: `GET /operations/grant` (the form), `POST /operations/grant/review` (the request
checked and normalized exactly as a grant would, nothing written, with the step-up target) and `POST /operations/grant/confirm`
(the grant). The script of the pages proves the passkey step-up for the review's target before the confirmation form is submitted.
The surface needs `identity` and `pages`, exists only in official-hosted mode and is never a default; it is in no checked-in
environment (production carries none; the acceptance environment keeps `identity,pages` until the coordinator enables `operations`
for the hosted proof). Where it is off, every route answers 404 as the pages surface does, with the security headers; a signed-in
account that is no operator (or whose account is not active) gets 403, audited as above. Every reply carries the seven page security headers byte for byte, `Cache-Control: no-store,
no-transform` included, and the Worker's page handler checks the surface of each route before anything else.

## The gate

`access.Authorize` decides a session call in seven stages. A stage that refuses ends the decision, so a call a stage refused never
reaches a later one, and the gate is the last:

| #   | Stage                   | Refusal                                                                                                             |
| --- | ----------------------- | ------------------------------------------------------------------------------------------------------------------- |
| 1   | Authentication          | `AUTHENTICATION/unauthenticated`                                                                                    |
| 2   | Ownership of the object | `STATE/not_found` for another account's object or none (a row names an `Object`; the handler supplies its owner)    |
| 3   | Scope and risk          | `permission_denied` (audited `access.refused`: `scope`, `restricted`), `step_up_required` (the session upgrade)     |
| 4   | AGENT/HUMAN separation  | `permission_denied` (audited `access.refused`: `principal`)                                                         |
| 5   | Resource controls       | the control's refusal (a rate limit now; quotas and budgets from AF-CTR-04, DC-07)                                  |
| 6   | Audit before the call   | the store failure when `access.authorized` cannot be appended (the call is refused)                                 |
| 7   | The gate                | `ENTITLEMENT/feature_not_entitled`, `state.reason` = the feature key, audited `access.gated` with the gate's reason |

An essential operation (sign-in, account, billing, security, recovery) has no `Feature` and is never gated; a gated row is audited
before the call (`access.CheckRow`). A gate that cannot read the entitlement is an unavailable store, never a refusal that says the
plan lacks the feature; an authorizer composed without a gate refuses every gated row. The context carries the caller's account
(`feature.WithAccount`).

The gate's decision in official-hosted mode: no catalogue is `plan_configuration_missing`, an invalid one
`plan_configuration_invalid`, a valid one the account's snapshot (`cap=` entries of the stored canonical text: granted, or the
resolver's reason). The reasons are the closed vocabulary of [feature availability](center.md#center-mode-and-feature-availability).

No gated operation is served before AF-CTR-04, so the gate is proved on test-only operations (F9): one per key behind the real
ingress pipeline, the real bearer verifier and a real PostgreSQL (`center/internal/access/gate_integration_test.go`), in every state
of the plan configuration (none, invalid, fixtures without a grant, fixtures with a grant, a test-injected production-classified
catalogue with and without a grant, a fixture under the production classification, the self-hosted default, a disabled key, the
missing push sender). A spy that delegates to the real gate shows it is not asked by an unauthenticated, foreign-device,
wrong-principal, restricted, upgrade-needing, resource-exhausted or unaudited call (the audit insert fails inside PostgreSQL through a
trigger that raises, F5). The routed task control table is in [feature availability](center.md#routed-task-control).

## Self-hosted mode

The built-in default enables every available gated key (`self_hosted_default`). `push` is available only when a push sender is
configured (`push_sender_not_configured` otherwise, DC-22); none exists before AF-CLD-06. The operator of a self-hosted center limits
keys with `ARCFORGES_CENTER_DISABLED_FEATURES` (exact known keys, comma-separated; they answer `operator_limit`): an unknown,
repeated or empty key refuses to start, the variable is refused in official-hosted mode, and the Worker never passes it to a hosted
Container (PLT-18, `tests/worker/container-classes.test.ts`). `IsSelfHostRealm` of the definitions comes from the center mode (DC-20):
the C# decisions ID-10 and ID-11 that derived it from a realm record are superseded. A paid grant that lapsed and an operator grant
that is in force are both still resolved by the resolver with the self-hosted definitions, which the tests show
(`TestALapsedPaidGrantPlusAnOperatorGrant`). Resource limits are enforced by the tasks whose operations they bound.

## The store

Migration `0003_entitlement.sql` (sha256 `8eaca09b91e57abc9514c70ced246f965b31f9a2bf898fdb9dabadb2bd7c3f9d`) adds the `entitlement`
schema and `identity.operator`: `grant`, `revocation`, `service_term`, `service_term_action`, `account_status_fact`,
`feature_release` and `definitions_activation` (append-only: a trigger refuses UPDATE and DELETE, and the runtime role has neither
privilege), `revision` and `snapshot` (derived, rewritten in place, the revision only advancing by one), and the operator role
(written by the migration role only). The runtime role may insert grants, revocations, definitions activations and service terms
and reads the rest; term actions, status facts and feature releases have no runtime writer until their tasks exist. The details,
the personal data and the retention are in [PostgreSQL store](postgres-store.md#entitlement-af-ctr-03-b).

## Post-deploy checklist

The hosted run on the proof environment is done by the coordinator after the merge and the deployment. Nothing below was run by the
author of this change (no hosted environment was touched).

1. **Production stays dark.** `center.surfaces` is still `none`; `ARCFORGES_CENTER_PLAN_CONFIGURATION` is unset in production; the
   migration gate applied `0003` to `neondb` (the tables exist and are empty; `identity.operator` has no row); no gated feature is
   reachable.
2. **The acceptance database** (`arcforges_acceptance`) is migrated to version 3 with the pinned checksum above.
3. **Enable the surface** on the proof environment by a reviewed change of `FLAGSHIP_SURFACES` to `identity,pages,operations` (it is
   not part of this change), then give the proving account the role with the deployment's migration-role path:
   `arcforges-center admin grant-operator --account <uuid> --reason "hosted proof of the operator grant" --days 7`.
4. **The page**, checked with `curl -si` and a browser: an unauthenticated `GET /api/operations/grant` is `303` to the sign-in
   page; the operator's session gets `200` with the seven security headers and `Cache-Control: no-store, no-transform`; any other
   account gets `403`.
5. **The grant** at API level with the fixture catalogue: review, confirm with the passkey, the done page names the term and the
   entitlement version; the same form again says it was already issued; a wrong or reused step-up is refused. No gated operation is
   served, so the hosted run shows the grant and the snapshot, not a gated call.
6. **Clean up:** `arcforges-center admin revoke-operator --account <uuid>`, and let the grants end at their expiry.

## What waits for later tasks

- **AF-CTR-09** (commerce, Paddle): a purchase becomes a service term, a plan's grants and the status facts; the writers of
  `service_term_action`, `account_status_fact` and `feature_release`; the offer and realm columns of the term; the refresh of the
  snapshot by the owner admission.
- **AF-OPS-01**: the OperatorService that replaces the interim page and calls `entitlement.Operator`.
- **H-07**: the approved prices, limits and the Neon plan and retention; until then the production catalogue is empty.
- **AF-CTR-04 and later**: the gated operations (task control, nodes, MCP), their quotas and budgets through the resource-control
  stage, and the rows of the operation table that carry a `Feature`.
- **AF-CTR-07** (MCP, agent grants) keeps the feature keys and the `feature.Gate` interface as they are; **AF-CLD-06** brings the
  push sender; **AF-PLAT-01** the retention sweeps and the erasure of an account's records.
