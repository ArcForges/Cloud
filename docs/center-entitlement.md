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

| Label      | What it is                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **REAL**   | The Go resolver replayed against every vector the six covered classes of the C# suites produce (recorded data, real logic; the C# persistence suites are not recorded, the Go tests pin the branches they reach); the store, the migration and the grants on a real PostgreSQL; the step-up evidence consumed by the real identity code; the audit chain; the real ingress pipeline and bearer verifier in front of the gate; the passkey ceremony of the page tests (a virtual authenticator, a real relying party). |
| **MOCKED** | The plan catalogue (the illustrative development fixture, or a document injected by a test), its prices (USD 5 and USD 15, illustrative and not approved); the test-only operations that stand for the gated operations no task serves yet; the step-up evidence stubbed in the rig that proves the gate after a grant.                                                                                                                                                                                               |

## The catalogue

`ARCFORGES_CENTER_PLAN_CONFIGURATION` is the only source of a catalogue (DC-12). There is no environment variable that carries a
catalogue document, no file path and no production slot:

| Value                  | Result                                                                                                                                                                                                                                                                                                  |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| empty (production)     | No catalogue: every gated key is unavailable (`plan_configuration_missing`) and operator grants are refused (`no_catalogue`). This is the production state until H-07.                                                                                                                                  |
| `development-fixtures` | The embedded `center/internal/feature/fixtures/development.json` (marked `"fixture": true`, with the plans `fixture-all` at an illustrative USD 15 and `fixture-view` at USD 5). Official-hosted only; the acceptance environment sets it, production never does (`tests/worker/proof-deploy.test.ts`). |
| anything else          | The center does not start.                                                                                                                                                                                                                                                                              |

A catalogue is strict JSON of at most 64 KiB (no unknown or repeated field, and every field name exactly as spelled below: `Version`
or `FIXTURE` is refused, not matched case-insensitively and not kept as a second value), with a version, the six gated keys as its
capabilities (exactly those, each once), and at most 16 plans of known keys. A price is allowed only in a fixture, as the
illustrative USD 5 or 15, and a fixture is allowed only under the development classification: a fixture under the production
classification, a price outside a fixture or any other violation makes the catalogue invalid, the start logs the rule that failed
(never a value; one ERROR line from `Center.logPlanConfiguration`, tested with an injected invalid catalogue), and every gated key is
unavailable (`plan_configuration_invalid`). The classification of a running center is development with the fixtures and production
without a catalogue; a production-classified catalogue exists only injected into `server.Options` by a test (the fields are
unexported, so no other package can set them, and `TestNoCodeOfTheRunningCenterInjectsACatalogue` parses the non-test sources of
the whole center module and fails if `Run` composes the center with anything but the literal `Options{}`, if anything but the two
values of the one `feature.Settings` literal in `New` mentions the fields, if `Injected` or `InjectedClass` is named anywhere else
outside package `feature`, or if `feature.Configure` or `feature.ParseCatalogue` is called beside `New`;
`TestThePinOnTheCatalogueInjectionFindsEachWayAroundIt` proves the pin on the real sources changed in each way. It is a scan of
the source text for those forms, not a proof; it does not see a call through an import alias of package `feature`, reflection, a
`feature.Configuration` literal or a write to its exported fields (`State`, `Catalogue`, `Class`) inside `New` or after it, a direct
`feature.DevelopmentFixtures()` call, or the inside of package `feature` itself, whose behaviour its own tests pin; the composed test
of the operator policy catches the first writes for a hosted center without a plan, and nothing catches a late write after `New`). The plans are configuration for AF-CTR-09, which turns a purchase of a plan into
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
  reason: `no_catalogue`, `self_hosted`, `catalogue_wide`, `self_approval_required`, `account_state`, `clock`, `history`, `invalid_state` for a state refusal without a reason, and `refused` for any other refusal, for
  example `CONFLICT/command_id_reused`); a refusal
  whose audit cannot be written surfaces the store failure instead of staying silent. The payload never holds the operator's raw
  text: the feature keys are the normalized keys of the catalogue (a name it does not know is only counted), with their count and the
  SHA-256 of the submitted list, so a refused request cannot put free text, control characters or a megabyte into the audit chain.
- **A stranger's request.** An account that is no operator and asks for the page (`GET` or `POST`, any of the three routes), or whose
  grant is refused because it stopped being an operator after the page loaded, is answered 403 and its refusal is audited as
  `entitlement.operator_grant.refused` (reason `not_operator`, with the route asked for on the page) in a transaction of its own and
  **once per hour and account**: the first refusal of the window is audited, the others are counted and answered without a row, so
  an authenticated stranger cannot flood the audit chain. This is the pattern of the sign-in failures ([audit](center-identity.md#audit):
  the first failure of a window per bucket): `ratelimit.Limiter.Fail` reports the first failure of a window. `Operator.check`
  decides the caller before the policy, so the bound holds on a center that has no policy as well (self-hosted, or hosted without
  a catalogue): a stranger there is `not_operator`, audited once per window, and only an operator is told `self_hosted` or
  `no_catalogue`. The other refusals of an
  operator (a bad request, a missing step-up) are audited every time: they take a signed-in live operator, and each of
  them is a decision the owner may need to read.
- **Concurrency.** Two operators granting to one account at once both succeed: the account's revision row is locked
  (`SELECT ... FOR UPDATE`, pinned by `TestManyOperatorsGrantingToOneAccountAtOnceAllSucceed`), the history is loaded under the lock
  and the commit is fenced by the revision. A command that finds the revision changed re-derives and tries again; the loop is bounded
  at **four attempts** (the service's `attempts`), immediately and without backoff, and when all of them lose nothing is written and
  the answer is `RESOURCE/overloaded` (the store's contention), after which the same command ID may be sent again. Because the grant
  holds the revision row's lock, a second attempt can only follow the race of two first commits of one account (the loser finds the
  row and writes nothing) or a deadlock victim (below), so in practice one more attempt is all that is ever needed. The bound
  itself is pinned: `TestAGrantStopsAfterFourAttemptsOfADeadlockVictim` makes every attempt a victim and counts exactly four calls
  (the answer is the contention, nothing is written or spent), and the behaviour is pinned by
  `TestManyOperatorsGrantingToOneAccountAtOnceAllSucceed`. The same command running twice at once answers the same way
  (`ErrCommandInProgress`).
- **Two operators granting to each other.** Each grant holds its operator's `identity.user` row and takes a share of the target's
  through the foreign keys of the rows it writes, so operator A granting to B while B grants to A (or to B's own account) deadlock:
  PostgreSQL ends one of them as the victim after its deadlock timeout (1 s, SQLSTATE 40P01). The grant's statements are sanitized
  inside the transaction, which hides that code from the store's own retry, so `Operator.Grant` recognizes the deadlock (and a
  serialization failure, 40001) itself and runs the command again, at most within the same four attempts: both grants are made, the
  victim after about a second (`TestTwoOperatorsGrantingToEachOtherAreBothServed`). The evidence is spent only by the attempt that commits.
- **The writers of the service are optimistic.** `Service.IssueGrant`, `RevokeGrant` and `Refresh` take no revision lock: they
  derive from the history they read and commit under the revision fence, four attempts, no backoff (the same constant as the
  grant's; `TestAWriterThatNeverWinsTheRaceFailsClosedWithATypedError` counts the four attempts of `IssueGrant`). Ten concurrent
  `IssueGrant` calls for one account lose grants to `ConcurrentUpdate`. Nothing served calls `IssueGrant` or `RevokeGrant` yet;
  `Refresh` is called by the gate's reader (`Service.Read`), which no served operation reaches until AF-CTR-04, where two first gated
  calls of one account race through it: the loser reloads and returns the winner's snapshot, and only a call that loses on all four
  attempts is answered `RESOURCE/overloaded`. See "What waits" (AF-CTR-09).

The records of a grant are the records the resolver reads (a grant is a fact; the snapshot is derived). A term, a status fact or a
feature release written by its owner admission must refresh the snapshot in the same unit (`Service.Refresh`), as the grant writers
do, because any record appended after a snapshot was computed is unknown to it until a refresh. The instants that the known records
set are already boundaries of the snapshot's validity (a grant's start and end, a revocation, a term's start, end, grace and term
actions, a feature release), so the snapshot expires by itself when something known changes meaning; what no boundary can cover is a
record the snapshot has not seen, and that holds for a grant as much as for a term. The owners of those records (commerce, trust and
safety, configuration) are later tasks and have no INSERT privilege on them yet.

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

| #   | Stage                   | Refusal                                                                                                                                                                                                                                                                                                             |
| --- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Authentication          | `AUTHENTICATION/unauthenticated`                                                                                                                                                                                                                                                                                    |
| 2   | Ownership of the object | `STATE/not_found` for another account's object or none (a row names an `Object`; the handler supplies its owner); a subject of another kind, or for a row that names no `Object`, is a handler defect: `permission_denied` (audited `access.refused`: `subject`); an owner that cannot be read is the store failure |
| 3   | Scope and risk          | `permission_denied` (audited `access.refused`: `scope`, `restricted`), `step_up_required` (the session upgrade)                                                                                                                                                                                                     |
| 4   | AGENT/HUMAN separation  | `permission_denied` (audited `access.refused`: `principal`)                                                                                                                                                                                                                                                         |
| 5   | Resource controls       | the refusal of a registered control (none is composed yet: the hook for the quotas and budgets of AF-CTR-04, DC-07)                                                                                                                                                                                                 |
| 6   | Audit before the call   | the store failure when `access.authorized` cannot be appended (the call is refused)                                                                                                                                                                                                                                 |
| 7   | The gate                | `ENTITLEMENT/feature_not_entitled`, `state.reason` = the feature key, audited `access.gated` with the gate's reason; a gate that cannot decide is the answer below                                                                                                                                                  |

An essential operation (sign-in, account, billing, security, recovery) has no `Feature` and is never gated; a gated row is audited
before the call (`access.CheckRow`). A gate that cannot decide is never a refusal that says the
plan lacks the feature, and nothing is audited as `access.gated` for it: a commit whose outcome is unknown, a refresh that lost its
race on every attempt and a center without an entitlement store are `RESOURCE/overloaded` (`access.gateFailure`: the call did not
happen, retry later; the gate runs before the handler, so the call's own effect is untouched); a store failure keeps its own class
for the transport (an unreachable store, a timeout and a context that ended are `RESOURCE/overloaded` too); anything else is a
defect and is `INTERNAL/internal`, as everywhere in the center. An authorizer composed without a gate refuses every gated row
(`mode_invalid`), and a hosted gate without an entitlement reader answers no availability with `ErrNoEntitlementStore`. The context carries the caller's account
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
trigger that raises, F5), and a counting resource control shows the same for the owner's budget: it runs once for each admitted call
and never for a call that stages 1 to 4 refused, which also pins the order of those stages (a foreign device is `not_found` whoever
asks, a restricted account is refused as restricted before its principal is looked at). The actor, the target and the exact payload of
one `access.authorized`, one `access.gated` and one `access.refused` row are pinned, and a high-risk row whose handler audits it in
its own transaction gets no `access.authorized` (`gate_order_integration_test.go`). The routed task control table is in [feature availability](center.md#routed-task-control).

## Self-hosted mode

The built-in default enables every available gated key (`self_hosted_default`). `push` is available only when a push sender is
configured (`push_sender_not_configured` otherwise, DC-22); none exists before AF-CLD-06. The operator of a self-hosted center limits
keys with `ARCFORGES_CENTER_DISABLED_FEATURES` (exact known keys, comma-separated; they answer `operator_limit`): an unknown,
repeated or empty key refuses to start, the variable is refused in official-hosted mode, and the Worker never passes it to a hosted
Container (PLT-18, `tests/worker/container-classes.test.ts`). `IsSelfHostRealm` of the definitions comes from the center mode (DC-20):
the C# decisions ID-10 and ID-11 that derived it from a realm record are superseded. On the official hosted center, an operator grant re-enables a key
whose paid grant lapsed, and the end of the operator grant returns the account to `subscription_expired`
(`TestALapsedPaidGrantPlusAnOperatorGrant`, which runs with the hosted definitions on the development fixtures). The self-host realm
ignores every official term, the compensation term an operator grant writes included, so an operator grant would do nothing there; it
is also refused there (`self_hosted`), and the self-hosted gate never reads the resolver. Resource limits are enforced by the tasks whose operations they bound.

## The store

Migration `0003_entitlement.sql` (sha256 `acc92fe98fdc5976d711f7cd393cdaf6781cc79029824559210e4dcf6121bbf2`) adds the `entitlement`
schema and `identity.operator`: `grant`, `revocation`, `service_term`, `service_term_action`, `account_status_fact`,
`feature_release` and `definitions_activation` (append-only: a trigger refuses UPDATE and DELETE, and the runtime role has neither
privilege), `revision` and `snapshot` (derived, rewritten in place, the revision only advancing by one), and the operator role
(written by the migration role only). The runtime role may insert grants, revocations, definitions activations and service terms
and reads the rest; term actions, status facts and feature releases have no runtime writer until their tasks exist. The service answers
an account that is no canonical uuid (the nil uuid and the upper-case and un-hyphenated spellings of a real one included), a reason on
an ordinary source and text that is not valid UTF-8 (in an actor, a reason, a source reference or a subject) as the typed refusal
`InvalidRequest`, before or as the database refuses it, never as an internal error. For a well-formed account that does not exist,
`Read`, `Refresh` and `IssueGrant` answer `InvalidRequest` ("The account does not exist."), `RevokeGrant` answers `UnknownGrant`
(it finds no grant) and `VerifyRebuild` reports an account without history (no snapshot). The details,
the personal data and the retention are in [PostgreSQL store](postgres-store.md#entitlement-af-ctr-03-b).

## Post-deploy checklist

The hosted run on the proof environment is done by the coordinator after the merge and the deployment. Nothing below was run by the
author of this change (no hosted environment was touched).

1. **Production stays dark.** `center.surfaces` is still `none`; `ARCFORGES_CENTER_PLAN_CONFIGURATION` is unset in production; the
   migration gate applied `0003` to the production database (the tables exist and are empty; `identity.operator` has no row, which
   is also what the next two commands must not change); no gated feature is reachable.
2. **The acceptance database** (`arcforges_acceptance`) is migrated to version 3 with the pinned checksum above.
3. **Enable the surface** on the proof environment by a reviewed change of `FLAGSHIP_SURFACES` to `identity,pages,operations` (it is
   not part of this change). The change must update every pin that guards against enabling it by accident. They were found by applying
   the change in a scratch copy and running `npm test` and `node tooling/dependency-policy.ts` (3 of 972 tests fail, the policy audit
   fails, nothing else):

   - `tests/worker/center-config.test.ts`: the literal pin of the proof environment's `FLAGSHIP_SURFACES` (test "production enables no
     surface and the acceptance environment enables identity and pages") and the loop of the test "the surface rule refuses unknown
     names, a wrong origin and the C# runtime" that says no checked-in environment enables `operations` (invert it for the proof
     environment, keep it for production);
   - `tests/worker/proof-deploy.test.ts`: the test "the checked-in proof environment is the isolated acceptance center";
   - `eng/policy/dependency-policy.json`: `wrangler.json` is an input of the dependency policy ("Dependency input changed without
     review: wrangler.json"), so the change needs a re-bound policy and a successor receipt (the next `eng/policy/dependency-reviews/af-ctr-03-rNN.json`), and
     that receipt, which carries the two legal-record digests every receipt carries, needs its own exact-row block in `.gitleaks.toml`
     and its pin in `tests/worker/provenance.test.ts` (which also holds the next-unreviewed-receipt negative control, the literal
     `eng/policy/dependency-reviews/af-ctr-03-r16.json` in its `for (const other of [...])` list: move it to the name after the new receipt, or the
     test fails), as the receipts of this task have, and its entry in the source inventory
     `eng/provenance/files.json` (`firstParty`; without it `node tooling/project.ts provenance`, which `npm run check` and the leg
     run, fails with "Source inventory drift", checked in a scratch copy with and without the entry);
   - the sentences that say the proof environment keeps `identity,pages` or list the values of `center.surfaces`: this checklist, the
     operations-page section of this document, `docs/deployment.md` and `docs/center-identity.md` (`docs/center.md` already lists
     `operations` among the values of `center.surfaces`).

   Then give the proving account the role with the deployment's migration-role path, **selecting the acceptance database explicitly**, because the command works on the
   database of the migration URL unless `ARCFORGES_CENTER_DATABASE_NAME` names another, and its output (`account`, `operatorId`,
   `grantedAt`, `expiresAt`) does not say which one it wrote:

   ```sh
   ARCFORGES_CENTER_MODE=official-hosted \
   ARCFORGES_CENTER_MIGRATION_DATABASE_URL=<the direct migration-role URL> \
   ARCFORGES_CENTER_DATABASE_NAME=arcforges_acceptance \
   arcforges-center admin grant-operator --account <uuid> --reason "hosted proof of the operator grant" --days 7
   ```

   Afterwards check that the row is in the acceptance database and not in the production one.

4. **The page**, checked with `curl -si` and a browser: an unauthenticated `GET /api/operations/grant` is `303` to the sign-in
   page; the operator's session gets `200` with the seven security headers and `Cache-Control: no-store, no-transform`; any other
   account gets `403`.
5. **The grant** at API level with the fixture catalogue: review, confirm with the passkey, the done page names the term and the
   entitlement version; the same form again says it was already issued; a wrong or reused step-up is refused. No gated operation is
   served, so the hosted run shows the grant and the snapshot, not a gated call.
6. **Clean up:** `arcforges-center admin revoke-operator --account <uuid>` with the same three variables as in step 3 (the acceptance
   database), and let the grants end at their expiry.

## What waits for later tasks

- **AF-CTR-09** (commerce, Paddle): a purchase becomes a service term, a plan's grants and the status facts; the writers of
  `service_term_action`, `account_status_fact` and `feature_release`; the offer and realm columns of the term; the refresh of the
  snapshot by the owner admission. The writers of `Service` (`IssueGrant`, `RevokeGrant`, `Refresh`) are optimistic: four attempts,
  no backoff and no revision lock, so concurrent handlers for one account lose grants to `ConcurrentUpdate` (ten concurrent issues
  gave six refusals in a probe). The commerce writer must serialize per account, or take the revision row's lock as `Operator.write`
  does, before it relies on them.
- **AF-OPS-01**: the OperatorService that replaces the interim page and calls `entitlement.Operator`. The interim page's review does
  not check what the confirmation will refuse (an unknown account, a source reference already used, a justification filled in for a
  grant to another account), so the passkey ceremony can be spent on a confirmation that refuses afterwards, and four honest-use
  refusals share one generic text; the replacement reads the target account and the live references before the ceremony and gives
  each refusal its own text (deferred in fix round 1, `page-3`: unreachable in production, where the surface is off and the catalogue
  is empty).
- **H-07**: the approved prices, limits and the Neon plan and retention; until then the production catalogue is empty.
- **Before the first gated operation (an AF-CTR-04 prerequisite) and before H-07**: the activation of definitions is per account and
  keyed by the version of the replica that reads. Two revisions with different definitions versions running side by side (a rolling
  deploy) each recompute and append an activation at every read of an account whose last activation is the other's, so the snapshot
  version climbs by one per read and the 2000-record bound (activations count) wedges the account for good. Unreachable today
  (production is dark, its catalogue empty, and no gated operation reads a snapshot); the fix is a deploy-level fact, a single row
  of the current definitions version written once by the revision that starts with it, which a replica whose version differs
  neither recomputes against nor writes (deferred in fix round 1, `store-1`).
- **Composition wirings pinned by name or in one mode only** (deferred in fix round 2, `gate-2`). The removal of each wire of the
  composition is killed by a test, but three variants are not: the authorizer's gate built apart from the center's (the self-hosted
  composed test has no database and so no authorizer, and the hosted one has no disabled key), a nil operator handed to the pages
  while `composePages` still calls `c.operator` (pinned by name), and an operator built over an entitlement service with other
  definitions (its snapshots would carry another version). Follow-up before the first gated operation: compose a self-hosted center
  over a database and run the disabled-key table through its authorizer's gate, request `/operations/grant` from the composed hosted
  center, and compare the operator's snapshot version with the gate's.
- **The cause of a gate failure is neither logged nor audited** (deferred, `gate-3`; an AF-CTR-04 prerequisite). `gateFailure`
  answers a commit without an answer, a refresh that lost its race and a missing entitlement store as a bare `RESOURCE/overloaded`
  and writes no `access.gated` row, so an operator cannot tell it from load. Follow-up: wrap the cause (`fmt.Errorf("%w: %w",
arc.Unavailable(), err)`) and log it with the correlation id in `identityapi.failure` and the pages' failure path, with a test that
  the line exists. Unreachable today: no gated operation is served.
- **The Docker-context test models the file rules** (`worker-1`). `tests/worker/docker-context.test.ts` decides what the context
  carries from the include rules of `.dockerignore` and the closing exclusions of the center, as the other tests of that file do; a
  real build carries every `center/` file those exclusions do not remove (`!center/` re-includes the tree), so a stray file such as
  `center/vendor/modules.txt`, a `.s` file or `go.work` would be carried and bound by no record with the test green. At the head every
  one of the 111 carried files is bound. Follow-up: make the model follow Docker, or add those names to the closing exclusions.
- **The Container-request scan is keyed on `CLOUD_CONTAINER.getByName(`** (`worker-2`). A request reached by an alias of the
  namespace, optional chaining, destructuring, bracket access or a helper that receives the namespace is not seen, and the stub-only
  check names the variable `stub`. The five sites are checked; a sixth in an unusual spelling is not. Follow-up: one helper that builds
  the request with `redirect: "manual"`, and a test that the namespace is named only in its module.
- **The clock floor lives only in the snapshot.** A computation never goes back past the stored one, but that floor is the stored
  snapshot's `computed_at`; the records carry their own creation instants and the revision its `updated_at`, and the service does not
  floor against them. A snapshot dropped while a replica's clock is behind the newest record is recomputed in the past. Follow-up
  (before the snapshot is ever dropped by an operation): floor every instant at the newest record creation or activation instant.
  (The comment of migration `0003` says the same as this paragraph since fix round 2; its checksum changed with it, while the
  migration was still unmerged.)
- **AF-CTR-04 and later**: the gated operations (task control, nodes, MCP), their quotas and budgets through the resource-control
  stage, and the rows of the operation table that carry a `Feature`. The production `Authorizer` is composed with **no resource
  control** today, so a gated call is not rate limited: AF-CTR-04 must register a per-account control before it serves a gated row,
  and must check every row that carries a `Feature` against `feature.OperationKeys` (`CheckRow` checks that the key is a gated key,
  not that it is the key of the row's group; nothing links the table to the operation table in code). Until a per-account control
  stands in front of it, a gated call appends up to two audit rows (`access.authorized`, and `access.gated` when refused) and
  serializes with every other audit writer on the single `audit.chain_head` row, entitled or not: that is the cost of the audit that
  comes before the call, and the reason the control comes first.
- **AF-CTR-07** (MCP, agent grants) keeps the feature keys and the `feature.Gate` interface as they are; **AF-CLD-06** brings the
  push sender; **AF-PLAT-01** the retention sweeps and the erasure of an account's records.
