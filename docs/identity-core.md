# Core identity model: realm, user, authentication identity, single-owner workspace

This document describes what CLOUD.11 (Design WP-22.00) delivers, the checks that enforce it, what each check proves and what it does not. The binding rules are the Design
[Cloud data model](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/architecture/data-model/01-cloud-data-model.md) (sections 3 and 4, including WO-01 to WO-05) and the
[identity requirements](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/requirements/02-identity-account-and-workspace.md) (ID-10 to ID-15, WS-01 to WS-10).
The planning repair that bound this task's write scope and recorded its decisions is Design #248.
CLOUD.72 (Design WP-22.00 part) adds the production store of this model: the D1 identity store, its random identifier source, the Abstractions family-execution port and its adapter, the
Workspace read port, the read plans that back them and the replay mapping of the service ([The production store](#the-production-store-cloud72), [Replay mapping](#replay-mapping-cloud72)). Its
write scope was bound by the CLOUD.72 planning repair (2026-10-05) and planning repair fix8a (Design #349, coordinator ruling S54).

## Decision in one sentence

A user is identified by `(realm, user id)`, owns exactly one workspace through the single column `workspace.owner_user_id`, and holds any number of authentication identities (credentials) that
come and go without ever changing the user, its identifier or the workspace; every change is one named plan or one guarded family batch that carries its own receipt, outbox event and change record.

## What exists

| Path                                                                                                                                                                                                  | Content                                                                                                                                                                                                                                                                                                                                          |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `src/ArcForges.Cloud.Modules.Identity/Core/Domain`                                                                                                                                                    | `RealmId`, `UserId`, `AuthIdentityId`, `WorkspaceId` (four distinct identifier types with no conversion), the records, `IdentityRules` (shape, last-credential rule, direct ownership check).                                                                                                                                                    |
| `src/ArcForges.Cloud.Modules.Identity/Core/Application`                                                                                                                                               | `IdentityService` (enrollment with the personal workspace, resolve, link, revoke, relabel, rename, ownership check), the `IIdentityStore` and `IIdentityIdSource` ports and the typed commits.                                                                                                                                                   |
| `src/ArcForges.Cloud.Modules.Identity/Core/Infrastructure`                                                                                                                                            | `IdentityStatements`: the arguments of each named plan and of the enrollment family, and the values of the commit tail. No SQL text and no reference to the plan bridge.                                                                                                                                                                         |
| `storage/plans/identity/*.sql`                                                                                                                                                                        | Eight named plans of the `identity` owner: three reads (`user-load`, `credential-find`, `credential-list`) and five writes (`credential-add`, `credential-revoke`, `credential-relabel`, `credential-touch`, `user-rename`).                                                                                                                     |
| `storage/plans/families.json`, `storage/plans/families/account-enrollment.create-user.sql`                                                                                                            | The family `account-enrollment` and its first plan: guards that the user, the credential and the owner's workspace do not exist, then the user, credential and workspace records and the commit tail.                                                                                                                                            |
| `tests/worker/identity-*.test.ts`, `tests/ArcForges.Cloud.Tests/Identity/*`, `Vectors/identity-plan-calls.json`                                                                                       | The SQLite oracle, the structural scans, the shared vector and the C# domain, service, statement and structure tests.                                                                                                                                                                                                                            |
| `eng/verification/d1-identity-local.ts`                                                                                                                                                               | The opt-in run on workerd's D1 under Miniflare (`npm run test:d1:identity:local`).                                                                                                                                                                                                                                                               |
| `src/ArcForges.Cloud.Modules.Identity/Persistence` (CLOUD.72)                                                                                                                                         | `D1IdentityStore` (the production `IIdentityStore`), `IdentityRowCodec`, `IdentityPlans` and `RandomIdentityIdSource`; internal, namespace `ArcForges.Cloud.Modules.Identity.Persistence.Infrastructure`, no SQL text, no table name and no Storage reference.                                                                                   |
| `src/ArcForges.Cloud.Modules.Identity/IdentityModule.cs` (CLOUD.72)                                                                                                                                   | The `Register` entry lists the store and the identifier source beside the service, over the host's plan and family port factories and the Workspace directory.                                                                                                                                                                                   |
| `src/ArcForges.Cloud.Modules.Abstractions/Families/ModuleFamilyPort.cs` (CLOUD.72)                                                                                                                    | The family-execution port (`IModuleFamilyPort`, `IModuleFamilyPortFactory`, `ModuleFamilyCall`, `FamilyStatement`): primitives only, namespace `ArcForges.Cloud.Modules` ([shared families](shared-families.md#the-module-family-port-cloud72)).                                                                                                 |
| `src/ArcForges.Cloud.Storage.D1/FamilyBinding` (CLOUD.72)                                                                                                                                             | `ModuleFamilyPortFactory` over the CLOUD.06 engine and `FamilyContributionPolicy` with its one reviewed exception; bound in the host by `ModuleFamilyBindingModule` (`Composition/HostModules.cs`).                                                                                                                                              |
| `src/ArcForges.Cloud.Modules.Abstractions/Workspace/WorkspaceDirectoryPort.cs`, `src/ArcForges.Cloud.Modules.Workspace/Persistence` (CLOUD.72)                                                        | The published workspace read port (`IWorkspaceDirectory`: by identifier or by owner, always scoped by realm, a `WorkspaceRecord` of primitives) and its implementation `D1WorkspaceDirectory` over the Workspace module's own plan port, listed by `WorkspaceModule.Register`.                                                                   |
| `storage/plans/identity/{credential-get,credential-rows,recovery-active}.sql`, `storage/plans/workspace/*.sql` (CLOUD.72)                                                                             | Three identity reads (the full credential row with its full user row in one statement; a user's full credential rows, at most 64; whether the user of the realm has a live recovery-code set) and two workspace reads (`workspace-get`, `workspace-by-owner`). The CLOUD.11 plans, the tables, the migrations and `families.json` are unchanged. |
| `tests/ArcForges.Cloud.Tests/{Identity,Families,Workspace}/*`, `tests/ArchitectureTests/{IdentityStore,FamilyPort}ArchitectureTests.cs`, `Identity/Vectors/identity-store-transcript.json` (CLOUD.72) | The store, family port, workspace port, replay, identifier, composition and architecture tests, and the recorded transcript of the store's plan calls.                                                                                                                                                                                           |

## The model

- **Realm.** A realm is deployment configuration, not a table: one D1 authority database serves one realm, and every identity and workspace row carries the configured `realm_id`. Every lookup, uniqueness rule and ownership check includes it,
  so the same credential or the same user identifier in another realm is a different identity (ID-10, ID-11).
- **User.** `identity_user` holds the profile and a `rev` that is the credential-lifecycle guard: linking or revoking a credential advances it, renaming advances it, relabelling a credential does not.
- **Authentication identity.** `identity_auth_identity` is unique by `(realm, provider, subject)`; a revoked credential keeps its row and so keeps its subject reserved, which means a credential never moves from one user to another. Passkey data and the password
  verifier are method-specific columns whose shape the physical checks enforce.
- **Workspace.** `workspace_workspace.owner_user_id` is the only relation between a user and a workspace. There is no membership table, join, role or seat anywhere (WO-01 to WO-05); `(realm, owner)` is unique, so the personal workspace is exactly one per user; no plan
  ever rewrites an owner. Authorization is `Actor -> owns -> Workspace` (`IdentityRules.Owns`): the caller's realm and the caller's user must be the workspace's.
- **Single-owner provisioning.** No task in the delivery graph owns the Workspace module's tables, so the enrollment family carries the `workspace` statements and the Identity core carries the minimal workspace model (planning repair, Design #248).

## Plans and the family

Every write plan declares its commit tail (`-- tail: v1 events=N`) and opens with a guard whose predicate names the revisions the decision read, so a writer that lost a race is refused whole as a failed precondition and recalculates.
`credential-revoke` evaluates the last-credential rule inside the batch (`identity.last_credential`: another unrevoked credential of the same user and realm, or a live recovery-code set), so two simultaneous revocations can never remove the last one.
`credential-touch` records a use and is the one plan with `-- tail: none` (no receipt, event or revision, and the instant only moves forward).

`account-enrollment` is registered with Identity and Workspace as required participants and Device, Entitlement and Notification as conditional on the completion that creates a session, applies configured initial grants or queues a security
notification: their tasks (CLOUD.12, CLOUD.13 and the grant tasks) append their own plans of the same family. The statements run in the fixed SU-04 order with the user row before the credential and workspace rows, because D1 enforces foreign keys immediately.
An enrollment whose credential already exists is a failed precondition, not a constraint violation, so the caller rereads and signs the existing user in without issuing initial grants (`EnrollmentOutcome.CreatedUser`).

## The production store (CLOUD.72)

`D1IdentityStore` is written only against the Abstractions ports, the pattern every module follows: a module project references only the Abstractions project and binds its own store under its own
`Persistence` folder, registered in its own `Register` entry with the ports created for its own descriptor.

- **Reads.** The user (`identity.user-load`), the credential with its user (`identity.credential-get`, one statement, so the credential and its user are read at one moment), a user's credentials
  (`identity.credential-rows`) and the recovery-path predicate (`identity.recovery-active`, the same predicate `credential-revoke` evaluates in its batch) go through the module's plan port. Every read
  is scoped by realm; these realm-level reads carry no workspace scope, so the realm is their owner scope and the exact realm-level exemptions of `StoragePlanGeneratorTests` name them (S54(6); `workspace.workspace-by-owner` is exempt the
  same way, while `workspace.workspace-get` binds the workspace identifier as its owner scope). Workspaces are read
  through the Workspace module's `IWorkspaceDirectory`, because each module reads only its own tables. Rows are decoded strictly (column count and kinds, canonical identifiers, the closed method and
  state lists, the shape the model writes, and the row must be the one asked for); anything else throws `IdentityStoreException` with `IdentityStoreFailure.Defect` and is never returned as a value.
- **Commits.** The arguments and the commit tail are exactly what `IdentityStatements` builds, so the CLOUD.11 shared vector holds them byte for byte. A module write plan goes through the plan port
  (`IModulePlanPort.WriteAsync`); an enrollment goes through the family port as the family `account-enrollment` and its plan `families.account-enrollment.create-user`. The commit context is the
  clock's instant, a random outbox identifier, the command identifier as the correlation, no causation and change-record schema version 1 (see the limits below).
- **Outcomes.** `Succeeded` is `Committed`; `GuardRefused` is `Refused`; `ConstraintRefused` is `Refused` only for an enrollment or an added credential (a key collision of a random identifier: a
  credential identifier, or a user identifier held in another realm, reaches the primary key), so the service retries with fresh identifiers, and a defect for any other commit; `Replayed`,
  `ReusedIdentifier`, `ReceiptExpired` and `UnknownOutcome` are the typed outcomes `Replayed`, `IdentifierConflict`, `ReceiptExpired` and `Unknown`; `Unavailable` and `StaleGeneration` throw
  `IdentityStoreFailure.Unavailable` (an outage is never reported as a conflict); `Rejected`, `ReplayedFailure` and any other status throw `IdentityStoreFailure.Defect`. No message carries a value.
- **Identifiers.** `RandomIdentityIdSource` draws 16 bytes from the operating system's cryptographic random generator, sets the version 4 nibble and the RFC 9562 variant bits (122 random bits)
  and writes the canonical lower-case form; nothing is derived from a clock, a counter or another identifier.
- **Family port.** The enrollment's `identity` and `workspace` statements and its commit tail go to `IModuleFamilyPort`; the adapter refuses an unknown family, a plan of another family, a
  non-participant caller, a platform statement and a statement of another module before the executor, with one reviewed exception: the enrollment initiator (Identity) contributes the `workspace`
  statements of `account-enrollment`, because the Workspace module has no write path ([shared families](shared-families.md#the-module-family-port-cloud72)).
- **Composition.** `IdentityModule.Register` and `WorkspaceModule.Register` list the store, the identifier source and the directory; the host lists `ModuleFamilyBindingModule` beside
  `ModulePlanBindingModule`. Both factories need the signed Worker executor and the recovery generation of the foundation configuration, so the service resolves only in a composition that binds them
  (`IdentityCompositionTests`: the host under the foundation configuration over the SQLite bridge executor resolves `IdentityService` over the D1 store and serves an enrollment; without that
  configuration nothing resolves it). No route, method or policy is added.

## Replay mapping (CLOUD.72)

The service keeps the CLOUD.11 vector (the receipt-probe design accepted in S54(4)); `IdentityError` gains exactly `IdentifierConflict` and `ReceiptExpired` (S54(2)).

- **Unknown outcome.** The identical commit (the same command, identifiers and revisions) is resent, at most `MaxAttempts` sends in all; its own receipt answers `Committed` or `Replayed`, and a
  command identifier is never replaced. An outcome still unknown after every send is the `Conflict` refusal; resending the same command later replays or commits once.
- **Replayed.** The original commit took effect under this command and is reported as the success it was. Where the request hash does not cover a value, the stored value is reread (the credential
  identifier of an added credential, the instant of a revocation); for a relabel and a rename the hash covers everything the result shows.
- **Reused identifier and expired receipt.** `IdentifierConflict` and `ReceiptExpired` refusals; nothing is executed again, and an expired receipt is never executed as a new command.
- **Enrollment.** An existing credential on the first read signs its user in (`CreatedUser = false`, no command executed). The enrollment receipt names the identifiers of the attempt, so an
  enrollment that meets its own command identifier with other identifiers rereads the credential and probes the receipt by resending the enrollment built from the existing user, credential and
  workspace under the same command. Every guard of that commit refuses existing records, so the probe can only replay or be refused, never write: `Replayed` signs the caller in with
  `CreatedUser = false` (initial grants were applied once, to the attempt that created the user), `ReceiptExpired` is that refusal, an outcome still unknown after every send is `Conflict`, and a
  refused probe (the receipt is gone, so nothing proves this command created the records), a missing or unusable credential or a missing workspace is `IdentifierConflict`. The identifiers the retry
  generated are discarded.

## What each check proves, and what it does not

- **SQLite oracle (`identity-core-oracle.test.ts`, hosted CI and locally):** the real migrations and plans through the production executor. It proves user continuity across linking, revoking, relabelling and renaming; the single-owner workspace; the last-credential rule with and
  without a recovery path; realm isolation (same subject in two realms, a user of another realm refused, scoped reads); tenant leakage refusals; stale-writer races of enrollment, linking and revocation decided from the same read; and that a receipt, event and
  archive record carry identifiers and numbers only. Sixteen deliberate plan mutants (a dropped guard, a widened state set, a lost realm predicate, a defeated last-credential rule and similar) were each killed by a test after three that first survived got their own cases. SQLite is not D1.
- **Shared vector (`identity-plan-calls.test.ts`, `IdentityStatementTests`):** the module's arguments equal the arguments an independent TypeScript implementation builds, for a fixed sequence of eight commits, and every statement has the checked-in plan's parameter kinds.
  The enrollment contributions are accepted and sealed by the real guarded-batch unit of work and the tail by the real `CommitTail`.
- **Structure (`identity-structure.test.ts`, `IdentityStructureTests`):** no table, column, enum, index, trigger, plan, generated contract identifier, operation-shaped literal or identity/workspace type or member names a membership, role, invitation, seat or shared-editor concept
  (exact, reasoned allowlist: the operator access `role`, which WO-05 excludes from workspace membership, and the chat message author enum); only the credential table carries an authentication-identity identifier; every user column references the user table; the owner column is the one
  user relation of a workspace and the API token is the only table that references both a user and a workspace. Each scan is proven on fixtures that break its rule.
- **C# tests:** domain rules, the service against an in-memory store that applies the same guards as the plans (a test double: it proves the service, not D1), concurrency of the service on that store, enumeration and tenant-leakage refusals.
- **workerd's D1 (opt-in, `npm run test:d1:identity:local`):** the closest local engine. It repeats the engine-dependent cases: the family order under immediate foreign keys, whole-batch rollback, 25 rounds of simultaneous writers enrolling, linking and revoking. It is not a Cloudflare provider result.
- **Store tests (CLOUD.72, C#, hosted CI and locally):** `IdentityStoreUnitTests` hold the store to plan-port fakes (exact plan ids, owner scopes and arguments, every status mapping, the defect rows of
  the strict decoding, the shared vector through the real ports); `IdentityStoreOracleTests` run the store through the real plan and family ports on the SQLite bridge over the real migrations and the
  production Worker plan code (every read scoped by realm, every commit variant, a refused guard writes no row, receipt or outbox event, 25 concurrent enrollments of one credential commit once,
  colliding identifiers refused whole and retried with fresh ones, replay after a lost response, resend after a lost request, expired receipts, reused identifiers and the enrollment receipt probe on
  real receipts); `IdentityReplayMappingTests` cover every replay mapping on the in-memory store, whose receipts carry the real tail identity; `IdentityReadPlanTests` and `WorkspaceReadPlanTests`
  exercise the new read plans and `WorkspaceDirectoryTests` the workspace port (realm and owner refusals, malformed identifiers refused before any plan call); `RandomIdentityIdSourceTests` check
  version, variant, canonical form and a large draw without repeats; `IdentityCompositionTests` prove service resolution in a composition that binds the plan executor. `Families/*` prove the family
  port (refusals before the executor with no executor call, the exception list of exactly one row and its negatives, the outcome and receipt reconciliation, the real enrollment plan on the bridge)
  and `IdentityStoreArchitectureTests` and `FamilyPortArchitectureTests` the boundaries (the Identity project references only the Abstractions, its sources reach storage only through the
  Abstractions ports and name no SQL statement or table, its persistence types are internal, only `D1IdentityStore` implements the store and only `Storage.D1/FamilyBinding` implements the family
  port; the scans do not depend on the order the filesystem returns files, which a planted-violation test checks). SQLite is not D1.
- **Store transcript on workerd's D1 (CLOUD.72, opt-in, never CI):** `IdentityStoreTranscriptTests` record every plan call the store builds on the SQLite bridge (plan, version, owner scope, typed
  arguments, the answer and the row counts of eight tables after each step, with three concurrent groups) in `Identity/Vectors/identity-store-transcript.json` (rewritten only with
  `IDENTITY_TRANSCRIPT_UPDATE=1`); the transcript mode of `npm run test:d1:identity:local` executes each C#-built call through the production Worker executor on workerd's D1 and compares statuses,
  changes, rows and table counts generically, with no TypeScript business assertion. The local run of 2026-10-10 answered 142 calls in 116 steps as recorded. It is not a Cloudflare provider result.

## Not claimed

- **Production resolution.** Production binds no plan executor and no recovery generation (the gap COM.16 recorded), so in the production composition the plan and family port factories, and
  with them the store and the service, do not resolve. Resolution is proven only in a composition that binds the executor (`IdentityCompositionTests`, the foundation configuration over the SQLite
  bridge). Production resolution is blocked on the production plan-executor composition (owner to be assigned by planning repair fix8), not proven. The host serves no Identity method either way.
- **Correlation and causation.** The commit context uses the command identifier as the correlation and no causation, because no Abstractions seam carries the edge correlation to a module yet (the
  COM.16 precedent). A store write is therefore not joined to the request's edge correlation.
- **Change-record schema version.** Every Identity commit records change-record schema version 1 as a store constant (the COM.16 precedent); no versioned Identity change-record schema is published.
- **The workspace statements of enrollment.** The Identity core contributes the `workspace` statements of `account-enrollment` through the one reviewed exception of the family adapter. The Workspace
  module gained only a read port (CLOUD.72); it has no write path of its own, so the exception stays until a Workspace task owns those statements.
- **Authentication itself.** Passkey, email-code, password and OIDC proofs, the native authorize/token ceremony and mail delivery are CLOUD.12; sessions, devices and trust are CLOUD.13 and CLOUD.14; tokens CLOUD.16; recovery, account states and deletion CLOUD.17. The core only models the credential and the rules that
  keep the user continuous, and its recovery-path predicate reads a recovery-code table that CLOUD.17 will populate.
- **Configured initial grants and the security notification** of the enrollment family are the Entitlement and Notification participants' later plans.
- **Deferred live checks** (need the `RES-cloud-deployment` lease and a proof environment, never CI): the provider's REST `batch` as one atomic transaction at production load, real D1 limits and latency for the enrollment batch, and a deployed contention run. CLOUD.70 owns the deployment migration step; this task adds no migration.
  The CLOUD.72 store on Cloudflare's D1 (its plan calls through the deployed Worker, the enrollment family batch at provider limits, concurrent enrollments on the provider) is blocked on the
  `RES-cloud-deployment` lease, a proof environment and the production plan-executor composition, not proven; CLOUD.72 adds no table or migration either.
- **A rename of the SU-01 row.** The conditional participants are a recorded decision raised to the Architecture Owner, not a settled change of the closed list.
