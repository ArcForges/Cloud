# Core identity model: realm, user, authentication identity, single-owner workspace

This document describes what CLOUD.11 (Design WP-22.00) delivers, the checks that enforce it, what each check proves and what it does not. The binding rules are the Design
[Cloud data model](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/architecture/data-model/01-cloud-data-model.md) (sections 3 and 4, including WO-01 to WO-05) and the
[identity requirements](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/requirements/02-identity-account-and-workspace.md) (ID-10 to ID-15, WS-01 to WS-10).
The planning repair that bound this task's write scope and recorded its decisions is Design #248.

## Decision in one sentence

A user is identified by `(realm, user id)`, owns exactly one workspace through the single column `workspace.owner_user_id`, and holds any number of authentication identities (credentials) that
come and go without ever changing the user, its identifier or the workspace; every change is one named plan or one guarded family batch that carries its own receipt, outbox event and change record.

## What exists

| Path                                                                                                            | Content                                                                                                                                                                                                                      |
| --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/ArcForges.Cloud.Modules.Identity/Core/Domain`                                                              | `RealmId`, `UserId`, `AuthIdentityId`, `WorkspaceId` (four distinct identifier types with no conversion), the records, `IdentityRules` (shape, last-credential rule, direct ownership check).                                |
| `src/ArcForges.Cloud.Modules.Identity/Core/Application`                                                         | `IdentityService` (enrollment with the personal workspace, resolve, link, revoke, relabel, rename, ownership check), the `IIdentityStore` and `IIdentityIdSource` ports and the typed commits.                               |
| `src/ArcForges.Cloud.Modules.Identity/Core/Infrastructure`                                                      | `IdentityStatements`: the arguments of each named plan and of the enrollment family, and the values of the commit tail. No SQL text and no reference to the plan bridge.                                                     |
| `storage/plans/identity/*.sql`                                                                                  | Eight named plans of the `identity` owner: three reads (`user-load`, `credential-find`, `credential-list`) and five writes (`credential-add`, `credential-revoke`, `credential-relabel`, `credential-touch`, `user-rename`). |
| `storage/plans/families.json`, `storage/plans/families/account-enrollment.create-user.sql`                      | The family `account-enrollment` and its first plan: guards that the user, the credential and the owner's workspace do not exist, then the user, credential and workspace records and the commit tail.                        |
| `tests/worker/identity-*.test.ts`, `tests/ArcForges.Cloud.Tests/Identity/*`, `Vectors/identity-plan-calls.json` | The SQLite oracle, the structural scans, the shared vector and the C# domain, service, statement and structure tests.                                                                                                        |
| `eng/verification/d1-identity-local.ts`                                                                         | The opt-in run on workerd's D1 under Miniflare (`npm run test:d1:identity:local`).                                                                                                                                           |

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

## Not claimed

- **No production store.** The module cannot reference the plan bridge, so the typed connection from `IdentityStatements` to a plan call (the Abstractions-level port that COM.16 and the module tasks own) does not exist yet: the host lists the service and serves no method, and
  resolving the service fails until a composition supplies a store. The oracle and the vector prove the plans and the argument builders, not their wiring.
- **Authentication itself.** Passkey, email-code, password and OIDC proofs, the native authorize/token ceremony and mail delivery are CLOUD.12; sessions, devices and trust are CLOUD.13 and CLOUD.14; tokens CLOUD.16; recovery, account states and deletion CLOUD.17. The core only models the credential and the rules that
  keep the user continuous, and its recovery-path predicate reads a recovery-code table that CLOUD.17 will populate.
- **Configured initial grants and the security notification** of the enrollment family are the Entitlement and Notification participants' later plans.
- **Deferred live checks** (need the `RES-cloud-deployment` lease and a proof environment, never CI): the provider's REST `batch` as one atomic transaction at production load, real D1 limits and latency for the enrollment batch, and a deployed contention run. CLOUD.70 owns the deployment migration step; this task adds no migration.
- **A rename of the SU-01 row.** The conditional participants are a recorded decision raised to the Architecture Owner, not a settled change of the closed list.
