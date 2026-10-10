# Shared atomic families and the guarded-batch engine

This document describes what CLOUD.06 (Design WP-21.05, generic engine and fixed module lock order only) delivers, the checks that enforce it, what each check proves and what it does not. The binding rules are the Design [D1 execution profile](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/architecture/data-model/04-d1-execution-profile.md) (section 4, "Shared family plans and the guard table") and the shared units of work [SU-01 to SU-07](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/architecture/data-model/00-data-model-overview.md#611-shared-units-of-work).

## Decision in one sentence

A shared transaction family is one named plan, one fixed `D1Database.batch()`, whose guard statements are generated from five primitives, whose statements run in the fixed SU-04 module order, and whose failure is a precondition that rolled everything back; the C# side seals the typed contributions of the participating modules into one plan call and rereads only after a false guard.

## What exists

| Path                                                                                          | Content                                                                                                                                                                                                                                                            |
| --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `storage/plans/families.json`                                                                 | The closed registry of families and their participants (SU-01). It ships **empty**: the module tasks append their declared family.                                                                                                                                 |
| `storage/plans/families/<family>.<name>.sql`                                                  | The reviewed family plans, id `families.<family>.<name>`. None ships with this task.                                                                                                                                                                               |
| `storage/plans/families.expanded.json`                                                        | Generated: every family plan with its expanded SQL, roles and parameter kinds, so a review reads what the Worker runs and C# recomputes the plan identities independently.                                                                                         |
| `tools/ArcForges.Cloud.Generation/StoragePlans` (C#, CLOUD.84 S40(1))                         | The family grammar: registry, `-- guard:` directives and their expansion against the physical manifest, the SU-04 order, the participant, ownership and guard-coverage rules. The TypeScript helpers in `eng/verification/storage-plans.ts` are test support only. |
| `src/ArcForges.Cloud.Storage.D1/SharedFamilies/`                                              | The C# engine: `ModuleLockOrder`, the family and role types, `FamilyPlanVerifier`, `FamilyGuards`, `FamilyUnitOfWork`, `FamilyExecutor`. Internal to `Storage.D1`; no SQL text.                                                                                    |
| `platform_command_guard` (`Migrations/0022_platform__command-guard.sql`, manifest `platform`) | The guard rows of one batch. A check named `af_guard_failed` refuses `allowed = 0`, so the whole batch rolls back and the Worker reports `precondition`.                                                                                                           |
| `eng/verification/d1-families-local.ts`                                                       | The opt-in local run on workerd's D1 (`npm run test:d1:families:local`).                                                                                                                                                                                           |

## The registry

`storage/plans/families.json` lists each family with its participants, each a module of the SU-04 order, `required` or `conditional` with the stated condition. Adding a family or a participant is a design change through the Architecture Owner (RES-shared-transaction-families); a module task appends only its declared family. The parser refuses a participant that is not one of the 17 modules of SU-04.

**Support and TrustSafety have no position in SU-04**, so no family can name them and the engine cannot enlist them, although the data model names TrustSafety in operator mutations. This is a recorded gap for the Architecture Owner to settle by extending the order; the engine refuses rather than inventing a position (D-001).

## The family plan file

```text
-- plan: families.<family>.<name>
-- version: 1
-- access: write
-- guard: kind=revision module=entitlement key=workspace-revision table=entitlement_revision by=scope:workspace_id rev=rev
-- guard: kind=balance module=entitlement key=quota table=entitlement_quota_budget by=scope_kind,scope_id,quota_key,period_key rev=rev exact=used,held
-- statement: module=entitlement class=bucket key=quota params=int64,int64,int64,text,text,text
UPDATE entitlement_quota_budget SET used = CAST(? AS INTEGER), held = CAST(? AS INTEGER), rev = rev + 1
WHERE scope_kind = CAST(? AS INTEGER) AND scope_id = ? AND quota_key = ? AND period_key = ?;
-- statement: module=platform class=record key=receipt params=...
INSERT INTO platform_command ...;
```

- A `-- guard:` directive stands for one **generated** statement; a hand-written `-- statement:` is always a mutation (`INSERT`, `UPDATE` or `DELETE`) of class `bucket`, `reservation` or `record`. The generator appends the one release statement, `DELETE FROM platform_command_guard WHERE command_id = ?`, itself.
- Every statement names the one module that owns every table it names; a table of another module is refused (CM-01 to CM-03). `platform_` tables belong to the pseudo-module `platform`. A mutation never names `platform_command_guard` or the migration bookkeeping tables.
- The existing statement rules apply unchanged: one statement, no comment inside it, DML or SELECT only, anonymous placeholders, every `int64` bound as `CAST(? AS INTEGER)`.
- A family plan's identity hashes the authored text **and** its expanded statements, so a change of a physical column or of the expansion rules changes the plan hash and with it the manifest identity that the Worker and the host compare.

## The five guard primitives

Each expands, against the physical manifest, to `INSERT INTO platform_command_guard (command_id, guard_key, allowed) SELECT ?, '<module>.<key>', CASE WHEN <predicate> THEN 1 ELSE 0 END;`. Parameter order: the command identity (supplied by the engine), the key columns, then the kind's own values. A key column written `scope:<column>` is bound as the owner scope, so the Worker refuses a call whose argument differs from the request scope.

| Kind                      | Fields                           | The predicate holds when                                                                                                                                      |
| ------------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `authorization`, `policy` | `by`, `match`, optional `fresh`  | the row found by its key columns has the matched columns equal to the values the caller decided on, and its `fresh` instant is later than the trusted instant |
| `revision`                | `by`, `rev`                      | the row's revision equals the revision the caller read (an absent row has revision zero)                                                                      |
| `balance`                 | `by`, `rev`, `exact`             | the row's revision and every captured exact column equal what the checked C# arithmetic used                                                                  |
| `lease`                   | `by`, `holder`, `fence`, `until` | the row's holder and fence equal the caller's and the lease is later than the trusted instant (a stale holder fails)                                          |

A name that is not a column of the table, a JSON or proto column, a column whose name SQLite reserves (plans never quote a name), a column used twice, a `rev`, `holder`, `fence` or `until` of the wrong kind, or a `scope:` on a column that is not text is refused. Exact 64-bit values compare as integers in SQL and travel as canonical decimal text, never through a float.

## The order (SU-04)

All guards, then all mutations, then the generated release. Inside a phase the statements run by module in the SU-04 order (Config, Identity, Workspace, Device, Entitlement, Commerce, Policy, Agent, Chat, Scope, Task, Search, PackageCatalog, Notification, Resource, Sync, Audit), with the `platform` pseudo-module first among guards and last among mutations, then by class (guards: authorization, revision, policy, balance, lease; mutations: bucket, reservation, record), then by stable key ascending, each combination at most once. Beyond the order the generator refuses a participant outside the family's registry entry, a required participant with no statement, a module that writes without a guard of its own, a plan without a guard or without a mutation, and a duplicate guard key. A module that only guards (a read-only authorization or policy port) is allowed.

The same rules are enforced again in C# when the generated manifest is loaded (`FamilyPlanVerifier`, defence in depth against a stale generated file), and both implementations are held to the shared vectors in `tests/ArcForges.Cloud.Tests/Vectors/family-lock-order.json`.

## The C# engine

- **`FamilyGuards`** builds the typed arguments of each primitive in the generated parameter order and refuses a value no guard could mean (a negative revision or fence, an empty key, a mutation of a guard class).
- **`FamilyUnitOfWork`** is the immutable commit plan of SU-02: each module `Contribute`s the arguments of its own statements by module, class and stable key; a contribution to a statement the plan does not have, a duplicate, a missing one and arguments that do not match the typed statement or the owner scope are refused (`FamilyViolation`, never carrying a value). `Seal` orders the arguments by the plan, puts the **command identity** in front of every guard and the release, and returns one `PlanCall`.
- **`FamilyExecutor`** executes the call on the existing `IPlanExecutor` (one fixed D1 batch, no second execution path) and maps the result: `Committed`; `GuardRefused` (nothing committed, reread and recalculate); `ConstraintRefused` (read the command receipt: the same hash returns the original result, a different hash is an idempotency conflict); `StaleGeneration`; `Overloaded` and `Unavailable` (nothing committed, retry later with the same command); `UnknownOutcome` (look the receipt up, never retry as a new command); `Rejected` (a defect or a deployment skew). `ExecuteWithRereadAsync` rebuilds the unit after a false guard (the caller rereads and recalculates), waits a bounded full jitter and tries again, at most `MaxAttempts` times, and refuses a rebuilt unit with a different command identity. It never rereads for any other failure.
- Modules reach the engine through typed contributions only. The Abstractions-level port that lets a module project (which references only `ArcForges.Cloud.Modules.Abstractions`) hand its contributions to the coordinator belongs to the module tasks and to COM.16's generic plan-execution port; it is not part of this task. CLOUD.72 added it: see [the module family port](#the-module-family-port-cloud72).

## The module family port (CLOUD.72)

A module project reaches a shared family through `IModuleFamilyPort` (`src/ArcForges.Cloud.Modules.Abstractions/Families/ModuleFamilyPort.cs`, namespace `ArcForges.Cloud.Modules`, primitives only), created for its own descriptor by `IModuleFamilyPortFactory.For`. A `ModuleFamilyCall` names the family, the family plan, the owner scope, the caller's `FamilyStatement` contributions (owner, class, stable key, typed arguments) and the commit tail; the answer is a `ModulePlanStatus` of the plan-execution vocabulary, with the stored result of a replay.

The adapter (`src/ArcForges.Cloud.Storage.D1/FamilyBinding`, bound by `ModuleFamilyBindingModule` in `Composition/HostModules.cs` over the signed executor and the foundation configuration's recovery generation) refuses an unknown family, a plan of another family, a caller that is not a participant (Support and TrustSafety have no SU-04 position), a platform statement and a statement of another module before anything reaches the executor. `FamilyContributionPolicy` holds the one reviewed exception: in `account-enrollment` the enrollment initiator (Identity) also contributes the `workspace` statements, because the Workspace module has no write path. A new exception row is a design change through the Architecture Owner. The adapter builds the plan's platform statements from the commit tail, seals one `FamilyUnitOfWork`, executes it with `FamilyExecutor` (no second execution path) and reconciles every non-success with the command receipt as the module plan port does. The first caller is the Identity store's enrollment ([identity core](identity-core.md#the-production-store-cloud72)); later participants (CLOUD.13, CLOUD.39, CLOUD.42, CLOUD.53, CLOUD.63) reuse it. The tests are `tests/ArcForges.Cloud.Tests/Families/*` and `tests/ArchitectureTests/FamilyPortArchitectureTests.cs`. Like the plan port, it resolves only where a composition binds the plan executor; production binds none today.

## How a module task adds its family

1. Append the family to `storage/plans/families.json` (the participants come from SU-01; a participant not in the closed list is an Architecture Owner decision).
2. Write `storage/plans/families/<family>.<name>.sql` with its guards and mutations in SU-04 order; run `dotnet run --project tools/ArcForges.Cloud.Generation/ArcForges.Cloud.Generation.csproj -c Release -- plans generate` and commit the regenerated Worker dictionary, C# manifest and `families.expanded.json`; read the expanded SQL in the diff.
3. Contribute each module's statements through `FamilyGuards` and `FamilyUnitOfWork`, execute with `FamilyExecutor`, and map the outcomes to the module's own typed refusals. A module project does this through the [module family port](#the-module-family-port-cloud72).
4. The manifest hash changes, so regenerate after every rebase (RES-cloud-storage-plans). Migrations are numbered by the integration owner at merge (RES-cloud-d1-migrations), and `platform_command_guard` is migration 0022 as numbered here.

## Checks

| Check                                                                                                                                                                                                                                          | Where                           |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| `npm run check:plans`, `tests/worker/family-plans.test.ts` (registry, grammar, primitives, every plan-level rule, the shared vectors, generated outputs)                                                                                       | hosted CI and locally           |
| `tests/worker/family-oracle.test.ts`: the generated SQL on the real numbered migrations in `node:sqlite` (every guard false, constraint after passing guards, two writers, a stale lease holder, exact 64-bit values, scope, argument refusal) | hosted CI and locally           |
| `tests/ArcForges.Cloud.Tests/SharedFamilies/*`: lock order, plan verification, guard arguments, unit of work, executor outcomes and bounded reread, the identity recomputation                                                                 | hosted CI and locally           |
| `npm run test:d1:families:local`: the fixture family on workerd's D1 under Miniflare (false guards, rollback, 25 rounds of 4 simultaneous writers, a stale holder, exact values)                                                               | explicit local opt-in, never CI |

## What each check proves, and what it does not

- The oracle proves the guard SQL, the `af_guard_failed` classification, the whole-batch rollback and the stale-writer and stale-holder behaviour on SQLite, the engine D1 shares. It is not D1.
- workerd's D1 is the closest local engine and ran the contention and stale-holder cases through the production executor. It is not a Cloudflare provider result.
- The C# tests prove the unit of work, the order refusal and the executor's mapping and reread bounds against a scripted bridge; they do not execute SQL.
- The fixture family is a test fixture: **no Design family is implemented here** (the first real one, `account-enrollment`, is CLOUD.11's: [identity core](identity-core.md)). Which modules enlist in which family, each family's real statements and the Abstractions port for modules belong to the module tasks (CLOUD.11, CLOUD.13, CLOUD.39, CLOUD.42, CLOUD.53) and CLOUD.63.

## Not claimed

- **The provider's REST `batch` is one atomic transaction** is not observed here (binding batch atomicity was observed on workerd). It, real D1 limits and latency, and a deployed contention run need the `RES-cloud-deployment` lease and the proof environment; they are deferred and never run in CI. CLOUD.70 owns the future deployment migration step that applies `0022`.
- **"Two Containers contend" with real Container processes**, "exact credits" (Commerce) and "sync cursor safety" (Sync) are the completion gate of WP-21.05 carried by CLOUD.63 and the module tasks; this task proves the generic mechanism they compose.
- **Receipts, outbox and the change archive** (CLOUD.04) are not written here: a family plan's `platform` statements are authored by the module tasks.
- A guard row is never retained by a batch that commits or rolls back; a provider path that were not atomic could leave rows of a crashed command behind. They are keyed by command and harmless to every other command, and a later sweep would need CLOUD.04's retention, which this task does not add.
