# Module boundaries and the D1 named-plan bridge

This document describes what CLOUD.02 (Design WP-21.02) delivers, which checks enforce it, and what is not claimed. The binding
rules are the Design [D1 execution profile](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/architecture/data-model/04-d1-execution-profile.md)
sections 2 and 3 and the [Cloud module projects](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/architecture/01-solution-and-project-layout.md#5-cloud-module-projects)
rules CM-01 to CM-04 and RD-01 to RD-04.

## Decision in one sentence

C# owns every business decision and asks the Worker to execute one exact, named and versioned plan; the Worker runs only SQL that is
checked into `storage/plans`, and no C# code, request field or module can name SQL or a table to run.

## Layout

| Path                                              | Owner                               | Content                                                                                                                                                                    |
| ------------------------------------------------- | ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/ArcForges.Cloud.Modules.<Name>`              | one module (19 projects)            | the module boundary: `<Name>Module` with its `ModuleDescriptor`; the module's Domain, Application and Infrastructure layers are folders and namespaces of this one project |
| `src/ArcForges.Cloud.Modules.Abstractions`        | shared boundary types               | `ModuleDescriptor` (name, schema, plan owner, table prefix) and `IModuleBoundary` (descriptor, service registration, route fragment)                                       |
| `src/ArcForges.Cloud.Storage.D1`                  | the bridge                          | plan definitions, exact D1 scalar values, the signed Worker executor, private request signing and the generated `PlanManifest`                                             |
| `storage/plans/<owner>/<name>.sql`, `owners.json` | each module owns its plan directory | the reviewed plans and the owner registry                                                                                                                                  |
| `src/ArcForges.Cloud`                             | the Native AOT host                 | lists the 19 boundaries in `Composition/ModuleBoundaries.cs`; nothing else changed                                                                                         |

The 19 modules are the domain owners of the Cloud schema map: Identity, Workspace, Devices, Entitlement, Commerce, Chat, Task,
Agent, Sync, Resource, Search, PackageCatalog, Notification, Policy, Scope, Configuration, Audit, Support and TrustSafety.
`platform` (receipts, outbox, inbox, commands, job leases, operating budgets) is shared infrastructure and has no module project.
The PRF.07 proof plans live under the `foundation` owner and use only `probe_*` tables of the isolated proof database.

The bridge was written for PRF.07 inside the host project. CLOUD.02 moved it, with its namespaces unchanged, into `Storage.D1`
(`ArcForges.Cloud.Storage`, `ArcForges.Cloud.Hmac`) and moved the plans, byte for byte, from `src/ArcForges.Cloud/Storage/Plans` to
`storage/plans`. The manifest hash did not change (`3716534c...`), because it is computed from the plan ids, versions and
normalized text and not from paths, and `worker/storage/plans.generated.ts` is byte-identical, so the Worker bundle did not change.

## Module boundary rules

- **A module references only the Abstractions** and no package, framework or other project. It never references another module, the
  host, the storage layer or a Contracts package. This is checked three ways: the project files (`ModuleBoundaryTests`,
  `tests/worker/module-layout.test.ts`), the compiled assembly references (`EachCompiledModuleAssemblyReferencesOnlyTheAbstractions`) and
  the namespaces used in source (`NoSourceFileCrossesAModuleBoundary`).
- **The host lists the modules and nothing else.** Listing a boundary opens no route and no public method: a module registers its own
  services and route fragment through `IModuleBoundary`, and the deny-by-default ingress pipeline of [cloud-ingress](cloud-ingress.md)
  still refuses every method that has no policy. `TheComposedHostStillServesOnlyHelloAndHealthAndRefusesEveryModulePath` runs the composed host.
- **Layers inside a project.** Domain references neither Application, Infrastructure nor generated Contracts types; Application does not
  reference Infrastructure nor Contracts types (RD-01, RD-02, RD-04). The modules hold no types yet, so `LayeringTests` proves the checker
  against fixture types that break each rule and holds the real assemblies to it from the first type a module task adds. The checker reads
  type signatures (base types, interfaces, fields, properties, method and constructor parameters and returns); it does not read method
  bodies, so a Domain method that constructs an Infrastructure type internally is not detected. Project and namespace import checks and
  review cover that until a module task adds a body-level check.
- **The `Task` namespace shadows `System.Threading.Tasks.Task`** inside the Task module. Write `global::System.Threading.Tasks.Task` or a
  using alias there.
- **Persistence ownership (CM-01 to CM-03).** A module owns the tables whose names start with its schema and an underscore
  (`<schema>_<snake_case_entity>`, for example `identity_user` or `package_catalog_package`) and the plans under
  `storage/plans/<owner>` where the owner is the schema with `_` written `-`. No other module reads or writes them.
- **Tests for module code** go in `tests/ArcForges.Cloud.Tests`; a module project holds no test code.

## Plans and the owner registry

`storage/plans/owners.json` lists the owners (the 19 modules, `platform` and the proof owner `foundation`) with the class name used in
the generated C# and the table prefix. It is an append-only registry owned by the Cloud integration owner under
RES-cloud-storage-plans: a module task adds nothing to it, because all nineteen modules are already registered.

`node eng/verification/storage-plans.ts` parses every plan file and refuses it unless:

- its directory is a registered owner and its plan id is `<owner>.<name>`;
- the SQL is DML or SELECT only, with typed `params=` and `returns=` kinds, anonymous placeholders, every `int64` bound as
  `CAST(? AS INTEGER)`, no comment inside a statement, no `PRAGMA`, DDL, `RETURNING`, `ATTACH` or `sqlite_` name (unchanged from PRF.07);
- **every table it names after FROM, JOIN, INTO or UPDATE starts with the owner's prefix, or with `platform_` for a module plan**, so a
  plan of one module can never name another module's table. A proof plan may touch `probe_` tables only and a `platform` plan `platform_`
  tables only. The check tokenizes the statement the way SQLite does (comments are whitespace, string literals are single tokens, every
  character from U+0080 up belongs to a word, only ASCII is case-folded) and **fails closed**: after FROM, JOIN, INTO and UPDATE it accepts
  only a bare table name, an allow-listed table-valued function (`json_each`, `json_tree`, FROM and JOIN only) or a parenthesised
  SELECT, WITH or VALUES subquery. Everything else is refused: single- or double-quoted, backtick and bracket names, parenthesised tables,
  schema-qualified names, numbers and keywords in a table position, comma joins (also after a JOIN, a subquery or a table function) and
  malformed WITH lists. A FROM clause ends only at a word SQLite reserves (WHERE, GROUP, ORDER, LIMIT, HAVING, UNION, INTERSECT, EXCEPT, SET), never at a word it also accepts as an alias or column name (DO, CONFLICT, WINDOW, KEY, REPLACE and the like); an oracle test tries about 100 such words in four alias and column shapes. A consequence is that a comma after a FROM clause at the same depth is refused until such a word appears, so an `INSERT ... SELECT ... FROM ... ON CONFLICT ... DO UPDATE SET a = ?, b = ?` is refused; use VALUES. A CTE name must start with `cte_`, which no owner prefix may, so a CTE can never stand in for a foreign table.
  `storage-plan-ownership.test.ts` checks every bypass spelling found in review against `node:sqlite` as the oracle (valid SQLite that
  reaches a foreign table) and the allowed constructs plans use. Plans were not changed by this rule: the manifest hash is unchanged.
  The rule checks which tables a statement names; it does not prove a column or function reference is harmless, which review of the plan does.

It then writes `worker/storage/plans.generated.ts` (the Worker dictionary) and `src/ArcForges.Cloud.Storage.D1/PlanManifest.g.cs`
(typed definitions, one nested class per owner so that two owners can share a plan name, for example `PlanManifest.Foundation.Readiness`) with one
SHA-256 manifest identity. `--check` (part of `npm run check`) fails when either file is stale. After a rebase regenerate with
`node eng/verification/storage-plans.ts` and commit the result (RES-cloud-storage-plans).

A guarded cross-module transaction family (CLOUD.06) needs participants from several owners in one batch. This rule does not allow it
and is not weakened here: the participant list is declared and changed only through the Architecture Owner, and the change belongs in the
registry and the generator in a reviewed pull request.

## What the bridge can and cannot send

A `PlanCall` carries a `PlanDefinition` (id, version, access, bounds and bind/result kinds: no SQL text), typed exact arguments, the owner
scope, a request id and the recovery generation. The generated `ExecutePlanRequest` has exactly the fields `planId`, `planVersion`,
`manifestHash`, `requestId`, `recoveryGeneration`, `ownerScope`, `arguments` and `deadlineUtc`. The Worker looks the SQL up by id and
version in its own dictionary and refuses an unknown plan, a different manifest hash, a stale generation, an expired or too distant
deadline and any argument that does not match the plan statement by statement. Writes run as one `D1Database.batch()`; an uncertain write
is `unknownOutcome` and is never retried automatically. These behaviors, and the signed `storage.internal` ingress that only the proof
Container's outbound handler reaches, were delivered and observed by PRF.07 ([foundation proof](prf-07-foundation-proof.md)).

## Shared architecture policy host

The GOV.09 policy host (`tests/ArchitectureTests`) classifies every project by an explicit role. The 21 projects of this task are
registered in `CloudRepository.Classifications` (an inventory binding under ADP-07, because the inventory test fails for any unclassified
project): the plan bridge is `Persistence` (the host, a shell, may reference it and no module may, AT-14 and AT-07), the Abstractions
project is `Abstractions`, and each module boundary is an `Abstractions` seam owned by its module, because it holds only a descriptor.
A module task that adds layered code re-reviews its role together with its own policy changes. The source scans that ran on the service
project alone (AOT suppression, unregistered JSON serialization, wire-type and RPC descriptor rules) now run on every production project,
since code also lives in the bridge and the boundaries, and the public module API is bound to real tests for RP-10.

## Image build

The Dockerfile copies the admitted `src/` tree before the locked restore (every referenced project and its lock file must be in the context),
so the restore layer is no longer cached separately from source changes. The image build is a CI build from a clean checkout, so this costs
build time, not correctness.

## Checks

| Check                                                                                                                                                        | Where                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------ |
| `npm run check:plans`, `tests/worker/storage-plans-generator.test.ts`, `storage-plan-ownership.test.ts` (generator rules, ownership, owner registry)         | hosted CI and locally          |
| `tests/worker/storage-boundary.test.ts` (a signed plan request is refused on every public path; only the Container's direction of the signature is accepted) | hosted CI and locally          |
| `tests/worker/module-layout.test.ts`, `tests/worker/docker-context.test.ts` (projects, references, context)                                                  | hosted CI and locally          |
| `ModuleBoundaryTests`, `LayeringTests`, `StoragePlanBoundaryTests` (architecture, import, plan-hash, no SQL in C#, nothing the bridge sends names SQL)       | hosted CI and locally          |
| `FoundationHostTests` (the host serves no storage endpoint and refuses the wrong direction of the signature)                                                 | hosted CI and locally          |
| Native AOT publish of the host with its twenty-one referenced projects                                                                                       | hosted CI image build, locally |

## Adding a module's plans

1. Write `storage/plans/<owner>/<name>.sql` for your own owner. Touch only your tables and, for receipts, outbox and similar, the
   `platform_` tables.
2. Run `node eng/verification/storage-plans.ts` and commit both generated files.
3. Call the plan through the typed repository API your task adds to `Storage.D1`. The executor and the exact scalar values are internal
   to the bridge today (`InternalsVisibleTo` for the host and its tests); a module reaches them only through that API, never through the
   Contracts wire records.

## Not claimed

- **No module owns a plan yet.** The module projects are boundaries with a descriptor. The physical tables and the migration runner exist
  ([D1 physical schema and migrations](d1-physical-schema.md), CLOUD.03), so a module plan names real tables; receipts, outbox and archive
  (CLOUD.04), the shared families (CLOUD.06) and every module's behavior are later tasks. The checks above prove the boundary and the rule,
  not a module implementation. The migration bookkeeping tables (`platform_schema_state`, `platform_migration_receipt`,
  `platform_backfill_checkpoint`) are written only by the migration runner: the ownership rule accepts any `platform_` table in a module plan,
  so a plan that names one of them is a review finding.
- **The typed repository API for modules does not exist yet.** The bridge is internal to the host and `Storage.D1`.
- **No new deployed observation.** CLOUD.02 changes where the proven bridge lives, not how it behaves; the manifest hash and the Worker
  dictionary are unchanged, and no deployment or live scenario was run for it. The PRF.07 live results apply to the same plans and the same
  executor.
- **SQLite is not D1.** The offline plan vectors prove SQL, constraints and batch rollback, not the provider's network path.
- **The layer rules are untested against real module code** because no module has a type yet (fixtures only).
