# D1 physical schema, exact adapters and migrations

This document describes what CLOUD.03 (Design WP-21.03) delivers, the checks that enforce it, what each check proves and what it does
not. The binding rules are the Design [D1 execution profile](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/architecture/data-model/04-d1-execution-profile.md)
(sections 2 and 6, including the physical manifest conventions and the migration bookkeeping) and the
[Cloud data model](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/architecture/data-model/01-cloud-data-model.md). Plans and the module
boundaries are described in [storage plans](storage-plans.md).

## What exists

| Path                                                          | Content                                                                                                                                            |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/ArcForges.Cloud.Storage.D1/Physical/manifest/*.json`     | The checked-in physical manifest: one file per owner (19 modules and `platform`) and the closed enum registry `enums.json`. 154 tables.            |
| `src/ArcForges.Cloud.Storage.D1/Physical/PhysicalSchema.g.cs` | Generated C# column maps, enum registry, manifest hash and migration-lock identity.                                                                |
| `src/ArcForges.Cloud.Storage.D1/Physical/*.cs`                | The typed exact bind/result adapters: `ColumnCodec`, `PhysicalValue`, `RowShape`, `ExactOrderBytes`, `Fts5Query`, `SchemaCompatibility`.           |
| `src/ArcForges.Cloud.Storage.D1/Migrations/`                  | The numbered, checksum-locked migrations (`NNNN_<module>__<slug>.sql`), `migrations.lock.json` and the `pending/` folder of unnumbered migrations. |
| `eng/verification/physical-schema.ts`                         | Manifest validator, baseline emitter, C# generator and migration-to-manifest drift check (`npm run check:physical`).                               |
| `eng/migrations/`                                             | The migration runner, its three D1 clients (SQLite, binding, REST), sequence assignment and the command line.                                      |
| `eng/verification/d1-physical-local.ts`                       | The opt-in local run against workerd's D1 under Miniflare (`npm run test:d1:local`).                                                               |

The host never reaches this layer yet: no module owns a plan or a repository over these tables, and nothing here is executed at startup. Migrations run from
the gated deployment job and never from the Container.

## The manifest and its conventions

Every table is a SQLite `STRICT` table named `<module>_<snake_case_entity>` (the prefixes are `storage/plans/owners.json`). A table whose only primary key is one
`INTEGER` column is also `WITHOUT ROWID`, because a rowid alias turns an inserted `NULL` into a generated value instead of refusing it. The logical types of model 01
become these stored forms, each with a `CHECK` that makes the database refuse every other form:

| Logical type                     | Stored as                                                                                                                                                   |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`                             | canonical lower-case UUID `TEXT` (pattern and alphabet checked)                                                                                             |
| signed 64-bit, `rev`, instants   | `INTEGER`; instants are UTC microseconds; bound as `CAST(? AS INTEGER)` from canonical decimal text and read as `CAST(column AS TEXT)`                      |
| `int`                            | `INTEGER` checked to 32 bits                                                                                                                                |
| `uint64`, `decimal(28,9)`        | canonical `TEXT` (no sign for `uint64`; at most 28 significant and 9 fractional digits, no trailing zero, no negative zero), never a number in SQL or in C# |
| `money`                          | two columns, `<name>` (decimal text) and `<name>_currency` (three upper-case letters), both null or both present                                            |
| `bool`                           | `INTEGER` 0 or 1                                                                                                                                            |
| closed `enum`                    | `INTEGER` registered number; named registry enums keep the proto numbers of contracts 04, inline enums number from 1 in listed order; never renumbered      |
| `Key`, `ReasonCode`, `ProductId` | `TEXT` constrained to the Key alphabet and length, or to the closed product set                                                                             |
| `hash` / `bytes` / `*_proto`     | `BLOB` (32 bytes exactly for `hash`)                                                                                                                        |
| `json`                           | `TEXT` with `json_valid`, and the root kind when the model fixes it                                                                                         |
| `AggregateRef`                   | two columns `<name>_kind` and `<name>_id`                                                                                                                   |

Immutable and append-only tables, columns that must never decrease (fences, watermarks, the migration schema version) and a few cross-column rules are enforced by
triggers whose abort message contains `CHECK constraint failed: af_immutable_<table>` or `af_monotonic_<table>_<column>`, so the Worker's existing classifier reports them as
a constraint failure. Model 01 section 12 invariants that span rows or modules stay in the guarded plans of their owners; each table's `note` in the manifest says what it
leaves to a plan. The 28 foreign keys that model 01 declares across modules are kept and pinned by a test, so adding one is an explicit, reviewed change.

### Not in the manifest

Model 01 describes these records without a field list; the owning task defines them in its own migration under RES-cloud-d1-migrations: the Sync bootstrap manifest and page
records, the change archive of the receipts/outbox task (CLOUD.04) and the sort-key columns of any table that a module orders by an exact decimal. The cloud
`search_retrieval_chunk` has no vector column: embeddings live in Vectorize.

## Typed exact adapters (C#)

`ColumnCodec.Encode` turns a `PhysicalValue` into the generated D1 scalar for its column and refuses a value the column cannot hold (range, alphabet, length, JSON shape and
depth, well-formed Unicode, enum registration); `Decode` is the strict inverse and treats a wrong kind or an unregistered enum number as a defect. `RowShape` fixes the ordered
columns of one plan statement, binds and reads whole rows, and yields the plan parameter kinds, so a plan definition cannot drift from the schema. `ExactOrderBytes` gives
order-preserving byte keys for `uint64`, signed 64-bit and decimal values (SQL may order by a `BLOB`, never by their text). `Fts5Query` is the only way to form a MATCH
expression: it starts with the workspace-and-product scope filter and quotes every user term inside the title and body columns, so an operator typed by the user is text.
`SchemaCompatibility` is the readiness rule for rolling an application back. There is no SQL text in any of it.

## Migrations

One global sequence, applied in order with receipts (RES-cloud-d1-migrations). A module task authors `Migrations/pending/<module>__<slug>.sql`; the Cloud integration owner runs
`node eng/migrations/cli.ts assign` at merge, which numbers the file, moves it beside the others and locks its checksum. A merged migration is never edited
(`node eng/migrations/cli.ts check --base origin/main`, part of `npm run check:physical`, refuses an edited or removed entry). Every file starts with `-- af-migration: module=<name> mode=<mode>`.

| Mode       | Contents                                                                                                                                                                                                                                                                                |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `expand`   | Additive DDL only: create table, index, trigger, virtual table; add a column.                                                                                                                                                                                                           |
| `backfill` | One guarded UPDATE per selected row, in pages of at most 100, with a checkpoint per page. The guard compares the owner revision, so a row written after it was read is counted stale and is converted from its new value in the next pass, never overwritten. `verify` must reach zero. |
| `cutover`  | Data statements plus one fenced move of the read and write horizons; it requires its backfills to be verified and re-runs their verify queries inside the cutover batch, under the fence, so a row written after a backfill finished blocks it.                                         |
| `contract` | The irreversible step: drops and renames. Refused until its cutover and a declared soak have passed and the deployment job passes `--allow-contract`.                                                                                                                                   |

The runner (`eng/migrations/runner.ts`) bootstraps with migration 0000, which creates the three bookkeeping tables, then runs under a lease and a fence held in
`platform_schema_state`. Each chunk of at most 25 statements is one atomic batch whose first statement advances the migration's receipt under the current fence and violates a
`CHECK` when the fence, the lease or the previous progress moved, so an interrupted run resumes from `statements_done`, a migrator that lost its lease cannot apply a
single statement, and an edited merged migration is refused by its receipt checksum. A receipt records the source revision, schema version, plan-manifest hash, ABI and runtime of
the release (WP-21 section 6). The compatible-rollback rule is `compatibility()` in the runner and `SchemaCompatibility` in C#, pinned by one shared vector file.

The virtual table of D1 FTS5 has its own migration (`NNNN_search__fts5.sql`) because the provider's export cannot carry virtual tables (recorded below).

## What each check proves, and what it does not

- **Oracle (hosted CI and locally):** `node:sqlite` runs the real migrations and the real SQL. It proves the structure equals the manifest, every table round-trips a typical and an extreme row,
  every column refuses its negative case, every foreign key, trigger and index behaves, the runner's ordering, receipts, idempotency, interruption at every chunk boundary, stale migrator,
  stale backfill, cutover and contract rules, and the shared exact-value, sort-key, FTS5 and compatibility vectors that the C# adapters also pass. SQLite is not D1.
- **workerd's D1 (opt-in, `npm run test:d1:local`):** the closest local engine. It reruns the structure, the vectors, FTS5, every table's extreme row, a batch's atomicity for DDL and data,
  interruption, a stale migrator and a stale backfill. It found three facts that SQLite does not show, all now fixed or guarded:
  1. D1 refuses a `LIKE` or `GLOB` pattern longer than 50 bytes when it is evaluated, not when the table is created (a decimal check was 53 bytes). A test bounds every pattern.
  2. D1 enforces foreign keys and cannot switch them off; `PRAGMA defer_foreign_keys` inside a batch is the only relief.
  3. D1 keeps `_cf_` tables in the database and refuses to describe them, so a structure comparison excludes them. An integer column read without `CAST(... AS TEXT)` loses precision above 2^53.
     It is not a Cloudflare provider result.
- **Known limits (reviewed, not fixed here):** a module plan could still name a bookkeeping table (the ownership rule accepts any `platform_` table, so review stops it); the binding and REST clients map a result row with `Object.values`, so a hand-written backfill page query must give every column a distinct alias (the runner's own queries do); `status` and `compat` report a database ahead of the release (a rolled-back release) while `apply` refuses it; the runner identity is `gh-<run>-<attempt>-<job>`, and two migrators that shared an identity would still be separated by the fence.
- **Not proven here (deferred live checks):** that the provider's REST `batch` is one atomic transaction (the runner's chunk guarantee depends on it, and fails closed on an unexpected error);
  the provider's behaviour for the FTS5 tokenizer build, export and Time Travel with a virtual table present; real D1 limits and latency; the migration run from the gated deployment job.
  They need the `RES-cloud-deployment` lease and a proof environment, are not run by CI, and never print a secret.
