# PostgreSQL store of the center

The Go center ([center](center.md)) keeps its relational records in PostgreSQL: Neon in the official deployment, any PostgreSQL
for a self-hosted center (ArcForges-Design AD-0021 §8, data/cloud-store.md §6). AF-CTR-02 delivers the store, its migrations,
the platform tables, the roles, the deployment step and the recovery procedure. The modules' own tables arrive with their tasks
(AF-CTR-03 onward). The driver and migration choice (pgx directly, an in-repository runner) and the alternatives it rejected are
recorded in [engineering controls](engineering-controls.md#postgresql-driver-query-and-migration-tooling-evaluation-for-part-b).

## Model

One schema per module, owned by the migration role. The model follows data/cloud-store.md §6:

- identifiers are `uuid`;
- instants are `timestamptz`;
- enumerations are `smallint` with named `CHECK` constraints;
- text is bounded where a contract bounds it;
- every constraint has a name, so an error names its constraint and never a value.

The first migration (`center/internal/schema/migrations/0001_platform_store.sql`) creates these tables:

| Table                         | Purpose                                                                                                                                                                 | Runtime role             |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| `platform.schema_migration`   | The applied migrations: version, name, SHA-256, time, role, duration and the build that applied them (created by the runner before the first migration)                 | `SELECT`                 |
| `platform.command_receipt`    | One receipt per principal and command ID: operation, SHA-256 of the transmitted request bytes, status, stored result or error code, expiry                              | `SELECT, INSERT, UPDATE` |
| `platform.inbox`              | One row per provider message (source, message ID): received, processed, outcome, expiry                                                                                 | `SELECT, INSERT, UPDATE` |
| `platform.outbox`             | Events committed with their business change: unique dedup key, topic, aggregate, payload, correlation, state, attempts, availability                                    | `SELECT, INSERT, UPDATE` |
| `platform.job_lease`          | Jobs with a holder, a lease expiry and a fence that increases with every claim                                                                                          | `SELECT, INSERT, UPDATE` |
| `platform.runtime_credential` | The two login roles of the runtime credential rotation and when each was rotated                                                                                        | none                     |
| `audit.audit_event`           | The append-only audit chain: each event's SHA-256 covers the previous event's hash and the event's fields                                                               | `SELECT, INSERT`         |
| `audit.chain_head`            | The chain's single head row, locked by every append                                                                                                                     | `SELECT, UPDATE`         |
| `fleet.signing_key`           | Signing-key metadata (key ID, purpose, algorithm, public key, the name of the platform secret that holds the private key, validity); private keys are never stored here | `SELECT`                 |

Retention sweeps (receipts after 90 days, the inbox, dispatched outbox rows, audit partitions) are AF-PLAT-01's. They run with the
migration role, because the runtime role can never delete.

## Guarantees

`center/internal/platform` re-implements the guarantees of the D1 storage plans with native transactions, constraints and row
locks. Integration tests against a real PostgreSQL cover each one.

- **Receipt-guarded commands** (`Execute`):
  - The receipt is inserted first, in the command's own transaction. A replay with the same digest returns the stored result
    without running the command.
  - A different operation or request digest under the same ID is refused (`ErrCommandIDReused`).
  - A concurrent duplicate waits on the receipt row and then answers from the committed receipt, so concurrent duplicates
    execute once. This holds under read committed and under serializable isolation.
  - A domain refusal (`Refusal`) rolls back the command's changes and is stored, so a replay answers the same refusal.
  - Any other failure rolls back everything and stores nothing, so a retry runs the command again.
  - The digest covers the request bytes as transmitted, never a re-encoding (AD-0021 §10).
- **Inbox** (`Receive`, `Processed`): the provider message is recorded in the transaction that applies it. A redelivery or a
  concurrent duplicate is recognized and not applied again.
- **Outbox** (`Enqueue`, `Publisher`):
  - A message commits or rolls back with its business change. The dedup key is unique.
  - The publisher claims a batch in a short transaction (`FOR UPDATE SKIP LOCKED`). The claim counts the attempt and extends
    each row's availability by a lease. The publisher then publishes outside any transaction and marks the row dispatched.
  - A crash between commit and publication, or between publication and the mark, leaves the row pending. It is published again
    after the lease, with the same dedup key: at least once, never lost.
  - Failures back off. After the maximum attempts the row is dead-lettered with a truncated last error.
  - The sink of the hosted deployment (the event queue) arrives with the first producer of events.
- **Job lease** (`Schedule`, `Claim`, `Renew`, `Fenced`, `Complete`, `Fail`):
  - A claim takes the oldest available job, or a job whose lease expired, and increments its fence.
  - A business transaction calls `Fenced` to lock the job row and check the fence. A holder whose lease was taken over can
    neither write, renew nor complete (`ErrLeaseLost`).
- **Audit** (`AppendAudit`, `VerifyAudit`):
  - Appends are serialized by the chain head row.
  - The runtime role can only insert and read. A trigger refuses every update, even by the owner.
  - `VerifyAudit` recomputes the chain and detects a removed, inserted or changed event.
- **Signing keys** (`RegisterKey`, `ValidKeys`), AD-0021 §10:
  - A command-signing or entitlement-token key is an ES256 P-256 public key. A relay key is HS256 and has no public key.
  - A key is valid for at most 400 days and is never backdated.
  - While keys of a purpose are valid, a successor must become valid at least 7 days before the latest of them expires, and must
    outlive it, so a node that refreshed its center keys within that window verifies both.
  - The runtime role reads the verification set (newest first; the first is the signing key). Registration runs with the
    migration role.
  - Generating keys, and storing them in platform secrets without displaying them, is AF-CTR-05's (command signing) and
    AF-CLD-03's (entitlement tokens). Production key material is Plan H-16.

`center/internal/store` is the runtime role's access:

- transactions with a deadline (10 s by default) and cancellation;
- a bounded retry of serialization failures and deadlocks (5 attempts with jittered backoff);
- errors that keep the operation, the SQLSTATE and the constraint name but never the server's message or detail, which can quote
  row values.

The pool runs in exec query mode and keeps no session state, so it works behind the Neon transaction pooler.

## Migrations

`arcforges-center migrate` applies the numbered files of `center/internal/schema/migrations`, which are embedded in the
executable:

- The files are `NNNN_name.sql`, versions 1, 2, … without a gap. Line endings are normalized to LF before hashing, so a
  checkout's conversion never changes a checksum.
- A run takes the session advisory lock `0x617263666f726765` ("arcforge" in ASCII) on a direct connection, waiting up to
  `ARCFORGES_CENTER_MIGRATION_LOCK_TIMEOUT` (2 minutes by default). Concurrent runs serialize, and the second applies nothing.
- `platform.schema_migration` is created if missing, by a bootstrap that never changes.
- The database's record is compared with the build before anything runs, and the run is refused (exit status 3) for:
  - an applied file whose checksum changed (edited);
  - an applied version missing or renamed (removed);
  - an applied version the build does not have (the database is ahead of the build).
- Each pending migration runs in its own transaction with `statement_timeout` (10 minutes) and `lock_timeout` (30 s). A failing
  migration rolls back completely and reports its SQLSTATE and primary message (never the detail). A crashed run (the session
  ends) rolls back and releases the lock.
- After the migrations the runner reconciles the runtime role's grants (below).
- `migrate status` and `migrate plan` report without the lock and without changing anything.
- The output is one JSON document on stdout: the database, the roles, the state (`uninitialized`, `pending`, `current` or
  `refused`), the applied versions with their checksums, the pending names, the migrations run and their durations, and any
  problems. Log lines go to stderr. Neither ever holds a credential.

A merged migration is never edited or removed: a change is a new migration, written as expand and contract (below). A migration
that cannot run in a transaction (for example `CREATE INDEX CONCURRENTLY`) is not supported.

## Roles

| Role                                                                                     | Rights                                                                                                                                                                                                                                           | Connection                                                           |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------- |
| Migration role                                                                           | Owns the schemas and tables; needs `CREATEROLE` (and `CREATEDB` for `admin ensure-database`), which Neon's owner role has through `neon_superuser`                                                                                               | The direct (unpooled) URL: `ARCFORGES_CENTER_MIGRATION_DATABASE_URL` |
| Runtime group role (`ARCFORGES_CENTER_RUNTIME_ROLE`, default `arcforges_center_runtime`) | `NOLOGIN`, no elevated attribute, member of no role; `USAGE` on the module schemas it uses and exactly the table privileges of `center/internal/schema` (`RuntimeGrants`); no `DELETE`, `TRUNCATE`, DDL, `CREATE` on the database or on `public` | none                                                                 |
| Login roles `<group>_a`, `<group>_b`                                                     | `LOGIN`, `INHERIT`, `CONNECTION LIMIT 16`, members of the runtime group only, no grant of their own                                                                                                                                              | The pooled URL: `ARCFORGES_CENTER_DATABASE_URL`                      |

On every run, `migrate` creates the group role if it is missing. It refuses a group role that can log in, has an elevated
attribute or is a member of another role. It revokes everything from `PUBLIC` and from the group on the module schemas, their
tables, sequences and functions, then grants exactly the declared privileges, in one transaction. A privilege granted by hand is
gone after the next run. Every table of a module schema must be listed either in `RuntimeGrants` or in `MigrationOnly`: an
integration test fails on a table with neither decision. The runtime role:

- can neither create, alter or drop a table, schema or index;
- can neither delete from nor truncate any table;
- can neither update the audit chain nor write signing keys or the migration record;
- can read no ungranted table or schema (`platform.runtime_credential`, another module's schema).

The test `TestTheRuntimeRoleHasExactlyItsGrants` checks each of these.

### Runtime credential rotation

`arcforges-center admin rotate-runtime-credential` rotates the runtime credential. It runs with the migration role, under the
migration lock, and has five steps:

1. It sets a new password on the login role of the slot rotated less recently (`a`, then `b`, then `a` …), creating that role and
   its membership if needed.
2. It records the rotation in `platform.runtime_credential`.
3. It composes the pooled runtime URL. For Neon it derives the `-pooler` endpoint from the direct host; any other host is kept,
   or `ARCFORGES_CENTER_RUNTIME_POOLED_HOST` names one.
4. Through that URL it proves that the new credential:
   - connects as the login role to the center's database;
   - reads a granted table;
   - can neither create a table nor read an ungranted one.

   The probe retries for up to a minute while a new password propagates to the pooler.

5. It writes the URL as `{"ARCFORGES_CENTER_DATABASE_URL": …}` into `ARCFORGES_CENTER_RUNTIME_SECRET_FILE`. That is a new file
   (never overwritten) with mode `0600`, in exactly the format of `wrangler deploy --secrets-file`.

The revision still running keeps the other slot's credential, so a deployment never breaks the running revision's connections.
One exception: after a deployment that failed after its rotation, the next rotation reuses the running revision's slot. The
running revision then fails new connections until the new revision runs. A retried deployment closes that window.

The password has 40 base64url characters (240 random bits), with lowercase, uppercase, a digit and a symbol and no character
three times in a row. Neon requires at least 60 bits of entropy and accepts no pre-hashed (SCRAM) password, so the password
travels inside the `ALTER ROLE` statement over the verified TLS connection. It is never printed, logged or returned except
inside the URL written to the secret file, and an error of that statement reports its SQLSTATE only. Neon's documentation does
not state whether roles created with SQL can connect through its pooler. The rotation's pooled probe establishes it on every
deployment, before promotion: if the pooler refused the role, the deployment would stop there and the running revision would
stay.

## Deployment

The protected main-push deployment (`.github/workflows/ci.yml`, job `deploy`, GitHub environment `cloudflare`) runs these steps:

1. **Migrate the D1 database (gated)**: unchanged; production has no D1 binding, so the C# gate records `not-applicable`.
2. **Migrate the PostgreSQL database (gated)**: `node tooling/postgres-deploy.ts migrate --target production`.
   - It loads the sealed candidate image, checks its id and runs the image's own `arcforges-center migrate`.
   - The executable runs in a read-only container without capabilities and with `no-new-privileges`.
   - It connects with `NEON_DATABASE_URL_DIRECT`, which Docker receives by variable name, never on a command line.
   - It writes `artifacts/postgres-gate-production.json`: target, revision, status, database, version, the migrations applied and
     the runtime role. No credential is in it, and it is kept as deployment evidence.
3. **`npm run deploy`** (`tooling/cloudflare.ts`):
   - It refuses without both passed gate records for this candidate.
   - It loads and pushes the image.
   - It rotates the runtime credential with the image's `admin rotate-runtime-credential`. The secret file goes to a private
     directory under the runner's temporary directory, outside every artifact directory.
   - It uploads the file with the Worker version (`--secrets-file`, together with the C# rollback path's unchanged
     `NEON_DATABASE_URL`) and removes the directory, whatever happens.
   - The Container passes `ARCFORGES_CENTER_DATABASE_URL` to the Go center, which then reads the Hello greeting through the runtime
     role (`helloBackend` `postgresql-runtime`). The Hello's own Neon credential reaches only the C# host.

A deployment that fails before step 3 changes nothing that the running revision uses. A migration is additive (expand) while the
previous revision may still run.

**Required secret.** `NEON_DATABASE_URL_DIRECT` is the direct (not `-pooler`) URL of the Neon owner role (the migration role),
with `sslmode=require` or `verify-full` and `channel_binding=require`, in the GitHub `cloudflare` environment. Without it the
migration step fails and nothing is promoted.

### Acceptance environment

The `proof` Worker (`proof.arcforges.com`, deployed only by the protected manual dispatch on `main`) is the acceptance
environment of the Go center since AF-CTR-02.

- **What it runs** (`worker/acceptance/entry.ts`): the production Worker and Container in official-hosted mode, with the
  development fixtures of the plan configuration (`ARCFORGES_CENTER_PLAN_CONFIGURATION=development-fixtures`, never set in
  production). The feature stub still enables nothing until AF-CTR-03 delivers the catalogue. The public base URL is
  `https://proof.arcforges.com/api`.
- **Its database:** its own database `arcforges_acceptance` in the same Neon project, created idempotently by
  `admin ensure-database` through the migration role's direct connection, with its own runtime role
  `arcforges_acceptance_runtime`. Neither environment's credential reaches the other's database.
- **The deployment job:** after the retained D1 gate, `node tooling/postgres-deploy.ts migrate --target acceptance` ensures the
  database and migrates it. `npm run deploy:proof` then rotates the acceptance credential and deploys the sealed acceptance
  bundle.
- **Its resources:** the dispatch's `provision` action also provisions the center's acceptance resources
  (`eng/verification/center-provision.ts`): the R2 bucket `arcforges-acceptance-center` and the queues
  `arcforges-acceptance-center-events` and `-dlq`. The bucket's lifecycle rules expire `support-bundles/` objects after 30 days
  and abort incomplete multipart uploads after a day.
- **Production resources:** the same script refuses the production target. AF-PROD-01 provisions production with the owner's
  approval (Plan H-20).
- **What stays from the C# proof:**
  - The Container class keeps the name `FoundationContainer`, so its Durable Object namespace and Container application stay.
  - The retired Durable Object classes (`FoundationJobCoordinator`, `HarnessRunAlarm`) stay exported and inert, so no stored
    state is deleted.
  - The retained D1 database stays bound for its gated C# step, until AF-CTR-09 inspects and keeps it.
  - The C# proof routes, its static profile assets, its R2 bucket and its queues are no longer bound and stay as they are. Their
    sources and historical evidence stay until AF-CTR-09.

## Self-hosted center

A self-hosted center runs the same commands against any PostgreSQL, with `ARCFORGES_CENTER_MODE=self-hosted`:

```sh
export ARCFORGES_CENTER_MODE=self-hosted
export ARCFORGES_CENTER_MIGRATION_DATABASE_URL='postgres://owner:…@127.0.0.1:5432/postgres?sslmode=disable'
export ARCFORGES_CENTER_DATABASE_NAME=center            # optional: another database than the URL's
arcforges-center admin ensure-database
arcforges-center migrate
ARCFORGES_CENTER_RUNTIME_SECRET_FILE=/run/center/runtime.json arcforges-center admin rotate-runtime-credential
# serve with ARCFORGES_CENTER_DATABASE_URL from runtime.json
```

A plaintext connection (`sslmode=disable`) is accepted only for a loopback host in self-hosted mode. Every other connection
needs `sslmode=require` or `verify-full` (upgraded to `verify-full`) and `channel_binding=require`.

## Connection budgets

| Connection            | Bound                                                                                            | Where                                                    |
| --------------------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------- |
| Runtime pool          | 4 per instance (1 to 32), idle 30 s, lifetime 1 h, connect timeout 10 s                          | `ARCFORGES_CENTER_DATABASE_MAX_CONNS`; `internal/config` |
| Hosted instances      | 1 (`max_instances`), so at most 4 runtime connections through the pooler                         | `wrangler.json`                                          |
| Login roles           | `CONNECTION LIMIT 16` each                                                                       | `admin rotate-runtime-credential`                        |
| Migration             | one direct session per run, for the run only                                                     | `migrate`                                                |
| Hello's own Neon pool | 2, only while no store is configured (the C# rollback has its own)                               | `internal/config`                                        |
| Neon pooler           | transaction mode, up to 10,000 clients, server pool 90 % of `max_connections` (not configurable) | Neon                                                     |

## Observability and alert conditions

These are exposed today:

- **Readiness** (`/readyz` on the admin listener) has two components:
  - `database`: a ping of the runtime pool;
  - `databaseSchema`: every migration of the build is applied exactly. Versions beyond the build are allowed, so the previous
    revision stays ready while the next one deploys.
- **Startup log:** the hosted Container has no admin listener, so the center logs `store ready` or `store not ready` with the
  components once it starts.
- **Metrics:**
  - `arcforges_center_db_pool_connections{pool,state}` (acquired, idle, constructing, max);
  - `arcforges_center_db_pool_acquires_total{pool,outcome}` (acquired, waited, cancelled);
  - `arcforges_center_db_pool_acquire_seconds_total{pool}`;
  - `arcforges_center_db_schema_version{source}` (database, build).
- **Migrations:** the deployment's gate record and the job log hold each migration's name, checksum and duration.

Alert conditions for AF-OPS-01:

- `store not ready` after a deployment, or readiness `unavailable` for more than 5 minutes;
- `arcforges_center_db_schema_version{source="database"}` below `{source="build"}`;
- waited acquires growing faster than acquires (a pool at its bound);
- a failed migration or rotation step of the deployment job;
- dead-lettered outbox rows or jobs (`state = 3` in `platform.outbox`, `state = 4` in `platform.job_lease`). This needs a
  metric of AF-PLAT-01's sweeps; until then it is a query.

## Recovery

- **Neon history retention.** Neon restores a branch to any point within the project's history retention window (point-in-time
  restore through a branch).
  - This repository has no Neon API credential, so the window is not read here.
  - The operator reads it, read-only, in the Neon console (project settings, history retention) or with
    `GET /api/v2/projects/{project_id}` (`history_retention_seconds`), and records it on the delivery.
  - Changing it is an owner decision.
- **Logical backup restore drill.** It runs on every Linux verification leg (`python eng/center.py check`, step
  `restore-drill`):
  1. Migrate a database with the native executable and rotate its runtime credential.
  2. Seed it through the runtime role: a receipt, an outbox message, a job and audit events.
  3. Dump it with `pg_dump --format=custom`.
  4. Restore it into a second, isolated PostgreSQL server (`pg_restore --no-owner --no-acl --role=<migration role>`).
  5. Run `migrate status`, which must report `current` with nothing pending.
  6. Run `migrate`, which applies nothing and reconciles the grants and the runtime role.
  7. Rotate the runtime credential there.
  8. Run the verify phase against the restored database, through the new runtime credential:
     - the receipt answers its replay without running the command;
     - the outbox message is published;
     - the job is claimed and completed;
     - the audit chain verifies and keeps growing.

  The same procedure restores production from a dump into a new Neon database. Grants and roles come from `migrate`, not from
  the dump.

- **Rollback: expand and contract.** A schema change the running revision must survive is split into migrations that are each
  compatible with both the previous and the next application revision. `TestTheExpandAndContractRollbackProcedure` exercises it
  for a new required column. The steps:
  1. **Expand:** an additive, nullable or defaulted change (for example `ADD COLUMN title text`). It is applied before the new
     revision is promoted. The previous revision ignores it.
  2. **Deploy** the revision that writes the new column and reads it with a fallback.
  3. **Roll back the application only**, if needed. A rollback is a reverted application commit deployed on `main`.
     - The migration files stay: removing an applied migration is refused, and nothing ever migrates down.
     - The previous revision runs on the expanded schema: its readiness accepts a database ahead of its build.
     - The rows it writes are read by the next revision's fallback.
  4. **Roll forward and backfill** in a later migration (`UPDATE … WHERE title IS NULL`).
  5. **Contract** (`SET NOT NULL`, drop the old column) only once the previous revision is no longer a rollback target, because
     from then on it would fail.

  Compatibility has four parts:
  - **application:** each revision runs on the schema of its own migrations and of the next one;
  - **schema:** expand changes are additive;
  - **protocol:** Protobuf fields are added, never renumbered or retyped (Contracts compatibility rules);
  - **data:** values written by either revision are readable by both.
