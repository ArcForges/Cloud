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
| `platform.runtime_credential` | The two login roles of the runtime credential rotation, when each was rotated and when its deployment was promoted                                                      | none                     |
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
  - Every mark of a failure is guarded by the attempt it claimed: a publisher whose lease expired, and whose row another
    publisher claimed again, can neither reschedule nor dead-letter it (it counts the delivery as superseded).
  - The sink of the hosted deployment (the event queue) arrives with the first producer of events.
- **Job lease** (`Schedule`, `Claim`, `Renew`, `Fenced`, `Complete`, `Fail`):
  - A claim takes the oldest available job, or a job whose lease expired, increments its fence and counts an attempt.
  - A job that is available again after the maximum attempts (its holders' leases kept expiring) is dead-lettered by the claim,
    in the same transaction, instead of being handed out again.
  - A business transaction calls `Fenced` to lock the job row and check the fence. A holder whose lease was taken over, or whose
    job was completed or dead-lettered, can neither write, renew nor complete (`ErrLeaseLost`).
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
  migration rolls back completely and reports its SQLSTATE. Its message never quotes a value: the server's primary message is
  kept only for class 42 (syntax error or access rule violation) and 0A (feature not supported), whose messages name objects and
  the migration's own text; any other error reports its class and the names of the constraint, table and column (a data error
  such as `22P02` quotes the offending value in its primary message, and the detail can quote whole rows). A crashed run (the
  session ends) rolls back and releases the lock.
- After the migrations the runner reconciles the runtime role's grants (below).
- `migrate status` and `migrate plan` report without the lock and without changing anything.
- The output is one JSON document on stdout: the database, the roles, the server's `server_version_num` (`serverVersionNum`,
  for example `180004` for PostgreSQL 18.4), the state (`uninitialized`, `pending`, `current` or `refused`), the applied
  versions with their checksums, the pending names, the migrations run and their durations, and any problems. Log lines go to
  stderr. Neither ever holds a credential. The output also names the tested major (`testedMajor`, 18: the integration tests and
  the restore drill run `postgres:18-alpine`, PostgreSQL 18.4) and whether the server's major matches it
  (`serverMajorMatchesTested`); a mismatch is logged as a warning, not refused. It records the logging settings too (`logging`: `pg_stat_statements.track`, `log_statement`,
  `log_min_duration_statement`). The repository records no Neon major; each
  deployment's gate record does.

A merged migration is never edited or removed: a change is a new migration, written as expand and contract (below). A migration
that cannot run in a transaction (for example `CREATE INDEX CONCURRENTLY`) is not supported.

## Roles

| Role                                                                                     | Rights                                                                                                                                                                                                                                                                                               | Connection                                                           |
| ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Migration role                                                                           | Owns the schemas and tables; needs `CREATEROLE` (and `CREATEDB` for `admin ensure-database`), which Neon's owner role has through `neon_superuser`                                                                                                                                                   | The direct (unpooled) URL: `ARCFORGES_CENTER_MIGRATION_DATABASE_URL` |
| Runtime group role (`ARCFORGES_CENTER_RUNTIME_ROLE`, default `arcforges_center_runtime`) | `NOLOGIN`, no elevated attribute, member of no role; `USAGE` on the module schemas it uses and exactly the table privileges of `center/internal/schema` (`RuntimeGrants`); no `DELETE`, `TRUNCATE`, DDL, `CREATE` on the database or on `public`; `CONNECT` on the center's database, no `TEMPORARY` | none                                                                 |
| Login roles `<group>_a`, `<group>_b`                                                     | `LOGIN`, `INHERIT`, `CONNECTION LIMIT 16`, members of the runtime group only (from PostgreSQL 16 `WITH INHERIT TRUE`), no grant of their own                                                                                                                                                         | The pooled URL: `ARCFORGES_CENTER_DATABASE_URL`                      |

On every run, `migrate` creates the group role if it is missing. It refuses a group role that can log in, has an elevated
attribute or is a member of another role. It revokes everything from `PUBLIC` and from the group on the module schemas, their
tables, sequences and functions, then grants exactly the declared privileges, in one transaction. A privilege granted by hand is
gone after the next run. Every table of a module schema must be listed either in `RuntimeGrants` or in `MigrationOnly`: an
integration test fails on a table with neither decision. The runtime role:

- can neither create, alter or drop a table, schema or index;
- can neither delete from nor truncate any table;
- can neither update the audit chain nor write signing keys or the migration record;
- can read no ungranted table or schema (`platform.runtime_credential`, another module's schema);
- can create no temporary table, and can connect to no other center database of the cluster.

The tests `TestTheRuntimeRoleHasExactlyItsGrants` and `TestTheRuntimeRoleConnectsOnlyToItsOwnDatabase` check each of these.

**Database privileges.** PostgreSQL gives `PUBLIC` `CONNECT` and `TEMPORARY` on every new database, and production and acceptance
share one Neon branch. On every run, `migrate` therefore revokes `CONNECT` and `TEMPORARY` on the center's database from
`PUBLIC`, revokes `CREATE` and `TEMPORARY` from the runtime group and grants it `CONNECT` (its login roles inherit it). It then
checks that `PUBLIC` holds neither privilege and that the runtime role can connect but not create temporary tables. The
migration role must own the database: another role's revocation would be ignored, and the check refuses the run. The owner keeps
its own rights.

- **Who connects.** The center's database admits only its owner and the runtime group. Nothing is granted to
  `neon_superuser` or to any other role.
  - The C# rollback path and the C# Hello connect with `NEON_DATABASE_URL`, which [Neon Hello](neon-hello.md) records as the
    provisioned Neon owner credential (`src/ArcForges.Cloud/NeonHello.cs` reads user and database from it). The owner's rights
    do not depend on `PUBLIC`. The deployment's migration step checks it before anything runs: it compares the role name (and,
    for production, the database name) of `NEON_DATABASE_URL` with those of the migration URL and refuses when the roles
    differ, because the revocation would lock that role out until it is granted `CONNECT` ([Deployment](#deployment)). The live
    revision at the merge of this store still uses that credential.
  - **Neon roles that may lose access.** Neon system roles whose `neon_superuser` membership is undocumented may no longer
    connect to the center's databases: `web_access` (older documentation: the SQL Editor and passwordless login), the Data API's
    `authenticator` and Managed Better Auth. ArcForges uses none of them; use the SQL Editor as the owner role.
  - **Self-hosted poolers.** A PgBouncer whose `auth_user` is not a superuser, and whose auth query connects to the center's
    database, fails after this revocation ("pgbouncer cannot connect to server"; CrunchyData postgres-operator issue #2800).
    Grant the pooler's auth role `CONNECT ON DATABASE <db>`. That adds one role that can connect to the center's database; it
    holds no table privilege there, and runtime roles of other centers stay excluded as long as they are not members of it.
    Neon avoids the failure only because its PgBouncer's `auth_user` is `cloud_admin`, a superuser, with `auth_dbname=postgres`.
    That comes from Neon's open-source compute configuration, not from documented behaviour; Neon does not publish its
    production auth lines.
- **What remains.** The runtime login roles can still connect to databases the migration role does not own, such as Neon's
  `postgres` database (owned by `cloud_admin`). They hold no table privileges there.
- **The proof.** Before promotion, the rotation checks that the login role inherits the runtime group
  (`pg_has_role(…, 'USAGE')`) and may connect (`has_database_privilege(…, 'CONNECT')`). It then opens one unpooled connection
  as the login role: only a server login to the center's database exercises `CONNECT`, and a direct connection always starts a
  new backend. The pooled probe proves the login through the Neon pooler, but its success says nothing about the revocation:
  the pooler's auth lookup goes to `postgres`, and it could answer with a server connection opened before the revocation.
- **If the revocation broke logins.** `migrate` revokes before any probe runs, so a revocation that broke Neon pooler logins
  would also break the running revision, not only stop the deployment. It should not happen: Neon's PgBouncer runs its auth
  lookup as `cloud_admin` in the `postgres` database, and Neon's proxy logs in as the client role (Neon's open-source compute;
  the production configuration is not published). Recovery: as the owner in the Neon SQL Editor,
  `GRANT CONNECT ON DATABASE <db> TO PUBLIC`, then re-run the deployment and report the failure.

### Runtime credential rotation

`arcforges-center admin rotate-runtime-credential` rotates the runtime credential. It runs with the migration role, under the
migration lock, and has five steps:

1. It picks the slot other than the most recently promoted one (`a` when none was promoted) and sets a new password on its
   login role, creating that role and its membership if needed. A slot rotated by a deployment that was never promoted is
   simply rotated again; the most recently promoted slot, which the running revision uses, is never touched. From PostgreSQL
   16 the membership is granted `WITH INHERIT TRUE`, which also corrects an existing membership that does not inherit. The
   rotation then checks that the login role inherits the runtime group and may connect.
2. It records the rotation in `platform.runtime_credential` as not yet promoted (`promoted_at` cleared).
3. It composes the pooled runtime URL. For Neon it derives the `-pooler` endpoint from the direct host; any other host is kept,
   or `ARCFORGES_CENTER_RUNTIME_POOLED_HOST` names one.
4. One unpooled connection as the login role proves `CONNECT` on a new backend. Through the pooled URL it then proves that
   the new credential:
   - connects as the login role to the center's database;
   - reads a granted table;
   - can neither create a table, nor a temporary table, nor read an ungranted one.

   The probe retries for up to a minute while a new password propagates to the pooler.

5. It writes the URL as `{"ARCFORGES_CENTER_DATABASE_URL": …}` into `ARCFORGES_CENTER_RUNTIME_SECRET_FILE`. That is a new file
   (never overwritten) with mode `0600`, in exactly the format of `wrangler deploy --secrets-file`.

`arcforges-center admin confirm-runtime-credential --slot a|b` records, with the migration role and under the migration lock,
that the deployment carrying the slot's current password was promoted (`promoted_at`). It is idempotent: a slot whose current
password was confirmed keeps its time. It refuses a slot other than `a` or `b` (exit 2) and a slot that was never rotated
(exit 1). The deployment runs it only after `wrangler deploy` succeeded.

So a failed deployment, retried any number of times, rotates only its own unpromoted slot, and the running revision keeps its
credential.

**The live slot comes from Cloudflare.** A confirmation can still be lost: the job is cancelled or times out between
`wrangler deploy` and the confirmation, or the confirmation fails and someone simply re-runs the deployment. So the deployment
does not trust the record alone:

- Every Worker version it publishes carries its slot in the version message, `runtime-slot=<a|b>` (`wrangler deploy --message`).
  The message is visible to the account's Cloudflare users only, never on a public route: health does not report the slot.
- Before rotating, it reads the live versions with the pinned Wrangler's machine-readable output, using the same token and
  environment as the deployment: `wrangler deployments status --json` (the live versions and their percentages), then
  `wrangler versions view <id> --json` (the annotation `workers/message`).
- If the live version is labelled, it first confirms that slot (self-heal; idempotent), then rotates with
  `admin rotate-runtime-credential --live-slot <slot>`, which takes the other slot whatever the record says.
- If this database never rotated the live version's slot (the acceptance database was recreated, or the target points at a
  new database), the confirmation exits with status 4. The live version then holds no credential for this database, so there
  is nothing to record: the job log says so and the other slot is rotated, without retries and without the post-promotion
  recovery text.
- If the live version carries no label (the first deployment of the store; the live revision then uses no runtime
  credential) or cannot be read, the record decides, and the job log says so.
- If several versions are live on different slots, or on a labelled and an unlabelled credential (a gradual rollout), it
  refuses to rotate.

A confirmation that keeps failing after a successful promotion (three attempts with a growing delay) still fails the
deployment command, naming the slot. The next deployment then reads the live slot and repairs the record before rotating. Only
if Cloudflare cannot be read at that moment would it rotate the live slot, breaking the running revision's new connections
until that deployment is promoted. To close that gap by hand, before the next deployment: run
`admin confirm-runtime-credential --slot <slot>` with the migration role's direct URL, or as the owner in the Neon SQL Editor
`UPDATE platform.runtime_credential SET promoted_at = now() WHERE slot = '<slot>' AND promoted_at IS NULL`.

The password has 40 base64url characters (240 random bits), with lowercase, uppercase, a digit and a symbol and no character
three times in a row. Neon requires at least 60 bits of entropy. The password is returned only inside the URL written to the
secret file, and the center never prints or logs it.

**How the secret reaches the server.** Neither the password nor a verifier ever appears in statement text, in a bind parameter
or in an error:

- The rotation loads the secret into a temporary table (`ON COMMIT DROP`) with binary `COPY FROM STDIN`, so the value travels
  in CopyData messages.
- A temporary PL/pgSQL function reads it from that table and runs `CREATE ROLE` or `ALTER ROLE … PASSWORD` with `EXECUTE`. The
  call is `SELECT pg_temp.arcforges_set_login($1, $2, $3)`, whose arguments are only the role name, the connection limit and
  whether to create the role.
- `pg_stat_statements` with `track = 'top'` (its default, which only a superuser can change) records top-level statements only:
  the `COPY`, the function's definition and the call, never the nested role statement.
  - The rotation reads the settings of every tool that can capture statements run inside functions. It records them in its
    output (`logging`), and `migrate` records them in the gate record. The decision table (`migrate.Logging.CaptureRefusal`,
    unit-tested):
    - `pg_stat_statements.track = 'all'` would record the nested role statement, so it is refused; `top` (the default),
      `none` and an unloaded module proceed.
    - `pg_stat_monitor.pgsm_track = 'all'` is refused for the same reason; `top` and an unloaded module proceed.
    - `pgaudit.log` (Neon's HIPAA audit option uses pgaudit) is recorded, not refused. pgaudit audits nested utility
      statements too: its ProcessUtility hook handles `context <= PROCESS_UTILITY_QUERY` and keeps the nested query string.
      But its `log_audit_event` replaces every character after the first `password` token with `<REDACTED>` for
      `T_CreateRoleStmt` and `T_AlterRoleStmt`, by statement type and whatever the nesting. This is in `pgaudit.c` at the tags
      Neon builds: 16.1, lines 556–602 (hook 1546–1584); 17.1, lines 612–659 (hook 1611–1649); and the current 18 tag, 18.0,
      lines 615–663 (hook 1638–1676). Neon's compute Dockerfile at `fa50421` builds 16.1 and 17.1, and its
      `pgaudit-parallel_workers` patches do not touch redaction. The secret follows the `PASSWORD` keyword, so it always lies after the first
      `password` token and inside the redacted part, whatever the role name.
    - `log_statement` and `log_min_duration_statement` are not refused: a logged statement text (`all` or `mod`, or a duration
      line with its parameters) holds no secret.
- The function's exception handler re-raises with the SQLSTATE and the fixed message `login role update failed`, so the dynamic
  statement never reaches an error's context, the client or the server log.
- **Tests.** They run on PostgreSQL 18.4 with `pg_stat_statements` preloaded, `log_statement = 'all'` and
  `log_min_duration_statement = 0`, and check that:
  - no `pg_stat_statements` row and no server log line holds the password or the verifier;
  - a forced failure's error and context fields hold neither (without the handler they would);
  - `track = 'all'` refuses the rotation.

What the secret is depends on one predicate, the one that derives the `-pooler` host (`provision.NeonHost`: a host
`ep-….<region>….neon.tech`):

- **Self-hosted (any other host): only a verifier leaves the center.** The rotation computes a SCRAM-SHA-256 verifier
  client-side: `SCRAM-SHA-256$4096:<salt>$<StoredKey>:<ServerKey>` (standard base64) with a random 16-byte salt.
  - SaltedPassword is PBKDF2-HMAC-SHA-256 (`crypto/pbkdf2`). ClientKey and ServerKey are HMAC-SHA-256 of it with `Client Key`
    and `Server Key`, and StoredKey is SHA-256 of ClientKey.
  - SASLprep is the identity on the generated alphabet, which the code asserts.
  - PostgreSQL stores a verifier as it is.
  - Tests check that the stored secret is the verifier of the runtime password, that a SCRAM login with the password succeeds,
    and that the verifier equals PostgreSQL's own for the same salt.
- **Neon: the password itself.** Neon does not support hashed passwords ("Passwords must be supplied in plain text but are
  encrypted when stored. Hashed passwords are not supported.", neon.com/docs/manage/roles). What remains by design:
  - Neon's compute forwards the nested role statement to Neon's control plane on commit, through its DDL forwarding (the 60-bit
    entropy check and the control-plane synchronization). The project setting `store_passwords` governs whether Neon keeps the
    password.
  - The client's TLS session ends at Neon's proxy, which routes by SNI. So the proxy sees everything the rotation sends, the
    `COPY` data included, and the rotation is not protected end to end to Postgres.
  - Neon's HIPAA audit option uses pgaudit, which logs the nested role statement with everything after `PASSWORD` redacted
    (above).
  - Neon documents neither `log_statement` nor `log_min_duration_statement`. The rotation records both; neither can expose the
    secret, which is in no statement text or parameter.
  - A `neon_superuser` member cannot set `pg_stat_statements.track` or `log_statement` (`42501`). The rotation therefore sets
    neither and only reads them.

Neon's documentation does not state whether roles created with SQL can connect through its pooler. The rotation's pooled probe
establishes it on every deployment, before promotion: if the pooler refused the role, the deployment would stop there and the
running revision would stay.

## Deployment

The protected main-push deployment (`.github/workflows/ci.yml`, job `deploy`, GitHub environment `cloudflare`) runs these steps:

1. **Migrate the D1 database (gated)**: unchanged; production has no D1 binding, so the C# gate records `not-applicable`.
2. **Migrate the PostgreSQL database (gated)**: `node tooling/postgres-deploy.ts migrate --target production`.
   - It loads the sealed candidate image, checks its id and runs the image's own `arcforges-center migrate`.
   - The executable runs in a read-only container without capabilities and with `no-new-privileges`.
   - It connects with `NEON_DATABASE_URL_DIRECT`, which Docker receives by variable name, never on a command line.
   - Before anything runs it compares `NEON_DATABASE_URL` (the C# Hello's credential) with the migration URL: the same role
     (and, here, the same database) passes; another role refuses the step, because the revocation of `PUBLIC`'s `CONNECT`
     would lock that role out until it is granted `CONNECT`; an absent variable is skipped and recorded. Acceptance, which has
     its own database, compares the role only, and only when its job carries the variable (today it does not). Neither value
     is printed.
   - It writes `artifacts/postgres-gate-production.json`: target, revision, status, database, version, the migrations applied,
     the runtime role, `serverVersionNum`, the tested major and whether the server's major matches it (a mismatch is a warning
     in the record and the log, not a failure), the logging settings, and the result of the `NEON_DATABASE_URL` comparison. No credential is in it,
     and it is kept as deployment evidence.
3. **`npm run deploy`** (`tooling/cloudflare.ts`):
   - It refuses without both passed gate records for this candidate.
   - It loads and pushes the image.
   - It reads the live version's runtime slot from Cloudflare and rotates the other slot with the image's
     `admin rotate-runtime-credential` ([rotation](#runtime-credential-rotation)). The secret file goes to a private directory
     under the runner's temporary directory, outside every artifact directory.
   - It uploads the file with the Worker version (`--secrets-file`, together with the C# rollback path's unchanged
     `NEON_DATABASE_URL`), labels the version `runtime-slot=<slot>` (`--message`) and removes the directory, whatever happens.
   - Only after `wrangler deploy` succeeded, it confirms the slot with the image's `admin confirm-runtime-credential`, retried
     up to three times; a confirmation that keeps failing fails the command with the recovery above.
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

- **Neon history window and instant restore.** Neon's instant restore (point-in-time restore) returns a branch to any moment
  within the project's history window.
  - **Where to read the window.** This repository has no Neon credential, so it does not read the window. The operator reads
    it read-only:
    - in the Console, under Settings → Instant restore (Neon's pages also call it the History window);
    - through the API, `GET /api/v2/projects/{project_id}`, field `history_retention_seconds` (needs a Neon credential);
    - with the CLI, `neon projects get`.
  - **The human action** records three values on the delivery: `history_retention_seconds`, `pg_version` and the plan.
  - **Choosing the window** is an owner decision. Neon recommends 7 days for production; the paid plans' default is 1 day.
  - **Limits of instant restore:**
    - it works only on root branches and only inside the window;
    - it overwrites every database on the branch. `arcforges_acceptance` is on the production branch: it is reached through the
      same direct endpoint (`NEON_DATABASE_URL_DIRECT`), and a Neon endpoint belongs to one branch. A production restore
      always rewinds acceptance too;
    - whether it reverts the rotated runtime role passwords is unknown. The restored `pg_authid` holds the older passwords,
      but Neon forwards `ALTER ROLE … PASSWORD` to its control plane, and the compute re-applies the control plane's stored
      verifier when it starts, so the newest password may be pushed back. Neon documents neither outcome. So rotate and
      redeploy right after any restore.
  - **Beyond the window**, snapshot schedules (paid plans, up to 35 days) keep restore points.
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
     - A Cloudflare version rollback (`wrangler rollback` or the dashboard) works only to the immediately previous version.
       That version's slot is the other one, which the last rotation left alone. Any older version carries a slot password
       that has since been rotated, so its connections would fail. A version rollback also reverts the version's secrets, its
       runtime credential included. The next deployment reads the rolled-back version's slot label and rotates the other
       slot.
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
