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

| Table                         | Purpose                                                                                                                                                                         | Runtime role             |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| `platform.schema_migration`   | The applied migrations: version, name, SHA-256, time, role, duration and the build that applied them (created by the runner before the first migration)                         | `SELECT`                 |
| `platform.command_receipt`    | One receipt per principal and command ID: operation, SHA-256 of the transmitted request bytes without `RequestMeta.correlation_id`, status, stored result or error code, expiry | `SELECT, INSERT, UPDATE` |
| `platform.inbox`              | One row per provider message (source, message ID): received, processed, outcome, expiry                                                                                         | `SELECT, INSERT, UPDATE` |
| `platform.outbox`             | Events committed with their business change: unique dedup key, topic, aggregate, payload, correlation, state, attempts, availability                                            | `SELECT, INSERT, UPDATE` |
| `platform.job_lease`          | Jobs with a holder, a lease expiry and a fence that increases with every claim                                                                                                  | `SELECT, INSERT, UPDATE` |
| `platform.runtime_credential` | The two login roles of the runtime credential rotation, when each was rotated and when its deployment was promoted                                                              | none                     |
| `audit.audit_event`           | The append-only audit chain: each event's SHA-256 covers the previous event's hash and the event's fields                                                                       | `SELECT, INSERT`         |
| `audit.chain_head`            | The chain's single head row, locked by every append                                                                                                                             | `SELECT, UPDATE`         |
| `fleet.signing_key`           | Signing-key metadata (key ID, purpose, algorithm, public key, the name of the platform secret that holds the private key, validity); private keys are never stored here         | `SELECT`                 |

Retention sweeps (receipts after 90 days, the inbox, dispatched outbox rows, audit partitions) are AF-PLAT-01's. They run with the
migration role, because the runtime role can never delete.

### Identity and device (AF-CTR-03)

The second migration (`center/internal/schema/migrations/0002_identity_device.sql`) creates the `identity` and `device` schemas
and the rate-limit table. The tables derive from the D1 manifests
`src/ArcForges.Cloud.Storage.D1/Physical/manifest/{identity,device}.json` by the rules above. AF-CTR-03 landed it whole in its
first part (A1a), including what its second part (A1b) writes (`identity.step_up_challenge`, the registration label of
`identity.auth_flow`, the device revocation's columns), so A1b adds no migration; a later change is a new migration. A1b's writes
run under command receipts (`platform.command_receipt`, [model](#model)) in the same transaction as their change.

| Table                        | Purpose                                                                                                                                                                                                                                    | Runtime role             |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------ |
| `identity.user`              | Accounts: display name, state (active, restricted, suspended, pending deletion, deleted), locale, timezone, the random 32-byte WebAuthn user handle, revision                                                                              | `SELECT, INSERT, UPDATE` |
| `identity.auth_identity`     | Credentials: passkeys (COSE key, user handle, counter, BE/BS flags, transports, AAGUID, attestation `none`; subject: the credential ID's base64url) and e-mail identities (subject: the address, in clear), unique by provider and subject | `SELECT, INSERT, UPDATE` |
| `identity.session`           | Native bearer sessions (access and refresh token digests, family, generation) and browser cookie sessions (cookie handle digest, origin, idle expiry); scope; device binding                                                               | `SELECT, INSERT, UPDATE` |
| `identity.spent_refresh`     | The digest of every rotated refresh token, so a second presentation revokes the family                                                                                                                                                     | `SELECT, INSERT`         |
| `identity.auth_flow`         | One row per passkey or e-mail ceremony: channel, kind, purpose, challenge or code verifier, an e-mail flow's address digest, a registration's label, installation claim, attempts, expiry, outcome; final once consumed (trigger)          | `SELECT, INSERT, UPDATE` |
| `identity.step_up_challenge` | Step-up evidence: one operation ID and target digest of one session, proved and consumed at most once                                                                                                                                      | `SELECT, INSERT, UPDATE` |
| `identity.bootstrap`         | The single owner bootstrap of the database (singleton key): the configured token's digest, the account it created, when                                                                                                                    | `SELECT, INSERT`         |
| `device.device`              | One record per node, phone and browser installation: name, platform, trust (untrusted, trusted, revoked), remote control, seen, revocation                                                                                                 | `SELECT, INSERT, UPDATE` |
| `device.installation`        | One per device and product (`arcscope`, `companion`, `arcforges-node`, `arcforges-mobile`, `arcforges-web`): version, platform, a browser's claimed ID, an optional key                                                                    | `SELECT, INSERT, UPDATE` |
| `platform.rate_limit`        | Fixed-window counters keyed by the SHA-256 of a bucket kind and key, reset in place                                                                                                                                                        | `SELECT, INSERT, UPDATE` |

Differences from the D1 model, for the data/cloud-store.md §6 companion list:

- no `realm_id`: one center database is one realm (the acceptance environment has its own database);
- `identity.user` gains `locale` and `timezone` (`NOT NULL`, defaults `en-US` and `UTC`) and `passkey_user_handle`;
  `device_installation.contract_set_version` is dropped;
- `identity.session` gains `scope` (account, mobile.limited, node, push, automation; there is no agent scope, AF-CTR-07 keeps
  agent grants in its own table), `auth_method`, `authenticated_at`, `refresh_expires_at` and `revoke_reason`, and keeps no
  `csrf_hash`: a browser session's CSRF token is derived from its cookie handle. Every session names a device and an
  installation (`NOT NULL`, bound to the account by composite foreign keys);
- `identity.auth_flow` replaces `identity_browser_auth_flow` and `identity_security_flow` for the passkey and e-mail ceremonies; an
  e-mail flow stores the unsalted SHA-256 of the normalised address, never the address, and a passkey registration flow the label
  its credential gets (bounded like `identity.auth_identity.label`);
- `device.installation.public_key` and `key_version` are nullable (node keys arrive with AF-CTR-04, phone keys with AF-CLD-02),
  and `client_installation_id` carries a browser's claimed installation ID, unique per account over live rows;
- the device trust level gains 3 = revoked, set only by the revocation cascade together with `revoked_at`;
- every identity and device foreign key is `NO ACTION`, as D1's restrict: the D1 cascades of `identity_session.user_id` and
  `device_installation.device_id` are dropped, so a sweep or purge deletes the children first (below).

Indexes: the three token digests are partial unique indexes; sessions are indexed by account (listing and mass revocation), device
and installation (the revocation cascade), family and expiry; flows, step-up challenges, spent refresh tokens
(`family_expires_at`) and rate-limit windows (`window_start`) are indexed by the instant their retention sweep reads. The
referencing column of every foreign key leads an index (spent refresh tokens and step-up challenges by session and account, flows
by session and account where they name one), so a sweep's or a purge's deletes check each reference through an index; only the
single bootstrap row has none.

Retention (AF-PLAT-01's sweeps with the migration role; AF-PROD-01 enables identity in production only after them). Each period is
a maximum:

- consumed or expired flows and step-up challenges after 7 days;
- spent refresh tokens until their family's absolute expiry or with their session, whichever comes first;
- revoked or expired sessions after 90 days;
- rate-limit windows after one window has passed;
- revoked devices 30 days after their revocation (Design 11 §5): the sweep deletes a revoked device's sessions (revoked with
  it, so before their own 90 days) and their children, then its installations, then the device (children first, below). Until
  then a revoked device's native installation ID is refused (`credential_revoked`); after the sweep the same client installation
  ID is accepted as new, so revoking an installation ID lasts 30 days (it is not a credential). Live devices go with the account;
- accounts (`identity.user`) and their credentials (`identity.auth_identity`, revoked credentials included) for the account's
  lifetime: they are removed with the account by AF-ID-02's account deletion;
- the bootstrap row (`identity.bootstrap`) permanently: it is the record that the database's one bootstrap was used (it names the
  owner's account, so purging that account is AF-ID-02's decision).

The acceptance environment's tables grow on the production Neon project until then. Its anonymous-flow ceiling bounds the flows
anonymous calls create and the failure rows and audit markers that need a flow; it does not bound the prefix-keyed buckets
(`sign_in_prefix`, `refresh_prefix`, `bootstrap_prefix`: one row per distinct client /24 or /56, reset in place) or the
once-per-window refusal audits (`identity.rate_limited`, `identity.bootstrap.refused`), which grow with distinct prefixes and with
prefixes times windows ([acceptance environment](#acceptance-environment)).

Every foreign key is `NO ACTION`, so a sweep or a purge deletes children before their parents: a session's spent refresh tokens,
flows and step-up challenges, then the session; a device's sessions, then its installations, then the device; and for an account,
those, then the flows that name it (`identity.auth_flow.user_id`; an e-mail code flow names the account without a session, and
anyone who knows the address can create one, so the 7-day flow sweep does not remove them all), then its credentials, then the
account; the owner's account is also named by the bootstrap row (above). Until the sweeps exist these tables only grow.

Personal data: e-mail addresses are stored in clear only as the subject of an e-mail identity (`identity.auth_identity`). An e-mail
flow (`identity.auth_flow.email_hash`) keeps the unsalted SHA-256 of the normalised address submitted, whether or not an account
has it, and a rate-limit bucket key is the SHA-256 of a client IP prefix, an account or an e-mail address. Such a digest can be
reversed by trying every value, so these rows are personal data, also of people without an account, under the retention above.

Command receipts (`platform.command_receipt.result`) hold no e-mail address: UpdateProfile stores its profile without
`primary_email` and fills it from the account's live e-mail identity when it answers ([center identity](center-identity.md#command-receipts)).
Receipt results do hold personal data:

- UpdateProfile's: the profile (display name, locale, time zone, revision);
- CompletePasskeyRegistration's and RenameAuthIdentity's: a credential summary (credential ID, kind, label, creation and last-use
  times);
- DeviceService.Rename's: the full device view (device ID, name, platform, trust level, remote-control flag, revision, revocation
  time, and each installed product with its version and install time);
- RemoveAuthIdentity's, RevokeSession's, RevokeAllSessions' and DeviceService.Revoke's: only the receipt (command ID, effect and
  the revision it produced, except RevokeAllSessions, which states none);
- a kept refusal: its `ArcError`, which can name the object the caller sent or, for `already_exists`, the account's own
  credential row ID.

They are a second copy under the receipts' own 90-day retention (above), separate from the account's, and the runtime role cannot
delete them, so AF-ID-02's account purge deletes `platform.command_receipt` rows by principal (the account) with the account.

### Entitlement (AF-CTR-03 B)

The third migration (`center/internal/schema/migrations/0003_entitlement.sql`, sha256
`8eaca09b91e57abc9514c70ced246f965b31f9a2bf898fdb9dabadb2bd7c3f9d`) creates the `entitlement` schema and `identity.operator`; the
logic is described in [center entitlement](center-entitlement.md). Its tables, the runtime role's privileges and who writes them:

- `entitlement.grant`, `revocation`, `service_term`, `definitions_activation`: append-only. A trigger refuses UPDATE and DELETE, and
  the runtime role has SELECT and INSERT only. The runtime writes grants, revocations and definitions activations (the entitlement
  service) and service terms (the operator grant's compensation term). Enums are 1-based `smallint` values (the 0002 convention),
  a grant's value is canonical JSON checked against its kind (`grant_value_shape`, with `COALESCE` so that a missing key cannot pass
  as NULL), and `grant_source_ref_once` makes a source reference unique per account and source (the idempotency of an issue).
- `entitlement.service_term_action`, `account_status_fact`, `feature_release`: append-only records the resolver reads. The runtime
  role has SELECT only: their writers (commerce, trust and safety, configuration) are later tasks, and a term, a status fact or a
  release must refresh the account's snapshot in the same unit when it is written.
- `entitlement.revision` (one row per account, advancing by exactly one: a trigger refuses any other change) and
  `entitlement.snapshot` (the derived snapshot, whose `content` is the canonical text the gate parses): rewritten in place by the
  runtime role (SELECT, INSERT, UPDATE). They are rebuildable from the records and may be dropped at any time; the next read
  recomputes the snapshot (`Service.VerifyRebuild` compares the two).
- `identity.operator`: the operator role. The migration role writes it (`arcforges-center admin grant-operator`, `revoke-operator`);
  a trigger lets a row change only by being revoked once; the runtime role reads it.

Every foreign key has an index (`TestEveryEntitlementForeignKeyHasAnIndex`), and the migration is rehearsed whole over version 2
with the production step (`TestMigration0003LandsWholeOverVersion2`). The hosted deployment applies it to `neondb` while production
is dark: the tables exist and stay empty.

Personal data: `account_id` ties every row to a person. `issued_by_actor` holds an actor reference (`account:<uuid>`,
`operator:<uuid>`, `operator:cli`), `source_ref` an opaque reference (a ticket or incident), and a grant's `reason` and
`identity.operator.reason` an operator's free text of up to 512 characters without control characters. The reason texts can name
people, so AF-PLAT-01's and AF-ID-02's erasure of an account must decide them. No row holds an e-mail address, a credential or a
token, and the audit events of the operator grant hold only the length and the SHA-256 of a reason. Retention: the records are the
audit trail of what an account was entitled to and are kept; the append-only triggers refuse deletion until a retention decision
(AF-PLAT-01, H-07) adds its own migration. The snapshot may be dropped at any time. Command receipts of the operator grant
(`center.operatorGrant`) hold the granted keys, the ids and the expiry, under the receipts' own retention.

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
  - The digest covers the request bytes as transmitted without `RequestMeta.correlation_id`, which is per attempt
    (`RequestDigestInput`): the message is walked on the wire and every kept byte is copied, never re-encoded (AD-0021 §10), so a
    retry under a new correlation id replays the receipt and any other difference (`command_id`, `expected_rev`, the body) is
    refused.
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
- a read-write transaction whose COMMIT was sent without a definite answer (a lost connection, a timeout, a cancellation, the
  pooler's `08P01`: anything but a class 40 or 23 refusal or a transaction that had failed) is never retried. When it carries the
  call's effect (a sign-in, the owner bootstrap, a refresh rotation, a flow's creation or its code's send, a step-up's begin or
  proof, a passkey registration's begin, every write under a command receipt, and each effect write a later slice adds) it is
  `ErrCommitUnknown`: it may have committed, and the identity surface answers `INTERNAL/internal` with effect `UNKNOWN` and retry
  `NEVER`. A transaction that carries no effect of the call (`TxOptions.Auxiliary`: rate-limit counts, reservations and
  give-backs, the attempt count, end and give-back of a flow, a step-up challenge or a registration, a step-up challenge's denial,
  refusal audits) runs before the effect or after its definite rollback, so its unanswered COMMIT is `ErrUnavailable`, answered
  `RESOURCE/overloaded` with `AFTER_TIME` and logged as one warning line with the call's correlation id (D10). A later slice's own
  counts, reservations, attempt bookkeeping and refusal audits set `Auxiliary`; the identity surface's roles are pinned by name
  (`TestEveryTransactionOfTheSurfaceStatesItsRole`);
- a panic in a transaction's callback rolls the transaction back and gives its connection back before it continues (D1);
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

The integration tests run every migration as a migration role that is not a superuser and has only `CREATEROLE` and `CREATEDB`,
as Neon's owner role. `TestMigration0002LandsWholeOverVersion1` rehearses the production step of 0002: over a database at version 1
the runner applies it and reconciles the grants; when it fails at its last statement, the database stays at version 1 with
nothing of it.

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
    differ, because the revocation would lock that role out. The remedy is to point `NEON_DATABASE_URL` at the migration
    (owner) role, as recorded, or for the owner to decide otherwise ([Deployment](#deployment)). The live
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
- If this database's record has no row for the live version's slot (the acceptance database was recreated, a restore
  rewound the record, or the target points at a new database), the confirmation exits with status 4 and the slot cannot be
  confirmed. The live login role and its password may still exist cluster-wide, because roles are not part of a database
  restore. The job log says so, and the other slot is rotated, without retries and without the post-promotion recovery
  text.
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

**How the secret reaches the server.** Neither the password nor a verifier appears in statement text or in a bind parameter:

- **Taking the role row.** In the rotation's transaction, a secret-free top-level statement takes the login role's catalog
  row: `CREATE ROLE <login> WITH LOGIN INHERIT CONNECTION LIMIT 16`, or the same `ALTER ROLE` for an existing role.
  - `SET LOCAL lock_timeout` (10 s) comes just before it. A session holding that row makes the rotation fail cleanly here,
    before any secret is involved, and a lock-wait message names only this statement.
  - The timeout bounds how long a blocked rotation holds the migration lock. Its value does not matter for confidentiality,
    because the nested password statement cannot wait.
- **Loading the secret.** It goes into a temporary table (`ON COMMIT DROP`) with binary `COPY FROM STDIN`, so the value travels
  in CopyData messages.
- **Setting the password.** A temporary PL/pgSQL function reads the secret from that table and runs only
  `ALTER ROLE %I PASSWORD %L` with `EXECUTE`, on the row this transaction already took, so it never waits on a lock.
  - The call is `SELECT pg_temp.arcforges_set_login($1)`, with the role name as its only argument.
  - The function sets `debug_print_parse`, `debug_print_rewritten` and `debug_print_plan` off for its own execution. These are
    user-settable, and without this a parse or rewrite dump of the nested statement, secret included, reaches the log
    (observed on PostgreSQL 18.4).
  - Its `EXCEPTION WHEN OTHERS OR query_canceled` handler re-raises with the SQLSTATE and the fixed message
    `login role update failed`, so a caught error never quotes the nested statement, to the client or to the log.
  - A LOG or WARNING message emitted while the nested statement runs carries it as context. The known emitters are
    removed:
    - the function's `SET` clauses switch `debug_print_*` off;
    - `password_encryption` is set to `scram-sha-256`. With `md5`, which the owner can set per session, role or database,
      PostgreSQL 18 logs an MD5 deprecation warning with the statement, plaintext included (observed on 18.4);
    - the secret-free statement taken first leaves no lock wait inside `EXECUTE`.
  - **The remaining class.** Any other WARNING that the nested `ALTER ROLE` raises carries the statement as context: a
    password-check hook such as credcheck, or a future deprecation. The migration role cannot change `log_min_messages`; the
    rotation records it. Operators must not install such hooks on a center database.
- **What records statements.** The rotation reads the settings of every tool that can capture statements run inside
  functions. It records them in its output (`logging`), and `migrate` records them in the gate record. The decision table
  (`migrate.Logging.CaptureRefusal`, unit-tested):
  - `pg_stat_statements.track = 'all'` would record the nested statement, so it is refused. `top` (the default, which only a
    superuser can change), `none` and an unloaded module record top-level statements only: the `COPY`, the function's
    definition and the call.
  - `pg_stat_monitor.pgsm_track = 'all'` is refused for the same reason; `top` and an unloaded module proceed.
  - `log_parser_stats = on` is refused: it logs parser statistics with the nested statement as context (observed on
    PostgreSQL 18.4), and only a superuser can switch it off.
  - `pgaudit.log` (Neon's HIPAA audit option uses pgaudit) is recorded, not refused.
    - pgaudit audits nested utility statements too: its ProcessUtility hook handles `context <= PROCESS_UTILITY_QUERY` and
      keeps the nested query string.
    - But its `log_audit_event` replaces every character after the first `password` token with `<REDACTED>` for
      `T_CreateRoleStmt` and `T_AlterRoleStmt`, by statement type and whatever the nesting.
    - This is in `pgaudit.c` at the tags Neon builds: 16.1, lines 556–602 (hook 1546–1584); 17.1, lines 612–659 (hook
      1611–1649); and the current 18 tag, 18.0, lines 615–663 (hook 1638–1676).
    - Neon's compute Dockerfile at `fa50421` builds 16.1 and 17.1, and its `pgaudit-parallel_workers` patches do not touch
      redaction.
    - The secret follows the `PASSWORD` keyword, so it always lies after the first `password` token and inside the redacted
      part, whatever the role name.
  - `auto_explain.log_min_duration` and `auto_explain.log_nested_statements` are recorded, not refused. auto_explain hooks
    only the executor (`contrib/auto_explain/auto_explain.c`, `REL_18_STABLE`, lines 251–258), which a role statement never
    reaches; nested logging shows only the function's secret-free `SELECT`. Neon's extension list does not name auto_explain.
  - `log_lock_waits`, `log_error_verbosity`, `log_min_messages` and `debug_print_*` are recorded, not refused. The nested
    statement waits on no lock, and `debug_print_*` are off inside the function. Neither `log_min_messages` at `debug5` nor
    the other `*_stats` settings put the nested statement into the log (observed).
  - `log_statement` and `log_min_duration_statement` are recorded, not refused: a logged statement text (`all` or `mod`, or a
    duration line with its parameters) holds no secret.
- **What remains.** A cancellation or termination during the nested statement can still log it as context. A termination
  (`pg_terminate_backend`, `transaction_timeout`) is uncatchable, and a caught cancellation is re-raised. But either aborts the
  rotation's transaction, so the logged value is never a working credential:
  - the role keeps its old password;
  - Neon's DDL forwarding, which runs at pre-commit, never fires;
  - no secret file is written;
  - the next rotation draws a new password.
- **Tests.** They run on PostgreSQL 18.4 with `pg_stat_statements` preloaded, `log_statement = 'all'` and
  `log_min_duration_statement = 0`, and check that:
  - no `pg_stat_statements` row and no server log line holds the password or the verifier;
  - with `debug_print_parse` and `debug_print_rewritten` on, no parse dump holds the secret (a control function without the
    `SET` clauses leaks);
  - a session holding the login role's row fails the rotation with `55P03` on the secret-free statement, and neither the
    error nor the logged lock wait holds the secret;
  - a cancelled password statement (`statement_timeout`) and a forced failure report `login role update failed` with no
    context holding the secret (a control without the handler leaks);
  - `track = 'all'` and `log_parser_stats = on` refuse the rotation.

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
     would lock that role out (the remedy: point `NEON_DATABASE_URL` at the migration role, or the owner decides otherwise); an
     absent variable is skipped and recorded. Acceptance, which has
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
  production). Its catalogue is the embedded illustrative one (no price is approved), so a gated feature is available to an account only through an operator grant ([center entitlement](center-entitlement.md)). The public base URL is
  `https://proof.arcforges.com/api`.
- **Its database:** its own database `arcforges_acceptance` in the same Neon project, created idempotently by
  `admin ensure-database` through the migration role's direct connection, with its own runtime role
  `arcforges_acceptance_runtime`. Neither environment's credential reaches the other's database.
- **Its growth counts against production:** the acceptance database shares the production Neon project, branch and compute, so its
  storage and connections count against production's. Its public identity surface (AF-CTR-03) writes flows, rate-limit windows and
  audit events that nothing deletes until AF-PLAT-01's sweeps exist. The opt-in anonymous-flow ceiling of its identity policy (600
  flows per hour, [identity policy](center-identity.md#identity-policy)) bounds the flows and the failure rows and markers that need
  a flow, not the prefix-keyed request and bootstrap buckets (one row per distinct client /24 or /56) or the once-per-window refusal
  audits, which grow with distinct prefixes and with prefixes times windows until the sweeps. Production sets no ceiling. The owner
  can drop `arcforges_acceptance` at any time; the next acceptance deployment recreates and migrates it.
- **The deployment job:** after the retained D1 gate, `node tooling/postgres-deploy.ts migrate --target acceptance` ensures the
  database and migrates it. `npm run deploy:proof` then detaches the retired C# queue consumers (below), rotates the acceptance
  credential and deploys the sealed acceptance bundle.
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
  - The C# proof routes, its static profile assets and its R2 bucket are no longer bound and stay as they are. Their sources and
    historical evidence stay until AF-CTR-09.
  - The queue `arcforges-proof-wake` and its dead-letter queue `arcforges-proof-wake-dlq` stay, unconsumed, until AF-CTR-09,
    with whatever messages they hold (transient container wake signals, not user data). The retired C# bundle consumed both,
    and Cloudflare refuses to upload a script that a queue still names as its consumer when the script has no `queue` handler
    (code 11001). Before the credential rotation and the upload, `npm run deploy:proof` therefore detaches the proof script's
    consumers of exactly these two queues, leaving every other consumer alone, and prints and records `detached` or
    `not attached` for each (`retiredQueueConsumers` in `artifacts/proof-deployment.json`). The consumer's own settings (six
    retries, dead-lettering into `arcforges-proof-wake-dlq`) go with it. It never deletes a queue or a message: messages left in
    the queues are no longer delivered and expire under each queue's own retention setting. A rerun finds `not attached` and
    changes nothing.
  - Once the consumers are detached, a later failure in the credential rotation or in `wrangler deploy` leaves the still-live C#
    proof Worker without its wake consumers. That is acceptable for the retired proof, and the next successful dispatch
    replaces that Worker.
  - Before it changes anything, the same step compares the live proof script with the generated proof configuration and refuses
    only what the deployment would leave in place undeclared:
    - a proof-script consumer of a queue that the configuration does not consume (consumers it declares, such as a later outbox
      sink, are Wrangler's to update);
    - a live cron schedule while the configuration declares no `triggers.crons` (declared crons replace every live schedule; the
      acceptance configuration declares none, and the proof never had a schedule);
    - a published Durable Object migration tag that the configuration does not list (it keeps `v1` and
      `harness-run-alarm-v1`).

    A configuration that consumes one of the two retired queues again is refused too. The step records the schedule count and
    the tag beside the consumers. It reads the queue list by the provider's paging details (`total_pages`, else `total_count`),
    at most 20 pages. An unreadable answer or a failed removal stops the deployment before Wrangler runs. Removing a consumer
    needs the deployment token's Queues write permission; adding it is the owner's action.

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

The identity surface (AF-CTR-03) keeps the runtime pool at four. Its calls hold short transactions only: a rate-limit count and a
flow attempt are each their own transaction before the work, no transaction is open while PBKDF2, WebAuthn or the mail provider
runs, and a success transaction ends with its audit event; the per-call counts are in
[accounts, sessions and devices](center-identity.md#transactions-per-request). The owner bootstrap's creating transaction takes a
transaction-scoped advisory lock (`pg_advisory_xact_lock`), which the transaction pooler admits.

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
- **Identity surface** (AF-CTR-03): `arcforges_center_identity_events_total{event,outcome}` counts sign-in stages
  (`sign_in_begin` by method, `sign_in_complete` succeeded or refused), refreshes (rotated, refused, reused), rate-limit refusals
  by bucket kind (`rate_limited`), bootstrap outcomes, e-mail code requests (`email_request` accepted) and e-mail deliveries
  (`email_send` sent or failed); since A1b also step-up stages (`step_up_begin` by method; `step_up_complete` proved, refused or
  upgraded, where `upgraded` is counted in addition to `proved`) and passkey registration (`registration_begin`;
  `registration_complete` succeeded or refused). The periodic metrics log line carries them.
- **Unanswered auxiliary commits** (D10): a transaction of auxiliary bookkeeping (a count, an attempt, a reservation, a denial, a
  give-back, a refusal audit) whose COMMIT went unanswered is answered `RESOURCE/overloaded` and logged as the WARN line
  `an auxiliary commit went unanswered`, with the method, the correlation id and the transaction's name (`operation`).

Alert conditions for AF-OPS-01:

- `store not ready` after a deployment, or readiness `unavailable` for more than 5 minutes;
- `arcforges_center_db_schema_version{source="database"}` below `{source="build"}`;
- waited acquires growing faster than acquires (a pool at its bound);
- a failed migration or rotation step of the deployment job;
- dead-lettered outbox rows or jobs (`state = 3` in `platform.outbox`, `state = 4` in `platform.job_lease`). This needs a
  metric of AF-PLAT-01's sweeps; until then it is a query.
- identity: any `refresh` `reused` (a stolen or replayed refresh token), `rate_limited` growing for one bucket kind (an attack
  or a misconfigured client), `bootstrap` outcomes other than `completed` on a deployment that has an owner, `email_send` `failed`,
  and `access.refused` audit events (a node, push or automation credential calling account methods);
- identity since A1b: `step_up_complete` `refused` growing without `rate_limited` for `sign_in_failures_account` following (a slow
  guessing of step-up proofs against one session that stays under the limit; `identity.step_up.failed` is audited only once per
  window), and `registration_complete` `refused` growing;
- the WARN line `an auxiliary commit went unanswered` recurring (the pooler or the network losing commits).

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
