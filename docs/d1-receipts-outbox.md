# Receipts, outbox, inbox dedup and change archive

This document describes what CLOUD.04 (Design WP-21.04) delivers, the checks that enforce it, what each check proves and what it does not. The binding rules are the Design
[D1 execution profile](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/architecture/data-model/04-d1-execution-profile.md) (the commit tail in section 4,
publication in section 5, the change archive in section 7) and the
[Cloud data model](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/architecture/data-model/01-cloud-data-model.md) (section 2, the platform records). Plans and
module boundaries are described in [storage plans](storage-plans.md), the physical schema in [D1 physical schema](d1-physical-schema.md).

## Decision in one sentence

Every guarded write of a module ends with one fixed, generator-verified tail of statements, so its owner receipt, its outbox rows, its change-archive row and (for a consumer)
its inbox claim commit in the same D1 batch as the effect or not at all; publication then advances over those rows only contiguously, under a guard.

## What exists

| Path                                                                                                                            | Content                                                                                                                                                                                                                                                                            |
| ------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `eng/verification/commit-tail.ts`                                                                                               | The one definition of the commit tail (statements, parameter kinds, the plan header that declares it, the verification) and the shared vector writer.                                                                                                                              |
| `eng/verification/storage-plans.ts`                                                                                             | The plan generator: a module write plan declares `-- tail: v1 [events=N] [inbox]` or `-- tail: none <reason>`, and a declared tail is verified statement by statement.                                                                                                             |
| `storage/plans/platform/*.sql`                                                                                                  | The platform owner's 16 named plans over `platform_` tables only: receipt, inbox, stream state, fence, outbox select, acknowledgement, attempt, dead letter, requeue, archive state, select, acknowledgement and purge, and the outbox purge.                                      |
| `src/ArcForges.Cloud.Storage.D1/Migrations/0023_platform__commit-tail.sql`                                                      | Three new records (one expand migration, generated from `Physical/manifest/platform.json`): `platform_sequence_stream`, `platform_outbox_position`, `platform_change_archive`. The guard table `platform_command_guard` (migration 0022) is the guarded-batch engine's (CLOUD.06). |
| `src/ArcForges.Cloud.Storage.D1/Receipts/`                                                                                      | The tail builder (`CommitTail`), command receipts and their replay rules, the inbox, and the executor that reconciles every non-success with the receipt (`CommitExecutor`).                                                                                                       |
| `src/ArcForges.Cloud.Storage.D1/Outbox/`                                                                                        | The outbox event, the stream state and the contiguous publisher (`OutboxPublisher`).                                                                                                                                                                                               |
| `src/ArcForges.Cloud.Storage.D1/Archive/`                                                                                       | The change record with its SHA-256 and the reader that verifies and acknowledges the archive (`ChangeArchiveReader`).                                                                                                                                                              |
| `tests/worker/commit-tail.test.ts`, `tests/worker/d1-receipts.test.ts`, `tests/ArcForges.Cloud.Tests/{Receipts,Outbox,Archive}` | The generator rule, the SQLite oracle scenarios and the host-side unit tests; `tests/ArcForges.Cloud.Tests/Vectors/commit-tail.json` is shared by the generator and the C# builder.                                                                                                |
| `eng/verification/d1-receipts-local.ts`                                                                                         | The explicit opt-in run against workerd's D1 (`npm run test:d1:receipts:local`).                                                                                                                                                                                                   |

The host does not use any of this yet: no module owns a plan that carries the tail and nothing in the host composition calls the publisher. They are the mechanism that
COM.16, CLOUD.06's families, CLOUD.31, CLOUD.39 and every module task use.

## The commit tail

A module write plan has one shape: one or more guard inserts (`INSERT INTO platform_command_guard (command_id, guard_key, allowed)` with a literal guard key, whose value is 1 only when the
guard's predicates hold, so a false predicate violates the constraint `af_guard_failed` and the whole batch rolls back), the module's own mutations, the tail and the guard release. The guard
table and the generated guard primitives are the guarded-batch engine's (CLOUD.06); the tail only follows the guards. The tail, in order:

1. optional inbox claim: `INSERT INTO platform_inbox` with outcome `applied`;
2. the receipt: `INSERT INTO platform_command` with status `succeeded`, the original response and the resulting revision (`-1` is bound for none and stored as NULL);
3. for each outbox event, three statements: the stream allocation upsert (`last_sequence + 1`), the `platform_outbox` insert (state `pending`, no attempts) and the `platform_outbox_position` insert
   that reads the allocated value;
4. the change-archive allocation upsert on the stream `platform:change-archive` and the `platform_change_archive` insert;

and the plan's last statement is the release (`DELETE FROM platform_command_guard WHERE command_id = ?`), which is not part of the tail so that a family plan can generate it.

`node eng/verification/commit-tail.ts print --events 2 [--inbox]` prints the canonical blocks to paste into a plan. The generator refuses a module write plan with no header, a declared tail
that does not start with a guard insert, puts a guard after a mutation or has no own mutation, a tail statement that differs (whitespace aside) from the canonical text or its parameter kinds, and an own statement that
writes a table only the tail may write (`platform_command`, `platform_inbox`, `platform_outbox`, `platform_outbox_position`, `platform_sequence_stream`, `platform_change_archive`,
`platform_command_guard`). The outbox stream key is the owner scope of the call (the plan binds it as the `scope` kind, so a caller cannot name another scope); the `platform:` prefix is reserved
for the archive and the table refuses an outbox position there.

**What this gives.** A false guard, a duplicate command id, a duplicate inbox key, a malformed event payload and a malformed or oversized change record each end in a constraint violation, so
the receipt, the outbox rows, the archive row, the allocated sequences and the effect all roll back together. A zero-row compare-and-swap can never publish: the guard, not the affected-row count, decides.

## Receipts (`platform_command`)

`CommandReceipt` is written by the tail. `CommandReceiptStore.LoadAsync` reads one (`platform.command-load`) and `CommandReplay.Classify` applies the rules: no receipt is `NotSeen`; the same
fingerprint, actor, operation and workspace returns the original result (`Replay`, or `ReplayOfFailure` for a recorded refusal); any difference is `ReusedIdentifier` and reveals nothing of the
stored result; a receipt at or past `expires_at` is `Expired` and is never executed as a new command. `RecordFailureAsync` writes a definite refusal alone (status `failed`, its stable code).
`inProgress` is not used by an atomic family. The retention sweep and the compact owner-lifetime fence that outlive the response window are not part of this task.

`CommitExecutor` runs a tail-carrying plan and reconciles: a failed guard or a constraint reads the receipt (and the inbox) and returns `Replayed`, `ReusedIdentifier`, `ReceiptExpired`,
`DuplicateMessage` or, with no receipt, `GuardFailed` (a definite rollback; the caller rereads and recalculates under the same command id); an unknown outcome returns `Committed` when the receipt
exists and `Unknown` when it does not, in which case only the same command id may be sent again. A constraint with no receipt and no inbox row is a defect and is rethrown.

## Inbox

The inbox key is the producing system (`<producing system>/<handler>` when two handlers apply one message), the message id and the recovery generation (`InboxKey`: the stored `message_id` is `<message id>@<generation>`). The claim is part of the consumer's batch, so a
redelivery violates the primary key and changes nothing; the same message under a new generation after a restore applies again. `InboxStore` reads an entry and records a refused (poison) message
alone so that its redelivery is a no-op.

## Outbox publication

Every commit increments its stream's `last_sequence` in the same batch and writes the row's position with that value. Writes of one D1 database are serialized and a rolled-back batch releases its
increments, so the committed sequences of a stream are 1, 2, 3 and so on in commit order, without a gap. `OutboxPublisher`:

- `SelectAsync` reads the stream and the pending rows after the watermark, in pages of at most 50, and verifies them: a missing, repeated or out-of-order sequence, a dispatched row above the
  watermark, and allocated sequences that cannot be read throw `OutboxIntegrityException` (nothing is skipped); a dead-lettered row ends the selection and is reported as the blocker.
- `AcknowledgeAsync` is one guarded batch that marks exactly the selected range `dispatched` and advances the watermark under the guard of the watermark, the publish revision, the fence and a count that
  proves every row of the range exists and is still pending. The publish revision advances only on an acknowledgement or a fence change, so a commit of unrelated work does not invalidate a selection.
- A failed or lost acknowledgement is reconciled by rereading the stream (`Applied`, `Acknowledged`, `NotApplied`, `Superseded`); nothing is numbered or marked again.
- `RecordAttemptAsync`, `DeadLetterAsync`, `RequeueAsync` and `AdvanceFenceAsync` are guarded by the row, its attempts and the fence the caller read. The watermark never passes a dead-lettered row until it is requeued.

Delivery is at-least-once (OB-03): the Durable Object feed (WP-24.04) and the Sync publisher (WP-25.02) deliver the rows and then call the acknowledgement; each adds its own batch logic and
consumes these rows.

## Change archive

Every commit writes one `platform_change_archive` row (its sequence, the command, the schema version, the record JSON of at most 64 KiB and the SHA-256 of its UTF-8 bytes), never updated and purged only by its retention plan. `ChangeArchiveReader`
reads the contiguous records after the acknowledged watermark in byte-bounded pages (96 KiB, a window function in the plan), verifies each record's hash and sequence (`ArchiveIntegrityException` on a
gap, a repeat or a mismatch) and advances the watermark under the same kind of guard only with the independent storage's receipt. The copy to independent storage, the signed backup watermark and the
restore replay are the backup tasks (WP-46); this is the D1 side.

## What each check proves, and what it does not

- **Plan generator (hosted CI and locally):** the tail rule above, for every module plan from the first one on. It proves text and parameter kinds, not the module's own guard predicate, which review covers.
- **SQLite oracle (`tests/worker/d1-receipts.test.ts`, hosted CI and locally):** the real migrations and plans through the production executor: the receipt, outbox, inbox and archive rows of a commit,
  gapless sequences across failures and replays (including a seeded random interleaving of commits, stale writers, replays and publishers), constraint-guard rollback, zero-row CAS, duplicate command and
  inbox key, contention between publishers, lost acknowledgement, dead letter and requeue, fences, the append-only triggers and the byte-bounded archive pages. SQLite is not D1.
- **Host unit tests (`tests/ArcForges.Cloud.Tests/{Receipts,Outbox,Archive}`):** the tail kinds against the shared vectors, the arguments of every statement, the replay rules, the reconciliation of every
  failure kind, the publisher and reader against scripted answers. The double validates arguments against the plan definition exactly like the production executor; it does not run SQL.
- **workerd's D1 (opt-in, `npm run test:d1:receipts:local`):** the closest local engine. It applies the real migrations through the real runner and repeats the engine-dependent scenarios: batch atomicity,
  the guard's error classification, foreign keys, triggers, the window-function pages, blob binding and the largest tail (sixteen events plus the inbox claim, 55 statements) in one batch. It is not a
  Cloudflare provider result.
- **Not proven here (deferred live checks):** that the provider's REST and binding `batch` is one atomic transaction at production load, real D1 limits and latency for the largest tail, and the
  behaviour of the window function and the guard classification on the deployed service. They need the `RES-cloud-deployment` lease and a proof environment, never run in CI and print no secret.

## Limits stated

- **No module owns a tail-carrying plan yet** (COM.16 and the CLOUD.06 families are the first), and the module-facing exposure of the tail (a port in `ArcForges.Cloud.Modules.Abstractions`) belongs to
  COM.16's generic plan-execution port: a module project cannot reference `Storage.D1`.
- **The guard primitives of CLOUD.06** (revision, lease and balance predicates, the SU-04 order, the guard table) are not here: a module plan writes its own guard predicates until the engine's generated
  guards exist, and this task's own plans use the guard table the same way. The tail and the release are statement-for-statement what a family plan appends.
- **Retention sweeps are not scheduled here.** What exists: the inbox minimum (an inbox row expires at least 30 days after receipt, `InboxRetention`), the purge plans (`platform.outbox-purge`: positions at or below the acknowledged watermark, then their dispatched outbox rows past the cutoff, positions first so the foreign key never blocks; `platform.archive-purge`: change records at or below the acknowledged archive watermark past the dependent-backup cutoff the caller supplies) with `OutboxPublisher.PurgeAsync` and `ChangeArchiveReader.PurgeAsync`, and the append-only rule for every module plan (no module plan may write these tables; the table refuses updates). What is not: the scheduled sweeps of expired receipts and inbox rows, and the compact command fence (id, request hash, actor, operation) that must outlive the response window so `command.receipt_expired` stays answerable.

- **The payload bounds are enforced in C#**, not by a column: an outbox payload at most 4 KiB, a receipt response at most 128 KiB, a change record at most 64 KiB (also a table check). A plan that wrote a
  larger outbox payload through its own SQL would not be published (the page budget is 64 KiB), which is a stop, not a loss.
- **Job leases:** the finite-job lease and fence plans over `platform_job_lease` are not part of WP-21.04 and are not delivered here.
