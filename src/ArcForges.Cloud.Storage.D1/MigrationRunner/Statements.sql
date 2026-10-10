-- SPDX-License-Identifier: AGPL-3.0-only
-- The D1 migration runner's own statements (CLOUD.84 U9, S42(1)). Each section is one statement or one fragment, named by the
-- line `-- name: <name>`. RunnerSql.Get loads a section by name from the embedded resource and fills its placeholders:
--   {guard}      the fence and lease guard (section guard), inserted as text
--   {applying}   the receipt state number of an applying migration (MigrationEngine.StateApplying)
--   {applied}    the receipt state number of an applied migration (MigrationEngine.StateApplied)
--   {extra}      and {finish} are supplied by the caller (see MigrationEngine.FenceGuardedProgress)
-- The `?` placeholders are bound positionally by the caller, in the order the engine lists them.

-- name: guard
EXISTS (SELECT 1 FROM platform_schema_state WHERE singleton = 1 AND fence = CAST(? AS INTEGER) AND lease_holder = ? AND lease_expires_at > CAST(? AS INTEGER))

-- name: table-exists
SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'platform_schema_state'

-- name: read-state
SELECT CAST(schema_version AS TEXT), CAST(read_horizon AS TEXT), CAST(write_horizon AS TEXT), CAST(fence AS TEXT), lease_holder, CAST(lease_expires_at AS TEXT) FROM platform_schema_state WHERE singleton = 1

-- name: read-receipts
SELECT CAST(sequence AS TEXT), file_name, checksum, state, statements_done, statement_count, CAST(applied_at AS TEXT) FROM platform_migration_receipt ORDER BY sequence

-- name: receipt-insert
INSERT INTO platform_migration_receipt (sequence, file_name, module, mode, checksum, state, statement_count, statements_done, runner, fence, started_at, applied_at, compatibility)
SELECT CAST(? AS INTEGER), ?, ?, ?, ?, {applying}, ?, 0, ?, CAST(? AS INTEGER), CAST(? AS INTEGER), NULL, ? WHERE {guard}

-- name: bootstrap-schema-state
INSERT INTO platform_schema_state (singleton, schema_version, read_horizon, write_horizon, fence, lease_holder, lease_expires_at, rev, updated_at) VALUES (1, 0, 0, 0, 1, ?, CAST(? AS INTEGER), 1, CAST(? AS INTEGER))

-- name: bootstrap-receipt
INSERT INTO platform_migration_receipt (sequence, file_name, module, mode, checksum, state, statement_count, statements_done, runner, fence, started_at, applied_at, compatibility)
VALUES (0, ?, ?, ?, ?, {applied}, ?, ?, ?, 1, CAST(? AS INTEGER), CAST(? AS INTEGER), ?)

-- name: acquire-lease
UPDATE platform_schema_state SET fence = fence + 1, lease_holder = ?, lease_expires_at = CAST(? AS INTEGER), rev = rev + 1, updated_at = CAST(? AS INTEGER)
WHERE singleton = 1 AND (lease_holder IS NULL OR lease_expires_at <= CAST(? AS INTEGER) OR lease_holder = ?)

-- name: release-lease
UPDATE platform_schema_state SET lease_holder = NULL, lease_expires_at = NULL, rev = rev + 1, updated_at = CAST(? AS INTEGER) WHERE singleton = 1 AND fence = CAST(? AS INTEGER) AND lease_holder = ?

-- name: progress
UPDATE platform_migration_receipt SET statements_done = CASE WHEN statements_done = CAST(? AS INTEGER) AND state = {applying} AND {guard}{extra} THEN CAST(? AS INTEGER) ELSE -1 END{finish} WHERE sequence = CAST(? AS INTEGER)

-- name: progress-finish
, state = {applied}, applied_at = CAST(? AS INTEGER)

-- name: renew-lease
UPDATE platform_schema_state SET lease_expires_at = CAST(? AS INTEGER) WHERE singleton = 1 AND fence = CAST(? AS INTEGER) AND lease_holder = ?

-- name: cutover-horizons
UPDATE platform_schema_state SET read_horizon = COALESCE(CAST(? AS INTEGER), read_horizon), write_horizon = COALESCE(CAST(? AS INTEGER), write_horizon), schema_version = CAST(? AS INTEGER), rev = rev + 1, updated_at = CAST(? AS INTEGER) WHERE singleton = 1 AND fence = CAST(? AS INTEGER)

-- name: schema-version
UPDATE platform_schema_state SET schema_version = CAST(? AS INTEGER), rev = rev + 1, updated_at = CAST(? AS INTEGER) WHERE singleton = 1 AND fence = CAST(? AS INTEGER)

-- name: checkpoint-verified-select
SELECT verified FROM platform_backfill_checkpoint WHERE sequence = CAST(? AS INTEGER)

-- name: checkpoint-state
SELECT last_key, CAST(rows_converted AS TEXT), CAST(rows_stale AS TEXT) FROM platform_backfill_checkpoint WHERE sequence = CAST(? AS INTEGER)

-- name: checkpoint-counts
SELECT CAST(rows_converted AS TEXT), CAST(rows_stale AS TEXT) FROM platform_backfill_checkpoint WHERE sequence = CAST(? AS INTEGER)

-- name: checkpoint-insert
INSERT INTO platform_backfill_checkpoint (sequence, last_key, pages_done, rows_converted, rows_stale, verified, updated_at)
SELECT CAST(? AS INTEGER), NULL, 0, 0, 0, 0, CAST(? AS INTEGER) WHERE {guard}

-- name: checkpoint-page
UPDATE platform_backfill_checkpoint SET pages_done = CASE WHEN COALESCE(last_key, '') = ? AND verified = 0 AND {guard} THEN pages_done + 1 ELSE -1 END, last_key = ?, updated_at = CAST(? AS INTEGER) WHERE sequence = CAST(? AS INTEGER)

-- name: checkpoint-counters
UPDATE platform_backfill_checkpoint SET rows_converted = rows_converted + changes(), rows_stale = rows_stale + (1 - changes()) WHERE sequence = CAST(? AS INTEGER)

-- name: checkpoint-restart
UPDATE platform_backfill_checkpoint SET pages_done = CASE WHEN {guard} THEN pages_done ELSE -1 END, last_key = NULL, updated_at = CAST(? AS INTEGER) WHERE sequence = CAST(? AS INTEGER)

-- name: checkpoint-verified
UPDATE platform_backfill_checkpoint SET verified = 1, updated_at = CAST(? AS INTEGER) WHERE sequence = CAST(? AS INTEGER)
