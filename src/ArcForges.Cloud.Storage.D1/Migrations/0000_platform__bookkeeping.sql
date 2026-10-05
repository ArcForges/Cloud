-- af-migration: module=platform mode=expand
-- The migration bookkeeping tables (Design D1 profile section 6). The runner applies this file first, together with its own receipt.
CREATE TABLE "platform_backfill_checkpoint" (
  "sequence" INTEGER NOT NULL,
  "last_key" TEXT,
  "pages_done" INTEGER NOT NULL,
  "rows_converted" INTEGER NOT NULL,
  "rows_stale" INTEGER NOT NULL,
  "verified" INTEGER NOT NULL CONSTRAINT "ck_platform_backfill_checkpoint__verified" CHECK ("verified" IN (0, 1)),
  "updated_at" INTEGER NOT NULL,
  CONSTRAINT "pk_platform_backfill_checkpoint" PRIMARY KEY ("sequence"),
  CONSTRAINT "fk_platform_backfill_checkpoint__sequence" FOREIGN KEY ("sequence") REFERENCES "platform_migration_receipt" ("sequence") ON DELETE RESTRICT,
  CONSTRAINT "ck_platform_backfill_checkpoint__counters" CHECK ("pages_done" >= 0 AND "rows_converted" >= 0 AND "rows_stale" >= 0)
) STRICT, WITHOUT ROWID;

CREATE TRIGGER "tr_platform_backfill_checkpoint__immutable_delete" BEFORE DELETE ON "platform_backfill_checkpoint"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_platform_backfill_checkpoint');
END;

CREATE TABLE "platform_migration_receipt" (
  "sequence" INTEGER NOT NULL,
  "file_name" TEXT NOT NULL,
  "module" TEXT NOT NULL CONSTRAINT "ck_platform_migration_receipt__module" CHECK (length("module") BETWEEN 1 AND 128 AND "module" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "mode" INTEGER NOT NULL CONSTRAINT "ck_platform_migration_receipt__mode" CHECK ("mode" IN (1, 2, 3, 4)),
  "checksum" TEXT NOT NULL,
  "state" INTEGER NOT NULL CONSTRAINT "ck_platform_migration_receipt__state" CHECK ("state" IN (1, 2)),
  "statement_count" INTEGER NOT NULL CONSTRAINT "ck_platform_migration_receipt__statement_count" CHECK ("statement_count" BETWEEN -2147483648 AND 2147483647),
  "statements_done" INTEGER NOT NULL CONSTRAINT "ck_platform_migration_receipt__statements_done" CHECK ("statements_done" BETWEEN -2147483648 AND 2147483647),
  "runner" TEXT NOT NULL,
  "fence" INTEGER NOT NULL,
  "started_at" INTEGER NOT NULL,
  "applied_at" INTEGER,
  "compatibility" TEXT NOT NULL CONSTRAINT "ck_platform_migration_receipt__compatibility" CHECK (CASE WHEN json_valid("compatibility") THEN json_type("compatibility") = 'object' ELSE 0 END),
  CONSTRAINT "pk_platform_migration_receipt" PRIMARY KEY ("sequence"),
  CONSTRAINT "ck_platform_migration_receipt__sequence_nonnegative" CHECK ("sequence" >= 0),
  CONSTRAINT "ck_platform_migration_receipt__checksum_shape" CHECK (length("checksum") = 64 AND "checksum" NOT GLOB '*[^0-9a-f]*'),
  CONSTRAINT "ck_platform_migration_receipt__progress" CHECK ("statement_count" >= 0 AND "statements_done" >= 0 AND "statements_done" <= "statement_count"),
  CONSTRAINT "ck_platform_migration_receipt__applied_complete" CHECK ("state" <> 2 OR ("applied_at" IS NOT NULL AND "statements_done" = "statement_count"))
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX "ux_platform_migration_receipt__file_name" ON "platform_migration_receipt" ("file_name");

CREATE TRIGGER "tr_platform_migration_receipt__limited_update" BEFORE UPDATE ON "platform_migration_receipt"
WHEN (OLD."sequence" IS NOT NEW."sequence" OR OLD."file_name" IS NOT NEW."file_name" OR OLD."module" IS NOT NEW."module" OR OLD."mode" IS NOT NEW."mode" OR OLD."checksum" IS NOT NEW."checksum" OR OLD."statement_count" IS NOT NEW."statement_count" OR OLD."runner" IS NOT NEW."runner" OR OLD."started_at" IS NOT NEW."started_at" OR OLD."compatibility" IS NOT NEW."compatibility") OR NOT (OLD."state" = 1)
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_platform_migration_receipt');
END;

CREATE TRIGGER "tr_platform_migration_receipt__immutable_delete" BEFORE DELETE ON "platform_migration_receipt"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_platform_migration_receipt');
END;

CREATE TABLE "platform_schema_state" (
  "singleton" INTEGER NOT NULL CONSTRAINT "ck_platform_schema_state__singleton" CHECK ("singleton" BETWEEN -2147483648 AND 2147483647),
  "schema_version" INTEGER NOT NULL,
  "read_horizon" INTEGER NOT NULL,
  "write_horizon" INTEGER NOT NULL,
  "fence" INTEGER NOT NULL,
  "lease_holder" TEXT,
  "lease_expires_at" INTEGER,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_platform_schema_state__rev" CHECK ("rev" >= 0),
  "updated_at" INTEGER NOT NULL,
  CONSTRAINT "pk_platform_schema_state" PRIMARY KEY ("singleton"),
  CONSTRAINT "ck_platform_schema_state__single_row" CHECK ("singleton" = 1),
  CONSTRAINT "ck_platform_schema_state__horizons" CHECK ("read_horizon" >= 0 AND "write_horizon" >= "read_horizon" AND "schema_version" >= "write_horizon" AND "fence" >= 0),
  CONSTRAINT "ck_platform_schema_state__lease_pair" CHECK (("lease_holder" IS NULL) = ("lease_expires_at" IS NULL))
) STRICT, WITHOUT ROWID;

CREATE TRIGGER "tr_platform_schema_state__immutable_delete" BEFORE DELETE ON "platform_schema_state"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_platform_schema_state');
END;

CREATE TRIGGER "tr_platform_schema_state__monotonic_schema_version" BEFORE UPDATE OF "schema_version" ON "platform_schema_state"
WHEN NEW."schema_version" < OLD."schema_version"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_monotonic_platform_schema_state_schema_version');
END;

CREATE TRIGGER "tr_platform_schema_state__monotonic_fence" BEFORE UPDATE OF "fence" ON "platform_schema_state"
WHEN NEW."fence" < OLD."fence"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_monotonic_platform_schema_state_fence');
END;
