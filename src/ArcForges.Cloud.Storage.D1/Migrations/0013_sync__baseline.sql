-- af-migration: module=sync mode=expand
-- Baseline physical schema of the sync owner (generated from Physical/manifest/sync.json; Design D1 profile section 2).
CREATE TABLE "sync_change" (
  "change_id" TEXT NOT NULL CONSTRAINT "ck_sync_change__change_id" CHECK (length("change_id") = 36 AND "change_id" GLOB '????????-????-????-????-????????????' AND "change_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_sync_change__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "aggregate_kind" TEXT NOT NULL,
  "aggregate_id" TEXT NOT NULL CONSTRAINT "ck_sync_change__aggregate_id" CHECK (length("aggregate_id") = 36 AND "aggregate_id" GLOB '????????-????-????-????-????????????' AND "aggregate_id" NOT GLOB '*[^0-9a-f-]*'),
  "aggregate_rev" INTEGER NOT NULL CONSTRAINT "ck_sync_change__aggregate_rev" CHECK ("aggregate_rev" >= 0),
  "change_kind" INTEGER NOT NULL CONSTRAINT "ck_sync_change__change_kind" CHECK ("change_kind" IN (1, 2)),
  "origin_kind" INTEGER NOT NULL CONSTRAINT "ck_sync_change__origin_kind" CHECK ("origin_kind" IN (1, 2)),
  "origin_device_id" TEXT CONSTRAINT "ck_sync_change__origin_device_id" CHECK (length("origin_device_id") = 36 AND "origin_device_id" GLOB '????????-????-????-????-????????????' AND "origin_device_id" NOT GLOB '*[^0-9a-f-]*'),
  "occurred_at" INTEGER NOT NULL,
  "publish_seq" INTEGER,
  "published_at" INTEGER,
  CONSTRAINT "pk_sync_change" PRIMARY KEY ("change_id"),
  CONSTRAINT "ck_sync_change__origin_device_agrees" CHECK (("origin_kind" = 1 AND "origin_device_id" IS NOT NULL) OR ("origin_kind" = 2 AND "origin_device_id" IS NULL))
) STRICT;

CREATE INDEX "ix_sync_change__workspace_id_publish_seq" ON "sync_change" ("workspace_id", "publish_seq") WHERE "publish_seq" IS NOT NULL;

CREATE INDEX "ix_sync_change__workspace_id_aggregate_kind_aggregate_id_aggregate_rev" ON "sync_change" ("workspace_id", "aggregate_kind", "aggregate_id", "aggregate_rev") WHERE "publish_seq" IS NULL;

CREATE UNIQUE INDEX "ux_sync_change__workspace_id_aggregate_kind_aggregate_id_aggregate_rev" ON "sync_change" ("workspace_id", "aggregate_kind", "aggregate_id", "aggregate_rev");

CREATE UNIQUE INDEX "ux_sync_change__workspace_id_publish_seq" ON "sync_change" ("workspace_id", "publish_seq");

CREATE TRIGGER "tr_sync_change__limited_update" BEFORE UPDATE ON "sync_change"
WHEN (OLD."change_id" IS NOT NEW."change_id" OR OLD."workspace_id" IS NOT NEW."workspace_id" OR OLD."aggregate_kind" IS NOT NEW."aggregate_kind" OR OLD."aggregate_id" IS NOT NEW."aggregate_id" OR OLD."aggregate_rev" IS NOT NEW."aggregate_rev" OR OLD."change_kind" IS NOT NEW."change_kind" OR OLD."origin_kind" IS NOT NEW."origin_kind" OR OLD."origin_device_id" IS NOT NEW."origin_device_id" OR OLD."occurred_at" IS NOT NEW."occurred_at") OR NOT (OLD."publish_seq" IS NULL)
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_sync_change');
END;

CREATE TABLE "sync_conflict" (
  "conflict_id" TEXT NOT NULL CONSTRAINT "ck_sync_conflict__conflict_id" CHECK (length("conflict_id") = 36 AND "conflict_id" GLOB '????????-????-????-????-????????????' AND "conflict_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_sync_conflict__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "aggregate_kind" TEXT NOT NULL,
  "aggregate_id" TEXT NOT NULL CONSTRAINT "ck_sync_conflict__aggregate_id" CHECK (length("aggregate_id") = 36 AND "aggregate_id" GLOB '????????-????-????-????-????????????' AND "aggregate_id" NOT GLOB '*[^0-9a-f-]*'),
  "base_rev" INTEGER NOT NULL CONSTRAINT "ck_sync_conflict__base_rev" CHECK ("base_rev" >= 0),
  "current_rev" INTEGER NOT NULL CONSTRAINT "ck_sync_conflict__current_rev" CHECK ("current_rev" >= 0),
  "incoming_hash" BLOB NOT NULL CONSTRAINT "ck_sync_conflict__incoming_hash" CHECK (length("incoming_hash") = 32),
  "retained_version_ref" TEXT NOT NULL CONSTRAINT "ck_sync_conflict__retained_version_ref" CHECK (length("retained_version_ref") = 36 AND "retained_version_ref" GLOB '????????-????-????-????-????????????' AND "retained_version_ref" NOT GLOB '*[^0-9a-f-]*'),
  "policy_version" TEXT NOT NULL,
  "state" INTEGER NOT NULL CONSTRAINT "ck_sync_conflict__state" CHECK ("state" IN (1, 2)),
  "resolution" TEXT CONSTRAINT "ck_sync_conflict__resolution" CHECK (length("resolution") BETWEEN 1 AND 128 AND "resolution" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "created_at" INTEGER NOT NULL,
  "resolved_at" INTEGER,
  "resolution_command_id" TEXT CONSTRAINT "ck_sync_conflict__resolution_command_id" CHECK (length("resolution_command_id") = 36 AND "resolution_command_id" GLOB '????????-????-????-????-????????????' AND "resolution_command_id" NOT GLOB '*[^0-9a-f-]*'),
  "rev" INTEGER NOT NULL CONSTRAINT "ck_sync_conflict__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_sync_conflict" PRIMARY KEY ("conflict_id")
) STRICT;

CREATE UNIQUE INDEX "ux_sync_conflict__resolution_command_id" ON "sync_conflict" ("resolution_command_id");

CREATE INDEX "ix_sync_conflict__workspace_id_state_created_at" ON "sync_conflict" ("workspace_id", "state", "created_at");

CREATE TABLE "sync_publication_watermark" (
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_sync_publication_watermark__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "last_seq" INTEGER NOT NULL,
  "last_aggregate_key" TEXT,
  "holder_instance" TEXT,
  "fence_token" INTEGER NOT NULL,
  "lease_expires_at" INTEGER,
  "updated_at" INTEGER NOT NULL,
  CONSTRAINT "pk_sync_publication_watermark" PRIMARY KEY ("workspace_id")
) STRICT;

CREATE TRIGGER "tr_sync_publication_watermark__monotonic_last_seq" BEFORE UPDATE OF "last_seq" ON "sync_publication_watermark"
WHEN NEW."last_seq" < OLD."last_seq"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_monotonic_sync_publication_watermark_last_seq');
END;

CREATE TRIGGER "tr_sync_publication_watermark__monotonic_fence_token" BEFORE UPDATE OF "fence_token" ON "sync_publication_watermark"
WHEN NEW."fence_token" < OLD."fence_token"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_monotonic_sync_publication_watermark_fence_token');
END;

CREATE TABLE "sync_sync_scope" (
  "sync_scope_id" TEXT NOT NULL CONSTRAINT "ck_sync_sync_scope__sync_scope_id" CHECK (length("sync_scope_id") = 36 AND "sync_scope_id" GLOB '????????-????-????-????-????????????' AND "sync_scope_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_sync_sync_scope__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "product_id" TEXT NOT NULL CONSTRAINT "ck_sync_sync_scope__product_id" CHECK ("product_id" IN ('arcscope', 'companion')),
  "scope_kind" TEXT NOT NULL,
  "scope_ref" TEXT CONSTRAINT "ck_sync_sync_scope__scope_ref" CHECK (length("scope_ref") = 36 AND "scope_ref" GLOB '????????-????-????-????-????????????' AND "scope_ref" NOT GLOB '*[^0-9a-f-]*'),
  "enabled" INTEGER NOT NULL CONSTRAINT "ck_sync_sync_scope__enabled" CHECK ("enabled" IN (0, 1)),
  "content_exclusions" TEXT NOT NULL CONSTRAINT "ck_sync_sync_scope__content_exclusions" CHECK (json_valid("content_exclusions")),
  "rev" INTEGER NOT NULL CONSTRAINT "ck_sync_sync_scope__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_sync_sync_scope" PRIMARY KEY ("sync_scope_id")
) STRICT;

CREATE UNIQUE INDEX "ux_sync_sync_scope__workspace_id_product_id_scope_kind_scope_ref" ON "sync_sync_scope" ("workspace_id", "product_id", "scope_kind", "scope_ref");

CREATE TABLE "sync_tombstone" (
  "aggregate_kind" TEXT NOT NULL,
  "aggregate_id" TEXT NOT NULL CONSTRAINT "ck_sync_tombstone__aggregate_id" CHECK (length("aggregate_id") = 36 AND "aggregate_id" GLOB '????????-????-????-????-????????????' AND "aggregate_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_sync_tombstone__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "deleted_at" INTEGER NOT NULL,
  "deleted_by_device_id" TEXT CONSTRAINT "ck_sync_tombstone__deleted_by_device_id" CHECK (length("deleted_by_device_id") = 36 AND "deleted_by_device_id" GLOB '????????-????-????-????-????????????' AND "deleted_by_device_id" NOT GLOB '*[^0-9a-f-]*'),
  "retain_until" INTEGER NOT NULL,
  CONSTRAINT "pk_sync_tombstone" PRIMARY KEY ("aggregate_kind", "aggregate_id")
) STRICT;

CREATE INDEX "ix_sync_tombstone__retain_until" ON "sync_tombstone" ("retain_until");
