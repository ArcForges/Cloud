-- af-migration: module=platform mode=expand
-- The publication sequence streams, the outbox positions and the change archive of every committed batch (CLOUD.04; Design model 01 section 2 and D1 profile sections 4 and 5; generated from Physical/manifest/platform.json).
CREATE TABLE "platform_sequence_stream" (
  "stream_key" TEXT NOT NULL CONSTRAINT "ck_platform_sequence_stream__stream_key" CHECK (length("stream_key") BETWEEN 1 AND 128 AND "stream_key" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "last_sequence" INTEGER NOT NULL,
  "published_watermark" INTEGER NOT NULL,
  "publish_rev" INTEGER NOT NULL CONSTRAINT "ck_platform_sequence_stream__publish_rev" CHECK ("publish_rev" >= 0),
  "fence" INTEGER NOT NULL,
  "ack_receipt" TEXT,
  "updated_at" INTEGER NOT NULL,
  CONSTRAINT "pk_platform_sequence_stream" PRIMARY KEY ("stream_key"),
  CONSTRAINT "ck_platform_sequence_stream__watermark_within_allocation" CHECK ("last_sequence" >= 0 AND "published_watermark" >= 0 AND "published_watermark" <= "last_sequence" AND "fence" >= 0)
) STRICT;

CREATE TRIGGER "tr_platform_sequence_stream__immutable_delete" BEFORE DELETE ON "platform_sequence_stream"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_platform_sequence_stream');
END;

CREATE TRIGGER "tr_platform_sequence_stream__monotonic_last_sequence" BEFORE UPDATE OF "last_sequence" ON "platform_sequence_stream"
WHEN NEW."last_sequence" < OLD."last_sequence"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_monotonic_platform_sequence_stream_last_sequence');
END;

CREATE TRIGGER "tr_platform_sequence_stream__monotonic_published_watermark" BEFORE UPDATE OF "published_watermark" ON "platform_sequence_stream"
WHEN NEW."published_watermark" < OLD."published_watermark"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_monotonic_platform_sequence_stream_published_watermark');
END;

CREATE TRIGGER "tr_platform_sequence_stream__monotonic_fence" BEFORE UPDATE OF "fence" ON "platform_sequence_stream"
WHEN NEW."fence" < OLD."fence"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_monotonic_platform_sequence_stream_fence');
END;

CREATE TABLE "platform_outbox_position" (
  "outbox_id" TEXT NOT NULL CONSTRAINT "ck_platform_outbox_position__outbox_id" CHECK (length("outbox_id") = 36 AND "outbox_id" GLOB '????????-????-????-????-????????????' AND "outbox_id" NOT GLOB '*[^0-9a-f-]*'),
  "stream_key" TEXT NOT NULL CONSTRAINT "ck_platform_outbox_position__stream_key" CHECK (length("stream_key") BETWEEN 1 AND 128 AND "stream_key" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "sequence" INTEGER NOT NULL,
  CONSTRAINT "pk_platform_outbox_position" PRIMARY KEY ("outbox_id"),
  CONSTRAINT "fk_platform_outbox_position__outbox_id" FOREIGN KEY ("outbox_id") REFERENCES "platform_outbox" ("outbox_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_platform_outbox_position__stream_key" FOREIGN KEY ("stream_key") REFERENCES "platform_sequence_stream" ("stream_key") ON DELETE RESTRICT,
  CONSTRAINT "ck_platform_outbox_position__sequence_positive" CHECK ("sequence" >= 1),
  CONSTRAINT "ck_platform_outbox_position__owner_stream" CHECK ("stream_key" NOT GLOB 'platform:*')
) STRICT;

CREATE UNIQUE INDEX "ux_platform_outbox_position__stream_key_sequence" ON "platform_outbox_position" ("stream_key", "sequence");

CREATE TRIGGER "tr_platform_outbox_position__immutable_update" BEFORE UPDATE ON "platform_outbox_position"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_platform_outbox_position');
END;

CREATE TABLE "platform_change_archive" (
  "archive_sequence" INTEGER NOT NULL,
  "command_id" TEXT NOT NULL CONSTRAINT "ck_platform_change_archive__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  "schema_version" INTEGER NOT NULL,
  "record" TEXT NOT NULL CONSTRAINT "ck_platform_change_archive__record" CHECK (CASE WHEN json_valid("record") THEN json_type("record") = 'object' ELSE 0 END),
  "record_hash" BLOB NOT NULL CONSTRAINT "ck_platform_change_archive__record_hash" CHECK (length("record_hash") = 32),
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_platform_change_archive" PRIMARY KEY ("archive_sequence"),
  CONSTRAINT "ck_platform_change_archive__positive" CHECK ("archive_sequence" >= 1 AND "schema_version" >= 0),
  CONSTRAINT "ck_platform_change_archive__record_bounded" CHECK (length(CAST("record" AS BLOB)) <= 65536)
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX "ux_platform_change_archive__command_id" ON "platform_change_archive" ("command_id");

CREATE TRIGGER "tr_platform_change_archive__immutable_update" BEFORE UPDATE ON "platform_change_archive"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_platform_change_archive');
END;
