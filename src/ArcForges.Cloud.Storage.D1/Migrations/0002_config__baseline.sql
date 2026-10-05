-- af-migration: module=config mode=expand
-- Baseline physical schema of the config owner (generated from Physical/manifest/config.json; Design D1 profile section 2).
CREATE TABLE "config_revision" (
  "config_revision_id" TEXT NOT NULL CONSTRAINT "ck_config_revision__config_revision_id" CHECK (length("config_revision_id") = 36 AND "config_revision_id" GLOB '????????-????-????-????-????????????' AND "config_revision_id" NOT GLOB '*[^0-9a-f-]*'),
  "schema_version" TEXT NOT NULL,
  "revision_identity" TEXT NOT NULL,
  "content_hash" BLOB NOT NULL,
  "environment" TEXT NOT NULL,
  "realm_id" TEXT NOT NULL CONSTRAINT "ck_config_revision__realm_id" CHECK (length("realm_id") = 36 AND "realm_id" GLOB '????????-????-????-????-????????????' AND "realm_id" NOT GLOB '*[^0-9a-f-]*'),
  "effective_at" INTEGER NOT NULL,
  "activated_at" INTEGER,
  "state" INTEGER NOT NULL CONSTRAINT "ck_config_revision__state" CHECK ("state" IN (1, 2, 3, 4)),
  "document" TEXT NOT NULL CONSTRAINT "ck_config_revision__document" CHECK (json_valid("document")),
  CONSTRAINT "pk_config_revision" PRIMARY KEY ("config_revision_id"),
  CONSTRAINT "ck_config_revision__active_has_activated_at" CHECK ("state" <> 2 OR "activated_at" IS NOT NULL)
) STRICT;

CREATE UNIQUE INDEX "ux_config_revision__revision_identity" ON "config_revision" ("revision_identity");

CREATE UNIQUE INDEX "ux_config_revision__realm_id_state" ON "config_revision" ("realm_id", "state") WHERE "state" = 2;

CREATE TRIGGER "tr_config_revision__limited_update" BEFORE UPDATE ON "config_revision"
WHEN (OLD."revision_identity" IS NOT NEW."revision_identity")
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_config_revision');
END;
