-- af-migration: module=workspace mode=expand
-- Baseline physical schema of the workspace owner (generated from Physical/manifest/workspace.json; Design D1 profile section 2).
CREATE TABLE "workspace_data_deletion" (
  "deletion_id" TEXT NOT NULL CONSTRAINT "ck_workspace_data_deletion__deletion_id" CHECK (length("deletion_id") = 36 AND "deletion_id" GLOB '????????-????-????-????-????????????' AND "deletion_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_workspace_data_deletion__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "preview_hash" BLOB NOT NULL CONSTRAINT "ck_workspace_data_deletion__preview_hash" CHECK (length("preview_hash") = 32),
  "captured_revision" INTEGER NOT NULL CONSTRAINT "ck_workspace_data_deletion__captured_revision" CHECK ("captured_revision" >= 0),
  "state" INTEGER NOT NULL CONSTRAINT "ck_workspace_data_deletion__state" CHECK ("state" IN (1, 2, 3, 4)),
  "owner_job_inventory" TEXT NOT NULL CONSTRAINT "ck_workspace_data_deletion__owner_job_inventory" CHECK (json_valid("owner_job_inventory")),
  "completed_at" INTEGER,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_workspace_data_deletion__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_workspace_data_deletion" PRIMARY KEY ("deletion_id"),
  CONSTRAINT "fk_workspace_data_deletion__workspace_id" FOREIGN KEY ("workspace_id") REFERENCES "workspace_workspace" ("workspace_id") ON DELETE RESTRICT
) STRICT;

CREATE TABLE "workspace_transfer_issue" (
  "transfer_id" TEXT NOT NULL CONSTRAINT "ck_workspace_transfer_issue__transfer_id" CHECK (length("transfer_id") = 36 AND "transfer_id" GLOB '????????-????-????-????-????????????' AND "transfer_id" NOT GLOB '*[^0-9a-f-]*'),
  "ordinal" INTEGER NOT NULL,
  "code" TEXT NOT NULL CONSTRAINT "ck_workspace_transfer_issue__code" CHECK (length("code") BETWEEN 1 AND 128 AND "code" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "source_kind" TEXT,
  "source_id" TEXT CONSTRAINT "ck_workspace_transfer_issue__source_id" CHECK (length("source_id") = 36 AND "source_id" GLOB '????????-????-????-????-????????????' AND "source_id" NOT GLOB '*[^0-9a-f-]*'),
  "blocks_commit" INTEGER NOT NULL CONSTRAINT "ck_workspace_transfer_issue__blocks_commit" CHECK ("blocks_commit" IN (0, 1)),
  "accepted_at" INTEGER,
  CONSTRAINT "pk_workspace_transfer_issue" PRIMARY KEY ("transfer_id", "ordinal"),
  CONSTRAINT "fk_workspace_transfer_issue__transfer_id" FOREIGN KEY ("transfer_id") REFERENCES "workspace_transfer_job" ("transfer_id") ON DELETE RESTRICT
) STRICT;

CREATE TABLE "workspace_transfer_job" (
  "transfer_id" TEXT NOT NULL CONSTRAINT "ck_workspace_transfer_job__transfer_id" CHECK (length("transfer_id") = 36 AND "transfer_id" GLOB '????????-????-????-????-????????????' AND "transfer_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_workspace_transfer_job__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "direction" INTEGER NOT NULL CONSTRAINT "ck_workspace_transfer_job__direction" CHECK ("direction" IN (1, 2)),
  "state" INTEGER NOT NULL CONSTRAINT "ck_workspace_transfer_job__state" CHECK ("state" IN (1, 2, 3, 4, 5, 6, 7, 8)),
  "manifest_hash" BLOB NOT NULL CONSTRAINT "ck_workspace_transfer_job__manifest_hash" CHECK (length("manifest_hash") = 32),
  "manifest_resource_id" TEXT CONSTRAINT "ck_workspace_transfer_job__manifest_resource_id" CHECK (length("manifest_resource_id") = 36 AND "manifest_resource_id" GLOB '????????-????-????-????-????????????' AND "manifest_resource_id" NOT GLOB '*[^0-9a-f-]*'),
  "preview_hash" BLOB CONSTRAINT "ck_workspace_transfer_job__preview_hash" CHECK (length("preview_hash") = 32),
  "rev" INTEGER NOT NULL CONSTRAINT "ck_workspace_transfer_job__rev" CHECK ("rev" >= 0),
  "created_at" INTEGER NOT NULL,
  "expires_at" INTEGER,
  "committed_roots" INTEGER NOT NULL,
  "total_roots" INTEGER NOT NULL,
  "reason" TEXT CONSTRAINT "ck_workspace_transfer_job__reason" CHECK (length("reason") BETWEEN 1 AND 128 AND "reason" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  CONSTRAINT "pk_workspace_transfer_job" PRIMARY KEY ("transfer_id"),
  CONSTRAINT "fk_workspace_transfer_job__workspace_id" FOREIGN KEY ("workspace_id") REFERENCES "workspace_workspace" ("workspace_id") ON DELETE RESTRICT
) STRICT;

CREATE INDEX "ix_workspace_transfer_job__workspace_id_state_created_at" ON "workspace_transfer_job" ("workspace_id", "state", "created_at");

CREATE TABLE "workspace_transfer_mapping" (
  "transfer_id" TEXT NOT NULL CONSTRAINT "ck_workspace_transfer_mapping__transfer_id" CHECK (length("transfer_id") = 36 AND "transfer_id" GLOB '????????-????-????-????-????????????' AND "transfer_id" NOT GLOB '*[^0-9a-f-]*'),
  "source_kind" TEXT NOT NULL,
  "source_id" TEXT NOT NULL CONSTRAINT "ck_workspace_transfer_mapping__source_id" CHECK (length("source_id") = 36 AND "source_id" GLOB '????????-????-????-????-????????????' AND "source_id" NOT GLOB '*[^0-9a-f-]*'),
  "target_kind" TEXT NOT NULL,
  "target_id" TEXT NOT NULL CONSTRAINT "ck_workspace_transfer_mapping__target_id" CHECK (length("target_id") = 36 AND "target_id" GLOB '????????-????-????-????-????????????' AND "target_id" NOT GLOB '*[^0-9a-f-]*'),
  "state" INTEGER NOT NULL CONSTRAINT "ck_workspace_transfer_mapping__state" CHECK ("state" IN (1, 2, 3, 4, 5, 6, 7, 8)),
  "source_hash" BLOB NOT NULL CONSTRAINT "ck_workspace_transfer_mapping__source_hash" CHECK (length("source_hash") = 32),
  "target_rev" INTEGER CONSTRAINT "ck_workspace_transfer_mapping__target_rev" CHECK ("target_rev" >= 0),
  "receipt_id" TEXT CONSTRAINT "ck_workspace_transfer_mapping__receipt_id" CHECK (length("receipt_id") = 36 AND "receipt_id" GLOB '????????-????-????-????-????????????' AND "receipt_id" NOT GLOB '*[^0-9a-f-]*'),
  CONSTRAINT "pk_workspace_transfer_mapping" PRIMARY KEY ("transfer_id", "source_kind", "source_id"),
  CONSTRAINT "fk_workspace_transfer_mapping__transfer_id" FOREIGN KEY ("transfer_id") REFERENCES "workspace_transfer_job" ("transfer_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_workspace_transfer_mapping__transfer_id_target_kind_target_id" ON "workspace_transfer_mapping" ("transfer_id", "target_kind", "target_id");

CREATE TABLE "workspace_workspace" (
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_workspace_workspace__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "realm_id" TEXT NOT NULL CONSTRAINT "ck_workspace_workspace__realm_id" CHECK (length("realm_id") = 36 AND "realm_id" GLOB '????????-????-????-????-????????????' AND "realm_id" NOT GLOB '*[^0-9a-f-]*'),
  "owner_user_id" TEXT NOT NULL CONSTRAINT "ck_workspace_workspace__owner_user_id" CHECK (length("owner_user_id") = 36 AND "owner_user_id" GLOB '????????-????-????-????-????????????' AND "owner_user_id" NOT GLOB '*[^0-9a-f-]*'),
  "name" TEXT NOT NULL,
  "data_region" TEXT NOT NULL,
  "protection_profile" INTEGER NOT NULL CONSTRAINT "ck_workspace_workspace__protection_profile" CHECK ("protection_profile" IN (1)),
  "state" INTEGER NOT NULL CONSTRAINT "ck_workspace_workspace__state" CHECK ("state" IN (1, 2, 3)),
  "created_at" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_workspace_workspace__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_workspace_workspace" PRIMARY KEY ("workspace_id"),
  CONSTRAINT "fk_workspace_workspace__owner_user_id" FOREIGN KEY ("owner_user_id") REFERENCES "identity_user" ("user_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_workspace_workspace__realm_id_owner_user_id" ON "workspace_workspace" ("realm_id", "owner_user_id");

CREATE INDEX "ix_workspace_workspace__owner_user_id_state" ON "workspace_workspace" ("owner_user_id", "state");

CREATE TRIGGER "tr_workspace_workspace__limited_update" BEFORE UPDATE ON "workspace_workspace"
WHEN (OLD."data_region" IS NOT NEW."data_region")
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_workspace_workspace');
END;
