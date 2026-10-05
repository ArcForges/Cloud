-- af-migration: module=entitlement mode=expand
-- The resolver's remaining append-only inputs: definitions activations, workspace status facts and feature releases (COM.16; Design model 01 section 6; generated from Physical/manifest/entitlement.json).
CREATE TABLE "entitlement_definitions_activation" (
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_definitions_activation__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "activated_at" INTEGER NOT NULL,
  "definitions_version" TEXT NOT NULL CONSTRAINT "ck_entitlement_definitions_activation__definitions_version" CHECK (length("definitions_version") BETWEEN 1 AND 128 AND "definitions_version" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  CONSTRAINT "pk_entitlement_definitions_activation" PRIMARY KEY ("workspace_id", "activated_at")
) STRICT;

CREATE TRIGGER "tr_entitlement_definitions_activation__immutable_update" BEFORE UPDATE ON "entitlement_definitions_activation"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_definitions_activation');
END;

CREATE TRIGGER "tr_entitlement_definitions_activation__immutable_delete" BEFORE DELETE ON "entitlement_definitions_activation"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_definitions_activation');
END;

CREATE TABLE "entitlement_feature_release" (
  "feature_key" TEXT NOT NULL CONSTRAINT "ck_entitlement_feature_release__feature_key" CHECK (length("feature_key") BETWEEN 1 AND 128 AND "feature_key" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "released_at" INTEGER NOT NULL,
  CONSTRAINT "pk_entitlement_feature_release" PRIMARY KEY ("feature_key")
) STRICT;

CREATE TRIGGER "tr_entitlement_feature_release__immutable_update" BEFORE UPDATE ON "entitlement_feature_release"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_feature_release');
END;

CREATE TRIGGER "tr_entitlement_feature_release__immutable_delete" BEFORE DELETE ON "entitlement_feature_release"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_feature_release');
END;

CREATE TABLE "entitlement_workspace_status_fact" (
  "status_fact_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_workspace_status_fact__status_fact_id" CHECK (length("status_fact_id") = 36 AND "status_fact_id" GLOB '????????-????-????-????-????????????' AND "status_fact_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_workspace_status_fact__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "recorded_at" INTEGER NOT NULL,
  "status" INTEGER NOT NULL CONSTRAINT "ck_entitlement_workspace_status_fact__status" CHECK ("status" IN (1, 2, 3)),
  "auto_renew" INTEGER NOT NULL CONSTRAINT "ck_entitlement_workspace_status_fact__auto_renew" CHECK ("auto_renew" IN (0, 1)),
  "purchase_pending" INTEGER NOT NULL CONSTRAINT "ck_entitlement_workspace_status_fact__purchase_pending" CHECK ("purchase_pending" IN (0, 1)),
  "source_ref" TEXT NOT NULL,
  CONSTRAINT "pk_entitlement_workspace_status_fact" PRIMARY KEY ("status_fact_id"),
  CONSTRAINT "ck_entitlement_workspace_status_fact__source_ref_shape" CHECK (length("source_ref") BETWEEN 1 AND 128)
) STRICT;

CREATE INDEX "ix_entitlement_workspace_status_fact__workspace_id_recorded_at" ON "entitlement_workspace_status_fact" ("workspace_id", "recorded_at");

CREATE UNIQUE INDEX "ux_entitlement_workspace_status_fact__source_ref" ON "entitlement_workspace_status_fact" ("source_ref");

CREATE TRIGGER "tr_entitlement_workspace_status_fact__immutable_update" BEFORE UPDATE ON "entitlement_workspace_status_fact"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_workspace_status_fact');
END;

CREATE TRIGGER "tr_entitlement_workspace_status_fact__immutable_delete" BEFORE DELETE ON "entitlement_workspace_status_fact"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_workspace_status_fact');
END;
