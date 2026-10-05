-- af-migration: module=agent mode=expand
-- Baseline physical schema of the agent owner (generated from Physical/manifest/agent.json; Design D1 profile section 2).
CREATE TABLE "agent_agent_profile" (
  "profile_id" TEXT NOT NULL CONSTRAINT "ck_agent_agent_profile__profile_id" CHECK (length("profile_id") = 36 AND "profile_id" GLOB '????????-????-????-????-????????????' AND "profile_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_agent_agent_profile__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "product_id" TEXT NOT NULL CONSTRAINT "ck_agent_agent_profile__product_id" CHECK ("product_id" IN ('arcscope', 'companion')),
  "revision" INTEGER NOT NULL CONSTRAINT "ck_agent_agent_profile__revision" CHECK ("revision" >= 0),
  "body_proto" BLOB NOT NULL,
  "deleted_at" INTEGER,
  CONSTRAINT "pk_agent_agent_profile" PRIMARY KEY ("profile_id", "revision")
) STRICT;

CREATE TRIGGER "tr_agent_agent_profile__immutable_update" BEFORE UPDATE ON "agent_agent_profile"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_agent_agent_profile');
END;

CREATE TABLE "agent_model_descriptor" (
  "model_descriptor_id" TEXT NOT NULL CONSTRAINT "ck_agent_model_descriptor__model_descriptor_id" CHECK (length("model_descriptor_id") = 36 AND "model_descriptor_id" GLOB '????????-????-????-????-????????????' AND "model_descriptor_id" NOT GLOB '*[^0-9a-f-]*'),
  "model_id" TEXT NOT NULL CONSTRAINT "ck_agent_model_descriptor__model_id" CHECK (length("model_id") BETWEEN 1 AND 256),
  "config_revision_id" TEXT NOT NULL CONSTRAINT "ck_agent_model_descriptor__config_revision_id" CHECK (length("config_revision_id") = 36 AND "config_revision_id" GLOB '????????-????-????-????-????????????' AND "config_revision_id" NOT GLOB '*[^0-9a-f-]*'),
  "provider" INTEGER NOT NULL CONSTRAINT "ck_agent_model_descriptor__provider" CHECK ("provider" IN (1)),
  "route" TEXT NOT NULL CONSTRAINT "ck_agent_model_descriptor__route" CHECK (length("route") BETWEEN 1 AND 128 AND "route" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "purpose" TEXT NOT NULL CONSTRAINT "ck_agent_model_descriptor__purpose" CHECK (length("purpose") BETWEEN 1 AND 128 AND "purpose" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "lifecycle_state" TEXT NOT NULL CONSTRAINT "ck_agent_model_descriptor__lifecycle_state" CHECK (length("lifecycle_state") BETWEEN 1 AND 128 AND "lifecycle_state" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "descriptor_json" TEXT NOT NULL CONSTRAINT "ck_agent_model_descriptor__descriptor_json" CHECK (CASE WHEN json_valid("descriptor_json") THEN json_type("descriptor_json") = 'object' ELSE 0 END),
  "descriptor_hash" BLOB NOT NULL CONSTRAINT "ck_agent_model_descriptor__descriptor_hash" CHECK (length("descriptor_hash") = 32),
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_agent_model_descriptor" PRIMARY KEY ("model_descriptor_id"),
  CONSTRAINT "fk_agent_model_descriptor__config_revision_id" FOREIGN KEY ("config_revision_id") REFERENCES "config_revision" ("config_revision_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_agent_model_descriptor__config_revision_id_model_id_purpose" ON "agent_model_descriptor" ("config_revision_id", "model_id", "purpose");

CREATE TABLE "agent_skill" (
  "skill_id" TEXT NOT NULL CONSTRAINT "ck_agent_skill__skill_id" CHECK (length("skill_id") = 36 AND "skill_id" GLOB '????????-????-????-????-????????????' AND "skill_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_agent_skill__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "product_id" TEXT NOT NULL CONSTRAINT "ck_agent_skill__product_id" CHECK ("product_id" IN ('arcscope', 'companion')),
  "revision" INTEGER NOT NULL CONSTRAINT "ck_agent_skill__revision" CHECK ("revision" >= 0),
  "body_proto" BLOB NOT NULL,
  "deleted_at" INTEGER,
  CONSTRAINT "pk_agent_skill" PRIMARY KEY ("skill_id", "revision")
) STRICT;

CREATE TRIGGER "tr_agent_skill__immutable_update" BEFORE UPDATE ON "agent_skill"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_agent_skill');
END;

CREATE TABLE "agent_supplier_price_version" (
  "supplier_price_version_id" TEXT NOT NULL CONSTRAINT "ck_agent_supplier_price_version__supplier_price_version_id" CHECK (length("supplier_price_version_id") = 36 AND "supplier_price_version_id" GLOB '????????-????-????-????-????????????' AND "supplier_price_version_id" NOT GLOB '*[^0-9a-f-]*'),
  "model_descriptor_id" TEXT NOT NULL CONSTRAINT "ck_agent_supplier_price_version__model_descriptor_id" CHECK (length("model_descriptor_id") = 36 AND "model_descriptor_id" GLOB '????????-????-????-????-????????????' AND "model_descriptor_id" NOT GLOB '*[^0-9a-f-]*'),
  "config_revision_id" TEXT NOT NULL CONSTRAINT "ck_agent_supplier_price_version__config_revision_id" CHECK (length("config_revision_id") = 36 AND "config_revision_id" GLOB '????????-????-????-????-????????????' AND "config_revision_id" NOT GLOB '*[^0-9a-f-]*'),
  "currency" TEXT NOT NULL,
  "valid_from" INTEGER NOT NULL,
  "valid_to" INTEGER,
  "rates_json" TEXT NOT NULL CONSTRAINT "ck_agent_supplier_price_version__rates_json" CHECK (CASE WHEN json_valid("rates_json") THEN json_type("rates_json") = 'object' ELSE 0 END),
  "rates_hash" BLOB NOT NULL CONSTRAINT "ck_agent_supplier_price_version__rates_hash" CHECK (length("rates_hash") = 32),
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_agent_supplier_price_version" PRIMARY KEY ("supplier_price_version_id"),
  CONSTRAINT "fk_agent_supplier_price_version__model_descriptor_id" FOREIGN KEY ("model_descriptor_id") REFERENCES "agent_model_descriptor" ("model_descriptor_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_agent_supplier_price_version__config_revision_id" FOREIGN KEY ("config_revision_id") REFERENCES "config_revision" ("config_revision_id") ON DELETE RESTRICT
) STRICT;

CREATE INDEX "ix_agent_supplier_price_version__model_descriptor_id_valid_from" ON "agent_supplier_price_version" ("model_descriptor_id", "valid_from");

CREATE TRIGGER "tr_agent_supplier_price_version__immutable_update" BEFORE UPDATE ON "agent_supplier_price_version"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_agent_supplier_price_version');
END;

CREATE TRIGGER "tr_agent_supplier_price_version__immutable_delete" BEFORE DELETE ON "agent_supplier_price_version"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_agent_supplier_price_version');
END;

CREATE TABLE "agent_tariff_version" (
  "tariff_version_id" TEXT NOT NULL CONSTRAINT "ck_agent_tariff_version__tariff_version_id" CHECK (length("tariff_version_id") = 36 AND "tariff_version_id" GLOB '????????-????-????-????-????????????' AND "tariff_version_id" NOT GLOB '*[^0-9a-f-]*'),
  "model_descriptor_id" TEXT NOT NULL CONSTRAINT "ck_agent_tariff_version__model_descriptor_id" CHECK (length("model_descriptor_id") = 36 AND "model_descriptor_id" GLOB '????????-????-????-????-????????????' AND "model_descriptor_id" NOT GLOB '*[^0-9a-f-]*'),
  "config_revision_id" TEXT NOT NULL CONSTRAINT "ck_agent_tariff_version__config_revision_id" CHECK (length("config_revision_id") = 36 AND "config_revision_id" GLOB '????????-????-????-????-????????????' AND "config_revision_id" NOT GLOB '*[^0-9a-f-]*'),
  "valid_from" INTEGER NOT NULL,
  "valid_to" INTEGER,
  "rates_json" TEXT NOT NULL CONSTRAINT "ck_agent_tariff_version__rates_json" CHECK (CASE WHEN json_valid("rates_json") THEN json_type("rates_json") = 'object' ELSE 0 END),
  "rates_hash" BLOB NOT NULL CONSTRAINT "ck_agent_tariff_version__rates_hash" CHECK (length("rates_hash") = 32),
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_agent_tariff_version" PRIMARY KEY ("tariff_version_id"),
  CONSTRAINT "fk_agent_tariff_version__model_descriptor_id" FOREIGN KEY ("model_descriptor_id") REFERENCES "agent_model_descriptor" ("model_descriptor_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_agent_tariff_version__config_revision_id" FOREIGN KEY ("config_revision_id") REFERENCES "config_revision" ("config_revision_id") ON DELETE RESTRICT
) STRICT;

CREATE INDEX "ix_agent_tariff_version__model_descriptor_id_valid_from" ON "agent_tariff_version" ("model_descriptor_id", "valid_from");

CREATE TRIGGER "tr_agent_tariff_version__immutable_update" BEFORE UPDATE ON "agent_tariff_version"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_agent_tariff_version');
END;

CREATE TRIGGER "tr_agent_tariff_version__immutable_delete" BEFORE DELETE ON "agent_tariff_version"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_agent_tariff_version');
END;
