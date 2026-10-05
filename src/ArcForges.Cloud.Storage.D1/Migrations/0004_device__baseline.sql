-- af-migration: module=device mode=expand
-- Baseline physical schema of the device owner (generated from Physical/manifest/device.json; Design D1 profile section 2).
CREATE TABLE "device_device" (
  "device_id" TEXT NOT NULL CONSTRAINT "ck_device_device__device_id" CHECK (length("device_id") = 36 AND "device_id" GLOB '????????-????-????-????-????????????' AND "device_id" NOT GLOB '*[^0-9a-f-]*'),
  "user_id" TEXT NOT NULL CONSTRAINT "ck_device_device__user_id" CHECK (length("user_id") = 36 AND "user_id" GLOB '????????-????-????-????-????????????' AND "user_id" NOT GLOB '*[^0-9a-f-]*'),
  "display_name" TEXT NOT NULL,
  "platform" INTEGER NOT NULL CONSTRAINT "ck_device_device__platform" CHECK ("platform" IN (1, 2, 3, 4, 5, 6)),
  "trust_level" INTEGER NOT NULL CONSTRAINT "ck_device_device__trust_level" CHECK ("trust_level" IN (1, 2)),
  "trust_raised_at" INTEGER,
  "remote_enabled" INTEGER NOT NULL CONSTRAINT "ck_device_device__remote_enabled" CHECK ("remote_enabled" IN (0, 1)),
  "first_seen_at" INTEGER NOT NULL,
  "last_seen_at" INTEGER NOT NULL,
  "revoked_at" INTEGER,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_device_device__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_device_device" PRIMARY KEY ("device_id"),
  CONSTRAINT "fk_device_device__user_id" FOREIGN KEY ("user_id") REFERENCES "identity_user" ("user_id") ON DELETE RESTRICT,
  CONSTRAINT "ck_device_device__remote_enabled_requires_trusted" CHECK ("remote_enabled" = 0 OR "trust_level" = 2)
) STRICT;

CREATE INDEX "ix_device_device__user_id_revoked_at" ON "device_device" ("user_id", "revoked_at");

CREATE TABLE "device_installation" (
  "installation_id" TEXT NOT NULL CONSTRAINT "ck_device_installation__installation_id" CHECK (length("installation_id") = 36 AND "installation_id" GLOB '????????-????-????-????-????????????' AND "installation_id" NOT GLOB '*[^0-9a-f-]*'),
  "device_id" TEXT NOT NULL CONSTRAINT "ck_device_installation__device_id" CHECK (length("device_id") = 36 AND "device_id" GLOB '????????-????-????-????-????????????' AND "device_id" NOT GLOB '*[^0-9a-f-]*'),
  "product_id" TEXT NOT NULL CONSTRAINT "ck_device_installation__product_id" CHECK ("product_id" IN ('arcscope', 'companion')),
  "app_version" TEXT NOT NULL,
  "contract_set_version" TEXT NOT NULL,
  "installed_at" INTEGER NOT NULL,
  "last_active_at" INTEGER NOT NULL,
  "platform" TEXT NOT NULL,
  "public_key" TEXT NOT NULL,
  "key_version" INTEGER NOT NULL,
  "revoked_at" INTEGER,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_device_installation__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_device_installation" PRIMARY KEY ("installation_id"),
  CONSTRAINT "fk_device_installation__device_id" FOREIGN KEY ("device_id") REFERENCES "device_device" ("device_id") ON DELETE CASCADE
) STRICT;

CREATE UNIQUE INDEX "ux_device_installation__device_id_product_id" ON "device_installation" ("device_id", "product_id");

CREATE INDEX "ix_device_installation__contract_set_version" ON "device_installation" ("contract_set_version");

CREATE TABLE "device_remote_policy" (
  "device_id" TEXT NOT NULL CONSTRAINT "ck_device_remote_policy__device_id" CHECK (length("device_id") = 36 AND "device_id" GLOB '????????-????-????-????-????????????' AND "device_id" NOT GLOB '*[^0-9a-f-]*'),
  "allowed_capabilities" TEXT NOT NULL CONSTRAINT "ck_device_remote_policy__allowed_capabilities" CHECK (CASE WHEN json_valid("allowed_capabilities") THEN json_type("allowed_capabilities") = 'array' ELSE 0 END),
  "local_confirmation_capabilities" TEXT NOT NULL CONSTRAINT "ck_device_remote_policy__local_confirmation_capabilities" CHECK (CASE WHEN json_valid("local_confirmation_capabilities") THEN json_type("local_confirmation_capabilities") = 'array' ELSE 0 END),
  "rev" INTEGER NOT NULL CONSTRAINT "ck_device_remote_policy__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_device_remote_policy" PRIMARY KEY ("device_id"),
  CONSTRAINT "fk_device_remote_policy__device_id" FOREIGN KEY ("device_id") REFERENCES "device_device" ("device_id") ON DELETE RESTRICT
) STRICT;
