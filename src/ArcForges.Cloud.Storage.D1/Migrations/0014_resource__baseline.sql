-- af-migration: module=resource mode=expand
-- Baseline physical schema of the resource owner (generated from Physical/manifest/resource.json; Design D1 profile section 2).
CREATE TABLE "resource_cf_instance_inventory" (
  "kind" TEXT NOT NULL,
  "instance_id" TEXT NOT NULL,
  "recovery_generation" INTEGER NOT NULL,
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_resource_cf_instance_inventory__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "owner_job_id" TEXT NOT NULL CONSTRAINT "ck_resource_cf_instance_inventory__owner_job_id" CHECK (length("owner_job_id") = 36 AND "owner_job_id" GLOB '????????-????-????-????-????????????' AND "owner_job_id" NOT GLOB '*[^0-9a-f-]*'),
  "worker_version" TEXT NOT NULL,
  "deletion_receipt" TEXT,
  "updated_at" INTEGER NOT NULL,
  CONSTRAINT "pk_resource_cf_instance_inventory" PRIMARY KEY ("kind", "instance_id", "recovery_generation")
) STRICT;

CREATE TABLE "resource_cloud_object" (
  "cloud_object_id" TEXT NOT NULL CONSTRAINT "ck_resource_cloud_object__cloud_object_id" CHECK (length("cloud_object_id") = 36 AND "cloud_object_id" GLOB '????????-????-????-????-????????????' AND "cloud_object_id" NOT GLOB '*[^0-9a-f-]*'),
  "quota_reservation_id" TEXT NOT NULL CONSTRAINT "ck_resource_cloud_object__quota_reservation_id" CHECK (length("quota_reservation_id") = 36 AND "quota_reservation_id" GLOB '????????-????-????-????-????????????' AND "quota_reservation_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_resource_cloud_object__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "owner_product" TEXT NOT NULL,
  "content_hash" TEXT NOT NULL,
  "size_bytes" INTEGER NOT NULL,
  "content_type" TEXT,
  "sensitivity" INTEGER NOT NULL CONSTRAINT "ck_resource_cloud_object__sensitivity" CHECK ("sensitivity" IN (1, 2, 3, 4)),
  "state" INTEGER NOT NULL CONSTRAINT "ck_resource_cloud_object__state" CHECK ("state" IN (1, 2, 3, 4, 5)),
  "storage_key" TEXT NOT NULL,
  "reference_count" INTEGER NOT NULL CONSTRAINT "ck_resource_cloud_object__reference_count" CHECK ("reference_count" BETWEEN -2147483648 AND 2147483647),
  "last_reference_released_at" INTEGER,
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_resource_cloud_object" PRIMARY KEY ("cloud_object_id"),
  CONSTRAINT "ck_resource_cloud_object__reference_count_nonnegative" CHECK ("reference_count" >= 0)
) STRICT;

CREATE INDEX "ix_resource_cloud_object__workspace_id_state" ON "resource_cloud_object" ("workspace_id", "state");

CREATE UNIQUE INDEX "ux_resource_cloud_object__workspace_id_content_hash_size_bytes" ON "resource_cloud_object" ("workspace_id", "content_hash", "size_bytes") WHERE "state" <> 5;

CREATE INDEX "ix_resource_cloud_object__state_last_reference_released_at" ON "resource_cloud_object" ("state", "last_reference_released_at");

CREATE TABLE "resource_object_reference" (
  "cloud_object_id" TEXT NOT NULL CONSTRAINT "ck_resource_object_reference__cloud_object_id" CHECK (length("cloud_object_id") = 36 AND "cloud_object_id" GLOB '????????-????-????-????-????????????' AND "cloud_object_id" NOT GLOB '*[^0-9a-f-]*'),
  "referrer_kind" TEXT NOT NULL,
  "referrer_id" TEXT NOT NULL CONSTRAINT "ck_resource_object_reference__referrer_id" CHECK (length("referrer_id") = 36 AND "referrer_id" GLOB '????????-????-????-????-????????????' AND "referrer_id" NOT GLOB '*[^0-9a-f-]*'),
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_resource_object_reference" PRIMARY KEY ("cloud_object_id", "referrer_kind", "referrer_id")
) STRICT;

CREATE TABLE "resource_service_object_grant" (
  "grant_id" TEXT NOT NULL CONSTRAINT "ck_resource_service_object_grant__grant_id" CHECK (length("grant_id") = 36 AND "grant_id" GLOB '????????-????-????-????-????????????' AND "grant_id" NOT GLOB '*[^0-9a-f-]*'),
  "realm_id" TEXT NOT NULL CONSTRAINT "ck_resource_service_object_grant__realm_id" CHECK (length("realm_id") = 36 AND "realm_id" GLOB '????????-????-????-????-????????????' AND "realm_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_resource_service_object_grant__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "owner_job_id" TEXT NOT NULL CONSTRAINT "ck_resource_service_object_grant__owner_job_id" CHECK (length("owner_job_id") = 36 AND "owner_job_id" GLOB '????????-????-????-????-????????????' AND "owner_job_id" NOT GLOB '*[^0-9a-f-]*'),
  "owner_kind" TEXT NOT NULL CONSTRAINT "ck_resource_service_object_grant__owner_kind" CHECK (length("owner_kind") BETWEEN 1 AND 128 AND "owner_kind" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "attempt_id" TEXT CONSTRAINT "ck_resource_service_object_grant__attempt_id" CHECK (length("attempt_id") = 36 AND "attempt_id" GLOB '????????-????-????-????-????????????' AND "attempt_id" NOT GLOB '*[^0-9a-f-]*'),
  "epoch" INTEGER NOT NULL,
  "recovery_generation" INTEGER NOT NULL,
  "direction" INTEGER NOT NULL CONSTRAINT "ck_resource_service_object_grant__direction" CHECK ("direction" IN (1, 2)),
  "resource_id" TEXT NOT NULL CONSTRAINT "ck_resource_service_object_grant__resource_id" CHECK (length("resource_id") = 36 AND "resource_id" GLOB '????????-????-????-????-????????????' AND "resource_id" NOT GLOB '*[^0-9a-f-]*'),
  "upload_id" TEXT CONSTRAINT "ck_resource_service_object_grant__upload_id" CHECK (length("upload_id") = 36 AND "upload_id" GLOB '????????-????-????-????-????????????' AND "upload_id" NOT GLOB '*[^0-9a-f-]*'),
  "byte_limit" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  "revoked_at" INTEGER,
  CONSTRAINT "pk_resource_service_object_grant" PRIMARY KEY ("grant_id")
) STRICT;

CREATE INDEX "ix_resource_service_object_grant__expires_at" ON "resource_service_object_grant" ("expires_at");

CREATE TABLE "resource_source_consent" (
  "consent_id" TEXT NOT NULL CONSTRAINT "ck_resource_source_consent__consent_id" CHECK (length("consent_id") = 36 AND "consent_id" GLOB '????????-????-????-????-????????????' AND "consent_id" NOT GLOB '*[^0-9a-f-]*'),
  "realm_id" TEXT NOT NULL CONSTRAINT "ck_resource_source_consent__realm_id" CHECK (length("realm_id") = 36 AND "realm_id" GLOB '????????-????-????-????-????????????' AND "realm_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_resource_source_consent__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "actor_id" TEXT NOT NULL CONSTRAINT "ck_resource_source_consent__actor_id" CHECK (length("actor_id") = 36 AND "actor_id" GLOB '????????-????-????-????-????????????' AND "actor_id" NOT GLOB '*[^0-9a-f-]*'),
  "operation_id" TEXT NOT NULL CONSTRAINT "ck_resource_source_consent__operation_id" CHECK (length("operation_id") BETWEEN 1 AND 128 AND "operation_id" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "purpose" TEXT NOT NULL CONSTRAINT "ck_resource_source_consent__purpose" CHECK (length("purpose") BETWEEN 1 AND 128 AND "purpose" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "source_manifest_hash" BLOB NOT NULL CONSTRAINT "ck_resource_source_consent__source_manifest_hash" CHECK (length("source_manifest_hash") = 32),
  "policy_rev" INTEGER NOT NULL CONSTRAINT "ck_resource_source_consent__policy_rev" CHECK ("policy_rev" >= 0),
  "max_bytes" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  "consumed_at" INTEGER,
  "revoked_at" INTEGER,
  "generation" INTEGER NOT NULL,
  CONSTRAINT "pk_resource_source_consent" PRIMARY KEY ("consent_id")
) STRICT;

CREATE INDEX "ix_resource_source_consent__expires_at" ON "resource_source_consent" ("expires_at");

CREATE TABLE "resource_upload_part" (
  "upload_id" TEXT NOT NULL CONSTRAINT "ck_resource_upload_part__upload_id" CHECK (length("upload_id") = 36 AND "upload_id" GLOB '????????-????-????-????-????????????' AND "upload_id" NOT GLOB '*[^0-9a-f-]*'),
  "part_number" INTEGER NOT NULL CONSTRAINT "ck_resource_upload_part__part_number" CHECK ("part_number" BETWEEN -2147483648 AND 2147483647),
  "offset" TEXT NOT NULL CONSTRAINT "ck_resource_upload_part__offset" CHECK (length("offset") BETWEEN 1 AND 20 AND "offset" NOT GLOB '*[^0-9]*' AND ("offset" = '0' OR "offset" NOT GLOB '0*') AND (length("offset") < 20 OR "offset" <= '18446744073709551615')),
  "length" TEXT NOT NULL CONSTRAINT "ck_resource_upload_part__length" CHECK (length("length") BETWEEN 1 AND 20 AND "length" NOT GLOB '*[^0-9]*' AND ("length" = '0' OR "length" NOT GLOB '0*') AND (length("length") < 20 OR "length" <= '18446744073709551615')),
  "sha256" BLOB NOT NULL CONSTRAINT "ck_resource_upload_part__sha256" CHECK (length("sha256") = 32),
  "provider_receipt" TEXT NOT NULL,
  "verified_at" INTEGER NOT NULL,
  CONSTRAINT "pk_resource_upload_part" PRIMARY KEY ("upload_id", "part_number")
) STRICT;

CREATE TABLE "resource_upload_session" (
  "upload_id" TEXT NOT NULL CONSTRAINT "ck_resource_upload_session__upload_id" CHECK (length("upload_id") = 36 AND "upload_id" GLOB '????????-????-????-????-????????????' AND "upload_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_resource_upload_session__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "operation_key" TEXT NOT NULL,
  "object_key" TEXT NOT NULL,
  "expected_hash" BLOB NOT NULL CONSTRAINT "ck_resource_upload_session__expected_hash" CHECK (length("expected_hash") = 32),
  "declared_max_bytes" INTEGER NOT NULL,
  "chunk_bitmap" BLOB NOT NULL,
  "reservation_group_id" TEXT NOT NULL CONSTRAINT "ck_resource_upload_session__reservation_group_id" CHECK (length("reservation_group_id") = 36 AND "reservation_group_id" GLOB '????????-????-????-????-????????????' AND "reservation_group_id" NOT GLOB '*[^0-9a-f-]*'),
  "state" INTEGER NOT NULL CONSTRAINT "ck_resource_upload_session__state" CHECK ("state" IN (1, 2, 3, 4, 5, 6)),
  "created_at" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  "extension_count" INTEGER NOT NULL CONSTRAINT "ck_resource_upload_session__extension_count" CHECK ("extension_count" BETWEEN -2147483648 AND 2147483647),
  "sealed_parts_proto" BLOB,
  "verification_job_id" TEXT CONSTRAINT "ck_resource_upload_session__verification_job_id" CHECK (length("verification_job_id") = 36 AND "verification_job_id" GLOB '????????-????-????-????-????????????' AND "verification_job_id" NOT GLOB '*[^0-9a-f-]*'),
  "verification_state" INTEGER NOT NULL CONSTRAINT "ck_resource_upload_session__verification_state" CHECK ("verification_state" IN (1, 2, 3, 4)),
  "verification_hash" BLOB CONSTRAINT "ck_resource_upload_session__verification_hash" CHECK (length("verification_hash") = 32),
  "provisional_pin_id" TEXT CONSTRAINT "ck_resource_upload_session__provisional_pin_id" CHECK (length("provisional_pin_id") = 36 AND "provisional_pin_id" GLOB '????????-????-????-????-????????????' AND "provisional_pin_id" NOT GLOB '*[^0-9a-f-]*'),
  "completed_at" INTEGER,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_resource_upload_session__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_resource_upload_session" PRIMARY KEY ("upload_id")
) STRICT;

CREATE UNIQUE INDEX "ux_resource_upload_session__workspace_id_operation_key" ON "resource_upload_session" ("workspace_id", "operation_key");
