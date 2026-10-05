-- af-migration: module=policy mode=expand
-- Baseline physical schema of the policy owner (generated from Physical/manifest/policy.json; Design D1 profile section 2).
CREATE TABLE "policy_policy_bundle" (
  "bundle_id" TEXT NOT NULL CONSTRAINT "ck_policy_policy_bundle__bundle_id" CHECK (length("bundle_id") = 36 AND "bundle_id" GLOB '????????-????-????-????-????????????' AND "bundle_id" NOT GLOB '*[^0-9a-f-]*'),
  "version" INTEGER NOT NULL,
  "schema_version" TEXT NOT NULL,
  "document_proto" BLOB NOT NULL,
  "hash" TEXT NOT NULL,
  "signature" TEXT NOT NULL,
  "issued_at" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  CONSTRAINT "pk_policy_policy_bundle" PRIMARY KEY ("bundle_id", "version")
) STRICT;

CREATE TRIGGER "tr_policy_policy_bundle__immutable_update" BEFORE UPDATE ON "policy_policy_bundle"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_policy_policy_bundle');
END;

CREATE TRIGGER "tr_policy_policy_bundle__immutable_delete" BEFORE DELETE ON "policy_policy_bundle"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_policy_policy_bundle');
END;

CREATE TABLE "policy_rollout_assignment" (
  "installation_id" TEXT NOT NULL CONSTRAINT "ck_policy_rollout_assignment__installation_id" CHECK (length("installation_id") = 36 AND "installation_id" GLOB '????????-????-????-????-????????????' AND "installation_id" NOT GLOB '*[^0-9a-f-]*'),
  "rollout_id" TEXT NOT NULL CONSTRAINT "ck_policy_rollout_assignment__rollout_id" CHECK (length("rollout_id") = 36 AND "rollout_id" GLOB '????????-????-????-????-????????????' AND "rollout_id" NOT GLOB '*[^0-9a-f-]*'),
  "rule_version" INTEGER NOT NULL,
  "bucket" INTEGER NOT NULL CONSTRAINT "ck_policy_rollout_assignment__bucket" CHECK ("bucket" BETWEEN -2147483648 AND 2147483647),
  "expires_at" INTEGER NOT NULL,
  CONSTRAINT "pk_policy_rollout_assignment" PRIMARY KEY ("installation_id", "rollout_id")
) STRICT;

CREATE TABLE "policy_source_policy" (
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_policy_source_policy__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "target_kind" TEXT NOT NULL CONSTRAINT "ck_policy_source_policy__target_kind" CHECK (length("target_kind") BETWEEN 1 AND 128 AND "target_kind" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "target_id" TEXT NOT NULL CONSTRAINT "ck_policy_source_policy__target_id" CHECK (length("target_id") = 36 AND "target_id" GLOB '????????-????-????-????-????????????' AND "target_id" NOT GLOB '*[^0-9a-f-]*'),
  "revision" INTEGER NOT NULL CONSTRAINT "ck_policy_source_policy__revision" CHECK ("revision" >= 0),
  "searchable" INTEGER CONSTRAINT "ck_policy_source_policy__searchable" CHECK ("searchable" IN (0, 1)),
  "cloud_index_allowed" INTEGER CONSTRAINT "ck_policy_source_policy__cloud_index_allowed" CHECK ("cloud_index_allowed" IN (0, 1)),
  "ai_retrieval_allowed" INTEGER CONSTRAINT "ck_policy_source_policy__ai_retrieval_allowed" CHECK ("ai_retrieval_allowed" IN (0, 1)),
  "managed_ai_processing_allowed" INTEGER CONSTRAINT "ck_policy_source_policy__managed_ai_processing_allowed" CHECK ("managed_ai_processing_allowed" IN (0, 1)),
  "updated_by" TEXT NOT NULL CONSTRAINT "ck_policy_source_policy__updated_by" CHECK (length("updated_by") = 36 AND "updated_by" GLOB '????????-????-????-????-????????????' AND "updated_by" NOT GLOB '*[^0-9a-f-]*'),
  "updated_at" INTEGER NOT NULL,
  "command_id" TEXT NOT NULL CONSTRAINT "ck_policy_source_policy__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  CONSTRAINT "pk_policy_source_policy" PRIMARY KEY ("workspace_id", "target_kind", "target_id")
) STRICT;
