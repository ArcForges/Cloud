-- af-migration: module=entitlement mode=expand
-- COM.18 immutable quota profiles and indexed original key meanings.
CREATE TABLE "entitlement_quota_definition_key" (
  "realm_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_quota_definition_key__realm_id" CHECK (length("realm_id") = 36 AND "realm_id" GLOB '????????-????-????-????-????????????' AND "realm_id" NOT GLOB '*[^0-9a-f-]*'),
  "quota_key" TEXT NOT NULL CONSTRAINT "ck_entitlement_quota_definition_key__quota_key" CHECK (length("quota_key") BETWEEN 1 AND 128 AND "quota_key" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "unit" INTEGER NOT NULL CONSTRAINT "ck_entitlement_quota_definition_key__unit" CHECK ("unit" IN (1, 2, 3, 4)),
  "mode" INTEGER NOT NULL CONSTRAINT "ck_entitlement_quota_definition_key__mode" CHECK ("mode" IN (1, 2)),
  "combination" INTEGER NOT NULL CONSTRAINT "ck_entitlement_quota_definition_key__combination" CHECK ("combination" IN (1, 2, 3)),
  "first_definitions_version" TEXT NOT NULL CONSTRAINT "ck_entitlement_quota_definition_key__first_definitions_version" CHECK (length(CAST("first_definitions_version" AS BLOB)) <= 128),
  CONSTRAINT "pk_entitlement_quota_definition_key" PRIMARY KEY ("realm_id", "quota_key"),
  CONSTRAINT "ck_entitlement_quota_definition_key__first_version_nonempty" CHECK (length("first_definitions_version") > 0)
) STRICT;

CREATE TRIGGER "tr_entitlement_quota_definition_key__immutable_update" BEFORE UPDATE ON "entitlement_quota_definition_key"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_quota_definition_key');
END;

CREATE TRIGGER "tr_entitlement_quota_definition_key__immutable_delete" BEFORE DELETE ON "entitlement_quota_definition_key"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_quota_definition_key');
END;

CREATE TABLE "entitlement_quota_definition_profile" (
  "realm_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_quota_definition_profile__realm_id" CHECK (length("realm_id") = 36 AND "realm_id" GLOB '????????-????-????-????-????????????' AND "realm_id" NOT GLOB '*[^0-9a-f-]*'),
  "definitions_version" TEXT NOT NULL CONSTRAINT "ck_entitlement_quota_definition_profile__definitions_version" CHECK (length(CAST("definitions_version" AS BLOB)) <= 128),
  "profile_hash" BLOB NOT NULL CONSTRAINT "ck_entitlement_quota_definition_profile__profile_hash" CHECK (length("profile_hash") = 32),
  "canonical_profile" TEXT NOT NULL CONSTRAINT "ck_entitlement_quota_definition_profile__canonical_profile" CHECK (length(CAST("canonical_profile" AS BLOB)) <= 65536),
  "artifact_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_quota_definition_profile__artifact_id" CHECK (length(CAST("artifact_id" AS BLOB)) <= 128),
  "artifact_hash" BLOB NOT NULL CONSTRAINT "ck_entitlement_quota_definition_profile__artifact_hash" CHECK (length("artifact_hash") = 32),
  "artifact_length" INTEGER NOT NULL,
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_entitlement_quota_definition_profile" PRIMARY KEY ("realm_id", "definitions_version"),
  CONSTRAINT "ck_entitlement_quota_definition_profile__version_nonempty" CHECK (length("definitions_version") > 0),
  CONSTRAINT "ck_entitlement_quota_definition_profile__artifact_nonempty" CHECK (length("artifact_id") > 0),
  CONSTRAINT "ck_entitlement_quota_definition_profile__artifact_length" CHECK ("artifact_length" BETWEEN 2 AND 65536 AND length(CAST("canonical_profile" AS BLOB)) = "artifact_length"),
  CONSTRAINT "ck_entitlement_quota_definition_profile__same_content_hash" CHECK ("profile_hash" = "artifact_hash")
) STRICT;

CREATE TRIGGER "tr_entitlement_quota_definition_profile__immutable_update" BEFORE UPDATE ON "entitlement_quota_definition_profile"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_quota_definition_profile');
END;

CREATE TRIGGER "tr_entitlement_quota_definition_profile__immutable_delete" BEFORE DELETE ON "entitlement_quota_definition_profile"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_quota_definition_profile');
END;
