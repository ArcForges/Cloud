-- af-migration: module=entitlement mode=expand
-- COM.20 immutable complete definitions; ordinal awaits actual accepted integration queue.
CREATE TABLE "entitlement_resolver_definition_profile" (
  "realm_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_resolver_definition_profile__realm_id" CHECK (length("realm_id") = 36 AND "realm_id" GLOB '????????-????-????-????-????????????' AND "realm_id" NOT GLOB '*[^0-9a-f-]*'),
  "definitions_version" TEXT NOT NULL CONSTRAINT "ck_entitlement_resolver_definition_profile__definitions_version" CHECK (length(CAST("definitions_version" AS BLOB)) <= 128),
  "profile_hash" BLOB NOT NULL CONSTRAINT "ck_entitlement_resolver_definition_profile__profile_hash" CHECK (length("profile_hash") = 32),
  "canonical_profile" TEXT NOT NULL CONSTRAINT "ck_entitlement_resolver_definition_profile__canonical_profile" CHECK (length(CAST("canonical_profile" AS BLOB)) <= 65536),
  "artifact_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_resolver_definition_profile__artifact_id" CHECK (length(CAST("artifact_id" AS BLOB)) <= 128),
  "artifact_hash" BLOB NOT NULL CONSTRAINT "ck_entitlement_resolver_definition_profile__artifact_hash" CHECK (length("artifact_hash") = 32),
  "artifact_length" INTEGER NOT NULL,
  "original_config_revision_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_resolver_definition_profile__original_config_revision_id" CHECK (length("original_config_revision_id") = 36 AND "original_config_revision_id" GLOB '????????-????-????-????-????????????' AND "original_config_revision_id" NOT GLOB '*[^0-9a-f-]*'),
  "original_config_document_hash" BLOB NOT NULL CONSTRAINT "ck_entitlement_resolver_definition_profile__original_config_document_hash" CHECK (length("original_config_document_hash") = 32),
  "realm_kind" INTEGER NOT NULL CONSTRAINT "ck_entitlement_resolver_definition_profile__realm_kind" CHECK ("realm_kind" IN (1, 2)),
  "publisher_ref" TEXT NOT NULL CONSTRAINT "ck_entitlement_resolver_definition_profile__publisher_ref" CHECK (length(CAST("publisher_ref" AS BLOB)) <= 256),
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_entitlement_resolver_definition_profile" PRIMARY KEY ("realm_id", "definitions_version"),
  CONSTRAINT "ck_entitlement_resolver_definition_profile__version_nonempty" CHECK (length("definitions_version") > 0),
  CONSTRAINT "ck_entitlement_resolver_definition_profile__artifact_nonempty" CHECK (length("artifact_id") > 0),
  CONSTRAINT "ck_entitlement_resolver_definition_profile__publisher_nonempty" CHECK (length("publisher_ref") > 0),
  CONSTRAINT "ck_entitlement_resolver_definition_profile__artifact_length" CHECK ("artifact_length" BETWEEN 2 AND 65536 AND length(CAST("canonical_profile" AS BLOB)) = "artifact_length"),
  CONSTRAINT "ck_entitlement_resolver_definition_profile__same_hash" CHECK ("profile_hash" = "artifact_hash")
) STRICT;

CREATE TRIGGER "tr_entitlement_resolver_definition_profile__immutable_update" BEFORE UPDATE ON "entitlement_resolver_definition_profile"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_resolver_definition_profile');
END;

CREATE TRIGGER "tr_entitlement_resolver_definition_profile__immutable_delete" BEFORE DELETE ON "entitlement_resolver_definition_profile"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_resolver_definition_profile');
END;
