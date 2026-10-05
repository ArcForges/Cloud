-- af-migration: module=package-catalog mode=expand
-- Baseline physical schema of the package-catalog owner (generated from Physical/manifest/package-catalog.json; Design D1 profile section 2).
CREATE TABLE "package_catalog_package" (
  "package_id" TEXT NOT NULL,
  "publisher_id" TEXT NOT NULL CONSTRAINT "ck_package_catalog_package__publisher_id" CHECK (length("publisher_id") = 36 AND "publisher_id" GLOB '????????-????-????-????-????????????' AND "publisher_id" NOT GLOB '*[^0-9a-f-]*'),
  "name" TEXT NOT NULL,
  "summary" TEXT NOT NULL,
  "kind" TEXT NOT NULL,
  "created_at" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_package_catalog_package__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_package_catalog_package" PRIMARY KEY ("package_id"),
  CONSTRAINT "fk_package_catalog_package__publisher_id" FOREIGN KEY ("publisher_id") REFERENCES "package_catalog_publisher" ("publisher_id") ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER "tr_package_catalog_package__limited_update" BEFORE UPDATE ON "package_catalog_package"
WHEN (OLD."package_id" IS NOT NEW."package_id" OR OLD."publisher_id" IS NOT NEW."publisher_id")
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_package_catalog_package');
END;

CREATE TABLE "package_catalog_publication" (
  "channel" TEXT NOT NULL,
  "revision" INTEGER NOT NULL,
  "index_hash" TEXT NOT NULL,
  "revocation_hash" TEXT NOT NULL,
  "signed_object_ref" TEXT,
  "state" INTEGER NOT NULL CONSTRAINT "ck_package_catalog_publication__state" CHECK ("state" IN (1, 2)),
  "updated_at" INTEGER NOT NULL,
  CONSTRAINT "pk_package_catalog_publication" PRIMARY KEY ("channel")
) STRICT;

CREATE TRIGGER "tr_package_catalog_publication__monotonic_revision" BEFORE UPDATE OF "revision" ON "package_catalog_publication"
WHEN NEW."revision" < OLD."revision"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_monotonic_package_catalog_publication_revision');
END;

CREATE TABLE "package_catalog_publisher" (
  "publisher_id" TEXT NOT NULL CONSTRAINT "ck_package_catalog_publisher__publisher_id" CHECK (length("publisher_id") = 36 AND "publisher_id" GLOB '????????-????-????-????-????????????' AND "publisher_id" NOT GLOB '*[^0-9a-f-]*'),
  "owner_user_id" TEXT NOT NULL CONSTRAINT "ck_package_catalog_publisher__owner_user_id" CHECK (length("owner_user_id") = 36 AND "owner_user_id" GLOB '????????-????-????-????-????????????' AND "owner_user_id" NOT GLOB '*[^0-9a-f-]*'),
  "domain" TEXT NOT NULL,
  "state" INTEGER NOT NULL CONSTRAINT "ck_package_catalog_publisher__state" CHECK ("state" IN (1, 2, 3)),
  "challenge_hash" TEXT NOT NULL,
  "challenge_expires_at" INTEGER NOT NULL,
  "verified_at" INTEGER,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_package_catalog_publisher__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_package_catalog_publisher" PRIMARY KEY ("publisher_id"),
  CONSTRAINT "fk_package_catalog_publisher__owner_user_id" FOREIGN KEY ("owner_user_id") REFERENCES "identity_user" ("user_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_package_catalog_publisher__domain" ON "package_catalog_publisher" ("domain");

CREATE TABLE "package_catalog_review" (
  "review_id" TEXT NOT NULL CONSTRAINT "ck_package_catalog_review__review_id" CHECK (length("review_id") = 36 AND "review_id" GLOB '????????-????-????-????-????????????' AND "review_id" NOT GLOB '*[^0-9a-f-]*'),
  "submission_id" TEXT NOT NULL CONSTRAINT "ck_package_catalog_review__submission_id" CHECK (length("submission_id") = 36 AND "submission_id" GLOB '????????-????-????-????-????????????' AND "submission_id" NOT GLOB '*[^0-9a-f-]*'),
  "operator_subject" TEXT NOT NULL,
  "decision" TEXT NOT NULL,
  "reason" TEXT NOT NULL,
  "evidence" TEXT NOT NULL,
  "proposal_hash" TEXT NOT NULL,
  "decided_at" INTEGER NOT NULL,
  "command_id" TEXT NOT NULL CONSTRAINT "ck_package_catalog_review__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  CONSTRAINT "pk_package_catalog_review" PRIMARY KEY ("review_id"),
  CONSTRAINT "fk_package_catalog_review__submission_id" FOREIGN KEY ("submission_id") REFERENCES "package_catalog_version" ("submission_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_package_catalog_review__command_id" ON "package_catalog_review" ("command_id");

CREATE TRIGGER "tr_package_catalog_review__immutable_update" BEFORE UPDATE ON "package_catalog_review"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_package_catalog_review');
END;

CREATE TRIGGER "tr_package_catalog_review__immutable_delete" BEFORE DELETE ON "package_catalog_review"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_package_catalog_review');
END;

CREATE TABLE "package_catalog_revocation" (
  "revocation_id" TEXT NOT NULL CONSTRAINT "ck_package_catalog_revocation__revocation_id" CHECK (length("revocation_id") = 36 AND "revocation_id" GLOB '????????-????-????-????-????????????' AND "revocation_id" NOT GLOB '*[^0-9a-f-]*'),
  "package_id" TEXT NOT NULL,
  "version" TEXT NOT NULL,
  "reason" TEXT NOT NULL,
  "operator_subject" TEXT NOT NULL,
  "revoked_at" INTEGER NOT NULL,
  "publication_revision" INTEGER NOT NULL,
  "command_id" TEXT NOT NULL CONSTRAINT "ck_package_catalog_revocation__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  CONSTRAINT "pk_package_catalog_revocation" PRIMARY KEY ("revocation_id"),
  CONSTRAINT "fk_package_catalog_revocation__package_id_version" FOREIGN KEY ("package_id", "version") REFERENCES "package_catalog_version" ("package_id", "version") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_package_catalog_revocation__publication_revision" ON "package_catalog_revocation" ("publication_revision");

CREATE UNIQUE INDEX "ux_package_catalog_revocation__command_id" ON "package_catalog_revocation" ("command_id");

CREATE TRIGGER "tr_package_catalog_revocation__immutable_delete" BEFORE DELETE ON "package_catalog_revocation"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_package_catalog_revocation');
END;

CREATE TABLE "package_catalog_version" (
  "package_id" TEXT NOT NULL,
  "version" TEXT NOT NULL,
  "submission_id" TEXT NOT NULL CONSTRAINT "ck_package_catalog_version__submission_id" CHECK (length("submission_id") = 36 AND "submission_id" GLOB '????????-????-????-????-????????????' AND "submission_id" NOT GLOB '*[^0-9a-f-]*'),
  "archive_resource_id" TEXT NOT NULL CONSTRAINT "ck_package_catalog_version__archive_resource_id" CHECK (length("archive_resource_id") = 36 AND "archive_resource_id" GLOB '????????-????-????-????-????????????' AND "archive_resource_id" NOT GLOB '*[^0-9a-f-]*'),
  "digest" TEXT NOT NULL,
  "manifest_hash" TEXT NOT NULL,
  "state" INTEGER NOT NULL CONSTRAINT "ck_package_catalog_version__state" CHECK ("state" IN (1, 2, 3, 4, 5)),
  "submitted_at" INTEGER NOT NULL,
  "published_at" INTEGER,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_package_catalog_version__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_package_catalog_version" PRIMARY KEY ("package_id", "version"),
  CONSTRAINT "fk_package_catalog_version__package_id" FOREIGN KEY ("package_id") REFERENCES "package_catalog_package" ("package_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_package_catalog_version__submission_id" ON "package_catalog_version" ("submission_id");

CREATE TRIGGER "tr_package_catalog_version__limited_update" BEFORE UPDATE ON "package_catalog_version"
WHEN (OLD."package_id" IS NOT NEW."package_id" OR OLD."version" IS NOT NEW."version" OR OLD."archive_resource_id" IS NOT NEW."archive_resource_id" OR OLD."digest" IS NOT NEW."digest" OR OLD."manifest_hash" IS NOT NEW."manifest_hash")
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_package_catalog_version');
END;
