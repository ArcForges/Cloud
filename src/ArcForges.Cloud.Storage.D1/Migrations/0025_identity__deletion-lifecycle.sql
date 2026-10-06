-- af-migration: module=identity mode=expand
-- Actual immutable disclosed deletion lifecycle; accepted baselines remain unchanged.
CREATE TABLE "identity_account_deletion" (
  "deletion_id" TEXT NOT NULL CONSTRAINT "ck_identity_account_deletion__deletion_id" CHECK (length("deletion_id") = 36 AND "deletion_id" GLOB '????????-????-????-????-????????????' AND "deletion_id" NOT GLOB '*[^0-9a-f-]*'),
  "realm_id" TEXT NOT NULL CONSTRAINT "ck_identity_account_deletion__realm_id" CHECK (length("realm_id") = 36 AND "realm_id" GLOB '????????-????-????-????-????????????' AND "realm_id" NOT GLOB '*[^0-9a-f-]*'),
  "user_id" TEXT NOT NULL CONSTRAINT "ck_identity_account_deletion__user_id" CHECK (length("user_id") = 36 AND "user_id" GLOB '????????-????-????-????-????????????' AND "user_id" NOT GLOB '*[^0-9a-f-]*'),
  "requested_at" INTEGER NOT NULL,
  "grace_ends_at" INTEGER NOT NULL,
  "policy_version" TEXT NOT NULL CONSTRAINT "ck_identity_account_deletion__policy_version" CHECK (length("policy_version") BETWEEN 1 AND 128 AND "policy_version" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "grace_seconds" INTEGER NOT NULL,
  "previous_user_state" INTEGER NOT NULL CONSTRAINT "ck_identity_account_deletion__previous_user_state" CHECK ("previous_user_state" IN (1, 2, 3, 4, 5)),
  "state" INTEGER NOT NULL CONSTRAINT "ck_identity_account_deletion__state" CHECK ("state" IN (1, 2, 3, 4)),
  "cancelled_at" INTEGER,
  "completed_at" INTEGER,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_identity_account_deletion__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_identity_account_deletion" PRIMARY KEY ("deletion_id"),
  CONSTRAINT "fk_identity_account_deletion__user_id" FOREIGN KEY ("user_id") REFERENCES "identity_user" ("user_id") ON DELETE RESTRICT,
  CONSTRAINT "ck_identity_account_deletion__deadline_duration" CHECK ("grace_seconds" > 0 AND "grace_seconds" <= 9223372036854 AND "requested_at" >= 0 AND "requested_at" <= 9223372036854775807 - "grace_seconds" * 1000000 AND "grace_ends_at" = "requested_at" + "grace_seconds" * 1000000 AND "grace_ends_at" > "requested_at"),
  CONSTRAINT "ck_identity_account_deletion__previous_state" CHECK ("previous_user_state" IN (1, 2, 3)),
  CONSTRAINT "ck_identity_account_deletion__terminal_facts" CHECK (("state" IN (1, 3) AND "cancelled_at" IS NULL AND "completed_at" IS NULL) OR ("state" = 2 AND "cancelled_at" IS NOT NULL AND "cancelled_at" >= "requested_at" AND "cancelled_at" < "grace_ends_at" AND "completed_at" IS NULL) OR ("state" = 4 AND "completed_at" IS NOT NULL AND "completed_at" >= "grace_ends_at" AND "cancelled_at" IS NULL))
) STRICT;

CREATE UNIQUE INDEX "ux_identity_account_deletion__user_id" ON "identity_account_deletion" ("user_id") WHERE "state" IN (1, 3);

CREATE INDEX "ix_identity_account_deletion__state_grace_ends_at" ON "identity_account_deletion" ("state", "grace_ends_at");

CREATE INDEX "ix_identity_account_deletion__user_id_requested_at" ON "identity_account_deletion" ("user_id", "requested_at");

CREATE TRIGGER "tr_identity_account_deletion__limited_update" BEFORE UPDATE ON "identity_account_deletion"
WHEN (OLD."deletion_id" IS NOT NEW."deletion_id" OR OLD."realm_id" IS NOT NEW."realm_id" OR OLD."user_id" IS NOT NEW."user_id" OR OLD."requested_at" IS NOT NEW."requested_at" OR OLD."grace_ends_at" IS NOT NEW."grace_ends_at" OR OLD."policy_version" IS NOT NEW."policy_version" OR OLD."grace_seconds" IS NOT NEW."grace_seconds" OR OLD."previous_user_state" IS NOT NEW."previous_user_state") OR NOT (OLD."state" IN (1, 3))
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_identity_account_deletion');
END;

CREATE TRIGGER "tr_identity_account_deletion__immutable_delete" BEFORE DELETE ON "identity_account_deletion"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_identity_account_deletion');
END;
