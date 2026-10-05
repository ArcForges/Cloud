-- af-migration: module=support mode=expand
-- Baseline physical schema of the support owner (generated from Physical/manifest/support.json; Design D1 profile section 2).
CREATE TABLE "support_access_grant" (
  "access_id" TEXT NOT NULL CONSTRAINT "ck_support_access_grant__access_id" CHECK (length("access_id") = 36 AND "access_id" GLOB '????????-????-????-????-????????????' AND "access_id" NOT GLOB '*[^0-9a-f-]*'),
  "case_id" TEXT NOT NULL CONSTRAINT "ck_support_access_grant__case_id" CHECK (length("case_id") = 36 AND "case_id" GLOB '????????-????-????-????-????????????' AND "case_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_support_access_grant__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "user_id" TEXT NOT NULL CONSTRAINT "ck_support_access_grant__user_id" CHECK (length("user_id") = 36 AND "user_id" GLOB '????????-????-????-????-????????????' AND "user_id" NOT GLOB '*[^0-9a-f-]*'),
  "operator_subject" TEXT NOT NULL,
  "scope_proto" TEXT NOT NULL CONSTRAINT "ck_support_access_grant__scope_proto" CHECK (json_valid("scope_proto")),
  "proposal_hash" BLOB NOT NULL CONSTRAINT "ck_support_access_grant__proposal_hash" CHECK (length("proposal_hash") = 32),
  "consented_at" INTEGER,
  "expires_at" INTEGER NOT NULL,
  "revoked_at" INTEGER,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_support_access_grant__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_support_access_grant" PRIMARY KEY ("access_id"),
  CONSTRAINT "fk_support_access_grant__case_id" FOREIGN KEY ("case_id") REFERENCES "support_support_case" ("case_id") ON DELETE RESTRICT
) STRICT;

CREATE INDEX "ix_support_access_grant__expires_at" ON "support_access_grant" ("expires_at");

CREATE TABLE "support_case_message" (
  "message_id" TEXT NOT NULL CONSTRAINT "ck_support_case_message__message_id" CHECK (length("message_id") = 36 AND "message_id" GLOB '????????-????-????-????-????????????' AND "message_id" NOT GLOB '*[^0-9a-f-]*'),
  "case_id" TEXT NOT NULL CONSTRAINT "ck_support_case_message__case_id" CHECK (length("case_id") = 36 AND "case_id" GLOB '????????-????-????-????-????????????' AND "case_id" NOT GLOB '*[^0-9a-f-]*'),
  "ordinal" INTEGER NOT NULL,
  "actor_ref" TEXT NOT NULL,
  "text" TEXT NOT NULL,
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_support_case_message" PRIMARY KEY ("message_id"),
  CONSTRAINT "fk_support_case_message__case_id" FOREIGN KEY ("case_id") REFERENCES "support_support_case" ("case_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_support_case_message__case_id_ordinal" ON "support_case_message" ("case_id", "ordinal");

CREATE TABLE "support_support_case" (
  "case_id" TEXT NOT NULL CONSTRAINT "ck_support_support_case__case_id" CHECK (length("case_id") = 36 AND "case_id" GLOB '????????-????-????-????-????????????' AND "case_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_support_support_case__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "user_id" TEXT NOT NULL CONSTRAINT "ck_support_support_case__user_id" CHECK (length("user_id") = 36 AND "user_id" GLOB '????????-????-????-????-????????????' AND "user_id" NOT GLOB '*[^0-9a-f-]*'),
  "category" TEXT NOT NULL,
  "subject" TEXT NOT NULL,
  "state" INTEGER NOT NULL CONSTRAINT "ck_support_support_case__state" CHECK ("state" IN (1, 2, 3, 4, 5)),
  "diagnostic_ref" TEXT CONSTRAINT "ck_support_support_case__diagnostic_ref" CHECK (length("diagnostic_ref") = 36 AND "diagnostic_ref" GLOB '????????-????-????-????-????????????' AND "diagnostic_ref" NOT GLOB '*[^0-9a-f-]*'),
  "created_at" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_support_support_case__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_support_support_case" PRIMARY KEY ("case_id")
) STRICT;

CREATE INDEX "ix_support_support_case__user_id_state_updated_at" ON "support_support_case" ("user_id", "state", "updated_at");
