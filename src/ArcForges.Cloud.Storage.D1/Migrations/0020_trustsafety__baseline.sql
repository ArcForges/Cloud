-- af-migration: module=trustsafety mode=expand
-- Baseline physical schema of the trustsafety owner (generated from Physical/manifest/trustsafety.json; Design D1 profile section 2).
CREATE TABLE "trustsafety_enforcement_action" (
  "action_id" TEXT NOT NULL CONSTRAINT "ck_trustsafety_enforcement_action__action_id" CHECK (length("action_id") = 36 AND "action_id" GLOB '????????-????-????-????-????????????' AND "action_id" NOT GLOB '*[^0-9a-f-]*'),
  "subject_ref_kind" TEXT NOT NULL CONSTRAINT "ck_trustsafety_enforcement_action__subject_ref_kind" CHECK (length("subject_ref_kind") BETWEEN 1 AND 128 AND "subject_ref_kind" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "subject_ref_id" TEXT NOT NULL CONSTRAINT "ck_trustsafety_enforcement_action__subject_ref_id" CHECK (length("subject_ref_id") = 36 AND "subject_ref_id" GLOB '????????-????-????-????-????????????' AND "subject_ref_id" NOT GLOB '*[^0-9a-f-]*'),
  "level" TEXT NOT NULL CONSTRAINT "ck_trustsafety_enforcement_action__level" CHECK (length("level") BETWEEN 1 AND 128 AND "level" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "reason" TEXT NOT NULL CONSTRAINT "ck_trustsafety_enforcement_action__reason" CHECK (length("reason") BETWEEN 1 AND 128 AND "reason" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "evidence_ref" TEXT NOT NULL,
  "operator_subject" TEXT NOT NULL,
  "notification_id" TEXT NOT NULL CONSTRAINT "ck_trustsafety_enforcement_action__notification_id" CHECK (length("notification_id") = 36 AND "notification_id" GLOB '????????-????-????-????-????????????' AND "notification_id" NOT GLOB '*[^0-9a-f-]*'),
  "appeal_state" INTEGER NOT NULL CONSTRAINT "ck_trustsafety_enforcement_action__appeal_state" CHECK ("appeal_state" IN (1, 2, 3, 4)),
  "created_at" INTEGER NOT NULL,
  "expires_at" INTEGER,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_trustsafety_enforcement_action__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_trustsafety_enforcement_action" PRIMARY KEY ("action_id")
) STRICT;

CREATE INDEX "ix_trustsafety_enforcement_action__subject_ref_kind_subject_ref_id_created_at" ON "trustsafety_enforcement_action" ("subject_ref_kind", "subject_ref_id", "created_at");

CREATE TABLE "trustsafety_report" (
  "report_id" TEXT NOT NULL CONSTRAINT "ck_trustsafety_report__report_id" CHECK (length("report_id") = 36 AND "report_id" GLOB '????????-????-????-????-????????????' AND "report_id" NOT GLOB '*[^0-9a-f-]*'),
  "reporter_user_id" TEXT NOT NULL CONSTRAINT "ck_trustsafety_report__reporter_user_id" CHECK (length("reporter_user_id") = 36 AND "reporter_user_id" GLOB '????????-????-????-????-????????????' AND "reporter_user_id" NOT GLOB '*[^0-9a-f-]*'),
  "subject_ref_kind" TEXT NOT NULL CONSTRAINT "ck_trustsafety_report__subject_ref_kind" CHECK (length("subject_ref_kind") BETWEEN 1 AND 128 AND "subject_ref_kind" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "subject_ref_id" TEXT NOT NULL CONSTRAINT "ck_trustsafety_report__subject_ref_id" CHECK (length("subject_ref_id") = 36 AND "subject_ref_id" GLOB '????????-????-????-????-????????????' AND "subject_ref_id" NOT GLOB '*[^0-9a-f-]*'),
  "reason" TEXT NOT NULL CONSTRAINT "ck_trustsafety_report__reason" CHECK (length("reason") BETWEEN 1 AND 128 AND "reason" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "evidence_ref" TEXT NOT NULL,
  "state" INTEGER NOT NULL CONSTRAINT "ck_trustsafety_report__state" CHECK ("state" IN (1, 2, 3, 4)),
  "action_id" TEXT CONSTRAINT "ck_trustsafety_report__action_id" CHECK (length("action_id") = 36 AND "action_id" GLOB '????????-????-????-????-????????????' AND "action_id" NOT GLOB '*[^0-9a-f-]*'),
  "created_at" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_trustsafety_report__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_trustsafety_report" PRIMARY KEY ("report_id")
) STRICT;

CREATE INDEX "ix_trustsafety_report__state_created_at" ON "trustsafety_report" ("state", "created_at");
