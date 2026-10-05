-- af-migration: module=audit mode=expand
-- Baseline physical schema of the audit owner (generated from Physical/manifest/audit.json; Design D1 profile section 2).
CREATE TABLE "audit_audit_event" (
  "event_id" TEXT NOT NULL CONSTRAINT "ck_audit_audit_event__event_id" CHECK (length("event_id") = 36 AND "event_id" GLOB '????????-????-????-????-????????????' AND "event_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT CONSTRAINT "ck_audit_audit_event__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "actor_ref" TEXT NOT NULL,
  "actor_proto" BLOB NOT NULL,
  "event_type" TEXT NOT NULL CONSTRAINT "ck_audit_audit_event__event_type" CHECK (length("event_type") BETWEEN 1 AND 128 AND "event_type" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "reason" TEXT NOT NULL CONSTRAINT "ck_audit_audit_event__reason" CHECK (length("reason") BETWEEN 1 AND 128 AND "reason" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "correlation_id" TEXT CONSTRAINT "ck_audit_audit_event__correlation_id" CHECK (length("correlation_id") = 36 AND "correlation_id" GLOB '????????-????-????-????-????????????' AND "correlation_id" NOT GLOB '*[^0-9a-f-]*'),
  "command_id" TEXT CONSTRAINT "ck_audit_audit_event__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  "target_ref_kind" TEXT CONSTRAINT "ck_audit_audit_event__target_ref_kind" CHECK (length("target_ref_kind") BETWEEN 1 AND 128 AND "target_ref_kind" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "target_ref_id" TEXT CONSTRAINT "ck_audit_audit_event__target_ref_id" CHECK (length("target_ref_id") = 36 AND "target_ref_id" GLOB '????????-????-????-????-????????????' AND "target_ref_id" NOT GLOB '*[^0-9a-f-]*'),
  "occurred_at" INTEGER NOT NULL,
  "payload_proto" TEXT NOT NULL CONSTRAINT "ck_audit_audit_event__payload_proto" CHECK (json_valid("payload_proto")),
  "previous_hash" BLOB NOT NULL CONSTRAINT "ck_audit_audit_event__previous_hash" CHECK (length("previous_hash") = 32),
  "event_hash" BLOB NOT NULL CONSTRAINT "ck_audit_audit_event__event_hash" CHECK (length("event_hash") = 32),
  CONSTRAINT "pk_audit_audit_event" PRIMARY KEY ("event_id"),
  CONSTRAINT "ck_audit_audit_event__both_or_none_target_ref" CHECK (("target_ref_kind" IS NULL AND "target_ref_id" IS NULL) OR ("target_ref_kind" IS NOT NULL AND "target_ref_id" IS NOT NULL))
) STRICT;

CREATE INDEX "ix_audit_audit_event__workspace_id_occurred_at" ON "audit_audit_event" ("workspace_id", "occurred_at");

CREATE INDEX "ix_audit_audit_event__actor_ref_occurred_at" ON "audit_audit_event" ("actor_ref", "occurred_at");

CREATE TRIGGER "tr_audit_audit_event__immutable_update" BEFORE UPDATE ON "audit_audit_event"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_audit_audit_event');
END;

CREATE TABLE "audit_operator_approval" (
  "approval_id" TEXT NOT NULL CONSTRAINT "ck_audit_operator_approval__approval_id" CHECK (length("approval_id") = 36 AND "approval_id" GLOB '????????-????-????-????-????????????' AND "approval_id" NOT GLOB '*[^0-9a-f-]*'),
  "proposal_id" TEXT NOT NULL CONSTRAINT "ck_audit_operator_approval__proposal_id" CHECK (length("proposal_id") = 36 AND "proposal_id" GLOB '????????-????-????-????-????????????' AND "proposal_id" NOT GLOB '*[^0-9a-f-]*'),
  "proposal_hash" BLOB NOT NULL CONSTRAINT "ck_audit_operator_approval__proposal_hash" CHECK (length("proposal_hash") = 32),
  "approver_subject" TEXT NOT NULL,
  "decision" INTEGER NOT NULL CONSTRAINT "ck_audit_operator_approval__decision" CHECK ("decision" IN (1, 2)),
  "reason" TEXT NOT NULL,
  "decided_at" INTEGER NOT NULL,
  "command_id" TEXT NOT NULL CONSTRAINT "ck_audit_operator_approval__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  CONSTRAINT "pk_audit_operator_approval" PRIMARY KEY ("approval_id"),
  CONSTRAINT "fk_audit_operator_approval__proposal_id" FOREIGN KEY ("proposal_id") REFERENCES "audit_operator_proposal" ("proposal_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_audit_operator_approval__proposal_id" ON "audit_operator_approval" ("proposal_id");

CREATE UNIQUE INDEX "ux_audit_operator_approval__command_id" ON "audit_operator_approval" ("command_id");

CREATE TRIGGER "tr_audit_operator_approval__immutable_update" BEFORE UPDATE ON "audit_operator_approval"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_audit_operator_approval');
END;

CREATE TRIGGER "tr_audit_operator_approval__immutable_delete" BEFORE DELETE ON "audit_operator_approval"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_audit_operator_approval');
END;

CREATE TABLE "audit_operator_proposal" (
  "proposal_id" TEXT NOT NULL CONSTRAINT "ck_audit_operator_proposal__proposal_id" CHECK (length("proposal_id") = 36 AND "proposal_id" GLOB '????????-????-????-????-????????????' AND "proposal_id" NOT GLOB '*[^0-9a-f-]*'),
  "realm_id" TEXT NOT NULL CONSTRAINT "ck_audit_operator_proposal__realm_id" CHECK (length("realm_id") = 36 AND "realm_id" GLOB '????????-????-????-????-????????????' AND "realm_id" NOT GLOB '*[^0-9a-f-]*'),
  "operation_id" TEXT NOT NULL CONSTRAINT "ck_audit_operator_proposal__operation_id" CHECK (length("operation_id") BETWEEN 1 AND 128 AND "operation_id" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "mutation_proto" BLOB NOT NULL,
  "case_id" TEXT CONSTRAINT "ck_audit_operator_proposal__case_id" CHECK (length("case_id") = 36 AND "case_id" GLOB '????????-????-????-????-????????????' AND "case_id" NOT GLOB '*[^0-9a-f-]*'),
  "incident_id" TEXT CONSTRAINT "ck_audit_operator_proposal__incident_id" CHECK (length("incident_id") = 36 AND "incident_id" GLOB '????????-????-????-????-????????????' AND "incident_id" NOT GLOB '*[^0-9a-f-]*'),
  "purpose" TEXT NOT NULL,
  "reason" TEXT NOT NULL,
  "proposer_subject" TEXT NOT NULL,
  "approver_subject" TEXT,
  "proposal_hash" BLOB NOT NULL CONSTRAINT "ck_audit_operator_proposal__proposal_hash" CHECK (length("proposal_hash") = 32),
  "configuration_hash" BLOB NOT NULL CONSTRAINT "ck_audit_operator_proposal__configuration_hash" CHECK (length("configuration_hash") = 32),
  "expected_owner_revision" INTEGER NOT NULL CONSTRAINT "ck_audit_operator_proposal__expected_owner_revision" CHECK ("expected_owner_revision" >= 0),
  "state" INTEGER NOT NULL CONSTRAINT "ck_audit_operator_proposal__state" CHECK ("state" IN (1, 2, 3, 4, 5, 6)),
  "created_at" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  "recovery_generation" INTEGER NOT NULL,
  "consumed_command_id" TEXT CONSTRAINT "ck_audit_operator_proposal__consumed_command_id" CHECK (length("consumed_command_id") = 36 AND "consumed_command_id" GLOB '????????-????-????-????-????????????' AND "consumed_command_id" NOT GLOB '*[^0-9a-f-]*'),
  "result_ref_kind" TEXT CONSTRAINT "ck_audit_operator_proposal__result_ref_kind" CHECK (length("result_ref_kind") BETWEEN 1 AND 128 AND "result_ref_kind" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "result_ref_id" TEXT CONSTRAINT "ck_audit_operator_proposal__result_ref_id" CHECK (length("result_ref_id") = 36 AND "result_ref_id" GLOB '????????-????-????-????-????????????' AND "result_ref_id" NOT GLOB '*[^0-9a-f-]*'),
  "rev" INTEGER NOT NULL CONSTRAINT "ck_audit_operator_proposal__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_audit_operator_proposal" PRIMARY KEY ("proposal_id"),
  CONSTRAINT "fk_audit_operator_proposal__case_id" FOREIGN KEY ("case_id") REFERENCES "support_support_case" ("case_id") ON DELETE RESTRICT,
  CONSTRAINT "ck_audit_operator_proposal__both_or_none_result_ref" CHECK (("result_ref_kind" IS NULL AND "result_ref_id" IS NULL) OR ("result_ref_kind" IS NOT NULL AND "result_ref_id" IS NOT NULL)),
  CONSTRAINT "ck_audit_operator_proposal__exactly_one_case_or_incident" CHECK (("case_id" IS NULL) <> ("incident_id" IS NULL)),
  CONSTRAINT "ck_audit_operator_proposal__expires_within_15_minutes" CHECK ("expires_at" <= "created_at" + 900000000)
) STRICT;

CREATE UNIQUE INDEX "ux_audit_operator_proposal__consumed_command_id" ON "audit_operator_proposal" ("consumed_command_id");

CREATE INDEX "ix_audit_operator_proposal__state_expires_at" ON "audit_operator_proposal" ("state", "expires_at");

CREATE INDEX "ix_audit_operator_proposal__case_id_created_at" ON "audit_operator_proposal" ("case_id", "created_at");

CREATE TRIGGER "tr_audit_operator_proposal__limited_update" BEFORE UPDATE ON "audit_operator_proposal"
WHEN (OLD."proposal_id" IS NOT NEW."proposal_id" OR OLD."mutation_proto" IS NOT NEW."mutation_proto" OR OLD."proposal_hash" IS NOT NEW."proposal_hash" OR OLD."configuration_hash" IS NOT NEW."configuration_hash")
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_audit_operator_proposal');
END;
