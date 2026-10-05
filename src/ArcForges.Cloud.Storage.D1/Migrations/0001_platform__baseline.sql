-- af-migration: module=platform mode=expand
-- Baseline physical schema of the platform owner (generated from Physical/manifest/platform.json; Design D1 profile section 2).
CREATE TABLE "platform_command" (
  "command_id" TEXT NOT NULL CONSTRAINT "ck_platform_command__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT CONSTRAINT "ck_platform_command__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "actor_ref" TEXT NOT NULL,
  "operation" TEXT NOT NULL,
  "request_hash" TEXT NOT NULL,
  "status" INTEGER NOT NULL CONSTRAINT "ck_platform_command__status" CHECK ("status" IN (1, 2, 3)),
  "result_payload" TEXT CONSTRAINT "ck_platform_command__result_payload" CHECK (json_valid("result_payload")),
  "result_rev" INTEGER CONSTRAINT "ck_platform_command__result_rev" CHECK ("result_rev" >= 0),
  "error_code" TEXT,
  "created_at" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  CONSTRAINT "pk_platform_command" PRIMARY KEY ("command_id"),
  CONSTRAINT "ck_platform_command__failed_has_error_code" CHECK ("status" <> 3 OR "error_code" IS NOT NULL)
) STRICT;

CREATE INDEX "ix_platform_command__expires_at" ON "platform_command" ("expires_at");

CREATE TABLE "platform_inbox" (
  "source" TEXT NOT NULL,
  "message_id" TEXT NOT NULL,
  "received_at" INTEGER NOT NULL,
  "processed_at" INTEGER,
  "outcome" INTEGER CONSTRAINT "ck_platform_inbox__outcome" CHECK ("outcome" IN (1, 2, 3)),
  "expires_at" INTEGER NOT NULL,
  CONSTRAINT "pk_platform_inbox" PRIMARY KEY ("source", "message_id")
) STRICT;

CREATE INDEX "ix_platform_inbox__expires_at" ON "platform_inbox" ("expires_at");

CREATE TABLE "platform_job_lease" (
  "job_id" TEXT NOT NULL CONSTRAINT "ck_platform_job_lease__job_id" CHECK (length("job_id") = 36 AND "job_id" GLOB '????????-????-????-????-????????????' AND "job_id" NOT GLOB '*[^0-9a-f-]*'),
  "job_type" TEXT NOT NULL,
  "holder" TEXT,
  "leased_until" INTEGER,
  "attempts" INTEGER NOT NULL CONSTRAINT "ck_platform_job_lease__attempts" CHECK ("attempts" BETWEEN -2147483648 AND 2147483647),
  "fence_token" INTEGER NOT NULL,
  "state" INTEGER NOT NULL CONSTRAINT "ck_platform_job_lease__state" CHECK ("state" IN (1, 2, 3, 4)),
  "payload" TEXT NOT NULL CONSTRAINT "ck_platform_job_lease__payload" CHECK (json_valid("payload")),
  "available_at" INTEGER NOT NULL,
  CONSTRAINT "pk_platform_job_lease" PRIMARY KEY ("job_id"),
  CONSTRAINT "ck_platform_job_lease__leased_has_holder" CHECK ("state" <> 2 OR ("holder" IS NOT NULL AND "leased_until" IS NOT NULL)),
  CONSTRAINT "ck_platform_job_lease__attempts_nonnegative" CHECK ("attempts" >= 0),
  CONSTRAINT "ck_platform_job_lease__fence_nonnegative" CHECK ("fence_token" >= 0)
) STRICT;

CREATE INDEX "ix_platform_job_lease__state_available_at" ON "platform_job_lease" ("state", "available_at");

CREATE TRIGGER "tr_platform_job_lease__monotonic_fence_token" BEFORE UPDATE OF "fence_token" ON "platform_job_lease"
WHEN NEW."fence_token" < OLD."fence_token"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_monotonic_platform_job_lease_fence_token');
END;

CREATE TABLE "platform_operating_budget" (
  "realm_id" TEXT NOT NULL CONSTRAINT "ck_platform_operating_budget__realm_id" CHECK (length("realm_id") = 36 AND "realm_id" GLOB '????????-????-????-????-????????????' AND "realm_id" NOT GLOB '*[^0-9a-f-]*'),
  "dimension" INTEGER NOT NULL CONSTRAINT "ck_platform_operating_budget__dimension" CHECK ("dimension" IN (1, 2, 3, 4, 5, 6, 7)),
  "period_start" INTEGER NOT NULL,
  "profile_hash" BLOB NOT NULL CONSTRAINT "ck_platform_operating_budget__profile_hash" CHECK (length("profile_hash") = 32),
  "ceiling" INTEGER NOT NULL,
  "used" INTEGER NOT NULL,
  "held" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_platform_operating_budget__rev" CHECK ("rev" >= 0),
  "updated_at" INTEGER NOT NULL,
  CONSTRAINT "pk_platform_operating_budget" PRIMARY KEY ("realm_id", "dimension", "period_start"),
  CONSTRAINT "ck_platform_operating_budget__nonnegative" CHECK ("ceiling" >= 0 AND "used" >= 0 AND "held" >= 0)
) STRICT;

CREATE TABLE "platform_operating_reservation" (
  "reservation_id" TEXT NOT NULL CONSTRAINT "ck_platform_operating_reservation__reservation_id" CHECK (length("reservation_id") = 36 AND "reservation_id" GLOB '????????-????-????-????-????????????' AND "reservation_id" NOT GLOB '*[^0-9a-f-]*'),
  "realm_id" TEXT NOT NULL CONSTRAINT "ck_platform_operating_reservation__realm_id" CHECK (length("realm_id") = 36 AND "realm_id" GLOB '????????-????-????-????-????????????' AND "realm_id" NOT GLOB '*[^0-9a-f-]*'),
  "dimension" INTEGER NOT NULL CONSTRAINT "ck_platform_operating_reservation__dimension" CHECK ("dimension" IN (1, 2, 3, 4, 5, 6, 7)),
  "period_start" INTEGER NOT NULL,
  "account_id" TEXT CONSTRAINT "ck_platform_operating_reservation__account_id" CHECK (length("account_id") = 36 AND "account_id" GLOB '????????-????-????-????-????????????' AND "account_id" NOT GLOB '*[^0-9a-f-]*'),
  "owner_ref_kind" TEXT NOT NULL CONSTRAINT "ck_platform_operating_reservation__owner_ref_kind" CHECK (length("owner_ref_kind") BETWEEN 1 AND 128 AND "owner_ref_kind" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "owner_ref_id" TEXT NOT NULL CONSTRAINT "ck_platform_operating_reservation__owner_ref_id" CHECK (length("owner_ref_id") = 36 AND "owner_ref_id" GLOB '????????-????-????-????-????????????' AND "owner_ref_id" NOT GLOB '*[^0-9a-f-]*'),
  "command_id" TEXT NOT NULL CONSTRAINT "ck_platform_operating_reservation__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  "reservation_key" TEXT NOT NULL CONSTRAINT "ck_platform_operating_reservation__reservation_key" CHECK (length("reservation_key") BETWEEN 1 AND 128 AND "reservation_key" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "dispatch_attempt_id" TEXT CONSTRAINT "ck_platform_operating_reservation__dispatch_attempt_id" CHECK (length("dispatch_attempt_id") = 36 AND "dispatch_attempt_id" GLOB '????????-????-????-????-????????????' AND "dispatch_attempt_id" NOT GLOB '*[^0-9a-f-]*'),
  "bound" INTEGER NOT NULL,
  "actual" INTEGER NOT NULL,
  "state" INTEGER NOT NULL CONSTRAINT "ck_platform_operating_reservation__state" CHECK ("state" IN (1, 2, 3, 4)),
  "fence" INTEGER NOT NULL,
  "recovery_generation" INTEGER NOT NULL,
  "created_at" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_platform_operating_reservation__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_platform_operating_reservation" PRIMARY KEY ("reservation_id"),
  CONSTRAINT "fk_platform_operating_reservation__realm_id_dimension_period_start" FOREIGN KEY ("realm_id", "dimension", "period_start") REFERENCES "platform_operating_budget" ("realm_id", "dimension", "period_start") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_platform_operating_reservation__realm_id_reservation_key_dimension" ON "platform_operating_reservation" ("realm_id", "reservation_key", "dimension");

CREATE INDEX "ix_platform_operating_reservation__state_updated_at" ON "platform_operating_reservation" ("state", "updated_at");

CREATE TABLE "platform_outbox" (
  "outbox_id" TEXT NOT NULL CONSTRAINT "ck_platform_outbox__outbox_id" CHECK (length("outbox_id") = 36 AND "outbox_id" GLOB '????????-????-????-????-????????????' AND "outbox_id" NOT GLOB '*[^0-9a-f-]*'),
  "aggregate_kind" TEXT NOT NULL,
  "aggregate_id" TEXT NOT NULL CONSTRAINT "ck_platform_outbox__aggregate_id" CHECK (length("aggregate_id") = 36 AND "aggregate_id" GLOB '????????-????-????-????-????????????' AND "aggregate_id" NOT GLOB '*[^0-9a-f-]*'),
  "aggregate_rev" INTEGER NOT NULL CONSTRAINT "ck_platform_outbox__aggregate_rev" CHECK ("aggregate_rev" >= 0),
  "event_type" TEXT NOT NULL,
  "payload" TEXT NOT NULL CONSTRAINT "ck_platform_outbox__payload" CHECK (json_valid("payload")),
  "workspace_id" TEXT CONSTRAINT "ck_platform_outbox__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "correlation_id" TEXT NOT NULL CONSTRAINT "ck_platform_outbox__correlation_id" CHECK (length("correlation_id") = 36 AND "correlation_id" GLOB '????????-????-????-????-????????????' AND "correlation_id" NOT GLOB '*[^0-9a-f-]*'),
  "causation_id" TEXT CONSTRAINT "ck_platform_outbox__causation_id" CHECK (length("causation_id") = 36 AND "causation_id" GLOB '????????-????-????-????-????????????' AND "causation_id" NOT GLOB '*[^0-9a-f-]*'),
  "state" INTEGER NOT NULL CONSTRAINT "ck_platform_outbox__state" CHECK ("state" IN (1, 2, 3)),
  "attempts" INTEGER NOT NULL CONSTRAINT "ck_platform_outbox__attempts" CHECK ("attempts" BETWEEN -2147483648 AND 2147483647),
  "created_at" INTEGER NOT NULL,
  "dispatched_at" INTEGER,
  CONSTRAINT "pk_platform_outbox" PRIMARY KEY ("outbox_id"),
  CONSTRAINT "ck_platform_outbox__attempts_nonnegative" CHECK ("attempts" >= 0)
) STRICT;

CREATE INDEX "ix_platform_outbox__state_created_at" ON "platform_outbox" ("state", "created_at");

CREATE INDEX "ix_platform_outbox__aggregate_kind_aggregate_id_aggregate_rev" ON "platform_outbox" ("aggregate_kind", "aggregate_id", "aggregate_rev");

CREATE TABLE "platform_recovery_epoch" (
  "realm_id" TEXT NOT NULL CONSTRAINT "ck_platform_recovery_epoch__realm_id" CHECK (length("realm_id") = 36 AND "realm_id" GLOB '????????-????-????-????-????????????' AND "realm_id" NOT GLOB '*[^0-9a-f-]*'),
  "recovery_generation" INTEGER NOT NULL,
  "recovery_point" TEXT NOT NULL,
  "journal_inventory_hash" BLOB NOT NULL CONSTRAINT "ck_platform_recovery_epoch__journal_inventory_hash" CHECK (length("journal_inventory_hash") = 32),
  "state" INTEGER NOT NULL CONSTRAINT "ck_platform_recovery_epoch__state" CHECK ("state" IN (1, 2, 3, 4)),
  "updated_at" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_platform_recovery_epoch__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_platform_recovery_epoch" PRIMARY KEY ("realm_id")
) STRICT;

CREATE TRIGGER "tr_platform_recovery_epoch__monotonic_recovery_generation" BEFORE UPDATE OF "recovery_generation" ON "platform_recovery_epoch"
WHEN NEW."recovery_generation" < OLD."recovery_generation"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_monotonic_platform_recovery_epoch_recovery_generation');
END;

CREATE TABLE "platform_safety_receipt" (
  "journal_record_id" TEXT NOT NULL,
  "record_hash" BLOB NOT NULL CONSTRAINT "ck_platform_safety_receipt__record_hash" CHECK (length("record_hash") = 32),
  "owner_command_id" TEXT NOT NULL CONSTRAINT "ck_platform_safety_receipt__owner_command_id" CHECK (length("owner_command_id") = 36 AND "owner_command_id" GLOB '????????-????-????-????-????????????' AND "owner_command_id" NOT GLOB '*[^0-9a-f-]*'),
  "recovery_generation" INTEGER NOT NULL,
  "kind" TEXT NOT NULL CONSTRAINT "ck_platform_safety_receipt__kind" CHECK (length("kind") BETWEEN 1 AND 128 AND "kind" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "status" INTEGER NOT NULL CONSTRAINT "ck_platform_safety_receipt__status" CHECK ("status" IN (1, 2)),
  "independent_receipt" TEXT,
  "created_at" INTEGER NOT NULL,
  "verified_at" INTEGER,
  CONSTRAINT "pk_platform_safety_receipt" PRIMARY KEY ("journal_record_id"),
  CONSTRAINT "ck_platform_safety_receipt__verified_has_receipt" CHECK ("status" <> 2 OR ("independent_receipt" IS NOT NULL AND "verified_at" IS NOT NULL))
) STRICT;

CREATE INDEX "ix_platform_safety_receipt__status_created_at" ON "platform_safety_receipt" ("status", "created_at");

CREATE TRIGGER "tr_platform_safety_receipt__limited_update" BEFORE UPDATE ON "platform_safety_receipt"
WHEN (OLD."journal_record_id" IS NOT NEW."journal_record_id" OR OLD."record_hash" IS NOT NEW."record_hash" OR OLD."owner_command_id" IS NOT NEW."owner_command_id" OR OLD."recovery_generation" IS NOT NEW."recovery_generation" OR OLD."kind" IS NOT NEW."kind" OR OLD."created_at" IS NOT NEW."created_at") OR NOT (OLD."status" = 1)
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_platform_safety_receipt');
END;
