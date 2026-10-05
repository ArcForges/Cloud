-- af-migration: module=entitlement mode=expand
-- Baseline physical schema of the entitlement owner (generated from Physical/manifest/entitlement.json; Design D1 profile section 2).
CREATE TABLE "entitlement_capacity_bucket" (
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_capacity_bucket__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "available_micro" INTEGER NOT NULL,
  "held_micro" INTEGER NOT NULL,
  "remainder_num" INTEGER NOT NULL,
  "remainder_den" INTEGER NOT NULL,
  "watermark_at" INTEGER NOT NULL,
  "activation_term_id" TEXT CONSTRAINT "ck_entitlement_capacity_bucket__activation_term_id" CHECK (length("activation_term_id") = 36 AND "activation_term_id" GLOB '????????-????-????-????-????????????' AND "activation_term_id" NOT GLOB '*[^0-9a-f-]*'),
  "rev" INTEGER NOT NULL CONSTRAINT "ck_entitlement_capacity_bucket__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_entitlement_capacity_bucket" PRIMARY KEY ("workspace_id"),
  CONSTRAINT "fk_entitlement_capacity_bucket__activation_term_id" FOREIGN KEY ("activation_term_id") REFERENCES "entitlement_service_term" ("service_term_id") ON DELETE RESTRICT,
  CONSTRAINT "ck_entitlement_capacity_bucket__available_nonnegative" CHECK ("available_micro" >= 0),
  CONSTRAINT "ck_entitlement_capacity_bucket__held_nonnegative" CHECK ("held_micro" >= 0)
) STRICT;

CREATE TRIGGER "tr_entitlement_capacity_bucket__monotonic_watermark_at" BEFORE UPDATE OF "watermark_at" ON "entitlement_capacity_bucket"
WHEN NEW."watermark_at" < OLD."watermark_at"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_monotonic_entitlement_capacity_bucket_watermark_at');
END;

CREATE TABLE "entitlement_capacity_plan_assignment" (
  "assignment_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_capacity_plan_assignment__assignment_id" CHECK (length("assignment_id") = 36 AND "assignment_id" GLOB '????????-????-????-????-????????????' AND "assignment_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_capacity_plan_assignment__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "offer_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_capacity_plan_assignment__offer_id" CHECK (length("offer_id") = 36 AND "offer_id" GLOB '????????-????-????-????-????????????' AND "offer_id" NOT GLOB '*[^0-9a-f-]*'),
  "term_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_capacity_plan_assignment__term_id" CHECK (length("term_id") = 36 AND "term_id" GLOB '????????-????-????-????-????????????' AND "term_id" NOT GLOB '*[^0-9a-f-]*'),
  "selection_priority" INTEGER NOT NULL,
  "effective_from" INTEGER NOT NULL,
  "effective_to" INTEGER,
  "cause_ref" TEXT NOT NULL CONSTRAINT "ck_entitlement_capacity_plan_assignment__cause_ref" CHECK (length("cause_ref") = 36 AND "cause_ref" GLOB '????????-????-????-????-????????????' AND "cause_ref" NOT GLOB '*[^0-9a-f-]*'),
  CONSTRAINT "pk_entitlement_capacity_plan_assignment" PRIMARY KEY ("assignment_id"),
  CONSTRAINT "fk_entitlement_capacity_plan_assignment__workspace_id" FOREIGN KEY ("workspace_id") REFERENCES "workspace_workspace" ("workspace_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_entitlement_capacity_plan_assignment__term_id" FOREIGN KEY ("term_id") REFERENCES "entitlement_service_term" ("service_term_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_entitlement_capacity_plan_assignment__workspace_id_effective_from" ON "entitlement_capacity_plan_assignment" ("workspace_id", "effective_from");

CREATE INDEX "ix_entitlement_capacity_plan_assignment__workspace_id_effective_to" ON "entitlement_capacity_plan_assignment" ("workspace_id", "effective_to");

CREATE TRIGGER "tr_entitlement_capacity_plan_assignment__limited_update" BEFORE UPDATE ON "entitlement_capacity_plan_assignment"
WHEN (OLD."assignment_id" IS NOT NEW."assignment_id" OR OLD."workspace_id" IS NOT NEW."workspace_id" OR OLD."offer_id" IS NOT NEW."offer_id" OR OLD."term_id" IS NOT NEW."term_id" OR OLD."selection_priority" IS NOT NEW."selection_priority" OR OLD."effective_from" IS NOT NEW."effective_from" OR OLD."cause_ref" IS NOT NEW."cause_ref") OR NOT (OLD."effective_to" IS NULL)
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_capacity_plan_assignment');
END;

CREATE TRIGGER "tr_entitlement_capacity_plan_assignment__immutable_delete" BEFORE DELETE ON "entitlement_capacity_plan_assignment"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_capacity_plan_assignment');
END;

CREATE TABLE "entitlement_capacity_policy_period" (
  "policy_period_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_capacity_policy_period__policy_period_id" CHECK (length("policy_period_id") = 36 AND "policy_period_id" GLOB '????????-????-????-????-????????????' AND "policy_period_id" NOT GLOB '*[^0-9a-f-]*'),
  "realm_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_capacity_policy_period__realm_id" CHECK (length("realm_id") = 36 AND "realm_id" GLOB '????????-????-????-????-????????????' AND "realm_id" NOT GLOB '*[^0-9a-f-]*'),
  "offer_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_capacity_policy_period__offer_id" CHECK (length("offer_id") = 36 AND "offer_id" GLOB '????????-????-????-????-????????????' AND "offer_id" NOT GLOB '*[^0-9a-f-]*'),
  "config_revision_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_capacity_policy_period__config_revision_id" CHECK (length("config_revision_id") = 36 AND "config_revision_id" GLOB '????????-????-????-????-????????????' AND "config_revision_id" NOT GLOB '*[^0-9a-f-]*'),
  "burst_micro" INTEGER NOT NULL,
  "rate_micro_per_second" INTEGER NOT NULL,
  "effective_from" INTEGER NOT NULL,
  "effective_to" INTEGER,
  CONSTRAINT "pk_entitlement_capacity_policy_period" PRIMARY KEY ("policy_period_id"),
  CONSTRAINT "fk_entitlement_capacity_policy_period__config_revision_id" FOREIGN KEY ("config_revision_id") REFERENCES "config_revision" ("config_revision_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_entitlement_capacity_policy_period__realm_id_offer_id_effective_from" ON "entitlement_capacity_policy_period" ("realm_id", "offer_id", "effective_from");

CREATE INDEX "ix_entitlement_capacity_policy_period__realm_id_offer_id_effective_from_effective_to" ON "entitlement_capacity_policy_period" ("realm_id", "offer_id", "effective_from", "effective_to");

CREATE TRIGGER "tr_entitlement_capacity_policy_period__limited_update" BEFORE UPDATE ON "entitlement_capacity_policy_period"
WHEN (OLD."policy_period_id" IS NOT NEW."policy_period_id" OR OLD."realm_id" IS NOT NEW."realm_id" OR OLD."offer_id" IS NOT NEW."offer_id" OR OLD."config_revision_id" IS NOT NEW."config_revision_id" OR OLD."burst_micro" IS NOT NEW."burst_micro" OR OLD."rate_micro_per_second" IS NOT NEW."rate_micro_per_second" OR OLD."effective_from" IS NOT NEW."effective_from") OR NOT (OLD."effective_to" IS NULL)
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_capacity_policy_period');
END;

CREATE TRIGGER "tr_entitlement_capacity_policy_period__immutable_delete" BEFORE DELETE ON "entitlement_capacity_policy_period"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_capacity_policy_period');
END;

CREATE TABLE "entitlement_capacity_reservation" (
  "reservation_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_capacity_reservation__reservation_id" CHECK (length("reservation_id") = 36 AND "reservation_id" GLOB '????????-????-????-????-????????????' AND "reservation_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_capacity_reservation__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "logical_request_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_capacity_reservation__logical_request_id" CHECK (length("logical_request_id") = 36 AND "logical_request_id" GLOB '????????-????-????-????-????????????' AND "logical_request_id" NOT GLOB '*[^0-9a-f-]*'),
  "from_capacity_micro" INTEGER NOT NULL,
  "from_compensation_micro" INTEGER NOT NULL,
  "from_purchased_micro" INTEGER NOT NULL,
  "state" INTEGER NOT NULL CONSTRAINT "ck_entitlement_capacity_reservation__state" CHECK ("state" IN (1, 2, 3, 4)),
  "expires_at" INTEGER NOT NULL,
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_entitlement_capacity_reservation" PRIMARY KEY ("reservation_id"),
  CONSTRAINT "fk_entitlement_capacity_reservation__workspace_id" FOREIGN KEY ("workspace_id") REFERENCES "entitlement_capacity_bucket" ("workspace_id") ON DELETE RESTRICT
) STRICT;

CREATE INDEX "ix_entitlement_capacity_reservation__workspace_id_state" ON "entitlement_capacity_reservation" ("workspace_id", "state");

CREATE INDEX "ix_entitlement_capacity_reservation__state_expires_at" ON "entitlement_capacity_reservation" ("state", "expires_at");

CREATE UNIQUE INDEX "ux_entitlement_capacity_reservation__logical_request_id" ON "entitlement_capacity_reservation" ("logical_request_id") WHERE "state" = 1;

CREATE TABLE "entitlement_grant" (
  "grant_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_grant__grant_id" CHECK (length("grant_id") = 36 AND "grant_id" GLOB '????????-????-????-????-????????????' AND "grant_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_grant__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "kind" INTEGER NOT NULL CONSTRAINT "ck_entitlement_grant__kind" CHECK ("kind" IN (1, 2, 3)),
  "subject" TEXT NOT NULL,
  "value" TEXT NOT NULL CONSTRAINT "ck_entitlement_grant__value" CHECK (json_valid("value")),
  "source" INTEGER NOT NULL CONSTRAINT "ck_entitlement_grant__source" CHECK ("source" IN (1, 2, 3, 4, 5, 6, 7)),
  "source_ref" TEXT,
  "effective_from" INTEGER NOT NULL,
  "effective_until" INTEGER,
  "issued_by_actor" TEXT NOT NULL,
  "created_at" INTEGER NOT NULL,
  "reason" TEXT,
  CONSTRAINT "pk_entitlement_grant" PRIMARY KEY ("grant_id"),
  CONSTRAINT "ck_entitlement_grant__reason_required_for_operator_sources" CHECK (("source" IN (5, 6, 7)) = ("reason" IS NOT NULL)),
  CONSTRAINT "ck_entitlement_grant__reason_shape" CHECK ("reason" IS NULL OR (length("reason") BETWEEN 1 AND 512 AND instr("reason", char(0)) = 0 AND "reason" NOT GLOB ('*[' || char(1) || '-' || char(31) || char(127) || ']*')))
) STRICT;

CREATE INDEX "ix_entitlement_grant__workspace_id_kind_effective_from" ON "entitlement_grant" ("workspace_id", "kind", "effective_from");

CREATE INDEX "ix_entitlement_grant__source_source_ref" ON "entitlement_grant" ("source", "source_ref");

CREATE TRIGGER "tr_entitlement_grant__immutable_update" BEFORE UPDATE ON "entitlement_grant"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_grant');
END;

CREATE TRIGGER "tr_entitlement_grant__immutable_delete" BEFORE DELETE ON "entitlement_grant"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_grant');
END;

CREATE TABLE "entitlement_quota_budget" (
  "scope_kind" INTEGER NOT NULL CONSTRAINT "ck_entitlement_quota_budget__scope_kind" CHECK ("scope_kind" IN (1, 2)),
  "scope_id" TEXT NOT NULL,
  "quota_key" TEXT NOT NULL,
  "period_key" TEXT NOT NULL,
  "unit" TEXT NOT NULL,
  "limit" INTEGER NOT NULL,
  "used" INTEGER NOT NULL,
  "held" INTEGER NOT NULL,
  "policy_version" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_entitlement_quota_budget__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_entitlement_quota_budget" PRIMARY KEY ("scope_kind", "scope_id", "quota_key", "period_key"),
  CONSTRAINT "ck_entitlement_quota_budget__limit_nonnegative" CHECK ("limit" >= 0),
  CONSTRAINT "ck_entitlement_quota_budget__used_nonnegative" CHECK ("used" >= 0),
  CONSTRAINT "ck_entitlement_quota_budget__held_nonnegative" CHECK ("held" >= 0)
) STRICT;

CREATE TABLE "entitlement_quota_event" (
  "reservation_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_quota_event__reservation_id" CHECK (length("reservation_id") = 36 AND "reservation_id" GLOB '????????-????-????-????-????????????' AND "reservation_id" NOT GLOB '*[^0-9a-f-]*'),
  "effect_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_quota_event__effect_id" CHECK (length("effect_id") = 36 AND "effect_id" GLOB '????????-????-????-????-????????????' AND "effect_id" NOT GLOB '*[^0-9a-f-]*'),
  "kind" INTEGER NOT NULL CONSTRAINT "ck_entitlement_quota_event__kind" CHECK ("kind" IN (1, 2, 3)),
  "measured_quantity" INTEGER NOT NULL,
  "budget_rev" INTEGER NOT NULL CONSTRAINT "ck_entitlement_quota_event__budget_rev" CHECK ("budget_rev" >= 0),
  "source_object_id" TEXT CONSTRAINT "ck_entitlement_quota_event__source_object_id" CHECK (length("source_object_id") = 36 AND "source_object_id" GLOB '????????-????-????-????-????????????' AND "source_object_id" NOT GLOB '*[^0-9a-f-]*'),
  "source_segment_id" TEXT CONSTRAINT "ck_entitlement_quota_event__source_segment_id" CHECK (length("source_segment_id") = 36 AND "source_segment_id" GLOB '????????-????-????-????-????????????' AND "source_segment_id" NOT GLOB '*[^0-9a-f-]*'),
  "deletion_receipt_id" TEXT CONSTRAINT "ck_entitlement_quota_event__deletion_receipt_id" CHECK (length("deletion_receipt_id") = 36 AND "deletion_receipt_id" GLOB '????????-????-????-????-????????????' AND "deletion_receipt_id" NOT GLOB '*[^0-9a-f-]*'),
  CONSTRAINT "pk_entitlement_quota_event" PRIMARY KEY ("reservation_id", "effect_id"),
  CONSTRAINT "fk_entitlement_quota_event__reservation_id" FOREIGN KEY ("reservation_id") REFERENCES "entitlement_quota_reservation" ("reservation_id") ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER "tr_entitlement_quota_event__immutable_update" BEFORE UPDATE ON "entitlement_quota_event"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_quota_event');
END;

CREATE TABLE "entitlement_quota_reservation" (
  "reservation_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_quota_reservation__reservation_id" CHECK (length("reservation_id") = 36 AND "reservation_id" GLOB '????????-????-????-????-????????????' AND "reservation_id" NOT GLOB '*[^0-9a-f-]*'),
  "operation_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_quota_reservation__operation_id" CHECK (length("operation_id") = 36 AND "operation_id" GLOB '????????-????-????-????-????????????' AND "operation_id" NOT GLOB '*[^0-9a-f-]*'),
  "scope_kind" INTEGER NOT NULL CONSTRAINT "ck_entitlement_quota_reservation__scope_kind" CHECK ("scope_kind" IN (1, 2)),
  "scope_id" TEXT NOT NULL,
  "quota_key" TEXT NOT NULL,
  "period_key" TEXT NOT NULL,
  "owner_kind" TEXT NOT NULL CONSTRAINT "ck_entitlement_quota_reservation__owner_kind" CHECK (length("owner_kind") BETWEEN 1 AND 128 AND "owner_kind" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "owner_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_quota_reservation__owner_id" CHECK (length("owner_id") = 36 AND "owner_id" GLOB '????????-????-????-????-????????????' AND "owner_id" NOT GLOB '*[^0-9a-f-]*'),
  "bound" INTEGER NOT NULL,
  "consumed" INTEGER NOT NULL,
  "state" INTEGER NOT NULL CONSTRAINT "ck_entitlement_quota_reservation__state" CHECK ("state" IN (1, 2, 3, 4)),
  "expires_at" INTEGER NOT NULL,
  "lease_until" INTEGER,
  "fence" INTEGER,
  CONSTRAINT "pk_entitlement_quota_reservation" PRIMARY KEY ("reservation_id"),
  CONSTRAINT "fk_entitlement_quota_reservation__scope_kind_scope_id_quota_key_period_key" FOREIGN KEY ("scope_kind", "scope_id", "quota_key", "period_key") REFERENCES "entitlement_quota_budget" ("scope_kind", "scope_id", "quota_key", "period_key") ON DELETE RESTRICT,
  CONSTRAINT "ck_entitlement_quota_reservation__consumed_within_bound" CHECK ("consumed" <= "bound")
) STRICT;

CREATE UNIQUE INDEX "ux_entitlement_quota_reservation__operation_id_scope_kind_scope_id_quota_key_period_key" ON "entitlement_quota_reservation" ("operation_id", "scope_kind", "scope_id", "quota_key", "period_key");

CREATE TABLE "entitlement_revision" (
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_revision__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "rev" INTEGER NOT NULL CONSTRAINT "ck_entitlement_revision__rev" CHECK ("rev" >= 0),
  "updated_at" INTEGER NOT NULL,
  CONSTRAINT "pk_entitlement_revision" PRIMARY KEY ("workspace_id")
) STRICT;

CREATE TABLE "entitlement_revocation" (
  "revocation_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_revocation__revocation_id" CHECK (length("revocation_id") = 36 AND "revocation_id" GLOB '????????-????-????-????-????????????' AND "revocation_id" NOT GLOB '*[^0-9a-f-]*'),
  "grant_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_revocation__grant_id" CHECK (length("grant_id") = 36 AND "grant_id" GLOB '????????-????-????-????-????????????' AND "grant_id" NOT GLOB '*[^0-9a-f-]*'),
  "reason_code" TEXT NOT NULL,
  "effective_from" INTEGER NOT NULL,
  "issued_by_actor" TEXT NOT NULL,
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_entitlement_revocation" PRIMARY KEY ("revocation_id"),
  CONSTRAINT "fk_entitlement_revocation__grant_id" FOREIGN KEY ("grant_id") REFERENCES "entitlement_grant" ("grant_id") ON DELETE RESTRICT
) STRICT;

CREATE INDEX "ix_entitlement_revocation__grant_id" ON "entitlement_revocation" ("grant_id");

CREATE TRIGGER "tr_entitlement_revocation__immutable_update" BEFORE UPDATE ON "entitlement_revocation"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_revocation');
END;

CREATE TRIGGER "tr_entitlement_revocation__immutable_delete" BEFORE DELETE ON "entitlement_revocation"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_revocation');
END;

CREATE TABLE "entitlement_service_term" (
  "service_term_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_service_term__service_term_id" CHECK (length("service_term_id") = 36 AND "service_term_id" GLOB '????????-????-????-????-????????????' AND "service_term_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_service_term__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "realm_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_service_term__realm_id" CHECK (length("realm_id") = 36 AND "realm_id" GLOB '????????-????-????-????-????????????' AND "realm_id" NOT GLOB '*[^0-9a-f-]*'),
  "kind" INTEGER NOT NULL CONSTRAINT "ck_entitlement_service_term__kind" CHECK ("kind" IN (1, 2, 3, 4)),
  "subscription_ref" TEXT,
  "period_ref" TEXT NOT NULL,
  "starts_at" INTEGER NOT NULL,
  "ends_at" INTEGER NOT NULL,
  "grace_ends_at" INTEGER,
  "supersedes_id" TEXT CONSTRAINT "ck_entitlement_service_term__supersedes_id" CHECK (length("supersedes_id") = 36 AND "supersedes_id" GLOB '????????-????-????-????-????????????' AND "supersedes_id" NOT GLOB '*[^0-9a-f-]*'),
  "offer_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_service_term__offer_id" CHECK (length("offer_id") = 36 AND "offer_id" GLOB '????????-????-????-????-????????????' AND "offer_id" NOT GLOB '*[^0-9a-f-]*'),
  "offer_snapshot_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_service_term__offer_snapshot_id" CHECK (length("offer_snapshot_id") = 36 AND "offer_snapshot_id" GLOB '????????-????-????-????-????????????' AND "offer_snapshot_id" NOT GLOB '*[^0-9a-f-]*'),
  "authorized_at" INTEGER NOT NULL,
  "selection_priority" INTEGER NOT NULL,
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_entitlement_service_term" PRIMARY KEY ("service_term_id"),
  CONSTRAINT "fk_entitlement_service_term__workspace_id" FOREIGN KEY ("workspace_id") REFERENCES "workspace_workspace" ("workspace_id") ON DELETE RESTRICT,
  CONSTRAINT "ck_entitlement_service_term__ends_after_starts" CHECK ("ends_at" > "starts_at"),
  CONSTRAINT "ck_entitlement_service_term__subscription_ref_matches_kind" CHECK (("kind" = 1 AND "subscription_ref" IS NOT NULL) OR ("kind" <> 1 AND "subscription_ref" IS NULL))
) STRICT;

CREATE UNIQUE INDEX "ux_entitlement_service_term__realm_id_kind_period_ref" ON "entitlement_service_term" ("realm_id", "kind", "period_ref");

CREATE INDEX "ix_entitlement_service_term__workspace_id_starts_at_ends_at" ON "entitlement_service_term" ("workspace_id", "starts_at", "ends_at");

CREATE INDEX "ix_entitlement_service_term__subscription_ref_starts_at" ON "entitlement_service_term" ("subscription_ref", "starts_at");

CREATE TRIGGER "tr_entitlement_service_term__immutable_update" BEFORE UPDATE ON "entitlement_service_term"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_service_term');
END;

CREATE TRIGGER "tr_entitlement_service_term__immutable_delete" BEFORE DELETE ON "entitlement_service_term"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_service_term');
END;

CREATE TABLE "entitlement_service_term_action" (
  "term_action_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_service_term_action__term_action_id" CHECK (length("term_action_id") = 36 AND "term_action_id" GLOB '????????-????-????-????-????????????' AND "term_action_id" NOT GLOB '*[^0-9a-f-]*'),
  "term_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_service_term_action__term_id" CHECK (length("term_id") = 36 AND "term_id" GLOB '????????-????-????-????-????????????' AND "term_id" NOT GLOB '*[^0-9a-f-]*'),
  "kind" INTEGER NOT NULL CONSTRAINT "ck_entitlement_service_term_action__kind" CHECK ("kind" IN (1, 2)),
  "effective_at" INTEGER NOT NULL,
  "recorded_at" INTEGER NOT NULL,
  "source_ref" TEXT NOT NULL,
  "replacement_term_id" TEXT CONSTRAINT "ck_entitlement_service_term_action__replacement_term_id" CHECK (length("replacement_term_id") = 36 AND "replacement_term_id" GLOB '????????-????-????-????-????????????' AND "replacement_term_id" NOT GLOB '*[^0-9a-f-]*'),
  CONSTRAINT "pk_entitlement_service_term_action" PRIMARY KEY ("term_action_id"),
  CONSTRAINT "fk_entitlement_service_term_action__term_id" FOREIGN KEY ("term_id") REFERENCES "entitlement_service_term" ("service_term_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_entitlement_service_term_action__replacement_term_id" FOREIGN KEY ("replacement_term_id") REFERENCES "entitlement_service_term" ("service_term_id") ON DELETE RESTRICT,
  CONSTRAINT "ck_entitlement_service_term_action__replacement_matches_kind" CHECK (("kind" = 1 AND "replacement_term_id" IS NOT NULL) OR ("kind" = 2 AND "replacement_term_id" IS NULL))
) STRICT;

CREATE UNIQUE INDEX "ux_entitlement_service_term_action__source_ref" ON "entitlement_service_term_action" ("source_ref");

CREATE TRIGGER "tr_entitlement_service_term_action__immutable_update" BEFORE UPDATE ON "entitlement_service_term_action"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_service_term_action');
END;

CREATE TRIGGER "tr_entitlement_service_term_action__immutable_delete" BEFORE DELETE ON "entitlement_service_term_action"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_entitlement_service_term_action');
END;

CREATE TABLE "entitlement_snapshot" (
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_snapshot__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "entitlement_version" INTEGER NOT NULL,
  "computed_at" INTEGER NOT NULL,
  "valid_until" INTEGER,
  "capabilities" TEXT NOT NULL CONSTRAINT "ck_entitlement_snapshot__capabilities" CHECK (CASE WHEN json_valid("capabilities") THEN json_type("capabilities") = 'object' ELSE 0 END),
  "quotas" TEXT NOT NULL CONSTRAINT "ck_entitlement_snapshot__quotas" CHECK (CASE WHEN json_valid("quotas") THEN json_type("quotas") = 'object' ELSE 0 END),
  "features" TEXT NOT NULL CONSTRAINT "ck_entitlement_snapshot__features" CHECK (json_valid("features")),
  CONSTRAINT "pk_entitlement_snapshot" PRIMARY KEY ("workspace_id")
) STRICT;

CREATE TABLE "entitlement_usage_counter" (
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_entitlement_usage_counter__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "quota_key" TEXT NOT NULL,
  "period_start" INTEGER NOT NULL,
  "used" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL,
  CONSTRAINT "pk_entitlement_usage_counter" PRIMARY KEY ("workspace_id", "quota_key", "period_start")
) STRICT;
