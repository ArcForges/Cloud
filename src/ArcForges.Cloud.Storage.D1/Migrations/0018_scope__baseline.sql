-- af-migration: module=scope mode=expand
-- Baseline physical schema of the scope owner (generated from Physical/manifest/scope.json; Design D1 profile section 2).
CREATE TABLE "scope_replica_revision" (
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_scope_replica_revision__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "aggregate_kind" TEXT NOT NULL,
  "aggregate_id" TEXT NOT NULL CONSTRAINT "ck_scope_replica_revision__aggregate_id" CHECK (length("aggregate_id") = 36 AND "aggregate_id" GLOB '????????-????-????-????-????????????' AND "aggregate_id" NOT GLOB '*[^0-9a-f-]*'),
  "rev" INTEGER NOT NULL CONSTRAINT "ck_scope_replica_revision__rev" CHECK ("rev" >= 0),
  "schema_version" TEXT NOT NULL,
  "payload_resource_id" TEXT NOT NULL CONSTRAINT "ck_scope_replica_revision__payload_resource_id" CHECK (length("payload_resource_id") = 36 AND "payload_resource_id" GLOB '????????-????-????-????-????????????' AND "payload_resource_id" NOT GLOB '*[^0-9a-f-]*'),
  "payload_hash" BLOB NOT NULL CONSTRAINT "ck_scope_replica_revision__payload_hash" CHECK (length("payload_hash") = 32),
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_scope_replica_revision" PRIMARY KEY ("workspace_id", "aggregate_kind", "aggregate_id", "rev")
) STRICT;

CREATE TRIGGER "tr_scope_replica_revision__immutable_update" BEFORE UPDATE ON "scope_replica_revision"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_scope_replica_revision');
END;

CREATE TABLE "scope_scenario_version" (
  "scenario_version_id" TEXT NOT NULL CONSTRAINT "ck_scope_scenario_version__scenario_version_id" CHECK (length("scenario_version_id") = 36 AND "scenario_version_id" GLOB '????????-????-????-????-????????????' AND "scenario_version_id" NOT GLOB '*[^0-9a-f-]*'),
  "definition_id" TEXT NOT NULL CONSTRAINT "ck_scope_scenario_version__definition_id" CHECK (length("definition_id") = 36 AND "definition_id" GLOB '????????-????-????-????-????????????' AND "definition_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_scope_scenario_version__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "version_ordinal" INTEGER NOT NULL CONSTRAINT "ck_scope_scenario_version__version_ordinal" CHECK ("version_ordinal" BETWEEN -2147483648 AND 2147483647),
  "channel_schema" TEXT NOT NULL CONSTRAINT "ck_scope_scenario_version__channel_schema" CHECK (json_valid("channel_schema")),
  "expression_ast" TEXT CONSTRAINT "ck_scope_scenario_version__expression_ast" CHECK (json_valid("expression_ast")),
  "fault_profile" TEXT CONSTRAINT "ck_scope_scenario_version__fault_profile" CHECK (json_valid("fault_profile")),
  "content_hash" BLOB NOT NULL,
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_scope_scenario_version" PRIMARY KEY ("scenario_version_id"),
  CONSTRAINT "fk_scope_scenario_version__workspace_id" FOREIGN KEY ("workspace_id") REFERENCES "workspace_workspace" ("workspace_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_scope_scenario_version__definition_id_version_ordinal" ON "scope_scenario_version" ("definition_id", "version_ordinal");

CREATE TRIGGER "tr_scope_scenario_version__immutable_update" BEFORE UPDATE ON "scope_scenario_version"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_scope_scenario_version');
END;

CREATE TABLE "scope_simulation_checkpoint" (
  "run_id" TEXT NOT NULL CONSTRAINT "ck_scope_simulation_checkpoint__run_id" CHECK (length("run_id") = 36 AND "run_id" GLOB '????????-????-????-????-????????????' AND "run_id" NOT GLOB '*[^0-9a-f-]*'),
  "next_tick" INTEGER NOT NULL,
  "rng_state" BLOB NOT NULL,
  "generator_state" TEXT NOT NULL CONSTRAINT "ck_scope_simulation_checkpoint__generator_state" CHECK (json_valid("generator_state")),
  "replay_position" TEXT CONSTRAINT "ck_scope_simulation_checkpoint__replay_position" CHECK (json_valid("replay_position")),
  "pending_fault_state" TEXT NOT NULL CONSTRAINT "ck_scope_simulation_checkpoint__pending_fault_state" CHECK (json_valid("pending_fault_state")),
  "committed_segment_sequence" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL,
  CONSTRAINT "pk_scope_simulation_checkpoint" PRIMARY KEY ("run_id")
) STRICT;

CREATE TABLE "scope_simulation_definition" (
  "definition_id" TEXT NOT NULL CONSTRAINT "ck_scope_simulation_definition__definition_id" CHECK (length("definition_id") = 36 AND "definition_id" GLOB '????????-????-????-????-????????????' AND "definition_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_scope_simulation_definition__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_scope_simulation_definition" PRIMARY KEY ("definition_id"),
  CONSTRAINT "fk_scope_simulation_definition__workspace_id" FOREIGN KEY ("workspace_id") REFERENCES "workspace_workspace" ("workspace_id") ON DELETE RESTRICT
) STRICT;

CREATE INDEX "ix_scope_simulation_definition__workspace_id" ON "scope_simulation_definition" ("workspace_id");

CREATE TABLE "scope_simulation_lease" (
  "run_id" TEXT NOT NULL CONSTRAINT "ck_scope_simulation_lease__run_id" CHECK (length("run_id") = 36 AND "run_id" GLOB '????????-????-????-????-????????????' AND "run_id" NOT GLOB '*[^0-9a-f-]*'),
  "holder_instance" TEXT NOT NULL,
  "fence_token" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  CONSTRAINT "pk_scope_simulation_lease" PRIMARY KEY ("run_id")
) STRICT;

CREATE TRIGGER "tr_scope_simulation_lease__monotonic_fence_token" BEFORE UPDATE OF "fence_token" ON "scope_simulation_lease"
WHEN NEW."fence_token" < OLD."fence_token"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_monotonic_scope_simulation_lease_fence_token');
END;

CREATE TABLE "scope_simulation_run" (
  "run_id" TEXT NOT NULL CONSTRAINT "ck_scope_simulation_run__run_id" CHECK (length("run_id") = 36 AND "run_id" GLOB '????????-????-????-????-????????????' AND "run_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_scope_simulation_run__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "scenario_version_id" TEXT NOT NULL CONSTRAINT "ck_scope_simulation_run__scenario_version_id" CHECK (length("scenario_version_id") = 36 AND "scenario_version_id" GLOB '????????-????-????-????-????????????' AND "scenario_version_id" NOT GLOB '*[^0-9a-f-]*'),
  "seed" INTEGER NOT NULL,
  "execution_profile" TEXT NOT NULL,
  "clock_mode" INTEGER NOT NULL CONSTRAINT "ck_scope_simulation_run__clock_mode" CHECK ("clock_mode" IN (1, 2)),
  "duration_ticks" INTEGER NOT NULL,
  "state" INTEGER NOT NULL CONSTRAINT "ck_scope_simulation_run__state" CHECK ("state" IN (1, 2, 3, 4, 5, 6, 7, 8, 9)),
  "terminal_reason" TEXT,
  "completed_ticks" INTEGER NOT NULL,
  "service_term_id" TEXT NOT NULL CONSTRAINT "ck_scope_simulation_run__service_term_id" CHECK (length("service_term_id") = 36 AND "service_term_id" GLOB '????????-????-????-????-????????????' AND "service_term_id" NOT GLOB '*[^0-9a-f-]*'),
  "rev" INTEGER NOT NULL CONSTRAINT "ck_scope_simulation_run__rev" CHECK ("rev" >= 0),
  "created_at" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL,
  "pacing_origin_at" INTEGER,
  "pacing_origin_tick" INTEGER NOT NULL,
  "next_due_at" INTEGER,
  "pacer_epoch" INTEGER NOT NULL,
  CONSTRAINT "pk_scope_simulation_run" PRIMARY KEY ("run_id"),
  CONSTRAINT "fk_scope_simulation_run__workspace_id" FOREIGN KEY ("workspace_id") REFERENCES "workspace_workspace" ("workspace_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_scope_simulation_run__scenario_version_id" FOREIGN KEY ("scenario_version_id") REFERENCES "scope_scenario_version" ("scenario_version_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_scope_simulation_run__service_term_id" FOREIGN KEY ("service_term_id") REFERENCES "entitlement_service_term" ("service_term_id") ON DELETE RESTRICT,
  CONSTRAINT "ck_scope_simulation_run__succeeded_complete" CHECK ("state" <> 8 OR "completed_ticks" = "duration_ticks")
) STRICT;

CREATE INDEX "ix_scope_simulation_run__workspace_id_state" ON "scope_simulation_run" ("workspace_id", "state");

CREATE INDEX "ix_scope_simulation_run__state_updated_at" ON "scope_simulation_run" ("state", "updated_at");

CREATE INDEX "ix_scope_simulation_run__state_next_due_at" ON "scope_simulation_run" ("state", "next_due_at");

CREATE INDEX "ix_scope_simulation_run__workspace_id_created_at_run_id" ON "scope_simulation_run" ("workspace_id", "created_at" DESC, "run_id" DESC);

CREATE INDEX "ix_scope_simulation_run__workspace_id_scenario_version_id_created_at_run_id" ON "scope_simulation_run" ("workspace_id", "scenario_version_id", "created_at" DESC, "run_id" DESC);

CREATE TRIGGER "tr_scope_simulation_run__monotonic_pacer_epoch" BEFORE UPDATE OF "pacer_epoch" ON "scope_simulation_run"
WHEN NEW."pacer_epoch" < OLD."pacer_epoch"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_monotonic_scope_simulation_run_pacer_epoch');
END;

CREATE TABLE "scope_simulation_segment" (
  "segment_id" TEXT NOT NULL CONSTRAINT "ck_scope_simulation_segment__segment_id" CHECK (length("segment_id") = 36 AND "segment_id" GLOB '????????-????-????-????-????????????' AND "segment_id" NOT GLOB '*[^0-9a-f-]*'),
  "run_id" TEXT NOT NULL CONSTRAINT "ck_scope_simulation_segment__run_id" CHECK (length("run_id") = 36 AND "run_id" GLOB '????????-????-????-????-????????????' AND "run_id" NOT GLOB '*[^0-9a-f-]*'),
  "sequence" INTEGER NOT NULL,
  "logical_from_tick" INTEGER NOT NULL,
  "logical_to_tick" INTEGER NOT NULL,
  "sample_count" INTEGER NOT NULL,
  "encoding" TEXT NOT NULL,
  "byte_length" INTEGER NOT NULL,
  "content_hash" BLOB NOT NULL,
  "object_key" TEXT NOT NULL,
  "fence_token" INTEGER NOT NULL,
  CONSTRAINT "pk_scope_simulation_segment" PRIMARY KEY ("segment_id"),
  CONSTRAINT "fk_scope_simulation_segment__run_id" FOREIGN KEY ("run_id") REFERENCES "scope_simulation_run" ("run_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_scope_simulation_segment__run_id_sequence" ON "scope_simulation_segment" ("run_id", "sequence");

CREATE UNIQUE INDEX "ux_scope_simulation_segment__run_id_logical_from_tick" ON "scope_simulation_segment" ("run_id", "logical_from_tick");

CREATE TABLE "scope_synced_aggregate" (
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_scope_synced_aggregate__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "aggregate_kind" TEXT NOT NULL,
  "aggregate_id" TEXT NOT NULL CONSTRAINT "ck_scope_synced_aggregate__aggregate_id" CHECK (length("aggregate_id") = 36 AND "aggregate_id" GLOB '????????-????-????-????-????????????' AND "aggregate_id" NOT GLOB '*[^0-9a-f-]*'),
  "rev" INTEGER NOT NULL CONSTRAINT "ck_scope_synced_aggregate__rev" CHECK ("rev" >= 0),
  "schema_version" TEXT NOT NULL,
  "payload_proto" BLOB NOT NULL,
  "source_device_id" TEXT NOT NULL CONSTRAINT "ck_scope_synced_aggregate__source_device_id" CHECK (length("source_device_id") = 36 AND "source_device_id" GLOB '????????-????-????-????-????????????' AND "source_device_id" NOT GLOB '*[^0-9a-f-]*'),
  "content_rev" INTEGER NOT NULL,
  "state" INTEGER NOT NULL CONSTRAINT "ck_scope_synced_aggregate__state" CHECK ("state" IN (1, 2)),
  "created_at" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL,
  "deleted_at" INTEGER,
  CONSTRAINT "pk_scope_synced_aggregate" PRIMARY KEY ("workspace_id", "aggregate_kind", "aggregate_id"),
  CONSTRAINT "ck_scope_synced_aggregate__state_deleted_at_agree" CHECK (("state" = 2) = ("deleted_at" IS NOT NULL))
) STRICT;

CREATE INDEX "ix_scope_synced_aggregate__workspace_id_aggregate_kind_state_aggregate_id" ON "scope_synced_aggregate" ("workspace_id", "aggregate_kind", "state", "aggregate_id");
