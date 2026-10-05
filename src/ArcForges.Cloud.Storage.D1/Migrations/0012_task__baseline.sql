-- af-migration: module=task mode=expand
-- Baseline physical schema of the task owner (generated from Physical/manifest/task.json; Design D1 profile section 2).
CREATE TABLE "task_approval" (
  "approval_id" TEXT NOT NULL CONSTRAINT "ck_task_approval__approval_id" CHECK (length("approval_id") = 36 AND "approval_id" GLOB '????????-????-????-????-????????????' AND "approval_id" NOT GLOB '*[^0-9a-f-]*'),
  "task_id" TEXT NOT NULL CONSTRAINT "ck_task_approval__task_id" CHECK (length("task_id") = 36 AND "task_id" GLOB '????????-????-????-????-????????????' AND "task_id" NOT GLOB '*[^0-9a-f-]*'),
  "run_id" TEXT NOT NULL CONSTRAINT "ck_task_approval__run_id" CHECK (length("run_id") = 36 AND "run_id" GLOB '????????-????-????-????-????????????' AND "run_id" NOT GLOB '*[^0-9a-f-]*'),
  "step_id" TEXT NOT NULL CONSTRAINT "ck_task_approval__step_id" CHECK (length("step_id") = 36 AND "step_id" GLOB '????????-????-????-????-????????????' AND "step_id" NOT GLOB '*[^0-9a-f-]*'),
  "proposal_hash" BLOB NOT NULL CONSTRAINT "ck_task_approval__proposal_hash" CHECK (length("proposal_hash") = 32),
  "actor_proto" BLOB NOT NULL,
  "frozen_context_proto" BLOB NOT NULL,
  "risk" TEXT NOT NULL CONSTRAINT "ck_task_approval__risk" CHECK (length("risk") BETWEEN 1 AND 128 AND "risk" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "local_presence_required" INTEGER NOT NULL CONSTRAINT "ck_task_approval__local_presence_required" CHECK ("local_presence_required" IN (0, 1)),
  "description" TEXT NOT NULL,
  "state" INTEGER NOT NULL CONSTRAINT "ck_task_approval__state" CHECK ("state" IN (1, 2, 3, 4, 5)),
  "decision_by" TEXT CONSTRAINT "ck_task_approval__decision_by" CHECK (length("decision_by") = 36 AND "decision_by" GLOB '????????-????-????-????-????????????' AND "decision_by" NOT GLOB '*[^0-9a-f-]*'),
  "created_at" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  "decided_at" INTEGER,
  "consumed_at" INTEGER,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_task_approval__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_task_approval" PRIMARY KEY ("approval_id"),
  CONSTRAINT "fk_task_approval__task_id" FOREIGN KEY ("task_id") REFERENCES "task_task" ("task_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_task_approval__run_id" FOREIGN KEY ("run_id") REFERENCES "task_run" ("run_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_task_approval__step_id" FOREIGN KEY ("step_id") REFERENCES "task_plan_step" ("plan_step_id") ON DELETE RESTRICT
) STRICT;

CREATE INDEX "ix_task_approval__task_id_state_expires_at" ON "task_approval" ("task_id", "state", "expires_at");

CREATE TABLE "task_attempt" (
  "attempt_id" TEXT NOT NULL CONSTRAINT "ck_task_attempt__attempt_id" CHECK (length("attempt_id") = 36 AND "attempt_id" GLOB '????????-????-????-????-????????????' AND "attempt_id" NOT GLOB '*[^0-9a-f-]*'),
  "run_id" TEXT NOT NULL CONSTRAINT "ck_task_attempt__run_id" CHECK (length("run_id") = 36 AND "run_id" GLOB '????????-????-????-????-????????????' AND "run_id" NOT GLOB '*[^0-9a-f-]*'),
  "step_id" TEXT NOT NULL CONSTRAINT "ck_task_attempt__step_id" CHECK (length("step_id") = 36 AND "step_id" GLOB '????????-????-????-????-????????????' AND "step_id" NOT GLOB '*[^0-9a-f-]*'),
  "command_id" TEXT NOT NULL CONSTRAINT "ck_task_attempt__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  "state" INTEGER NOT NULL CONSTRAINT "ck_task_attempt__state" CHECK ("state" IN (1, 2, 3, 4, 5)),
  "attempt_ordinal" INTEGER NOT NULL CONSTRAINT "ck_task_attempt__attempt_ordinal" CHECK ("attempt_ordinal" BETWEEN -2147483648 AND 2147483647),
  "failure_class" INTEGER CONSTRAINT "ck_task_attempt__failure_class" CHECK ("failure_class" IN (1, 2, 3, 4, 5)),
  "effect_certainty" INTEGER CONSTRAINT "ck_task_attempt__effect_certainty" CHECK ("effect_certainty" IN (1, 2, 3)),
  "started_at" INTEGER,
  "ended_at" INTEGER,
  CONSTRAINT "pk_task_attempt" PRIMARY KEY ("attempt_id")
) STRICT;

CREATE UNIQUE INDEX "ux_task_attempt__command_id_attempt_ordinal" ON "task_attempt" ("command_id", "attempt_ordinal");

CREATE TABLE "task_automation_definition" (
  "automation_id" TEXT NOT NULL CONSTRAINT "ck_task_automation_definition__automation_id" CHECK (length("automation_id") = 36 AND "automation_id" GLOB '????????-????-????-????-????????????' AND "automation_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_task_automation_definition__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "product_id" TEXT NOT NULL CONSTRAINT "ck_task_automation_definition__product_id" CHECK ("product_id" IN ('arcscope', 'companion')),
  "definition_version" INTEGER NOT NULL,
  "definition_proto" BLOB NOT NULL,
  "enabled" INTEGER NOT NULL CONSTRAINT "ck_task_automation_definition__enabled" CHECK ("enabled" IN (0, 1)),
  "next_due_at" INTEGER,
  "event_cursor" TEXT,
  "created_at" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_task_automation_definition__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_task_automation_definition" PRIMARY KEY ("automation_id"),
  CONSTRAINT "fk_task_automation_definition__workspace_id" FOREIGN KEY ("workspace_id") REFERENCES "workspace_workspace" ("workspace_id") ON DELETE RESTRICT
) STRICT;

CREATE INDEX "ix_task_automation_definition__enabled_next_due_at" ON "task_automation_definition" ("enabled", "next_due_at");

CREATE TABLE "task_automation_occurrence" (
  "occurrence_id" TEXT NOT NULL CONSTRAINT "ck_task_automation_occurrence__occurrence_id" CHECK (length("occurrence_id") = 36 AND "occurrence_id" GLOB '????????-????-????-????-????????????' AND "occurrence_id" NOT GLOB '*[^0-9a-f-]*'),
  "automation_id" TEXT NOT NULL CONSTRAINT "ck_task_automation_occurrence__automation_id" CHECK (length("automation_id") = 36 AND "automation_id" GLOB '????????-????-????-????-????????????' AND "automation_id" NOT GLOB '*[^0-9a-f-]*'),
  "definition_version" INTEGER NOT NULL,
  "occurrence_key" TEXT NOT NULL,
  "scheduled_at" INTEGER NOT NULL,
  "event_id" TEXT CONSTRAINT "ck_task_automation_occurrence__event_id" CHECK (length("event_id") = 36 AND "event_id" GLOB '????????-????-????-????-????????????' AND "event_id" NOT GLOB '*[^0-9a-f-]*'),
  "state" INTEGER NOT NULL CONSTRAINT "ck_task_automation_occurrence__state" CHECK ("state" IN (1, 2, 3, 4, 5, 6)),
  "task_id" TEXT CONSTRAINT "ck_task_automation_occurrence__task_id" CHECK (length("task_id") = 36 AND "task_id" GLOB '????????-????-????-????-????????????' AND "task_id" NOT GLOB '*[^0-9a-f-]*'),
  "reason" TEXT CONSTRAINT "ck_task_automation_occurrence__reason" CHECK (length("reason") BETWEEN 1 AND 128 AND "reason" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "completed_at" INTEGER,
  CONSTRAINT "pk_task_automation_occurrence" PRIMARY KEY ("occurrence_id"),
  CONSTRAINT "fk_task_automation_occurrence__automation_id" FOREIGN KEY ("automation_id") REFERENCES "task_automation_definition" ("automation_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_task_automation_occurrence__automation_id_definition_version_occurrence_key" ON "task_automation_occurrence" ("automation_id", "definition_version", "occurrence_key");

CREATE INDEX "ix_task_automation_occurrence__state_scheduled_at" ON "task_automation_occurrence" ("state", "scheduled_at");

CREATE TABLE "task_cf_instance_inventory" (
  "kind" TEXT NOT NULL,
  "instance_id" TEXT NOT NULL,
  "recovery_generation" INTEGER NOT NULL,
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_task_cf_instance_inventory__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "owner_job_id" TEXT NOT NULL CONSTRAINT "ck_task_cf_instance_inventory__owner_job_id" CHECK (length("owner_job_id") = 36 AND "owner_job_id" GLOB '????????-????-????-????-????????????' AND "owner_job_id" NOT GLOB '*[^0-9a-f-]*'),
  "worker_version" TEXT NOT NULL,
  "deletion_receipt" TEXT,
  "updated_at" INTEGER NOT NULL,
  CONSTRAINT "pk_task_cf_instance_inventory" PRIMARY KEY ("kind", "instance_id", "recovery_generation")
) STRICT;

CREATE TABLE "task_control_receipt" (
  "command_id" TEXT NOT NULL CONSTRAINT "ck_task_control_receipt__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  "owner_id" TEXT NOT NULL CONSTRAINT "ck_task_control_receipt__owner_id" CHECK (length("owner_id") = 36 AND "owner_id" GLOB '????????-????-????-????-????????????' AND "owner_id" NOT GLOB '*[^0-9a-f-]*'),
  "kind" TEXT NOT NULL CONSTRAINT "ck_task_control_receipt__kind" CHECK (length("kind") BETWEEN 1 AND 128 AND "kind" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "state" INTEGER NOT NULL CONSTRAINT "ck_task_control_receipt__state" CHECK ("state" IN (1, 2, 3, 4)),
  "requested_at" INTEGER NOT NULL,
  "acknowledged_at" INTEGER,
  "reason" TEXT CONSTRAINT "ck_task_control_receipt__reason" CHECK (length("reason") BETWEEN 1 AND 128 AND "reason" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "request_hash" BLOB NOT NULL CONSTRAINT "ck_task_control_receipt__request_hash" CHECK (length("request_hash") = 32),
  CONSTRAINT "pk_task_control_receipt" PRIMARY KEY ("command_id"),
  CONSTRAINT "fk_task_control_receipt__owner_id" FOREIGN KEY ("owner_id") REFERENCES "task_task" ("task_id") ON DELETE RESTRICT
) STRICT;

CREATE INDEX "ix_task_control_receipt__owner_id_requested_at" ON "task_control_receipt" ("owner_id", "requested_at");

CREATE TABLE "task_execution_command" (
  "command_id" TEXT NOT NULL CONSTRAINT "ck_task_execution_command__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  "run_id" TEXT NOT NULL CONSTRAINT "ck_task_execution_command__run_id" CHECK (length("run_id") = 36 AND "run_id" GLOB '????????-????-????-????-????????????' AND "run_id" NOT GLOB '*[^0-9a-f-]*'),
  "epoch" INTEGER NOT NULL,
  "operation" TEXT NOT NULL,
  "request_sha256" TEXT NOT NULL,
  "state" TEXT NOT NULL,
  "result_ref" TEXT CONSTRAINT "ck_task_execution_command__result_ref" CHECK (json_valid("result_ref")),
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_task_execution_command" PRIMARY KEY ("command_id"),
  CONSTRAINT "fk_task_execution_command__run_id" FOREIGN KEY ("run_id") REFERENCES "task_run" ("run_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_task_execution_command__run_id_operation_command_id" ON "task_execution_command" ("run_id", "operation", "command_id");

CREATE TABLE "task_execution_lease" (
  "run_id" TEXT NOT NULL CONSTRAINT "ck_task_execution_lease__run_id" CHECK (length("run_id") = 36 AND "run_id" GLOB '????????-????-????-????-????????????' AND "run_id" NOT GLOB '*[^0-9a-f-]*'),
  "holder" TEXT NOT NULL,
  "workflow_id" TEXT NOT NULL,
  "worker_version" TEXT NOT NULL,
  "epoch" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  "recovery_generation" INTEGER NOT NULL,
  CONSTRAINT "pk_task_execution_lease" PRIMARY KEY ("run_id"),
  CONSTRAINT "fk_task_execution_lease__run_id" FOREIGN KEY ("run_id") REFERENCES "task_run" ("run_id") ON DELETE RESTRICT
) STRICT;

CREATE INDEX "ix_task_execution_lease__expires_at" ON "task_execution_lease" ("expires_at");

CREATE TABLE "task_iteration_output" (
  "output_id" TEXT NOT NULL CONSTRAINT "ck_task_iteration_output__output_id" CHECK (length("output_id") = 36 AND "output_id" GLOB '????????-????-????-????-????????????' AND "output_id" NOT GLOB '*[^0-9a-f-]*'),
  "run_id" TEXT NOT NULL CONSTRAINT "ck_task_iteration_output__run_id" CHECK (length("run_id") = 36 AND "run_id" GLOB '????????-????-????-????-????????????' AND "run_id" NOT GLOB '*[^0-9a-f-]*'),
  "iteration_ordinal" INTEGER NOT NULL CONSTRAINT "ck_task_iteration_output__iteration_ordinal" CHECK ("iteration_ordinal" BETWEEN -2147483648 AND 2147483647),
  "logical_request_id" TEXT NOT NULL CONSTRAINT "ck_task_iteration_output__logical_request_id" CHECK (length("logical_request_id") = 36 AND "logical_request_id" GLOB '????????-????-????-????-????????????' AND "logical_request_id" NOT GLOB '*[^0-9a-f-]*'),
  "provider_attempt_id" TEXT NOT NULL CONSTRAINT "ck_task_iteration_output__provider_attempt_id" CHECK (length("provider_attempt_id") = 36 AND "provider_attempt_id" GLOB '????????-????-????-????-????????????' AND "provider_attempt_id" NOT GLOB '*[^0-9a-f-]*'),
  "state" INTEGER NOT NULL CONSTRAINT "ck_task_iteration_output__state" CHECK ("state" IN (1, 2, 3, 4)),
  "parts_proto" BLOB,
  "body_resource_id" TEXT CONSTRAINT "ck_task_iteration_output__body_resource_id" CHECK (length("body_resource_id") = 36 AND "body_resource_id" GLOB '????????-????-????-????-????????????' AND "body_resource_id" NOT GLOB '*[^0-9a-f-]*'),
  "checksum" BLOB NOT NULL CONSTRAINT "ck_task_iteration_output__checksum" CHECK (length("checksum") = 32),
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_task_iteration_output" PRIMARY KEY ("output_id"),
  CONSTRAINT "fk_task_iteration_output__run_id" FOREIGN KEY ("run_id") REFERENCES "task_run" ("run_id") ON DELETE RESTRICT,
  CONSTRAINT "ck_task_iteration_output__exactly_one_body" CHECK (("parts_proto" IS NULL) <> ("body_resource_id" IS NULL))
) STRICT;

CREATE UNIQUE INDEX "ux_task_iteration_output__run_id_iteration_ordinal" ON "task_iteration_output" ("run_id", "iteration_ordinal");

CREATE TRIGGER "tr_task_iteration_output__immutable_update" BEFORE UPDATE ON "task_iteration_output"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_task_iteration_output');
END;

CREATE TABLE "task_plan_step" (
  "plan_step_id" TEXT NOT NULL CONSTRAINT "ck_task_plan_step__plan_step_id" CHECK (length("plan_step_id") = 36 AND "plan_step_id" GLOB '????????-????-????-????-????????????' AND "plan_step_id" NOT GLOB '*[^0-9a-f-]*'),
  "run_id" TEXT NOT NULL CONSTRAINT "ck_task_plan_step__run_id" CHECK (length("run_id") = 36 AND "run_id" GLOB '????????-????-????-????-????????????' AND "run_id" NOT GLOB '*[^0-9a-f-]*'),
  "step_ordinal" INTEGER NOT NULL CONSTRAINT "ck_task_plan_step__step_ordinal" CHECK ("step_ordinal" BETWEEN -2147483648 AND 2147483647),
  "capability_key" TEXT NOT NULL,
  "tool_locality" INTEGER NOT NULL CONSTRAINT "ck_task_plan_step__tool_locality" CHECK ("tool_locality" IN (1, 2)),
  "target_device_id" TEXT CONSTRAINT "ck_task_plan_step__target_device_id" CHECK (length("target_device_id") = 36 AND "target_device_id" GLOB '????????-????-????-????-????????????' AND "target_device_id" NOT GLOB '*[^0-9a-f-]*'),
  "target_product_id" TEXT CONSTRAINT "ck_task_plan_step__target_product_id" CHECK ("target_product_id" IN ('arcscope', 'companion')),
  "target_installation_id" TEXT CONSTRAINT "ck_task_plan_step__target_installation_id" CHECK (length("target_installation_id") = 36 AND "target_installation_id" GLOB '????????-????-????-????-????????????' AND "target_installation_id" NOT GLOB '*[^0-9a-f-]*'),
  "target_instance_epoch" INTEGER,
  "arguments_proto" BLOB NOT NULL,
  "approval_required" INTEGER NOT NULL CONSTRAINT "ck_task_plan_step__approval_required" CHECK ("approval_required" IN (0, 1)),
  "compensation_proto" BLOB,
  "state" TEXT NOT NULL,
  "reason_facet" TEXT,
  CONSTRAINT "pk_task_plan_step" PRIMARY KEY ("plan_step_id"),
  CONSTRAINT "fk_task_plan_step__run_id" FOREIGN KEY ("run_id") REFERENCES "task_run" ("run_id") ON DELETE CASCADE,
  CONSTRAINT "ck_task_plan_step__locality_target" CHECK (("tool_locality" = 2 AND "target_device_id" IS NOT NULL AND "target_product_id" IS NOT NULL AND "target_installation_id" IS NOT NULL) OR ("tool_locality" = 1 AND "target_device_id" IS NULL AND "target_product_id" IS NULL AND "target_installation_id" IS NULL AND "target_instance_epoch" IS NULL))
) STRICT;

CREATE INDEX "ix_task_plan_step__target_device_id_target_installation_id_state" ON "task_plan_step" ("target_device_id", "target_installation_id", "state");

CREATE TABLE "task_run" (
  "run_id" TEXT NOT NULL CONSTRAINT "ck_task_run__run_id" CHECK (length("run_id") = 36 AND "run_id" GLOB '????????-????-????-????-????????????' AND "run_id" NOT GLOB '*[^0-9a-f-]*'),
  "task_id" TEXT NOT NULL CONSTRAINT "ck_task_run__task_id" CHECK (length("task_id") = 36 AND "task_id" GLOB '????????-????-????-????-????????????' AND "task_id" NOT GLOB '*[^0-9a-f-]*'),
  "ordinal" INTEGER NOT NULL CONSTRAINT "ck_task_run__ordinal" CHECK ("ordinal" BETWEEN -2147483648 AND 2147483647),
  "state" INTEGER NOT NULL CONSTRAINT "ck_task_run__state" CHECK ("state" IN (1, 2, 3, 4, 5, 6, 7, 8, 9)),
  "workflow_id" TEXT NOT NULL,
  "worker_version" TEXT NOT NULL,
  "recovery_generation" INTEGER NOT NULL,
  "last_iteration_receipt" BLOB CONSTRAINT "ck_task_run__last_iteration_receipt" CHECK (length("last_iteration_receipt") = 32),
  "created_at" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_task_run__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_task_run" PRIMARY KEY ("run_id"),
  CONSTRAINT "fk_task_run__task_id" FOREIGN KEY ("task_id") REFERENCES "task_task" ("task_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_task_run__task_id_ordinal" ON "task_run" ("task_id", "ordinal");

CREATE INDEX "ix_task_run__state_updated_at" ON "task_run" ("state", "updated_at");

CREATE TABLE "task_task" (
  "task_id" TEXT NOT NULL CONSTRAINT "ck_task_task__task_id" CHECK (length("task_id") = 36 AND "task_id" GLOB '????????-????-????-????-????????????' AND "task_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_task_task__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "origin_surface" INTEGER NOT NULL CONSTRAINT "ck_task_task__origin_surface" CHECK ("origin_surface" IN (1, 2, 3, 4)),
  "origin_device_id" TEXT CONSTRAINT "ck_task_task__origin_device_id" CHECK (length("origin_device_id") = 36 AND "origin_device_id" GLOB '????????-????-????-????-????????????' AND "origin_device_id" NOT GLOB '*[^0-9a-f-]*'),
  "state" INTEGER NOT NULL CONSTRAINT "ck_task_task__state" CHECK ("state" IN (1, 2, 3, 4, 5, 6, 7, 8, 9)),
  "reason_facet" INTEGER NOT NULL CONSTRAINT "ck_task_task__reason_facet" CHECK ("reason_facet" IN (1, 2, 3, 4, 5, 6)),
  "intent_summary" TEXT NOT NULL,
  "created_at" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_task_task__rev" CHECK ("rev" >= 0),
  "product_id" TEXT NOT NULL CONSTRAINT "ck_task_task__product_id" CHECK ("product_id" IN ('arcscope', 'companion')),
  "origin_installation_id" TEXT CONSTRAINT "ck_task_task__origin_installation_id" CHECK (length("origin_installation_id") = 36 AND "origin_installation_id" GLOB '????????-????-????-????-????????????' AND "origin_installation_id" NOT GLOB '*[^0-9a-f-]*'),
  "transient_input_ref" TEXT CONSTRAINT "ck_task_task__transient_input_ref" CHECK (length("transient_input_ref") = 36 AND "transient_input_ref" GLOB '????????-????-????-????-????????????' AND "transient_input_ref" NOT GLOB '*[^0-9a-f-]*'),
  "transient_output_receipt_id" TEXT CONSTRAINT "ck_task_task__transient_output_receipt_id" CHECK (length("transient_output_receipt_id") = 36 AND "transient_output_receipt_id" GLOB '????????-????-????-????-????????????' AND "transient_output_receipt_id" NOT GLOB '*[^0-9a-f-]*'),
  "current_iteration" INTEGER NOT NULL CONSTRAINT "ck_task_task__current_iteration" CHECK ("current_iteration" BETWEEN -2147483648 AND 2147483647),
  "current_provider_attempt_id" TEXT CONSTRAINT "ck_task_task__current_provider_attempt_id" CHECK (length("current_provider_attempt_id") = 36 AND "current_provider_attempt_id" GLOB '????????-????-????-????-????????????' AND "current_provider_attempt_id" NOT GLOB '*[^0-9a-f-]*'),
  "final_message_id" TEXT CONSTRAINT "ck_task_task__final_message_id" CHECK (length("final_message_id") = 36 AND "final_message_id" GLOB '????????-????-????-????-????????????' AND "final_message_id" NOT GLOB '*[^0-9a-f-]*'),
  "terminal_output_commit_id" TEXT CONSTRAINT "ck_task_task__terminal_output_commit_id" CHECK (length("terminal_output_commit_id") = 36 AND "terminal_output_commit_id" GLOB '????????-????-????-????-????????????' AND "terminal_output_commit_id" NOT GLOB '*[^0-9a-f-]*'),
  "no_answer_reason" TEXT CONSTRAINT "ck_task_task__no_answer_reason" CHECK (length("no_answer_reason") BETWEEN 1 AND 128 AND "no_answer_reason" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "has_unknown_effect" INTEGER NOT NULL CONSTRAINT "ck_task_task__has_unknown_effect" CHECK ("has_unknown_effect" IN (0, 1)),
  "history_mode" INTEGER NOT NULL CONSTRAINT "ck_task_task__history_mode" CHECK ("history_mode" IN (1, 2)),
  CONSTRAINT "pk_task_task" PRIMARY KEY ("task_id"),
  CONSTRAINT "ck_task_task__waiting_facet" CHECK (("state" = 3) = ("reason_facet" <> 1)),
  CONSTRAINT "ck_task_task__current_iteration_nonnegative" CHECK ("current_iteration" >= 0),
  CONSTRAINT "ck_task_task__local_history_has_origin_installation" CHECK ("history_mode" <> 1 OR "origin_installation_id" IS NOT NULL),
  CONSTRAINT "ck_task_task__cloud_history_has_no_transient_refs" CHECK ("history_mode" <> 2 OR ("transient_input_ref" IS NULL AND "transient_output_receipt_id" IS NULL))
) STRICT;

CREATE INDEX "ix_task_task__workspace_id_state_updated_at" ON "task_task" ("workspace_id", "state", "updated_at");

CREATE TABLE "task_tool_request" (
  "tool_request_id" TEXT NOT NULL CONSTRAINT "ck_task_tool_request__tool_request_id" CHECK (length("tool_request_id") = 36 AND "tool_request_id" GLOB '????????-????-????-????-????????????' AND "tool_request_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_task_tool_request__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "product_id" TEXT NOT NULL CONSTRAINT "ck_task_tool_request__product_id" CHECK ("product_id" IN ('arcscope', 'companion')),
  "task_id" TEXT NOT NULL CONSTRAINT "ck_task_tool_request__task_id" CHECK (length("task_id") = 36 AND "task_id" GLOB '????????-????-????-????-????????????' AND "task_id" NOT GLOB '*[^0-9a-f-]*'),
  "run_id" TEXT NOT NULL CONSTRAINT "ck_task_tool_request__run_id" CHECK (length("run_id") = 36 AND "run_id" GLOB '????????-????-????-????-????????????' AND "run_id" NOT GLOB '*[^0-9a-f-]*'),
  "step_id" TEXT NOT NULL CONSTRAINT "ck_task_tool_request__step_id" CHECK (length("step_id") = 36 AND "step_id" GLOB '????????-????-????-????-????????????' AND "step_id" NOT GLOB '*[^0-9a-f-]*'),
  "attempt_id" TEXT NOT NULL CONSTRAINT "ck_task_tool_request__attempt_id" CHECK (length("attempt_id") = 36 AND "attempt_id" GLOB '????????-????-????-????-????????????' AND "attempt_id" NOT GLOB '*[^0-9a-f-]*'),
  "command_id" TEXT NOT NULL CONSTRAINT "ck_task_tool_request__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  "target_device_id" TEXT CONSTRAINT "ck_task_tool_request__target_device_id" CHECK (length("target_device_id") = 36 AND "target_device_id" GLOB '????????-????-????-????-????????????' AND "target_device_id" NOT GLOB '*[^0-9a-f-]*'),
  "target_installation_id" TEXT CONSTRAINT "ck_task_tool_request__target_installation_id" CHECK (length("target_installation_id") = 36 AND "target_installation_id" GLOB '????????-????-????-????-????????????' AND "target_installation_id" NOT GLOB '*[^0-9a-f-]*'),
  "target_product_id" TEXT CONSTRAINT "ck_task_tool_request__target_product_id" CHECK ("target_product_id" IN ('arcscope', 'companion')),
  "target_instance_epoch" INTEGER,
  "capability" TEXT NOT NULL,
  "arguments_proto" BLOB NOT NULL,
  "context_proto" BLOB NOT NULL,
  "actor_proto" BLOB NOT NULL,
  "approval_id" TEXT CONSTRAINT "ck_task_tool_request__approval_id" CHECK (length("approval_id") = 36 AND "approval_id" GLOB '????????-????-????-????-????????????' AND "approval_id" NOT GLOB '*[^0-9a-f-]*'),
  "expires_at" INTEGER NOT NULL,
  "state" INTEGER NOT NULL CONSTRAINT "ck_task_tool_request__state" CHECK ("state" IN (1, 2, 3, 4, 5)),
  "rev" INTEGER NOT NULL CONSTRAINT "ck_task_tool_request__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_task_tool_request" PRIMARY KEY ("tool_request_id"),
  CONSTRAINT "fk_task_tool_request__task_id" FOREIGN KEY ("task_id") REFERENCES "task_task" ("task_id") ON DELETE RESTRICT,
  CONSTRAINT "ck_task_tool_request__device_target_full_or_none" CHECK (("target_device_id" IS NOT NULL AND "target_installation_id" IS NOT NULL AND "target_product_id" IS NOT NULL) OR ("target_device_id" IS NULL AND "target_installation_id" IS NULL AND "target_product_id" IS NULL AND "target_instance_epoch" IS NULL))
) STRICT;

CREATE INDEX "ix_task_tool_request__workspace_id_target_installation_id_state_expires_at" ON "task_tool_request" ("workspace_id", "target_installation_id", "state", "expires_at");

CREATE TRIGGER "tr_task_tool_request__limited_update" BEFORE UPDATE ON "task_tool_request"
WHEN (OLD."arguments_proto" IS NOT NEW."arguments_proto" OR OLD."context_proto" IS NOT NEW."context_proto" OR OLD."actor_proto" IS NOT NEW."actor_proto")
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_task_tool_request');
END;

CREATE TABLE "task_tool_result" (
  "tool_request_id" TEXT NOT NULL CONSTRAINT "ck_task_tool_result__tool_request_id" CHECK (length("tool_request_id") = 36 AND "tool_request_id" GLOB '????????-????-????-????-????????????' AND "tool_request_id" NOT GLOB '*[^0-9a-f-]*'),
  "attempt_id" TEXT NOT NULL CONSTRAINT "ck_task_tool_result__attempt_id" CHECK (length("attempt_id") = 36 AND "attempt_id" GLOB '????????-????-????-????-????????????' AND "attempt_id" NOT GLOB '*[^0-9a-f-]*'),
  "command_id" TEXT NOT NULL CONSTRAINT "ck_task_tool_result__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  "result_hash" BLOB NOT NULL CONSTRAINT "ck_task_tool_result__result_hash" CHECK (length("result_hash") = 32),
  "body_proto" BLOB NOT NULL,
  "effect_certainty" INTEGER NOT NULL CONSTRAINT "ck_task_tool_result__effect_certainty" CHECK ("effect_certainty" IN (1, 2, 3)),
  "received_at" INTEGER NOT NULL,
  CONSTRAINT "pk_task_tool_result" PRIMARY KEY ("tool_request_id", "attempt_id", "command_id"),
  CONSTRAINT "fk_task_tool_result__tool_request_id" FOREIGN KEY ("tool_request_id") REFERENCES "task_tool_request" ("tool_request_id") ON DELETE RESTRICT
) STRICT;
