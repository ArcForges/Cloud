-- af-migration: module=chat mode=expand
-- Baseline physical schema of the chat owner (generated from Physical/manifest/chat.json; Design D1 profile section 2).
CREATE TABLE "chat_branch" (
  "branch_id" TEXT NOT NULL CONSTRAINT "ck_chat_branch__branch_id" CHECK (length("branch_id") = 36 AND "branch_id" GLOB '????????-????-????-????-????????????' AND "branch_id" NOT GLOB '*[^0-9a-f-]*'),
  "conversation_id" TEXT NOT NULL CONSTRAINT "ck_chat_branch__conversation_id" CHECK (length("conversation_id") = 36 AND "conversation_id" GLOB '????????-????-????-????-????????????' AND "conversation_id" NOT GLOB '*[^0-9a-f-]*'),
  "parent_branch_id" TEXT CONSTRAINT "ck_chat_branch__parent_branch_id" CHECK (length("parent_branch_id") = 36 AND "parent_branch_id" GLOB '????????-????-????-????-????????????' AND "parent_branch_id" NOT GLOB '*[^0-9a-f-]*'),
  "fork_message_id" TEXT CONSTRAINT "ck_chat_branch__fork_message_id" CHECK (length("fork_message_id") = 36 AND "fork_message_id" GLOB '????????-????-????-????-????????????' AND "fork_message_id" NOT GLOB '*[^0-9a-f-]*'),
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_chat_branch" PRIMARY KEY ("branch_id"),
  CONSTRAINT "fk_chat_branch__conversation_id" FOREIGN KEY ("conversation_id") REFERENCES "chat_conversation" ("conversation_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_chat_branch__parent_branch_id" FOREIGN KEY ("parent_branch_id") REFERENCES "chat_branch" ("branch_id") ON DELETE RESTRICT
) STRICT;

CREATE TABLE "chat_cf_instance_inventory" (
  "kind" TEXT NOT NULL,
  "instance_id" TEXT NOT NULL,
  "recovery_generation" INTEGER NOT NULL,
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_chat_cf_instance_inventory__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "owner_job_id" TEXT NOT NULL CONSTRAINT "ck_chat_cf_instance_inventory__owner_job_id" CHECK (length("owner_job_id") = 36 AND "owner_job_id" GLOB '????????-????-????-????-????????????' AND "owner_job_id" NOT GLOB '*[^0-9a-f-]*'),
  "worker_version" TEXT NOT NULL,
  "deletion_receipt" TEXT,
  "updated_at" INTEGER NOT NULL,
  CONSTRAINT "pk_chat_cf_instance_inventory" PRIMARY KEY ("kind", "instance_id", "recovery_generation")
) STRICT;

CREATE TABLE "chat_compaction_record" (
  "compaction_id" TEXT NOT NULL CONSTRAINT "ck_chat_compaction_record__compaction_id" CHECK (length("compaction_id") = 36 AND "compaction_id" GLOB '????????-????-????-????-????????????' AND "compaction_id" NOT GLOB '*[^0-9a-f-]*'),
  "conversation_id" TEXT NOT NULL CONSTRAINT "ck_chat_compaction_record__conversation_id" CHECK (length("conversation_id") = 36 AND "conversation_id" GLOB '????????-????-????-????-????????????' AND "conversation_id" NOT GLOB '*[^0-9a-f-]*'),
  "branch_id" TEXT NOT NULL CONSTRAINT "ck_chat_compaction_record__branch_id" CHECK (length("branch_id") = 36 AND "branch_id" GLOB '????????-????-????-????-????????????' AND "branch_id" NOT GLOB '*[^0-9a-f-]*'),
  "through_ordinal" INTEGER NOT NULL,
  "source_hash" BLOB NOT NULL CONSTRAINT "ck_chat_compaction_record__source_hash" CHECK (length("source_hash") = 32),
  "summary_resource_id" TEXT NOT NULL CONSTRAINT "ck_chat_compaction_record__summary_resource_id" CHECK (length("summary_resource_id") = 36 AND "summary_resource_id" GLOB '????????-????-????-????-????????????' AND "summary_resource_id" NOT GLOB '*[^0-9a-f-]*'),
  "summary_hash" BLOB NOT NULL CONSTRAINT "ck_chat_compaction_record__summary_hash" CHECK (length("summary_hash") = 32),
  "model_id" TEXT NOT NULL,
  "config_version" TEXT NOT NULL,
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_chat_compaction_record" PRIMARY KEY ("compaction_id"),
  CONSTRAINT "fk_chat_compaction_record__conversation_id" FOREIGN KEY ("conversation_id") REFERENCES "chat_conversation" ("conversation_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_chat_compaction_record__branch_id" FOREIGN KEY ("branch_id") REFERENCES "chat_branch" ("branch_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_chat_compaction_record__branch_id_through_ordinal_source_hash_config_version" ON "chat_compaction_record" ("branch_id", "through_ordinal", "source_hash", "config_version");

CREATE TABLE "chat_control_receipt" (
  "command_id" TEXT NOT NULL CONSTRAINT "ck_chat_control_receipt__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  "owner_id" TEXT NOT NULL CONSTRAINT "ck_chat_control_receipt__owner_id" CHECK (length("owner_id") = 36 AND "owner_id" GLOB '????????-????-????-????-????????????' AND "owner_id" NOT GLOB '*[^0-9a-f-]*'),
  "kind" TEXT NOT NULL CONSTRAINT "ck_chat_control_receipt__kind" CHECK (length("kind") BETWEEN 1 AND 128 AND "kind" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "state" INTEGER NOT NULL CONSTRAINT "ck_chat_control_receipt__state" CHECK ("state" IN (1, 2, 3, 4)),
  "requested_at" INTEGER NOT NULL,
  "acknowledged_at" INTEGER,
  "reason" TEXT CONSTRAINT "ck_chat_control_receipt__reason" CHECK (length("reason") BETWEEN 1 AND 128 AND "reason" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "request_hash" BLOB NOT NULL CONSTRAINT "ck_chat_control_receipt__request_hash" CHECK (length("request_hash") = 32),
  CONSTRAINT "pk_chat_control_receipt" PRIMARY KEY ("command_id"),
  CONSTRAINT "fk_chat_control_receipt__owner_id" FOREIGN KEY ("owner_id") REFERENCES "chat_turn" ("turn_id") ON DELETE RESTRICT
) STRICT;

CREATE INDEX "ix_chat_control_receipt__owner_id_requested_at" ON "chat_control_receipt" ("owner_id", "requested_at");

CREATE TABLE "chat_conversation" (
  "conversation_id" TEXT NOT NULL CONSTRAINT "ck_chat_conversation__conversation_id" CHECK (length("conversation_id") = 36 AND "conversation_id" GLOB '????????-????-????-????-????????????' AND "conversation_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_chat_conversation__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "product_id" TEXT NOT NULL CONSTRAINT "ck_chat_conversation__product_id" CHECK ("product_id" IN ('arcscope', 'companion')),
  "title" TEXT NOT NULL,
  "active_branch_id" TEXT NOT NULL CONSTRAINT "ck_chat_conversation__active_branch_id" CHECK (length("active_branch_id") = 36 AND "active_branch_id" GLOB '????????-????-????-????-????????????' AND "active_branch_id" NOT GLOB '*[^0-9a-f-]*'),
  "project_id" TEXT CONSTRAINT "ck_chat_conversation__project_id" CHECK (length("project_id") = 36 AND "project_id" GLOB '????????-????-????-????-????????????' AND "project_id" NOT GLOB '*[^0-9a-f-]*'),
  "mode" TEXT NOT NULL CONSTRAINT "ck_chat_conversation__mode" CHECK (length("mode") BETWEEN 1 AND 128 AND "mode" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "created_at" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL,
  "deleted_at" INTEGER,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_chat_conversation__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_chat_conversation" PRIMARY KEY ("conversation_id"),
  CONSTRAINT "ck_chat_conversation__mode_cloud" CHECK ("mode" = 'cloud')
) STRICT;

CREATE UNIQUE INDEX "ux_chat_conversation__workspace_id_product_id_conversation_id" ON "chat_conversation" ("workspace_id", "product_id", "conversation_id");

CREATE INDEX "ix_chat_conversation__workspace_id_product_id_deleted_at_updated_at_conversation_id" ON "chat_conversation" ("workspace_id", "product_id", "deleted_at", "updated_at", "conversation_id");

CREATE TABLE "chat_execution_command" (
  "command_id" TEXT NOT NULL CONSTRAINT "ck_chat_execution_command__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  "run_id" TEXT NOT NULL CONSTRAINT "ck_chat_execution_command__run_id" CHECK (length("run_id") = 36 AND "run_id" GLOB '????????-????-????-????-????????????' AND "run_id" NOT GLOB '*[^0-9a-f-]*'),
  "epoch" INTEGER NOT NULL,
  "operation" TEXT NOT NULL,
  "request_sha256" TEXT NOT NULL,
  "state" TEXT NOT NULL,
  "result_ref" TEXT CONSTRAINT "ck_chat_execution_command__result_ref" CHECK (json_valid("result_ref")),
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_chat_execution_command" PRIMARY KEY ("command_id"),
  CONSTRAINT "fk_chat_execution_command__run_id" FOREIGN KEY ("run_id") REFERENCES "chat_run" ("run_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_chat_execution_command__run_id_operation_command_id" ON "chat_execution_command" ("run_id", "operation", "command_id");

CREATE TABLE "chat_execution_lease" (
  "run_id" TEXT NOT NULL CONSTRAINT "ck_chat_execution_lease__run_id" CHECK (length("run_id") = 36 AND "run_id" GLOB '????????-????-????-????-????????????' AND "run_id" NOT GLOB '*[^0-9a-f-]*'),
  "holder" TEXT NOT NULL,
  "workflow_id" TEXT NOT NULL,
  "worker_version" TEXT NOT NULL,
  "epoch" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  "recovery_generation" INTEGER NOT NULL,
  CONSTRAINT "pk_chat_execution_lease" PRIMARY KEY ("run_id"),
  CONSTRAINT "fk_chat_execution_lease__run_id" FOREIGN KEY ("run_id") REFERENCES "chat_run" ("run_id") ON DELETE RESTRICT
) STRICT;

CREATE INDEX "ix_chat_execution_lease__expires_at" ON "chat_execution_lease" ("expires_at");

CREATE TABLE "chat_iteration_output" (
  "output_id" TEXT NOT NULL CONSTRAINT "ck_chat_iteration_output__output_id" CHECK (length("output_id") = 36 AND "output_id" GLOB '????????-????-????-????-????????????' AND "output_id" NOT GLOB '*[^0-9a-f-]*'),
  "run_id" TEXT NOT NULL CONSTRAINT "ck_chat_iteration_output__run_id" CHECK (length("run_id") = 36 AND "run_id" GLOB '????????-????-????-????-????????????' AND "run_id" NOT GLOB '*[^0-9a-f-]*'),
  "iteration_ordinal" INTEGER NOT NULL CONSTRAINT "ck_chat_iteration_output__iteration_ordinal" CHECK ("iteration_ordinal" BETWEEN -2147483648 AND 2147483647),
  "logical_request_id" TEXT NOT NULL CONSTRAINT "ck_chat_iteration_output__logical_request_id" CHECK (length("logical_request_id") = 36 AND "logical_request_id" GLOB '????????-????-????-????-????????????' AND "logical_request_id" NOT GLOB '*[^0-9a-f-]*'),
  "provider_attempt_id" TEXT NOT NULL CONSTRAINT "ck_chat_iteration_output__provider_attempt_id" CHECK (length("provider_attempt_id") = 36 AND "provider_attempt_id" GLOB '????????-????-????-????-????????????' AND "provider_attempt_id" NOT GLOB '*[^0-9a-f-]*'),
  "state" INTEGER NOT NULL CONSTRAINT "ck_chat_iteration_output__state" CHECK ("state" IN (1, 2, 3, 4)),
  "parts_proto" BLOB,
  "body_resource_id" TEXT CONSTRAINT "ck_chat_iteration_output__body_resource_id" CHECK (length("body_resource_id") = 36 AND "body_resource_id" GLOB '????????-????-????-????-????????????' AND "body_resource_id" NOT GLOB '*[^0-9a-f-]*'),
  "checksum" BLOB NOT NULL CONSTRAINT "ck_chat_iteration_output__checksum" CHECK (length("checksum") = 32),
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_chat_iteration_output" PRIMARY KEY ("output_id"),
  CONSTRAINT "fk_chat_iteration_output__run_id" FOREIGN KEY ("run_id") REFERENCES "chat_run" ("run_id") ON DELETE RESTRICT,
  CONSTRAINT "ck_chat_iteration_output__exactly_one_body" CHECK (("parts_proto" IS NULL) <> ("body_resource_id" IS NULL))
) STRICT;

CREATE UNIQUE INDEX "ux_chat_iteration_output__run_id_iteration_ordinal" ON "chat_iteration_output" ("run_id", "iteration_ordinal");

CREATE TRIGGER "tr_chat_iteration_output__immutable_update" BEFORE UPDATE ON "chat_iteration_output"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_chat_iteration_output');
END;

CREATE TABLE "chat_message" (
  "message_id" TEXT NOT NULL CONSTRAINT "ck_chat_message__message_id" CHECK (length("message_id") = 36 AND "message_id" GLOB '????????-????-????-????-????????????' AND "message_id" NOT GLOB '*[^0-9a-f-]*'),
  "conversation_id" TEXT NOT NULL CONSTRAINT "ck_chat_message__conversation_id" CHECK (length("conversation_id") = 36 AND "conversation_id" GLOB '????????-????-????-????-????????????' AND "conversation_id" NOT GLOB '*[^0-9a-f-]*'),
  "branch_id" TEXT NOT NULL CONSTRAINT "ck_chat_message__branch_id" CHECK (length("branch_id") = 36 AND "branch_id" GLOB '????????-????-????-????-????????????' AND "branch_id" NOT GLOB '*[^0-9a-f-]*'),
  "ordinal" INTEGER NOT NULL,
  "role" INTEGER NOT NULL CONSTRAINT "ck_chat_message__role" CHECK ("role" IN (1, 2, 3, 4)),
  "state" TEXT NOT NULL,
  "parts_proto" BLOB,
  "body_resource_id" TEXT CONSTRAINT "ck_chat_message__body_resource_id" CHECK (length("body_resource_id") = 36 AND "body_resource_id" GLOB '????????-????-????-????-????????????' AND "body_resource_id" NOT GLOB '*[^0-9a-f-]*'),
  "body_hash" BLOB NOT NULL CONSTRAINT "ck_chat_message__body_hash" CHECK (length("body_hash") = 32),
  "task_id" TEXT CONSTRAINT "ck_chat_message__task_id" CHECK (length("task_id") = 36 AND "task_id" GLOB '????????-????-????-????-????????????' AND "task_id" NOT GLOB '*[^0-9a-f-]*'),
  "turn_id" TEXT CONSTRAINT "ck_chat_message__turn_id" CHECK (length("turn_id") = 36 AND "turn_id" GLOB '????????-????-????-????-????????????' AND "turn_id" NOT GLOB '*[^0-9a-f-]*'),
  "created_at" INTEGER NOT NULL,
  "conversation_rev_at_commit" INTEGER NOT NULL CONSTRAINT "ck_chat_message__conversation_rev_at_commit" CHECK ("conversation_rev_at_commit" >= 0),
  CONSTRAINT "pk_chat_message" PRIMARY KEY ("message_id"),
  CONSTRAINT "fk_chat_message__conversation_id" FOREIGN KEY ("conversation_id") REFERENCES "chat_conversation" ("conversation_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_chat_message__branch_id" FOREIGN KEY ("branch_id") REFERENCES "chat_branch" ("branch_id") ON DELETE RESTRICT,
  CONSTRAINT "ck_chat_message__exactly_one_body" CHECK (("parts_proto" IS NULL) <> ("body_resource_id" IS NULL)),
  CONSTRAINT "ck_chat_message__task_or_turn_at_most_one" CHECK ("task_id" IS NULL OR "turn_id" IS NULL)
) STRICT;

CREATE UNIQUE INDEX "ux_chat_message__branch_id_ordinal" ON "chat_message" ("branch_id", "ordinal");

CREATE TRIGGER "tr_chat_message__immutable_update" BEFORE UPDATE ON "chat_message"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_chat_message');
END;

CREATE TABLE "chat_project" (
  "project_id" TEXT NOT NULL CONSTRAINT "ck_chat_project__project_id" CHECK (length("project_id") = 36 AND "project_id" GLOB '????????-????-????-????-????????????' AND "project_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_chat_project__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "product_id" TEXT NOT NULL CONSTRAINT "ck_chat_project__product_id" CHECK ("product_id" IN ('arcscope', 'companion')),
  "body_proto" BLOB NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_chat_project__rev" CHECK ("rev" >= 0),
  "deleted_at" INTEGER,
  CONSTRAINT "pk_chat_project" PRIMARY KEY ("project_id")
) STRICT;

CREATE INDEX "ix_chat_project__workspace_id_product_id_deleted_at" ON "chat_project" ("workspace_id", "product_id", "deleted_at");

CREATE TABLE "chat_run" (
  "run_id" TEXT NOT NULL CONSTRAINT "ck_chat_run__run_id" CHECK (length("run_id") = 36 AND "run_id" GLOB '????????-????-????-????-????????????' AND "run_id" NOT GLOB '*[^0-9a-f-]*'),
  "turn_id" TEXT NOT NULL CONSTRAINT "ck_chat_run__turn_id" CHECK (length("turn_id") = 36 AND "turn_id" GLOB '????????-????-????-????-????????????' AND "turn_id" NOT GLOB '*[^0-9a-f-]*'),
  "ordinal" INTEGER NOT NULL CONSTRAINT "ck_chat_run__ordinal" CHECK ("ordinal" BETWEEN -2147483648 AND 2147483647),
  "state" INTEGER NOT NULL CONSTRAINT "ck_chat_run__state" CHECK ("state" IN (1, 2, 3, 4, 5, 6, 7, 8, 9)),
  "workflow_id" TEXT NOT NULL,
  "worker_version" TEXT NOT NULL,
  "recovery_generation" INTEGER NOT NULL,
  "last_iteration_receipt" BLOB CONSTRAINT "ck_chat_run__last_iteration_receipt" CHECK (length("last_iteration_receipt") = 32),
  "created_at" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_chat_run__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_chat_run" PRIMARY KEY ("run_id"),
  CONSTRAINT "fk_chat_run__turn_id" FOREIGN KEY ("turn_id") REFERENCES "chat_turn" ("turn_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_chat_run__turn_id_ordinal" ON "chat_run" ("turn_id", "ordinal");

CREATE INDEX "ix_chat_run__state_updated_at" ON "chat_run" ("state", "updated_at");

CREATE TABLE "chat_tool_request" (
  "tool_request_id" TEXT NOT NULL CONSTRAINT "ck_chat_tool_request__tool_request_id" CHECK (length("tool_request_id") = 36 AND "tool_request_id" GLOB '????????-????-????-????-????????????' AND "tool_request_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_chat_tool_request__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "product_id" TEXT NOT NULL CONSTRAINT "ck_chat_tool_request__product_id" CHECK ("product_id" IN ('arcscope', 'companion')),
  "turn_id" TEXT NOT NULL CONSTRAINT "ck_chat_tool_request__turn_id" CHECK (length("turn_id") = 36 AND "turn_id" GLOB '????????-????-????-????-????????????' AND "turn_id" NOT GLOB '*[^0-9a-f-]*'),
  "run_id" TEXT NOT NULL CONSTRAINT "ck_chat_tool_request__run_id" CHECK (length("run_id") = 36 AND "run_id" GLOB '????????-????-????-????-????????????' AND "run_id" NOT GLOB '*[^0-9a-f-]*'),
  "step_id" TEXT NOT NULL CONSTRAINT "ck_chat_tool_request__step_id" CHECK (length("step_id") = 36 AND "step_id" GLOB '????????-????-????-????-????????????' AND "step_id" NOT GLOB '*[^0-9a-f-]*'),
  "attempt_id" TEXT NOT NULL CONSTRAINT "ck_chat_tool_request__attempt_id" CHECK (length("attempt_id") = 36 AND "attempt_id" GLOB '????????-????-????-????-????????????' AND "attempt_id" NOT GLOB '*[^0-9a-f-]*'),
  "command_id" TEXT NOT NULL CONSTRAINT "ck_chat_tool_request__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  "target_device_id" TEXT CONSTRAINT "ck_chat_tool_request__target_device_id" CHECK (length("target_device_id") = 36 AND "target_device_id" GLOB '????????-????-????-????-????????????' AND "target_device_id" NOT GLOB '*[^0-9a-f-]*'),
  "target_installation_id" TEXT CONSTRAINT "ck_chat_tool_request__target_installation_id" CHECK (length("target_installation_id") = 36 AND "target_installation_id" GLOB '????????-????-????-????-????????????' AND "target_installation_id" NOT GLOB '*[^0-9a-f-]*'),
  "target_product_id" TEXT CONSTRAINT "ck_chat_tool_request__target_product_id" CHECK ("target_product_id" IN ('arcscope', 'companion')),
  "target_instance_epoch" INTEGER,
  "capability" TEXT NOT NULL,
  "arguments_proto" BLOB NOT NULL,
  "context_proto" BLOB NOT NULL,
  "actor_proto" BLOB NOT NULL,
  "approval_id" TEXT CONSTRAINT "ck_chat_tool_request__approval_id" CHECK (length("approval_id") = 36 AND "approval_id" GLOB '????????-????-????-????-????????????' AND "approval_id" NOT GLOB '*[^0-9a-f-]*'),
  "expires_at" INTEGER NOT NULL,
  "state" INTEGER NOT NULL CONSTRAINT "ck_chat_tool_request__state" CHECK ("state" IN (1, 2, 3, 4, 5)),
  "rev" INTEGER NOT NULL CONSTRAINT "ck_chat_tool_request__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_chat_tool_request" PRIMARY KEY ("tool_request_id"),
  CONSTRAINT "fk_chat_tool_request__turn_id" FOREIGN KEY ("turn_id") REFERENCES "chat_turn" ("turn_id") ON DELETE RESTRICT,
  CONSTRAINT "ck_chat_tool_request__device_target_full_or_none" CHECK (("target_device_id" IS NOT NULL AND "target_installation_id" IS NOT NULL AND "target_product_id" IS NOT NULL) OR ("target_device_id" IS NULL AND "target_installation_id" IS NULL AND "target_product_id" IS NULL AND "target_instance_epoch" IS NULL))
) STRICT;

CREATE INDEX "ix_chat_tool_request__workspace_id_target_installation_id_state_expires_at" ON "chat_tool_request" ("workspace_id", "target_installation_id", "state", "expires_at");

CREATE TRIGGER "tr_chat_tool_request__limited_update" BEFORE UPDATE ON "chat_tool_request"
WHEN (OLD."arguments_proto" IS NOT NEW."arguments_proto" OR OLD."context_proto" IS NOT NEW."context_proto" OR OLD."actor_proto" IS NOT NEW."actor_proto")
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_chat_tool_request');
END;

CREATE TABLE "chat_tool_result" (
  "tool_request_id" TEXT NOT NULL CONSTRAINT "ck_chat_tool_result__tool_request_id" CHECK (length("tool_request_id") = 36 AND "tool_request_id" GLOB '????????-????-????-????-????????????' AND "tool_request_id" NOT GLOB '*[^0-9a-f-]*'),
  "attempt_id" TEXT NOT NULL CONSTRAINT "ck_chat_tool_result__attempt_id" CHECK (length("attempt_id") = 36 AND "attempt_id" GLOB '????????-????-????-????-????????????' AND "attempt_id" NOT GLOB '*[^0-9a-f-]*'),
  "command_id" TEXT NOT NULL CONSTRAINT "ck_chat_tool_result__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  "result_hash" BLOB NOT NULL CONSTRAINT "ck_chat_tool_result__result_hash" CHECK (length("result_hash") = 32),
  "body_proto" BLOB NOT NULL,
  "effect_certainty" INTEGER NOT NULL CONSTRAINT "ck_chat_tool_result__effect_certainty" CHECK ("effect_certainty" IN (1, 2, 3)),
  "received_at" INTEGER NOT NULL,
  CONSTRAINT "pk_chat_tool_result" PRIMARY KEY ("tool_request_id", "attempt_id", "command_id"),
  CONSTRAINT "fk_chat_tool_result__tool_request_id" FOREIGN KEY ("tool_request_id") REFERENCES "chat_tool_request" ("tool_request_id") ON DELETE RESTRICT
) STRICT;

CREATE TABLE "chat_transient_content" (
  "resource_id" TEXT NOT NULL CONSTRAINT "ck_chat_transient_content__resource_id" CHECK (length("resource_id") = 36 AND "resource_id" GLOB '????????-????-????-????-????????????' AND "resource_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_chat_transient_content__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "product_id" TEXT NOT NULL CONSTRAINT "ck_chat_transient_content__product_id" CHECK ("product_id" IN ('arcscope', 'companion')),
  "origin_installation_id" TEXT NOT NULL CONSTRAINT "ck_chat_transient_content__origin_installation_id" CHECK (length("origin_installation_id") = 36 AND "origin_installation_id" GLOB '????????-????-????-????-????????????' AND "origin_installation_id" NOT GLOB '*[^0-9a-f-]*'),
  "turn_id" TEXT CONSTRAINT "ck_chat_transient_content__turn_id" CHECK (length("turn_id") = 36 AND "turn_id" GLOB '????????-????-????-????-????????????' AND "turn_id" NOT GLOB '*[^0-9a-f-]*'),
  "task_id" TEXT CONSTRAINT "ck_chat_transient_content__task_id" CHECK (length("task_id") = 36 AND "task_id" GLOB '????????-????-????-????-????????????' AND "task_id" NOT GLOB '*[^0-9a-f-]*'),
  "purpose" INTEGER NOT NULL CONSTRAINT "ck_chat_transient_content__purpose" CHECK ("purpose" IN (1, 2)),
  "key_ref" TEXT NOT NULL,
  "ciphertext_ref" TEXT NOT NULL,
  "sha256" BLOB NOT NULL CONSTRAINT "ck_chat_transient_content__sha256" CHECK (length("sha256") = 32),
  "size" INTEGER NOT NULL,
  "expires_at" INTEGER NOT NULL,
  "closed_at" INTEGER,
  "purged_at" INTEGER,
  CONSTRAINT "pk_chat_transient_content" PRIMARY KEY ("resource_id"),
  CONSTRAINT "ck_chat_transient_content__size_nonnegative" CHECK ("size" >= 0),
  CONSTRAINT "ck_chat_transient_content__exactly_one_owner" CHECK (("turn_id" IS NULL) <> ("task_id" IS NULL))
) STRICT;

CREATE INDEX "ix_chat_transient_content__expires_at_purged_at" ON "chat_transient_content" ("expires_at", "purged_at");

CREATE TABLE "chat_turn" (
  "turn_id" TEXT NOT NULL CONSTRAINT "ck_chat_turn__turn_id" CHECK (length("turn_id") = 36 AND "turn_id" GLOB '????????-????-????-????-????????????' AND "turn_id" NOT GLOB '*[^0-9a-f-]*'),
  "workspace_id" TEXT NOT NULL CONSTRAINT "ck_chat_turn__workspace_id" CHECK (length("workspace_id") = 36 AND "workspace_id" GLOB '????????-????-????-????-????????????' AND "workspace_id" NOT GLOB '*[^0-9a-f-]*'),
  "product_id" TEXT NOT NULL CONSTRAINT "ck_chat_turn__product_id" CHECK ("product_id" IN ('arcscope', 'companion')),
  "history_mode" INTEGER NOT NULL CONSTRAINT "ck_chat_turn__history_mode" CHECK ("history_mode" IN (1, 2, 3)),
  "origin_installation_id" TEXT CONSTRAINT "ck_chat_turn__origin_installation_id" CHECK (length("origin_installation_id") = 36 AND "origin_installation_id" GLOB '????????-????-????-????-????????????' AND "origin_installation_id" NOT GLOB '*[^0-9a-f-]*'),
  "conversation_id" TEXT CONSTRAINT "ck_chat_turn__conversation_id" CHECK (length("conversation_id") = 36 AND "conversation_id" GLOB '????????-????-????-????-????????????' AND "conversation_id" NOT GLOB '*[^0-9a-f-]*'),
  "input_message_id" TEXT CONSTRAINT "ck_chat_turn__input_message_id" CHECK (length("input_message_id") = 36 AND "input_message_id" GLOB '????????-????-????-????-????????????' AND "input_message_id" NOT GLOB '*[^0-9a-f-]*'),
  "final_message_id" TEXT CONSTRAINT "ck_chat_turn__final_message_id" CHECK (length("final_message_id") = 36 AND "final_message_id" GLOB '????????-????-????-????-????????????' AND "final_message_id" NOT GLOB '*[^0-9a-f-]*'),
  "mode" INTEGER NOT NULL CONSTRAINT "ck_chat_turn__mode" CHECK ("mode" IN (1, 2, 3)),
  "state" INTEGER NOT NULL CONSTRAINT "ck_chat_turn__state" CHECK ("state" IN (1, 2, 3, 4, 5, 6, 7)),
  "rev" INTEGER NOT NULL CONSTRAINT "ck_chat_turn__rev" CHECK ("rev" >= 0),
  "run_id" TEXT CONSTRAINT "ck_chat_turn__run_id" CHECK (length("run_id") = 36 AND "run_id" GLOB '????????-????-????-????-????????????' AND "run_id" NOT GLOB '*[^0-9a-f-]*'),
  "stream_id" TEXT CONSTRAINT "ck_chat_turn__stream_id" CHECK (length("stream_id") = 36 AND "stream_id" GLOB '????????-????-????-????-????????????' AND "stream_id" NOT GLOB '*[^0-9a-f-]*'),
  "reason" TEXT CONSTRAINT "ck_chat_turn__reason" CHECK (length("reason") BETWEEN 1 AND 128 AND "reason" NOT GLOB '*[^A-Za-z0-9._:/-]*'),
  "created_at" INTEGER NOT NULL,
  "expires_at" INTEGER,
  "has_unknown_effect" INTEGER NOT NULL CONSTRAINT "ck_chat_turn__has_unknown_effect" CHECK ("has_unknown_effect" IN (0, 1)),
  "transient_input_ref" TEXT CONSTRAINT "ck_chat_turn__transient_input_ref" CHECK (length("transient_input_ref") = 36 AND "transient_input_ref" GLOB '????????-????-????-????-????????????' AND "transient_input_ref" NOT GLOB '*[^0-9a-f-]*'),
  "transient_output_receipt_id" TEXT CONSTRAINT "ck_chat_turn__transient_output_receipt_id" CHECK (length("transient_output_receipt_id") = 36 AND "transient_output_receipt_id" GLOB '????????-????-????-????-????????????' AND "transient_output_receipt_id" NOT GLOB '*[^0-9a-f-]*'),
  CONSTRAINT "pk_chat_turn" PRIMARY KEY ("turn_id"),
  CONSTRAINT "fk_chat_turn__conversation_id" FOREIGN KEY ("conversation_id") REFERENCES "chat_conversation" ("conversation_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_chat_turn__input_message_id" FOREIGN KEY ("input_message_id") REFERENCES "chat_message" ("message_id") ON DELETE RESTRICT,
  CONSTRAINT "ck_chat_turn__temporary_requires_temporary_mode" CHECK (("history_mode" = 3) = ("mode" = 3)),
  CONSTRAINT "ck_chat_turn__non_temporary_requires_ordinary_mode" CHECK ("history_mode" = 3 OR "mode" = 1),
  CONSTRAINT "ck_chat_turn__cloud_history_has_conversation_and_input" CHECK ("history_mode" <> 2 OR ("conversation_id" IS NOT NULL AND "input_message_id" IS NOT NULL)),
  CONSTRAINT "ck_chat_turn__local_or_temporary_has_no_cloud_rows" CHECK ("history_mode" = 2 OR ("conversation_id" IS NULL AND "input_message_id" IS NULL AND "final_message_id" IS NULL AND "origin_installation_id" IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX "ux_chat_turn__workspace_id_input_message_id" ON "chat_turn" ("workspace_id", "input_message_id");

CREATE INDEX "ix_chat_turn__workspace_id_product_id_state_created_at" ON "chat_turn" ("workspace_id", "product_id", "state", "created_at");

CREATE TABLE "chat_turn_promotion" (
  "turn_id" TEXT NOT NULL CONSTRAINT "ck_chat_turn_promotion__turn_id" CHECK (length("turn_id") = 36 AND "turn_id" GLOB '????????-????-????-????-????????????' AND "turn_id" NOT GLOB '*[^0-9a-f-]*'),
  "task_id" TEXT NOT NULL CONSTRAINT "ck_chat_turn_promotion__task_id" CHECK (length("task_id") = 36 AND "task_id" GLOB '????????-????-????-????-????????????' AND "task_id" NOT GLOB '*[^0-9a-f-]*'),
  "preview_hash" BLOB NOT NULL CONSTRAINT "ck_chat_turn_promotion__preview_hash" CHECK (length("preview_hash") = 32),
  "command_id" TEXT NOT NULL CONSTRAINT "ck_chat_turn_promotion__command_id" CHECK (length("command_id") = 36 AND "command_id" GLOB '????????-????-????-????-????????????' AND "command_id" NOT GLOB '*[^0-9a-f-]*'),
  "created_at" INTEGER NOT NULL,
  CONSTRAINT "pk_chat_turn_promotion" PRIMARY KEY ("turn_id"),
  CONSTRAINT "fk_chat_turn_promotion__turn_id" FOREIGN KEY ("turn_id") REFERENCES "chat_turn" ("turn_id") ON DELETE RESTRICT,
  CONSTRAINT "fk_chat_turn_promotion__task_id" FOREIGN KEY ("task_id") REFERENCES "task_task" ("task_id") ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX "ux_chat_turn_promotion__task_id" ON "chat_turn_promotion" ("task_id");

CREATE UNIQUE INDEX "ux_chat_turn_promotion__command_id" ON "chat_turn_promotion" ("command_id");
