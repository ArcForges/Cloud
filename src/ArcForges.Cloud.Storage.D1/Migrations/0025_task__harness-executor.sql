-- af-migration: module=task mode=expand
-- Durable per-run counters of the C# Harness executor (HAR.40): counted steps, subrequests, model calls and tool invocations.
-- They are written only by the executor's fenced plans, survive restart, wake and lease takeover, and never decrease
-- (the reviewed C# budget definition of HAR.00 validation (1) and (2); contracts 05 section 4).
CREATE TABLE "task_harness_budget" (
  "run_id" TEXT NOT NULL CONSTRAINT "ck_task_harness_budget__run_id" CHECK (length("run_id") = 36 AND "run_id" GLOB '????????-????-????-????-????????????' AND "run_id" NOT GLOB '*[^0-9a-f-]*'),
  "counted_steps" INTEGER NOT NULL CONSTRAINT "ck_task_harness_budget__counted_steps" CHECK ("counted_steps" BETWEEN 0 AND 25000),
  "subrequests" INTEGER NOT NULL CONSTRAINT "ck_task_harness_budget__subrequests" CHECK ("subrequests" BETWEEN 0 AND 1000000),
  "model_calls" INTEGER NOT NULL CONSTRAINT "ck_task_harness_budget__model_calls" CHECK ("model_calls" BETWEEN 0 AND 64),
  "tool_invocations" INTEGER NOT NULL CONSTRAINT "ck_task_harness_budget__tool_invocations" CHECK ("tool_invocations" BETWEEN 0 AND 256),
  "updated_at" INTEGER NOT NULL,
  "rev" INTEGER NOT NULL CONSTRAINT "ck_task_harness_budget__rev" CHECK ("rev" >= 0),
  CONSTRAINT "pk_task_harness_budget" PRIMARY KEY ("run_id"),
  CONSTRAINT "fk_task_harness_budget__run_id" FOREIGN KEY ("run_id") REFERENCES "task_run" ("run_id") ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER "tr_task_harness_budget__immutable_delete" BEFORE DELETE ON "task_harness_budget"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_task_harness_budget');
END;

CREATE TRIGGER "tr_task_harness_budget__monotonic_counted_steps" BEFORE UPDATE OF "counted_steps" ON "task_harness_budget"
WHEN NEW."counted_steps" < OLD."counted_steps"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_monotonic_task_harness_budget_counted_steps');
END;

CREATE TRIGGER "tr_task_harness_budget__monotonic_subrequests" BEFORE UPDATE OF "subrequests" ON "task_harness_budget"
WHEN NEW."subrequests" < OLD."subrequests"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_monotonic_task_harness_budget_subrequests');
END;

CREATE TRIGGER "tr_task_harness_budget__monotonic_model_calls" BEFORE UPDATE OF "model_calls" ON "task_harness_budget"
WHEN NEW."model_calls" < OLD."model_calls"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_monotonic_task_harness_budget_model_calls');
END;

CREATE TRIGGER "tr_task_harness_budget__monotonic_tool_invocations" BEFORE UPDATE OF "tool_invocations" ON "task_harness_budget"
WHEN NEW."tool_invocations" < OLD."tool_invocations"
BEGIN
  SELECT RAISE(ABORT, 'CHECK constraint failed: af_monotonic_task_harness_budget_tool_invocations');
END;
