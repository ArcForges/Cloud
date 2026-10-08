-- plan: task.harness-executor-claim
-- version: 1
-- access: write
-- tail: none the lease claim is fenced by its own guard row and carries no owner receipt; a replay re-reads the lease and never claims twice; a running run is taken over only after its lease expired; the pinned model and tariff snapshot is stored at the first claim and a different pair is refused before any lease is taken
-- statement: params=text,text,scope,int64,text,int64,text,text,text,text
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'task.harness-claim', CASE WHEN
  EXISTS (SELECT 1 FROM task_run r JOIN task_task t ON t.task_id = r.task_id
    WHERE r.run_id = ? AND t.workspace_id = ? AND r.recovery_generation = CAST(? AS INTEGER) AND r.state IN (1, 2, 3, 5))
  AND NOT EXISTS (SELECT 1 FROM task_execution_lease l WHERE l.run_id = ? AND l.expires_at > CAST(? AS INTEGER))
  AND (NOT EXISTS (SELECT 1 FROM task_harness_budget p WHERE p.run_id = ?)
    OR EXISTS (SELECT 1 FROM task_harness_budget p WHERE p.run_id = ? AND p.pinned_model_id = ? AND p.pinned_tariff_snapshot_id = ?))
THEN 1 ELSE 0 END;
-- statement: params=text,text,text,text,int64,int64
INSERT INTO task_execution_lease (run_id, holder, workflow_id, worker_version, epoch, expires_at, recovery_generation)
VALUES (?, ?, ?, ?, 1, CAST(? AS INTEGER), CAST(? AS INTEGER))
ON CONFLICT (run_id) DO UPDATE SET holder = excluded.holder, workflow_id = excluded.workflow_id,
  worker_version = excluded.worker_version, epoch = task_execution_lease.epoch + 1,
  expires_at = excluded.expires_at, recovery_generation = excluded.recovery_generation;
-- statement: params=text,int64,int64,text,text,int64
INSERT INTO task_harness_budget (run_id, counted_steps, subrequests, model_calls, tool_invocations, pinned_model_id, pinned_tariff_snapshot_id, updated_at, rev)
VALUES (?, CAST(? AS INTEGER), CAST(? AS INTEGER), 0, 0, ?, ?, CAST(? AS INTEGER), 0)
ON CONFLICT (run_id) DO UPDATE SET counted_steps = task_harness_budget.counted_steps + excluded.counted_steps,
  subrequests = task_harness_budget.subrequests + excluded.subrequests, updated_at = excluded.updated_at, rev = task_harness_budget.rev + 1;
-- statement: params=text,text,int64,int64,text
UPDATE task_run SET state = 2, workflow_id = ?, worker_version = ?, recovery_generation = CAST(? AS INTEGER),
  updated_at = CAST(? AS INTEGER), rev = rev + 1
WHERE run_id = ? AND state IN (1, 2, 3, 5);
-- statement: params=text
DELETE FROM platform_command_guard WHERE command_id = ?;
