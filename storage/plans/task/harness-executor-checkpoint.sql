-- plan: task.harness-executor-checkpoint
-- version: 1
-- access: write
-- tail: none a checkpoint stores one receipt reference of the run under the live fence; it carries no prompt, output or other body
-- statement: params=text,text,scope,text,int64,int64,int64
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'task.harness-checkpoint', CASE WHEN EXISTS (SELECT 1 FROM task_execution_lease l
  JOIN task_run r ON r.run_id = l.run_id JOIN task_task t ON t.task_id = r.task_id
  WHERE l.run_id = ? AND t.workspace_id = ? AND l.holder = ? AND l.epoch = CAST(? AS INTEGER)
    AND l.recovery_generation = CAST(? AS INTEGER) AND l.expires_at > CAST(? AS INTEGER) AND r.state = 2)
THEN 1 ELSE 0 END;
-- statement: params=bytes,int64,text
UPDATE task_run SET last_iteration_receipt = ?, updated_at = CAST(? AS INTEGER), rev = rev + 1 WHERE run_id = ? AND state = 2;
-- statement: params=int64,int64,int64,text
UPDATE task_harness_budget SET counted_steps = counted_steps + CAST(? AS INTEGER), subrequests = subrequests + CAST(? AS INTEGER),
  updated_at = CAST(? AS INTEGER), rev = rev + 1 WHERE run_id = ?;
-- statement: params=text
DELETE FROM platform_command_guard WHERE command_id = ?;
