-- plan: task.harness-executor-yield
-- version: 1
-- access: write
-- tail: none the executor gives up its lease and records the run's next state under the live fence; the lease epoch is kept so the next claim is strictly newer
-- statement: params=text,text,scope,text,int64,int64,int64
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'task.harness-yield', CASE WHEN EXISTS (SELECT 1 FROM task_execution_lease l
  JOIN task_run r ON r.run_id = l.run_id JOIN task_task t ON t.task_id = r.task_id
  WHERE l.run_id = ? AND t.workspace_id = ? AND l.holder = ? AND l.epoch = CAST(? AS INTEGER)
    AND l.recovery_generation = CAST(? AS INTEGER) AND l.expires_at > CAST(? AS INTEGER) AND r.state = 2)
THEN 1 ELSE 0 END;
-- statement: params=int64,int64,text
UPDATE task_run SET state = CAST(? AS INTEGER), updated_at = CAST(? AS INTEGER), rev = rev + 1 WHERE run_id = ? AND state = 2;
-- statement: params=text,text,int64
UPDATE task_execution_lease SET expires_at = 0 WHERE run_id = ? AND holder = ? AND epoch = CAST(? AS INTEGER);
-- statement: params=int64,int64,int64,text
UPDATE task_harness_budget SET counted_steps = counted_steps + CAST(? AS INTEGER), subrequests = subrequests + CAST(? AS INTEGER),
  updated_at = CAST(? AS INTEGER), rev = rev + 1 WHERE run_id = ?;
-- statement: params=text
DELETE FROM platform_command_guard WHERE command_id = ?;
