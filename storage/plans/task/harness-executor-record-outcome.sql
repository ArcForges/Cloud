-- plan: task.harness-executor-record-outcome
-- version: 1
-- access: write
-- tail: none an attempt outcome is fenced by the live lease and the expected states of its attempt and command; a stale writer's outcome is refused
-- statement: params=text,text,scope,text,int64,int64,int64,text,int64,text
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'task.harness-outcome', CASE WHEN EXISTS (SELECT 1 FROM task_execution_lease l
  JOIN task_run r ON r.run_id = l.run_id
  JOIN task_task t ON t.task_id = r.task_id
  JOIN task_attempt a ON a.run_id = r.run_id
  JOIN task_execution_command c ON c.command_id = a.command_id
  WHERE l.run_id = ? AND t.workspace_id = ? AND l.holder = ? AND l.epoch = CAST(? AS INTEGER)
    AND l.recovery_generation = CAST(? AS INTEGER) AND l.expires_at > CAST(? AS INTEGER) AND r.state = 2
    AND a.attempt_id = ? AND a.state = CAST(? AS INTEGER) AND c.state = ? AND c.run_id = r.run_id)
THEN 1 ELSE 0 END;
-- statement: params=int64,int64,int64,int64,text,text,int64
UPDATE task_attempt SET state = CAST(? AS INTEGER), failure_class = NULLIF(CAST(? AS INTEGER), -1),
  effect_certainty = NULLIF(CAST(? AS INTEGER), -1), ended_at = CAST(? AS INTEGER)
WHERE attempt_id = ? AND run_id = ? AND state = CAST(? AS INTEGER);
-- statement: params=text,text?,text,text,text,text
UPDATE task_execution_command SET state = ?, result_ref = ?
WHERE command_id = (SELECT command_id FROM task_attempt WHERE attempt_id = ? AND run_id = ?) AND run_id = ? AND state = ?;
-- statement: params=int64,int64,int64,text
UPDATE task_harness_budget SET counted_steps = counted_steps + CAST(? AS INTEGER), subrequests = subrequests + CAST(? AS INTEGER),
  updated_at = CAST(? AS INTEGER), rev = rev + 1 WHERE run_id = ?;
-- statement: params=text
DELETE FROM platform_command_guard WHERE command_id = ?;
