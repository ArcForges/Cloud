-- plan: task.harness-executor-mark-dispatch
-- version: 1
-- access: write
-- tail: none the dispatch intent is the durable fenced record that must exist before the external call; it carries no owner receipt
-- statement: params=text,text,scope,text,int64,int64,int64,text
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'task.harness-dispatch', CASE WHEN EXISTS (SELECT 1 FROM task_execution_lease l
  JOIN task_run r ON r.run_id = l.run_id
  JOIN task_task t ON t.task_id = r.task_id
  JOIN task_attempt a ON a.run_id = r.run_id
  JOIN task_execution_command c ON c.command_id = a.command_id
  WHERE l.run_id = ? AND t.workspace_id = ? AND l.holder = ? AND l.epoch = CAST(? AS INTEGER)
    AND l.recovery_generation = CAST(? AS INTEGER) AND l.expires_at > CAST(? AS INTEGER) AND r.state = 2
    AND a.attempt_id = ? AND a.state = 1 AND c.state = 'reserved' AND c.run_id = r.run_id)
THEN 1 ELSE 0 END;
-- statement: params=int64,text,text
UPDATE task_attempt SET state = 2, started_at = CAST(? AS INTEGER) WHERE attempt_id = ? AND run_id = ? AND state = 1;
-- statement: params=text,text,text
UPDATE task_execution_command SET state = 'dispatching'
WHERE command_id = (SELECT command_id FROM task_attempt WHERE attempt_id = ? AND run_id = ?) AND run_id = ? AND state = 'reserved';
-- statement: params=text
DELETE FROM platform_command_guard WHERE command_id = ?;
