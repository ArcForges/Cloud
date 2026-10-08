-- plan: task.harness-executor-attempt-load
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=text,scope returns=text,text,text,text,text,text?,text?
SELECT a.attempt_id, a.step_id, a.command_id, CAST(a.attempt_ordinal AS TEXT), CAST(a.state AS TEXT), c.state, CAST(c.epoch AS TEXT)
FROM task_attempt a
LEFT JOIN task_execution_command c ON c.command_id = a.command_id
WHERE a.run_id = ? AND a.state IN (1, 2)
  AND EXISTS (SELECT 1 FROM task_run r JOIN task_task t ON t.task_id = r.task_id WHERE r.run_id = a.run_id AND t.workspace_id = ?)
ORDER BY a.attempt_ordinal DESC
LIMIT 1;
