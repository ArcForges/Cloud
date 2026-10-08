-- plan: task.harness-executor-run-load
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=text,scope returns=text,text,text,text,text,text?,text?,text?,text?,text?,text?,text?,text?,bytes?
SELECT CAST(r.state AS TEXT), CAST(r.rev AS TEXT), CAST(r.recovery_generation AS TEXT), r.workflow_id, r.worker_version,
  l.holder, CAST(l.epoch AS TEXT), CAST(l.expires_at AS TEXT), CAST(l.recovery_generation AS TEXT),
  CAST(b.counted_steps AS TEXT), CAST(b.subrequests AS TEXT), CAST(b.model_calls AS TEXT), CAST(b.tool_invocations AS TEXT),
  r.last_iteration_receipt
FROM task_run r
JOIN task_task t ON t.task_id = r.task_id
LEFT JOIN task_execution_lease l ON l.run_id = r.run_id
LEFT JOIN task_harness_budget b ON b.run_id = r.run_id
WHERE r.run_id = ? AND t.workspace_id = ?;
