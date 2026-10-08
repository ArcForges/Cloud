-- plan: task.harness-executor-reserve-step
-- version: 1
-- access: write
-- tail: none a counted step is reserved under the live fence before any dispatch; the reservation is the durable record that precedes the external call
-- statement: params=text,text,scope,text,int64,int64,int64,int64,int64,int64,int64,int64,int64,int64,int64,text,text,text
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'task.harness-reserve', CASE WHEN
  EXISTS (SELECT 1 FROM task_execution_lease l
    JOIN task_run r ON r.run_id = l.run_id
    JOIN task_task t ON t.task_id = r.task_id
    JOIN task_harness_budget b ON b.run_id = l.run_id
    WHERE l.run_id = ? AND t.workspace_id = ? AND l.holder = ? AND l.epoch = CAST(? AS INTEGER)
      AND l.recovery_generation = CAST(? AS INTEGER) AND l.expires_at > CAST(? AS INTEGER) AND r.state = 2
      AND b.counted_steps + CAST(? AS INTEGER) <= CAST(? AS INTEGER)
      AND b.subrequests + CAST(? AS INTEGER) <= CAST(? AS INTEGER)
      AND b.model_calls + CAST(? AS INTEGER) <= CAST(? AS INTEGER)
      AND b.tool_invocations + CAST(? AS INTEGER) <= CAST(? AS INTEGER)
      AND b.pinned_model_id = ? AND b.pinned_tariff_snapshot_id = ?)
  AND NOT EXISTS (SELECT 1 FROM task_execution_command c WHERE c.command_id = ? AND c.state <> 'refused')
THEN 1 ELSE 0 END;
-- statement: params=int64,int64,int64,int64,int64,text
UPDATE task_harness_budget SET counted_steps = counted_steps + CAST(? AS INTEGER),
  subrequests = subrequests + CAST(? AS INTEGER), model_calls = model_calls + CAST(? AS INTEGER),
  tool_invocations = tool_invocations + CAST(? AS INTEGER), updated_at = CAST(? AS INTEGER), rev = rev + 1
WHERE run_id = ?;
-- statement: params=text,text,int64,text,text,int64
INSERT INTO task_execution_command (command_id, run_id, epoch, operation, request_sha256, state, result_ref, created_at)
VALUES (?, ?, CAST(? AS INTEGER), ?, ?, 'reserved', NULL, CAST(? AS INTEGER))
ON CONFLICT (command_id) DO UPDATE SET state = 'reserved', epoch = excluded.epoch
WHERE task_execution_command.state = 'refused';
-- statement: params=text,text,text,text,int64
INSERT INTO task_attempt (attempt_id, run_id, step_id, command_id, state, attempt_ordinal, failure_class, effect_certainty, started_at, ended_at)
VALUES (?, ?, ?, ?, 1, CAST(? AS INTEGER), NULL, NULL, NULL, NULL);
-- statement: params=text
DELETE FROM platform_command_guard WHERE command_id = ?;
