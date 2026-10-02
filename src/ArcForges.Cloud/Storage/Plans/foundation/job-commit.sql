-- plan: foundation.job-commit
-- version: 1
-- access: write
-- statement: params=text,scope,text,int64,text,int64,int64
INSERT INTO probe_guard (command_id, allowed)
SELECT ?, CASE WHEN EXISTS (SELECT 1 FROM probe_job WHERE scope = ? AND job_id = ? AND state = 'running'
  AND fence = CAST(? AS INTEGER) AND lease_owner = ? AND cursor = CAST(? AS INTEGER) AND lease_until > CAST(? AS INTEGER)) THEN 1 ELSE 0 END;
-- statement: params=scope,text,text
INSERT INTO probe_job_item (scope, job_id, item_no, amount)
SELECT ?, ?, CAST(json_extract(value, '$.n') AS INTEGER), CAST(json_extract(value, '$.a') AS INTEGER) FROM json_each(?);
-- statement: params=int64,uint64,int64,scope,text,int64
UPDATE probe_job SET cursor = CAST(? AS INTEGER), checksum = ?,
  state = CASE WHEN CAST(? AS INTEGER) >= total THEN 'complete' ELSE 'running' END, revision = revision + 1,
  lease_owner = NULL, lease_until = NULL
WHERE scope = ? AND job_id = ? AND fence = CAST(? AS INTEGER);
-- statement: params=scope,text,int64
INSERT INTO probe_inbox (scope, consumer, event_id, generation) VALUES (?, 'job-slice', ?, CAST(? AS INTEGER));
-- statement: params=scope,text,text,text
INSERT INTO probe_outbox (scope, command_id, event_key, payload_json) VALUES (?, ?, ?, ?);
-- statement: params=text
DELETE FROM probe_guard WHERE command_id = ?;
