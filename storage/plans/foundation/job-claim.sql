-- plan: foundation.job-claim
-- version: 1
-- access: write
-- statement: params=text,scope,text,int64,text
INSERT INTO probe_guard (command_id, allowed)
SELECT ?, CASE WHEN EXISTS (SELECT 1 FROM probe_job WHERE scope = ? AND job_id = ? AND state = 'running'
  AND (lease_owner IS NULL OR lease_until <= CAST(? AS INTEGER) OR lease_owner = ?)) THEN 1 ELSE 0 END;
-- statement: params=text,int64,scope,text
UPDATE probe_job SET lease_owner = ?, lease_until = CAST(? AS INTEGER), fence = fence + 1 WHERE scope = ? AND job_id = ?;
-- statement: params=text
DELETE FROM probe_guard WHERE command_id = ?;
