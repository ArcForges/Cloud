-- plan: platform.capacity-job-due
-- version: 1
-- access: read
-- maxRows: 10
-- statement: params=scope,text,text,int64,int64,int64,text returns=text,text,text?,int64?,int64,int64,int64,text,int64,int64
SELECT job_id, job_type, holder, CAST(leased_until AS TEXT), CAST(attempts AS TEXT), CAST(fence_token AS TEXT), CAST(state AS TEXT), payload, CAST(available_at AS TEXT),
 CAST(CASE WHEN state = 1 THEN available_at ELSE leased_until END AS TEXT)
FROM platform_job_lease
WHERE json_extract(payload, '$.Definition.Owner.RealmId') = ?
 AND json_type(payload, '$.Definition.RecoveryGeneration') = 'text'
 AND json_extract(payload, '$.Definition.RecoveryGeneration') = ?
 AND job_type IN (SELECT value FROM json_each(?))
 AND state IN (1, 2)
 AND CASE WHEN state = 1 THEN available_at ELSE leased_until END <= CAST(? AS INTEGER)
 AND (CASE WHEN state = 1 THEN available_at ELSE leased_until END > CAST(? AS INTEGER)
  OR CASE WHEN state = 1 THEN available_at ELSE leased_until END = CAST(? AS INTEGER) AND job_id > ?)
ORDER BY CASE WHEN state = 1 THEN available_at ELSE leased_until END, job_id LIMIT 10;
