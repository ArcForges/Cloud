-- plan: platform.capacity-job-load
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=text,scope returns=text,text,text?,int64?,int64,int64,int64,text,int64
SELECT job_id, job_type, holder, CAST(leased_until AS TEXT), CAST(attempts AS TEXT), CAST(fence_token AS TEXT), CAST(state AS TEXT), payload, CAST(available_at AS TEXT)
FROM platform_job_lease WHERE job_id = ? AND json_extract(payload, '$.Definition.Owner.RealmId') = ?;
