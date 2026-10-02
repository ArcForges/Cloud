-- plan: foundation.job-items
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope,text returns=int64,int64
SELECT CAST(COUNT(*) AS TEXT), CAST(COALESCE(SUM(amount), 0) AS TEXT) FROM probe_job_item WHERE scope = ? AND job_id = ?;
