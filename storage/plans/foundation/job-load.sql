-- plan: foundation.job-load
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope,text returns=int64,int64,int64,text?,int64?,text,uint64,int64
SELECT CAST(total AS TEXT), CAST(cursor AS TEXT), CAST(fence AS TEXT), lease_owner, CAST(lease_until AS TEXT), state, checksum, CAST(revision AS TEXT)
FROM probe_job WHERE scope = ? AND job_id = ?;
