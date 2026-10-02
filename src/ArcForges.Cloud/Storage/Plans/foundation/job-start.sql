-- plan: foundation.job-start
-- version: 1
-- access: write
-- statement: params=scope,text,int64
INSERT INTO probe_job (scope, job_id, total, cursor, fence, lease_owner, lease_until, state, checksum, revision)
VALUES (?, ?, CAST(? AS INTEGER), 0, 0, NULL, NULL, 'running', '0', 1);
-- statement: params=scope,text,text,text
INSERT INTO probe_outbox (scope, command_id, event_key, payload_json) VALUES (?, ?, ?, ?);
