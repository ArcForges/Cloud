-- plan: foundation.inbox-seen
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope,text,int64 returns=int64
SELECT CAST(COUNT(*) AS TEXT) FROM probe_inbox WHERE scope = ? AND consumer = 'job-slice' AND event_id = ? AND generation = CAST(? AS INTEGER);
