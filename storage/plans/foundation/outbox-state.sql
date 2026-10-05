-- plan: foundation.outbox-state
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope returns=int64,int64
SELECT CAST(COUNT(*) AS TEXT), CAST(COALESCE(MAX(sequence), 0) AS TEXT) FROM probe_outbox WHERE scope = ?;
