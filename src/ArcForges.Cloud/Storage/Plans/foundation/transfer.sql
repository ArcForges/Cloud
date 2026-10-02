-- plan: foundation.transfer
-- version: 1
-- access: write
-- statement: params=text,scope,text,int64,int64,scope,text,int64
INSERT INTO probe_guard (command_id, allowed)
SELECT ?, CASE WHEN
  EXISTS (SELECT 1 FROM probe_account WHERE scope = ? AND id = ? AND revision = CAST(? AS INTEGER) AND balance >= CAST(? AS INTEGER))
  AND EXISTS (SELECT 1 FROM probe_account WHERE scope = ? AND id = ? AND revision = CAST(? AS INTEGER))
THEN 1 ELSE 0 END;
-- statement: params=int64,scope,text,int64
UPDATE probe_account SET balance = balance - CAST(? AS INTEGER), revision = revision + 1
WHERE scope = ? AND id = ? AND revision = CAST(? AS INTEGER);
-- statement: params=int64,scope,text,int64
UPDATE probe_account SET balance = balance + CAST(? AS INTEGER), revision = revision + 1
WHERE scope = ? AND id = ? AND revision = CAST(? AS INTEGER);
-- statement: params=scope,text,text,text
INSERT INTO probe_receipt (scope, command_id, request_hash, result_json) VALUES (?, ?, ?, ?);
-- statement: params=scope,text,text,text
INSERT INTO probe_outbox (scope, command_id, event_key, payload_json) VALUES (?, ?, ?, ?);
-- statement: params=text
DELETE FROM probe_guard WHERE command_id = ?;
