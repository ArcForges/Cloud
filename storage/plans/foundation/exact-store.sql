-- plan: foundation.exact-store
-- version: 1
-- access: write
-- statement: params=text,scope,text,int64
INSERT INTO probe_guard (command_id, allowed)
SELECT ?, CASE WHEN COALESCE((SELECT revision FROM probe_exact WHERE scope = ? AND id = ?), 0) = CAST(? AS INTEGER) THEN 1 ELSE 0 END;
-- statement: params=scope,text,int64,uint64,decimal,bytes?,int64
INSERT INTO probe_exact (scope, id, signed_value, unsigned_text, decimal_text, payload, revision)
VALUES (?, ?, CAST(? AS INTEGER), ?, ?, ?, CAST(? AS INTEGER) + 1)
ON CONFLICT (scope, id) DO UPDATE SET signed_value = excluded.signed_value, unsigned_text = excluded.unsigned_text,
  decimal_text = excluded.decimal_text, payload = excluded.payload, revision = excluded.revision;
-- statement: params=scope,text,text,text
INSERT INTO probe_receipt (scope, command_id, request_hash, result_json) VALUES (?, ?, ?, ?);
-- statement: params=text
DELETE FROM probe_guard WHERE command_id = ?;
