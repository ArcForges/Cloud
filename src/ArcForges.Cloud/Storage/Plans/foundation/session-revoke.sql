-- plan: foundation.session-revoke
-- version: 1
-- access: write
-- statement: params=text,scope,text
INSERT INTO probe_guard (command_id, allowed)
SELECT ?, CASE WHEN EXISTS (SELECT 1 FROM probe_session WHERE scope = ? AND session_id = ? AND revoked_at IS NULL) THEN 1 ELSE 0 END;
-- statement: params=int64,text,scope,text
UPDATE probe_session SET revoked_at = CAST(? AS INTEGER), revoke_reason = ?
WHERE scope = ? AND session_id = ? AND revoked_at IS NULL;
-- statement: params=scope,text,text,text
INSERT INTO probe_outbox (scope, command_id, event_key, payload_json) VALUES (?, ?, ?, ?);
-- statement: params=text
DELETE FROM probe_guard WHERE command_id = ?;
