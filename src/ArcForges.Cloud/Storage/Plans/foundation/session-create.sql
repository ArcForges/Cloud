-- plan: foundation.session-create
-- version: 1
-- access: write
-- statement: params=scope,text,bytes,text,text,text,int64,int64,int64,int64,int64,int64
INSERT INTO probe_session (scope, session_id, handle_hash, user_id, device_id, workspace_ids_json, recovery_generation, auth_epoch,
  created_at, absolute_expires_at, idle_expires_at, last_seen_at, revoked_at, revoke_reason)
VALUES (?, ?, ?, ?, ?, ?, CAST(? AS INTEGER), CAST(? AS INTEGER), CAST(? AS INTEGER), CAST(? AS INTEGER), CAST(? AS INTEGER), CAST(? AS INTEGER), NULL, NULL);
-- statement: params=scope,text,text,text
INSERT INTO probe_outbox (scope, command_id, event_key, payload_json) VALUES (?, ?, ?, ?);
