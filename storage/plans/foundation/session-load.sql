-- plan: foundation.session-load
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope,bytes returns=text,text,text,text,int64,int64,int64,int64,int64,int64,int64?,text?
SELECT session_id, user_id, device_id, workspace_ids_json, CAST(recovery_generation AS TEXT), CAST(auth_epoch AS TEXT),
  CAST(created_at AS TEXT), CAST(absolute_expires_at AS TEXT), CAST(idle_expires_at AS TEXT), CAST(last_seen_at AS TEXT),
  CAST(revoked_at AS TEXT), revoke_reason
FROM probe_session WHERE scope = ? AND handle_hash = ?;
