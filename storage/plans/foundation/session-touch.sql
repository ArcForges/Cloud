-- plan: foundation.session-touch
-- version: 1
-- access: write
-- statement: params=int64,int64,scope,bytes,int64,int64
UPDATE probe_session SET last_seen_at = CAST(? AS INTEGER), idle_expires_at = CAST(? AS INTEGER)
WHERE scope = ? AND handle_hash = ? AND revoked_at IS NULL
  AND idle_expires_at > CAST(? AS INTEGER) AND absolute_expires_at > CAST(? AS INTEGER);
