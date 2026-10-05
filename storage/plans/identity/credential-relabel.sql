-- plan: identity.credential-relabel
-- version: 1
-- access: write
-- tail: v1 events=1
-- statement: params=text,text,text,text,int64,text,text
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'identity.credential-relabel', CASE WHEN
  EXISTS (SELECT 1 FROM identity_auth_identity WHERE realm_id = ? AND auth_identity_id = ? AND user_id = ? AND rev = CAST(? AS INTEGER) AND revoked_at IS NULL)
  AND EXISTS (SELECT 1 FROM identity_user WHERE realm_id = ? AND user_id = ? AND state IN (1, 2))
THEN 1 ELSE 0 END;
-- statement: params=text?,text,text,text,int64
UPDATE identity_auth_identity SET label = ?, rev = rev + 1
WHERE realm_id = ? AND auth_identity_id = ? AND user_id = ? AND rev = CAST(? AS INTEGER) AND revoked_at IS NULL;
-- statement: params=text,text?,text,text,text,text,int64,int64,int64
INSERT INTO platform_command (command_id, workspace_id, actor_ref, operation, request_hash, status, result_payload, result_rev, error_code, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, 2, ?, NULLIF(CAST(? AS INTEGER), -1), NULL, CAST(? AS INTEGER), CAST(? AS INTEGER));
-- statement: params=scope,int64
INSERT INTO platform_sequence_stream (stream_key, last_sequence, published_watermark, publish_rev, fence, ack_receipt, updated_at)
VALUES (?, 1, 0, 0, 0, NULL, CAST(? AS INTEGER))
ON CONFLICT (stream_key) DO UPDATE SET last_sequence = last_sequence + 1, updated_at = excluded.updated_at;
-- statement: params=text,text,text,int64,text,text,text?,text,text?,int64
INSERT INTO platform_outbox (outbox_id, aggregate_kind, aggregate_id, aggregate_rev, event_type, payload, workspace_id, correlation_id, causation_id, state, attempts, created_at, dispatched_at)
VALUES (?, ?, ?, CAST(? AS INTEGER), ?, ?, ?, ?, ?, 1, 0, CAST(? AS INTEGER), NULL);
-- statement: params=text,scope,scope
INSERT INTO platform_outbox_position (outbox_id, stream_key, sequence)
VALUES (?, ?, (SELECT last_sequence FROM platform_sequence_stream WHERE stream_key = ?));
-- statement: params=int64
INSERT INTO platform_sequence_stream (stream_key, last_sequence, published_watermark, publish_rev, fence, ack_receipt, updated_at)
VALUES ('platform:change-archive', 1, 0, 0, 0, NULL, CAST(? AS INTEGER))
ON CONFLICT (stream_key) DO UPDATE SET last_sequence = last_sequence + 1, updated_at = excluded.updated_at;
-- statement: params=text,int64,text,bytes,int64
INSERT INTO platform_change_archive (archive_sequence, command_id, schema_version, record, record_hash, created_at)
VALUES ((SELECT last_sequence FROM platform_sequence_stream WHERE stream_key = 'platform:change-archive'), ?, CAST(? AS INTEGER), ?, ?, CAST(? AS INTEGER));
-- statement: params=text
DELETE FROM platform_command_guard WHERE command_id = ?;
