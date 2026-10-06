-- plan: platform.capacity-job-create
-- version: 1
-- access: write
-- tail: v1 events=0
-- statement: params=text,scope,text
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'platform.capacity-job-new', CASE WHEN c.scope_id = json_extract(c.payload, '$.Definition.Owner.RealmId') THEN 1 ELSE 0 END
FROM (SELECT ? scope_id, ? payload) c;
-- statement: params=text,text,text,int64
INSERT INTO platform_job_lease (job_id, job_type, holder, leased_until, attempts, fence_token, state, payload, available_at)
VALUES (?, ?, NULL, NULL, 0, 0, 1, ?, CAST(? AS INTEGER));
-- statement: params=text,text?,text,text,text,text,int64,int64,int64
INSERT INTO platform_command (command_id, workspace_id, actor_ref, operation, request_hash, status, result_payload, result_rev, error_code, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, 2, ?, NULLIF(CAST(? AS INTEGER), -1), NULL, CAST(? AS INTEGER), CAST(? AS INTEGER));
-- statement: params=int64
INSERT INTO platform_sequence_stream (stream_key, last_sequence, published_watermark, publish_rev, fence, ack_receipt, updated_at)
VALUES ('platform:change-archive', 1, 0, 0, 0, NULL, CAST(? AS INTEGER))
ON CONFLICT (stream_key) DO UPDATE SET last_sequence = last_sequence + 1, updated_at = excluded.updated_at;
-- statement: params=text,int64,text,bytes,int64
INSERT INTO platform_change_archive (archive_sequence, command_id, schema_version, record, record_hash, created_at)
VALUES ((SELECT last_sequence FROM platform_sequence_stream WHERE stream_key = 'platform:change-archive'), ?, CAST(? AS INTEGER), ?, ?, CAST(? AS INTEGER));
-- statement: params=text
DELETE FROM platform_command_guard WHERE command_id = ?;
