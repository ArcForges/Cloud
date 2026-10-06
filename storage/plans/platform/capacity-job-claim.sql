-- plan: platform.capacity-job-claim
-- version: 1
-- access: write
-- tail: v1 events=0
-- statement: params=text,text,scope,int64,int64,text,int64
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'platform.capacity-job-claim', CASE WHEN EXISTS (SELECT 1 FROM platform_job_lease j
 WHERE j.job_id = c.job_id AND json_extract(j.payload, '$.Definition.Owner.RealmId') = c.scope_id
 AND j.fence_token = c.fence AND c.fence < 9223372036854775807 AND j.attempts = c.attempts
 AND j.payload = c.payload AND j.attempts <= CAST(json_extract(j.payload, '$.Definition.MaximumAttempts') AS INTEGER)
 AND j.available_at <= c.now AND (j.state = 1 OR j.state = 2 AND j.leased_until <= c.now)
 AND c.new_until > c.now AND c.new_until <= c.now + 60000000) THEN 1 ELSE 0 END
FROM (SELECT ? job_id, ? scope_id, CAST(? AS INTEGER) fence, CAST(? AS INTEGER) attempts, ? payload, CAST(? AS INTEGER) new_until,
 CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + CAST(substr(strftime('%f', 'now'), 4, 3) AS INTEGER) * 1000 now) c;
-- statement: params=text?,int64,int64,int64,int64,text
UPDATE platform_job_lease SET holder = ?, leased_until = NULLIF(CAST(? AS INTEGER), -1), attempts = CAST(? AS INTEGER), fence_token = CAST(? AS INTEGER), state = CAST(? AS INTEGER)
WHERE job_id = ?;
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
