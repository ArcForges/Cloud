-- plan: entitlement.quota-kernel-publish
-- version: 1
-- access: write
-- tail: v1 events=0
-- statement: params=text,int64,scope,text,text,text,int64,int64,int64
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'entitlement.quota-policy', CASE WHEN c.kind IN (1, 2) AND c.limit_value >= 0 AND c.version > 0 AND c.expected_rev >= 0 AND c.expected_rev < 9223372036854775807
AND (NOT EXISTS (SELECT 1 FROM entitlement_quota_budget b WHERE b.scope_kind = c.kind AND b.scope_id = c.scope_id AND b.quota_key = c.quota_key AND b.period_key = c.period_key) AND c.expected_rev = 0
OR EXISTS (SELECT 1 FROM entitlement_quota_budget b WHERE b.scope_kind = c.kind AND b.scope_id = c.scope_id AND b.quota_key = c.quota_key AND b.period_key = c.period_key
  AND b.rev = c.expected_rev AND b.unit = c.unit AND c.version >= b.policy_version
  AND (c.version > b.policy_version OR c.limit_value = b."limit"))) THEN 1 ELSE 0 END
FROM (SELECT CAST(? AS INTEGER) kind, ? scope_id, ? quota_key, ? period_key, ? unit, CAST(? AS INTEGER) limit_value, CAST(? AS INTEGER) version, CAST(? AS INTEGER) expected_rev) c;
-- statement: params=int64,scope,text,text,text,int64,int64,int64
INSERT INTO entitlement_quota_budget (scope_kind, scope_id, quota_key, period_key, unit, "limit", used, held, policy_version, rev)
VALUES (CAST(? AS INTEGER), ?, ?, ?, ?, CAST(? AS INTEGER), 0, 0, CAST(? AS INTEGER), CAST(? AS INTEGER) + 1)
ON CONFLICT (scope_kind, scope_id, quota_key, period_key) DO UPDATE SET "limit" = excluded."limit", policy_version = excluded.policy_version, rev = excluded.rev;
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
