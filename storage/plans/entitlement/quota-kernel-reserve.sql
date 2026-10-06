-- plan: entitlement.quota-kernel-reserve
-- version: 1
-- access: write
-- tail: v1 events=0
-- statement: params=text,text,scope
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'entitlement.quota-admission', CASE WHEN json_type(json_extract(c.data, '$.items')) = 'array' AND json_array_length(json_extract(c.data, '$.items')) BETWEEN 1 AND 8
AND NOT EXISTS (SELECT 1 FROM json_each(json_extract(c.data, '$.items')) j LEFT JOIN entitlement_quota_budget b
 ON b.scope_kind = CAST(json_extract(j.value, '$.scopeKind') AS INTEGER) AND b.scope_id = json_extract(j.value, '$.scopeId')
 AND b.quota_key = json_extract(j.value, '$.quotaKey') AND b.period_key = json_extract(j.value, '$.periodKey')
 WHERE b.rev IS NULL OR b.rev <> CAST(json_extract(j.value, '$.revision') AS INTEGER) OR b.rev >= 9223372036854775807
 OR CAST(CAST(json_extract(j.value, '$.revision') AS INTEGER) AS TEXT) <> json_extract(j.value, '$.revision')
 OR b.policy_version <> CAST(json_extract(j.value, '$.policyVersion') AS INTEGER)
 OR CAST(CAST(json_extract(j.value, '$.policyVersion') AS INTEGER) AS TEXT) <> json_extract(j.value, '$.policyVersion')
 OR CAST(json_extract(j.value, '$.bound') AS INTEGER) <= 0
 OR CAST(CAST(json_extract(j.value, '$.bound') AS INTEGER) AS TEXT) <> json_extract(j.value, '$.bound')
 OR (json_extract(j.value, '$.admissionCeiling') IS NOT NULL AND (CAST(json_extract(j.value, '$.admissionCeiling') AS INTEGER) < 0
 OR CAST(CAST(json_extract(j.value, '$.admissionCeiling') AS INTEGER) AS TEXT) <> json_extract(j.value, '$.admissionCeiling')))
 OR MIN(b."limit", COALESCE(CAST(json_extract(j.value, '$.admissionCeiling') AS INTEGER), b."limit")) < CAST(json_extract(j.value, '$.bound') AS INTEGER)
 OR b.used > MIN(b."limit", COALESCE(CAST(json_extract(j.value, '$.admissionCeiling') AS INTEGER), b."limit")) - CAST(json_extract(j.value, '$.bound') AS INTEGER)
 OR b.held > MIN(b."limit", COALESCE(CAST(json_extract(j.value, '$.admissionCeiling') AS INTEGER), b."limit")) - CAST(json_extract(j.value, '$.bound') AS INTEGER) - b.used)
AND NOT EXISTS (SELECT 1 FROM json_each(json_extract(c.data, '$.items')) GROUP BY json_extract(value, '$.scopeKind'), json_extract(value, '$.scopeId'), json_extract(value, '$.quotaKey'), json_extract(value, '$.periodKey') HAVING count(*) > 1)
AND NOT EXISTS (SELECT 1 FROM json_each(json_extract(c.data, '$.items')) GROUP BY json_extract(value, '$.reservationId') HAVING count(*) > 1)
AND NOT EXISTS (SELECT 1 FROM json_each(json_extract(c.data, '$.items')) WHERE CAST(json_extract(value, '$.scopeKind') AS INTEGER) = 1 AND json_extract(value, '$.scopeId') <> c.scope_id)
AND (json_extract(c.data, '$.jobId') IS NULL OR EXISTS (SELECT 1 FROM platform_job_lease j
 WHERE j.job_id = json_extract(c.data, '$.jobId') AND j.state = 2 AND j.holder = json_extract(c.data, '$.holder')
 AND j.fence_token = CAST(json_extract(c.data, '$.fence') AS INTEGER) AND j.leased_until = CAST(json_extract(c.data, '$.leaseUntil') AS INTEGER)
 AND json_extract(j.payload, '$.Definition.Owner.RealmId') = json_extract(c.data, '$.realm')
 AND json_extract(j.payload, '$.Definition.Owner.WorkspaceId') IS json_extract(c.data, '$.workspace')
 AND json_extract(j.payload, '$.Definition.Owner.Kind') = json_extract(c.data, '$.ownerKind')
 AND json_extract(j.payload, '$.Definition.Owner.OwnerId') = json_extract(c.data, '$.ownerId')
 AND json_type(j.payload, '$.Definition.RecoveryGeneration') = 'text'
 AND json_extract(j.payload, '$.Definition.RecoveryGeneration') = json_extract(c.data, '$.generation')
 AND j.leased_until > CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + CAST(substr(strftime('%f', 'now'), 4, 3) AS INTEGER) * 1000))
THEN 1 ELSE 0 END FROM (SELECT ? data, ? scope_id) c;
-- statement: params=text,text
UPDATE entitlement_quota_budget SET held = held + (
 SELECT CAST(json_extract(j.value, '$.bound') AS INTEGER) FROM json_each(?) j
 WHERE CAST(json_extract(j.value, '$.scopeKind') AS INTEGER) = entitlement_quota_budget.scope_kind
 AND json_extract(j.value, '$.scopeId') = entitlement_quota_budget.scope_id AND json_extract(j.value, '$.quotaKey') = entitlement_quota_budget.quota_key
 AND json_extract(j.value, '$.periodKey') = entitlement_quota_budget.period_key), rev = rev + 1
WHERE EXISTS (SELECT 1 FROM json_each(?) j WHERE CAST(json_extract(j.value, '$.scopeKind') AS INTEGER) = entitlement_quota_budget.scope_kind
 AND json_extract(j.value, '$.scopeId') = entitlement_quota_budget.scope_id AND json_extract(j.value, '$.quotaKey') = entitlement_quota_budget.quota_key
 AND json_extract(j.value, '$.periodKey') = entitlement_quota_budget.period_key);
-- statement: params=text,text,text,int64,int64,int64,text
INSERT INTO entitlement_quota_reservation (reservation_id, operation_id, scope_kind, scope_id, quota_key, period_key, owner_kind, owner_id, bound, consumed, state, expires_at, lease_until, fence)
SELECT json_extract(j.value, '$.reservationId'), ?, CAST(json_extract(j.value, '$.scopeKind') AS INTEGER), json_extract(j.value, '$.scopeId'),
 json_extract(j.value, '$.quotaKey'), json_extract(j.value, '$.periodKey'), ?, ?, CAST(json_extract(j.value, '$.bound') AS INTEGER), 0, 1, CAST(? AS INTEGER), NULLIF(CAST(? AS INTEGER), -1), NULLIF(CAST(? AS INTEGER), -1)
FROM json_each(?) j;
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
