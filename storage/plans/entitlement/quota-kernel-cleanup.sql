-- plan: entitlement.quota-kernel-cleanup
-- version: 1
-- access: write
-- tail: v1 events=0
-- statement: params=text,text,scope
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'entitlement.quota-cleanup', CASE WHEN EXISTS (
 SELECT 1 FROM entitlement_quota_reservation r JOIN entitlement_quota_budget b
 ON b.scope_kind = r.scope_kind AND b.scope_id = r.scope_id AND b.quota_key = r.quota_key AND b.period_key = r.period_key
 WHERE r.reservation_id = json_extract(c.data, '$.reservationId') AND r.scope_id = c.scope_id
 AND r.owner_kind = json_extract(c.data, '$.ownerKind') AND r.owner_id = json_extract(c.data, '$.ownerId')
 AND b.rev = CAST(json_extract(c.data, '$.revision') AS INTEGER) AND b.rev < 9223372036854775807
 AND b.used = CAST(json_extract(c.data, '$.oldUsed') AS INTEGER) AND b.held = CAST(json_extract(c.data, '$.oldHeld') AS INTEGER)
 AND r.consumed = CAST(json_extract(c.data, '$.oldConsumed') AS INTEGER) AND r.state = CAST(json_extract(c.data, '$.oldState') AS INTEGER)
 AND r.bound = CAST(json_extract(c.data, '$.bound') AS INTEGER) AND r.fence IS CAST(json_extract(c.data, '$.oldFence') AS INTEGER)
 AND (r.fence IS NULL AND json_extract(c.data, '$.jobId') IS NULL
  OR r.fence IS NOT NULL AND CAST(json_extract(c.data, '$.fence') AS INTEGER) >= r.fence
   AND EXISTS (SELECT 1 FROM platform_job_lease j WHERE j.job_id = json_extract(c.data, '$.jobId') AND j.state = 2
    AND j.holder = json_extract(c.data, '$.holder') AND j.fence_token = CAST(json_extract(c.data, '$.fence') AS INTEGER)
    AND j.leased_until = CAST(json_extract(c.data, '$.leaseUntil') AS INTEGER)
    AND json_extract(j.payload, '$.Definition.Owner.RealmId') = json_extract(c.data, '$.realm')
 AND json_extract(j.payload, '$.Definition.Owner.WorkspaceId') IS json_extract(c.data, '$.workspace')
 AND json_extract(j.payload, '$.Definition.Owner.Kind') = json_extract(c.data, '$.ownerKind')
 AND json_extract(j.payload, '$.Definition.Owner.OwnerId') = json_extract(c.data, '$.ownerId')
 AND json_type(j.payload, '$.Definition.RecoveryGeneration') = 'text'
 AND json_extract(j.payload, '$.Definition.RecoveryGeneration') = json_extract(c.data, '$.generation')
 AND j.leased_until > CAST(strftime('%s', 'now') AS INTEGER) * 1000000 + CAST(substr(strftime('%f', 'now'), 4, 3) AS INTEGER) * 1000))
 AND r.state IN (1, 3) AND CAST(json_extract(c.data, '$.state') AS INTEGER) = 3
 AND CAST(json_extract(c.data, '$.used') AS INTEGER) = b.used AND CAST(json_extract(c.data, '$.held') AS INTEGER) = b.held
 AND CAST(json_extract(c.data, '$.consumed') AS INTEGER) = r.consumed
) THEN 1 ELSE 0 END FROM (SELECT ? data, ? scope_id) c;
-- statement: params=text
UPDATE entitlement_quota_budget SET rev = rev + 1 FROM (SELECT ? data) c
WHERE scope_kind = CAST(json_extract(c.data, '$.scopeKind') AS INTEGER) AND scope_id = json_extract(c.data, '$.scopeId')
AND quota_key = json_extract(c.data, '$.quotaKey') AND period_key = json_extract(c.data, '$.periodKey');
-- statement: params=text
UPDATE entitlement_quota_reservation SET state = 3, lease_until = CAST(json_extract(c.data, '$.leaseUntil') AS INTEGER), fence = CAST(json_extract(c.data, '$.fence') AS INTEGER) FROM (SELECT ? data) c WHERE reservation_id = json_extract(c.data, '$.reservationId');
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
