-- plan: entitlement.quota-definition-publish
-- version: 1
-- access: write
-- tail: v1 events=0
-- statement: params=text,scope,text,bytes,text,text,bytes,int64,text
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'entitlement.quota-definition-publish', CASE WHEN
c.artifact_length BETWEEN 2 AND 65536 AND length(CAST(c.canonical_profile AS BLOB)) = c.artifact_length
AND c.profile_hash = c.artifact_hash AND json_valid(c.entries) AND json_type(c.entries) = 'array' AND json_array_length(c.entries) <= 64
AND NOT EXISTS (SELECT 1 FROM json_each(c.entries) e WHERE json_extract(e.value, '$.unit') NOT IN (1,2,3,4)
 OR json_extract(e.value, '$.mode') NOT IN (1,2) OR json_extract(e.value, '$.combination') NOT IN (1,2,3))
AND NOT EXISTS (SELECT 1 FROM entitlement_quota_definition_profile p WHERE p.realm_id = c.realm_id AND p.definitions_version = c.definitions_version
 AND (p.profile_hash != c.profile_hash OR p.canonical_profile != c.canonical_profile OR p.artifact_id != c.artifact_id OR p.artifact_hash != c.artifact_hash OR p.artifact_length != c.artifact_length))
AND NOT EXISTS (SELECT 1 FROM json_each(c.entries) e JOIN entitlement_quota_definition_key k
 ON k.realm_id = c.realm_id AND k.quota_key = json_extract(e.value, '$.key')
 WHERE k.unit != json_extract(e.value, '$.unit') OR k.mode != json_extract(e.value, '$.mode') OR k.combination != json_extract(e.value, '$.combination'))
THEN 1 ELSE 0 END
FROM (SELECT ? realm_id, ? definitions_version, ? profile_hash, ? canonical_profile, ? artifact_id, ? artifact_hash, CAST(? AS INTEGER) artifact_length, ? entries) c;
-- statement: params=scope,text,bytes,text,text,bytes,int64,int64
INSERT INTO entitlement_quota_definition_profile (realm_id, definitions_version, profile_hash, canonical_profile, artifact_id, artifact_hash, artifact_length, created_at)
VALUES (?, ?, ?, ?, ?, ?, CAST(? AS INTEGER), CAST(? AS INTEGER)) ON CONFLICT (realm_id, definitions_version) DO NOTHING;
-- statement: params=scope,text,text
INSERT INTO entitlement_quota_definition_key (realm_id, quota_key, unit, mode, combination, first_definitions_version)
SELECT c.realm_id, json_extract(e.value, '$.key'), json_extract(e.value, '$.unit'), json_extract(e.value, '$.mode'), json_extract(e.value, '$.combination'), c.version
FROM (SELECT ? realm_id, ? version, ? entries) c JOIN json_each(c.entries) e ON 1=1 WHERE 1
ON CONFLICT (realm_id, quota_key) DO NOTHING;
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
