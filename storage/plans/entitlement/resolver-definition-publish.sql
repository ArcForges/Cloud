-- plan: entitlement.resolver-definition-publish
-- version: 1
-- access: write
-- tail: v1 events=0
-- statement: params=text,scope,text,bytes,text,text,bytes,int64,int64
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'entitlement.resolver-definition-publish', CASE WHEN
c.artifact_length BETWEEN 2 AND 65536 AND length(CAST(c.canonical_profile AS BLOB)) = c.artifact_length
AND c.profile_hash = c.artifact_hash AND c.realm_kind IN (1,2)
AND json_valid(c.canonical_profile) AND json_type(c.canonical_profile) = 'object'
AND json_extract(c.canonical_profile, '$.schemaVersion') = 'entitlement.resolver-definitions.v1'
AND json_extract(c.canonical_profile, '$.definitionsVersion') = c.definitions_version
AND NOT EXISTS (SELECT 1 FROM entitlement_resolver_definition_profile p
 WHERE p.realm_id = c.realm_id AND p.definitions_version = c.definitions_version
 AND (p.profile_hash != c.profile_hash OR p.canonical_profile != c.canonical_profile OR p.artifact_id != c.artifact_id
 OR p.artifact_hash != c.artifact_hash OR p.artifact_length != c.artifact_length OR p.realm_kind != c.realm_kind))
THEN 1 ELSE 0 END
FROM (SELECT ? realm_id, ? definitions_version, ? profile_hash, ? canonical_profile, ? artifact_id, ? artifact_hash,
CAST(? AS INTEGER) artifact_length, CAST(? AS INTEGER) realm_kind) c;
-- statement: params=scope,text,bytes,text,text,bytes,int64,text,bytes,int64,text,int64
INSERT INTO entitlement_resolver_definition_profile
(realm_id, definitions_version, profile_hash, canonical_profile, artifact_id, artifact_hash, artifact_length,
 original_config_revision_id, original_config_document_hash, realm_kind, publisher_ref, created_at)
SELECT c.realm_id, c.definitions_version, c.profile_hash, c.canonical_profile, c.artifact_id, c.artifact_hash, c.artifact_length,
c.original_config_revision_id, c.original_config_document_hash, c.realm_kind, c.publisher_ref, c.created_at
FROM (SELECT ? realm_id, ? definitions_version, ? profile_hash, ? canonical_profile, ? artifact_id, ? artifact_hash,
CAST(? AS INTEGER) artifact_length, ? original_config_revision_id, ? original_config_document_hash,
CAST(? AS INTEGER) realm_kind, ? publisher_ref, CAST(? AS INTEGER) created_at) c
WHERE NOT EXISTS (SELECT 1 FROM entitlement_resolver_definition_profile p WHERE p.realm_id = c.realm_id AND p.definitions_version = c.definitions_version);
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
