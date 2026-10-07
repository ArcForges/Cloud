-- plan: entitlement.quota-definition-compatible
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope,text,bytes,text,text returns=int64
SELECT CAST(CASE WHEN json_valid(c.entries) AND json_type(c.entries) = 'array' AND json_array_length(c.entries) <= 64
AND NOT EXISTS (SELECT 1 FROM entitlement_quota_definition_profile p WHERE p.realm_id = c.realm_id AND p.definitions_version = c.definitions_version
 AND (p.profile_hash != c.profile_hash OR p.canonical_profile != c.canonical_profile))
AND NOT EXISTS (SELECT 1 FROM json_each(c.entries) e JOIN entitlement_quota_definition_key k
 ON k.realm_id = c.realm_id AND k.quota_key = json_extract(e.value, '$.key')
 WHERE k.unit != json_extract(e.value, '$.unit') OR k.mode != json_extract(e.value, '$.mode') OR k.combination != json_extract(e.value, '$.combination'))
THEN 1 ELSE 0 END AS TEXT)
FROM (SELECT ? realm_id, ? definitions_version, ? profile_hash, ? canonical_profile, ? entries) c;
