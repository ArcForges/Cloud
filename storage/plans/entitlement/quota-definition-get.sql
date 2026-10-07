-- plan: entitlement.quota-definition-get
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope,text returns=text,text,bytes,text,text,bytes,int64,int64
SELECT realm_id, definitions_version, profile_hash, canonical_profile, artifact_id, artifact_hash, CAST(artifact_length AS TEXT), CAST(created_at AS TEXT)
FROM entitlement_quota_definition_profile WHERE realm_id = ? AND definitions_version = ?;
