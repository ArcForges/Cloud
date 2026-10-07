-- plan: entitlement.resolver-definition-get
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope,text returns=text,text,bytes,text,text,bytes,int64,text,bytes,int64,text,int64
SELECT realm_id, definitions_version, profile_hash, canonical_profile, artifact_id, artifact_hash,
CAST(artifact_length AS TEXT), original_config_revision_id, original_config_document_hash,
CAST(realm_kind AS TEXT), publisher_ref, CAST(created_at AS TEXT)
FROM entitlement_resolver_definition_profile WHERE realm_id = ? AND definitions_version = ?;
