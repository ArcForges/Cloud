-- plan: identity.credential-list
-- version: 1
-- access: read
-- maxRows: 64
-- statement: params=text,text returns=text,int64,text,text?,int64,int64?,int64?,int64
SELECT auth_identity_id, CAST(method AS TEXT), provider_id, label, CAST(created_at AS TEXT), CAST(last_used_at AS TEXT), CAST(revoked_at AS TEXT), CAST(rev AS TEXT)
FROM identity_auth_identity WHERE realm_id = ? AND user_id = ?
ORDER BY created_at, auth_identity_id;
