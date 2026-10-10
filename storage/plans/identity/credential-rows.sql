-- plan: identity.credential-rows
-- version: 1
-- access: read
-- maxRows: 64
-- statement: params=text,text returns=text,text,int64,text,bytes?,bytes?,int64?,int64?,text?,int64?,text?,int64,int64?,int64?,text,text,text?,int64
SELECT auth_identity_id, user_id, CAST(method AS TEXT), subject, public_key, user_handle, CAST(backup_eligible AS TEXT), CAST(backup_state AS TEXT), transports, CAST(sign_count AS TEXT), label, CAST(created_at AS TEXT), CAST(last_used_at AS TEXT), CAST(revoked_at AS TEXT), realm_id, provider_id, password_hash, CAST(rev AS TEXT)
FROM identity_auth_identity WHERE realm_id = ? AND user_id = ?
ORDER BY created_at, auth_identity_id;
