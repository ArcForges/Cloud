-- plan: identity.credential-list
-- version: 2
-- access: read
-- maxRows: 64
-- statement: params=scope,text,int64,text returns=text,int64,text,text?,int64,int64?,int64?,int64,text,text,text,bytes?,bytes?,bool?,bool?,text?,int64?,text?
SELECT auth_identity_id, CAST(method AS TEXT), provider_id, label, CAST(created_at AS TEXT), CAST(last_used_at AS TEXT), CAST(revoked_at AS TEXT), CAST(rev AS TEXT),
  user_id, realm_id, subject, public_key, user_handle, backup_eligible, backup_state, transports, CAST(sign_count AS TEXT), password_hash
FROM identity_auth_identity WHERE realm_id = ? AND user_id = ?
  AND (created_at, auth_identity_id) > (CAST(? AS INTEGER), ?)
ORDER BY created_at, auth_identity_id LIMIT 64;
