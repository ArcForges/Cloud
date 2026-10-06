-- plan: identity.credential-find
-- version: 2
-- access: read
-- maxRows: 1
-- statement: params=text,text,text returns=text,text,int64,text?,int64,int64?,int64?,int64,int64,int64,text,text,text,bytes?,bytes?,bool?,bool?,text?,int64?,text?,text,int64,int64?
SELECT a.auth_identity_id, a.user_id, CAST(a.method AS TEXT), a.label, CAST(a.created_at AS TEXT), CAST(a.last_used_at AS TEXT), CAST(a.revoked_at AS TEXT), CAST(a.rev AS TEXT), CAST(u.state AS TEXT), CAST(u.rev AS TEXT),
  a.realm_id, a.provider_id, a.subject, a.public_key, a.user_handle, a.backup_eligible, a.backup_state, a.transports, CAST(a.sign_count AS TEXT), a.password_hash,
  u.display_name, CAST(u.created_at AS TEXT), CAST(u.deletion_requested_at AS TEXT)
FROM identity_auth_identity a JOIN identity_user u ON u.user_id = a.user_id AND u.realm_id = a.realm_id
WHERE a.realm_id = ? AND a.provider_id = ? AND a.subject = ?;
