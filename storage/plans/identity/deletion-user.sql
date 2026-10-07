-- plan: identity.deletion-user
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope,text returns=text,text,int64,int64?,int64
SELECT realm_id, user_id, CAST(state AS TEXT), CAST(deletion_requested_at AS TEXT), CAST(rev AS TEXT)
FROM identity_user WHERE realm_id = ? AND user_id = ?;
