-- plan: identity.user-load
-- version: 2
-- access: read
-- maxRows: 1
-- statement: params=text,text returns=text,text,int64,int64,int64?,int64,text
SELECT user_id, display_name, CAST(state AS TEXT), CAST(created_at AS TEXT), CAST(deletion_requested_at AS TEXT), CAST(rev AS TEXT), realm_id
FROM identity_user WHERE realm_id = ? AND user_id = ?;
