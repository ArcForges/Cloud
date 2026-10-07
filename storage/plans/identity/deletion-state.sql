-- plan: identity.deletion-state
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope,text,text returns=text,text,text,int64,int64,text,int64,int64,int64,int64?,int64?,int64,int64,int64,int64?
SELECT d.deletion_id, d.realm_id, d.user_id, CAST(d.requested_at AS TEXT), CAST(d.grace_ends_at AS TEXT),
       d.policy_version, CAST(d.grace_seconds AS TEXT), CAST(d.previous_user_state AS TEXT), CAST(d.state AS TEXT),
       CAST(d.cancelled_at AS TEXT), CAST(d.completed_at AS TEXT), CAST(d.rev AS TEXT), CAST(u.state AS TEXT), CAST(u.rev AS TEXT), CAST(u.deletion_requested_at AS TEXT)
FROM identity_account_deletion d JOIN identity_user u ON u.user_id = d.user_id AND u.realm_id = d.realm_id
WHERE d.realm_id = ? AND d.user_id = ? AND d.deletion_id = ?;
