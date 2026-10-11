-- plan: identity.recovery-active
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=text,text returns=bool
SELECT EXISTS (SELECT 1 FROM identity_recovery_code r WHERE r.user_id = u.user_id AND r.consumed_at IS NULL AND r.invalidated_at IS NULL)
FROM identity_user u WHERE u.realm_id = ? AND u.user_id = ?;
