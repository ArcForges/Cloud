-- plan: identity.recovery-active
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope,text returns=bool
SELECT EXISTS (
  SELECT 1 FROM identity_recovery_code c JOIN identity_user u ON u.user_id = c.user_id
  WHERE u.realm_id = ? AND u.user_id = ? AND c.consumed_at IS NULL AND c.invalidated_at IS NULL
);
