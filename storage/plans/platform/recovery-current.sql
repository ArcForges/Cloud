-- plan: platform.recovery-current
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=text returns=text,int64,int64,int64
SELECT realm_id, CAST(recovery_generation AS TEXT), CAST(state AS TEXT), CAST(rev AS TEXT)
FROM platform_recovery_epoch WHERE realm_id = ? LIMIT 1;
