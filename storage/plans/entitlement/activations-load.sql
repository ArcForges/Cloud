-- plan: entitlement.activations-load
-- version: 1
-- access: read
-- maxRows: 100
-- statement: params=scope,int64 returns=text,int64
SELECT definitions_version, CAST(activated_at AS TEXT)
FROM entitlement_definitions_activation
WHERE workspace_id = ? AND activated_at > CAST(? AS INTEGER)
ORDER BY activated_at LIMIT 100;
