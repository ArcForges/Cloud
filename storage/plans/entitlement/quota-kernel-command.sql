-- plan: entitlement.quota-kernel-command
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=text,scope,text returns=text,text,text,int64,text?,int64
SELECT actor_ref, operation, request_hash, CAST(status AS TEXT), result_payload, CAST(expires_at AS TEXT)
FROM platform_command WHERE command_id = ? AND (workspace_id = ? OR workspace_id IS NULL AND actor_ref = ?);
