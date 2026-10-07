-- plan: entitlement.resolver-definition-command
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=text,text,scope returns=text,text,text,int64,text?,int64
SELECT actor_ref, operation, request_hash, CAST(status AS TEXT), result_payload, CAST(expires_at AS TEXT)
FROM platform_command WHERE command_id = ? AND workspace_id IS NULL AND actor_ref = ?
AND operation = 'entitlement.resolver-definition-publish' AND (status = 3 OR json_extract(result_payload, '$.realmId') = ?);
