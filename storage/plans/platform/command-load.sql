-- plan: platform.command-load
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=text returns=text,int64,text?,int64?,text?,int64,text,text,text?
SELECT request_hash, CAST(status AS TEXT), result_payload, CAST(result_rev AS TEXT), error_code, CAST(expires_at AS TEXT), actor_ref, operation, workspace_id
FROM platform_command WHERE command_id = ?;
