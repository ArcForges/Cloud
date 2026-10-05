-- plan: platform.command-record-failure
-- version: 1
-- access: write
-- statement: params=text,text?,text,text,text,text,int64,int64
INSERT INTO platform_command (command_id, workspace_id, actor_ref, operation, request_hash, status, result_payload, result_rev, error_code, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, 3, NULL, NULL, ?, CAST(? AS INTEGER), CAST(? AS INTEGER));
