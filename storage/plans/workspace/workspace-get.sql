-- plan: workspace.workspace-get
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=text,scope returns=text,text,text,text,text,int64,int64,int64,int64
SELECT workspace_id, realm_id, owner_user_id, name, data_region, CAST(protection_profile AS TEXT), CAST(state AS TEXT), CAST(created_at AS TEXT), CAST(rev AS TEXT)
FROM workspace_workspace WHERE realm_id = ? AND workspace_id = ?;
