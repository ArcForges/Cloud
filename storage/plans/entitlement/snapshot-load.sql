-- plan: entitlement.snapshot-load
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope returns=int64,int64,int64?,text,text,text
SELECT CAST(entitlement_version AS TEXT), CAST(computed_at AS TEXT), CAST(valid_until AS TEXT), capabilities, quotas, features FROM entitlement_snapshot WHERE workspace_id = ?;
