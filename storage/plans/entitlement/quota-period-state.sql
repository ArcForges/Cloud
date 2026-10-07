-- plan: entitlement.quota-period-state
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope returns=int64,int64,int64,int64?,text,text,text
SELECT CAST(r.rev AS TEXT), CAST(s.entitlement_version AS TEXT), CAST(s.computed_at AS TEXT), CAST(s.valid_until AS TEXT), s.capabilities, s.quotas, s.features
FROM entitlement_revision r JOIN entitlement_snapshot s ON s.workspace_id = r.workspace_id WHERE r.workspace_id = ?;
