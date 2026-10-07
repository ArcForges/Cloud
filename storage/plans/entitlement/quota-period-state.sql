-- plan: entitlement.quota-period-state
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope returns=int64,int64,int64,int64?,text?,text?,text?,int64,int64,int64
SELECT CAST(r.rev AS TEXT), CAST(s.entitlement_version AS TEXT), CAST(s.computed_at AS TEXT), CAST(s.valid_until AS TEXT),
 CASE WHEN length(CAST(s.capabilities AS BLOB)) <= 256 THEN s.capabilities ELSE NULL END,
 CASE WHEN length(CAST(s.quotas AS BLOB)) <= 256 THEN s.quotas ELSE NULL END,
 CASE WHEN length(CAST(s.features AS BLOB)) <= 256 THEN s.features ELSE NULL END,
 CAST(length(CAST(s.capabilities AS BLOB)) AS TEXT), CAST(length(CAST(s.quotas AS BLOB)) AS TEXT), CAST(length(CAST(s.features AS BLOB)) AS TEXT)
FROM entitlement_revision r JOIN entitlement_snapshot s ON s.workspace_id = r.workspace_id WHERE r.workspace_id = ?;
