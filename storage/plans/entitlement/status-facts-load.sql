-- plan: entitlement.status-facts-load
-- version: 1
-- access: read
-- maxRows: 100
-- statement: params=scope,int64,text returns=text,int64,int64,int64,int64
SELECT status_fact_id, CAST(recorded_at AS TEXT), CAST(status AS TEXT), CAST(auto_renew AS TEXT), CAST(purchase_pending AS TEXT)
FROM entitlement_workspace_status_fact
WHERE workspace_id = ? AND (recorded_at, status_fact_id) > (CAST(? AS INTEGER), ?)
ORDER BY recorded_at, status_fact_id LIMIT 100;
