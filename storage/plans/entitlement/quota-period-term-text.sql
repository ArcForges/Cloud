-- plan: entitlement.quota-period-term-text
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=int64,scope,text,int64 returns=bytes
SELECT substr(CAST(period_ref AS BLOB), CAST(? AS INTEGER) + 1, 16384)
FROM entitlement_service_term WHERE workspace_id = ? AND service_term_id = ? AND length(CAST(period_ref AS BLOB)) = CAST(? AS INTEGER);
