-- plan: entitlement.quota-period-action-text
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=int64,scope,text,int64 returns=bytes
SELECT substr(CAST(source_ref AS BLOB), CAST(? AS INTEGER) + 1, 16384)
FROM entitlement_service_term_action WHERE term_id IN (SELECT service_term_id FROM entitlement_service_term WHERE workspace_id = ?) AND term_action_id = ? AND length(CAST(source_ref AS BLOB)) = CAST(? AS INTEGER);
