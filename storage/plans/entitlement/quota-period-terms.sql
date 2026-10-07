-- plan: entitlement.quota-period-terms
-- version: 1
-- access: read
-- maxRows: 100
-- statement: params=scope,int64,text returns=text,text,text,int64,text,int64,int64,int64,int64,int64
SELECT service_term_id, realm_id, workspace_id, CAST(kind AS TEXT), period_ref, CAST(starts_at AS TEXT), CAST(ends_at AS TEXT), CAST(authorized_at AS TEXT), CAST(selection_priority AS TEXT), CAST(created_at AS TEXT)
FROM entitlement_service_term WHERE workspace_id = ? AND (starts_at, service_term_id) > (CAST(? AS INTEGER), ?)
ORDER BY starts_at, service_term_id LIMIT 100;
