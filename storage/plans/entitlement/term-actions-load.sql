-- plan: entitlement.term-actions-load
-- version: 1
-- access: read
-- maxRows: 100
-- statement: params=scope,int64,text returns=text,text,int64,int64,int64
SELECT a.term_action_id, a.term_id, CAST(a.kind AS TEXT), CAST(a.effective_at AS TEXT), CAST(a.recorded_at AS TEXT)
FROM entitlement_service_term_action a JOIN entitlement_service_term t ON t.service_term_id = a.term_id
WHERE t.workspace_id = ? AND (a.recorded_at, a.term_action_id) > (CAST(? AS INTEGER), ?)
ORDER BY a.recorded_at, a.term_action_id LIMIT 100;
