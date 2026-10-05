-- plan: entitlement.grants-load
-- version: 1
-- access: read
-- maxRows: 100
-- statement: params=scope,int64,int64,text returns=text,int64,text,text,int64,text?,int64,int64?,text,int64,text?
SELECT grant_id, CAST(kind AS TEXT), subject, value, CAST(source AS TEXT), source_ref, CAST(effective_from AS TEXT), CAST(effective_until AS TEXT), issued_by_actor, CAST(created_at AS TEXT), reason
FROM entitlement_grant
WHERE workspace_id = ? AND (kind, effective_from, grant_id) > (CAST(? AS INTEGER), CAST(? AS INTEGER), ?)
ORDER BY kind, effective_from, grant_id LIMIT 100;
