-- plan: entitlement.revocations-load
-- version: 1
-- access: read
-- maxRows: 100
-- statement: params=scope,int64,text returns=text,text,text,int64,text,int64
SELECT r.revocation_id, r.grant_id, r.reason_code, CAST(r.effective_from AS TEXT), r.issued_by_actor, CAST(r.created_at AS TEXT)
FROM entitlement_revocation r JOIN entitlement_grant g ON g.grant_id = r.grant_id
WHERE g.workspace_id = ? AND (r.created_at, r.revocation_id) > (CAST(? AS INTEGER), ?)
ORDER BY r.created_at, r.revocation_id LIMIT 100;
