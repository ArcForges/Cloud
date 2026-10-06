-- plan: entitlement.quota-kernel-reservation
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=text,text,text,scope returns=text,text,int64,text,text,text,text,text,int64,int64,int64,int64,int64?,int64?
SELECT reservation_id, operation_id, CAST(scope_kind AS TEXT), scope_id, quota_key, period_key, owner_kind, owner_id,
CAST(bound AS TEXT), CAST(consumed AS TEXT), CAST(state AS TEXT), CAST(expires_at AS TEXT), CAST(lease_until AS TEXT), CAST(fence AS TEXT)
FROM entitlement_quota_reservation WHERE reservation_id = ? AND owner_kind = ? AND owner_id = ? AND (scope_kind = 2 OR scope_id = ?);
