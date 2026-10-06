-- plan: entitlement.quota-kernel-budget
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=int64,scope,text,text returns=int64,text,text,text,text,int64,int64,int64,int64,int64
SELECT CAST(scope_kind AS TEXT), scope_id, quota_key, period_key, unit, CAST("limit" AS TEXT), CAST(used AS TEXT), CAST(held AS TEXT), CAST(policy_version AS TEXT), CAST(rev AS TEXT)
FROM entitlement_quota_budget WHERE scope_kind = CAST(? AS INTEGER) AND scope_id = ? AND quota_key = ? AND period_key = ?;
