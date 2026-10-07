-- plan: entitlement.quota-period-snapshot-text
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope,int64,int64,int64,int64,int64 returns=bytes
WITH cte_snapshot AS (
 SELECT capabilities, quotas, features FROM entitlement_snapshot WHERE workspace_id = ? AND entitlement_version = CAST(? AS INTEGER) AND computed_at = CAST(? AS INTEGER)
), cte_field AS (
 SELECT CASE CAST(? AS INTEGER) WHEN 1 THEN capabilities WHEN 2 THEN quotas WHEN 3 THEN features ELSE NULL END AS content FROM cte_snapshot
)
SELECT substr(CAST(content AS BLOB), CAST(? AS INTEGER) + 1, 16384) FROM cte_field WHERE length(CAST(content AS BLOB)) = CAST(? AS INTEGER);
