-- plan: entitlement.quota-period-terms
-- version: 1
-- access: read
-- maxRows: 100
-- statement: params=scope,int64,text returns=text,text,text,int64,text?,int64,int64,int64,int64,int64,int64
WITH cte_candidates AS (
 SELECT service_term_id, realm_id, workspace_id, kind, period_ref, starts_at, ends_at, authorized_at, selection_priority, created_at, length(CAST(period_ref AS BLOB)) AS text_bytes,
  6 * MIN(length(CAST(period_ref AS BLOB)), 256) + 2048 AS row_bytes
 FROM entitlement_service_term WHERE workspace_id = ? AND (starts_at, service_term_id) > (CAST(? AS INTEGER), ?)
 ORDER BY starts_at, service_term_id LIMIT 100
), cte_bounded AS (
 SELECT service_term_id, realm_id, workspace_id, kind, period_ref, starts_at, ends_at, authorized_at, selection_priority, created_at, text_bytes,
  SUM(row_bytes) OVER (ORDER BY starts_at, service_term_id ROWS UNBOUNDED PRECEDING) AS total_bytes,
  ROW_NUMBER() OVER (ORDER BY starts_at, service_term_id) AS position
 FROM cte_candidates
)
SELECT service_term_id, realm_id, workspace_id, CAST(kind AS TEXT), CASE WHEN text_bytes <= 256 THEN period_ref ELSE NULL END, CAST(starts_at AS TEXT), CAST(ends_at AS TEXT), CAST(authorized_at AS TEXT), CAST(selection_priority AS TEXT), CAST(created_at AS TEXT), CAST(text_bytes AS TEXT)
FROM cte_bounded WHERE total_bytes <= 196608 OR position = 1
ORDER BY starts_at, service_term_id;
