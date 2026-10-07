-- plan: entitlement.quota-period-actions
-- version: 1
-- access: read
-- maxRows: 100
-- statement: params=scope,int64,text returns=text,text,int64,int64,int64,text?,text?,int64
WITH cte_candidates AS (
 SELECT term_action_id, term_id, kind, effective_at, recorded_at, source_ref, replacement_term_id, length(CAST(source_ref AS BLOB)) AS text_bytes,
  6 * MIN(length(CAST(source_ref AS BLOB)), 256) + 2048 AS row_bytes
 FROM entitlement_service_term_action WHERE term_id IN (SELECT service_term_id FROM entitlement_service_term WHERE workspace_id = ?) AND (recorded_at, term_action_id) > (CAST(? AS INTEGER), ?)
 ORDER BY recorded_at, term_action_id LIMIT 100
), cte_bounded AS (
 SELECT term_action_id, term_id, kind, effective_at, recorded_at, source_ref, replacement_term_id, text_bytes,
  SUM(row_bytes) OVER (ORDER BY recorded_at, term_action_id ROWS UNBOUNDED PRECEDING) AS total_bytes,
  ROW_NUMBER() OVER (ORDER BY recorded_at, term_action_id) AS position
 FROM cte_candidates
)
SELECT term_action_id, term_id, CAST(kind AS TEXT), CAST(effective_at AS TEXT), CAST(recorded_at AS TEXT), CASE WHEN text_bytes <= 256 THEN source_ref ELSE NULL END, replacement_term_id, CAST(text_bytes AS TEXT)
FROM cte_bounded WHERE total_bytes <= 196608 OR position = 1
ORDER BY recorded_at, term_action_id;
