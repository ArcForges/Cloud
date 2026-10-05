-- plan: platform.outbox-select
-- version: 1
-- access: read
-- maxRows: 50
-- statement: params=scope,int64,int64 returns=int64,text,text,text,int64,text,text,text?,text,text?,int64,int64,int64
SELECT CAST(sequence AS TEXT), outbox_id, aggregate_kind, aggregate_id, CAST(aggregate_rev AS TEXT), event_type, payload, workspace_id, correlation_id, causation_id, CAST(state AS TEXT), CAST(attempts AS TEXT), CAST(created_at AS TEXT)
FROM (
  SELECT p.sequence AS sequence, o.outbox_id AS outbox_id, o.aggregate_kind AS aggregate_kind, o.aggregate_id AS aggregate_id, o.aggregate_rev AS aggregate_rev, o.event_type AS event_type, o.payload AS payload, o.workspace_id AS workspace_id, o.correlation_id AS correlation_id, o.causation_id AS causation_id, o.state AS state, o.attempts AS attempts, o.created_at AS created_at,
    SUM(length(CAST(o.payload AS BLOB))) OVER (ORDER BY p.sequence) AS running_bytes
  FROM platform_outbox_position p JOIN platform_outbox o ON o.outbox_id = p.outbox_id
  WHERE p.stream_key = ? AND p.sequence > CAST(? AS INTEGER) AND p.sequence <= CAST(? AS INTEGER)
)
WHERE running_bytes <= 65536 ORDER BY sequence;
