-- plan: platform.archive-select
-- version: 1
-- access: read
-- maxRows: 100
-- statement: params=int64,int64 returns=int64,text,int64,text,bytes,int64
SELECT CAST(archive_sequence AS TEXT), command_id, CAST(schema_version AS TEXT), record, record_hash, CAST(created_at AS TEXT)
FROM (
  SELECT archive_sequence, command_id, schema_version, record, record_hash, created_at,
    SUM(length(CAST(record AS BLOB))) OVER (ORDER BY archive_sequence) AS running_bytes
  FROM platform_change_archive
  WHERE archive_sequence > CAST(? AS INTEGER) AND archive_sequence <= CAST(? AS INTEGER)
)
WHERE running_bytes <= 98304 ORDER BY archive_sequence;
