-- plan: platform.outbox-attempt
-- version: 1
-- access: write
-- statement: params=text,text,scope,int64,int64
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'platform.outbox-attempt', CASE WHEN EXISTS (
  SELECT 1 FROM platform_outbox o JOIN platform_outbox_position p ON p.outbox_id = o.outbox_id JOIN platform_sequence_stream s ON s.stream_key = p.stream_key
  WHERE o.outbox_id = ? AND p.stream_key = ? AND o.state = 1 AND o.attempts = CAST(? AS INTEGER) AND s.fence = CAST(? AS INTEGER)
) THEN 1 ELSE 0 END;
-- statement: params=text,int64
UPDATE platform_outbox SET attempts = attempts + 1 WHERE outbox_id = ? AND state = 1 AND attempts = CAST(? AS INTEGER);
-- statement: params=text
DELETE FROM platform_command_guard WHERE command_id = ?;
