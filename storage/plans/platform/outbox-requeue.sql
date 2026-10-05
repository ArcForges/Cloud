-- plan: platform.outbox-requeue
-- version: 1
-- access: write
-- statement: params=text,text,scope,int64
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'platform.outbox-requeue', CASE WHEN EXISTS (
  SELECT 1 FROM platform_outbox o JOIN platform_outbox_position p ON p.outbox_id = o.outbox_id JOIN platform_sequence_stream s ON s.stream_key = p.stream_key
  WHERE o.outbox_id = ? AND p.stream_key = ? AND o.state = 3 AND s.fence = CAST(? AS INTEGER)
) THEN 1 ELSE 0 END;
-- statement: params=text
UPDATE platform_outbox SET state = 1, attempts = 0 WHERE outbox_id = ? AND state = 3;
-- statement: params=text
DELETE FROM platform_command_guard WHERE command_id = ?;
