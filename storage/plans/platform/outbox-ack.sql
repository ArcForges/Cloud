-- plan: platform.outbox-ack
-- version: 1
-- access: write
-- statement: params=text,scope,int64,int64,int64,int64,scope,int64,int64,int64
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'platform.outbox-ack', CASE WHEN
  EXISTS (SELECT 1 FROM platform_sequence_stream WHERE stream_key = ? AND published_watermark = CAST(? AS INTEGER) AND publish_rev = CAST(? AS INTEGER) AND fence = CAST(? AS INTEGER) AND last_sequence >= CAST(? AS INTEGER))
  AND (SELECT COUNT(*) FROM platform_outbox_position p JOIN platform_outbox o ON o.outbox_id = p.outbox_id WHERE p.stream_key = ? AND p.sequence > CAST(? AS INTEGER) AND p.sequence <= CAST(? AS INTEGER) AND o.state = 1) = CAST(? AS INTEGER)
THEN 1 ELSE 0 END;
-- statement: params=int64,scope,int64,int64
UPDATE platform_outbox SET state = 2, dispatched_at = CAST(? AS INTEGER)
WHERE state = 1 AND outbox_id IN (SELECT outbox_id FROM platform_outbox_position WHERE stream_key = ? AND sequence > CAST(? AS INTEGER) AND sequence <= CAST(? AS INTEGER));
-- statement: params=int64,text,int64,scope,int64,int64,int64
UPDATE platform_sequence_stream SET published_watermark = CAST(? AS INTEGER), publish_rev = publish_rev + 1, ack_receipt = ?, updated_at = CAST(? AS INTEGER)
WHERE stream_key = ? AND published_watermark = CAST(? AS INTEGER) AND publish_rev = CAST(? AS INTEGER) AND fence = CAST(? AS INTEGER);
-- statement: params=text
DELETE FROM platform_command_guard WHERE command_id = ?;
