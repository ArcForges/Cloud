-- plan: platform.archive-ack
-- version: 1
-- access: write
-- statement: params=text,int64,int64,int64,int64,int64,int64,int64
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'platform.archive-ack', CASE WHEN
  EXISTS (SELECT 1 FROM platform_sequence_stream WHERE stream_key = 'platform:change-archive' AND published_watermark = CAST(? AS INTEGER) AND publish_rev = CAST(? AS INTEGER) AND fence = CAST(? AS INTEGER) AND last_sequence >= CAST(? AS INTEGER))
  AND (SELECT COUNT(*) FROM platform_change_archive WHERE archive_sequence > CAST(? AS INTEGER) AND archive_sequence <= CAST(? AS INTEGER)) = CAST(? AS INTEGER)
THEN 1 ELSE 0 END;
-- statement: params=int64,text,int64,int64,int64,int64
UPDATE platform_sequence_stream SET published_watermark = CAST(? AS INTEGER), publish_rev = publish_rev + 1, ack_receipt = ?, updated_at = CAST(? AS INTEGER)
WHERE stream_key = 'platform:change-archive' AND published_watermark = CAST(? AS INTEGER) AND publish_rev = CAST(? AS INTEGER) AND fence = CAST(? AS INTEGER);
-- statement: params=text
DELETE FROM platform_command_guard WHERE command_id = ?;
