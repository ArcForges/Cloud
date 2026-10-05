-- plan: platform.outbox-purge
-- version: 1
-- access: write
-- statement: params=text,scope,int64
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'platform.outbox-purge', CASE WHEN EXISTS (SELECT 1 FROM platform_sequence_stream WHERE stream_key = ? AND published_watermark >= CAST(? AS INTEGER)) THEN 1 ELSE 0 END;
-- statement: params=scope,int64,scope,int64
DELETE FROM platform_outbox_position WHERE stream_key = ? AND sequence <= MIN(CAST(? AS INTEGER), COALESCE((SELECT published_watermark FROM platform_sequence_stream WHERE stream_key = ?), 0)) AND outbox_id IN (SELECT outbox_id FROM platform_outbox WHERE state = 2 AND created_at < CAST(? AS INTEGER));
-- statement: params=int64
DELETE FROM platform_outbox WHERE state = 2 AND created_at < CAST(? AS INTEGER) AND outbox_id NOT IN (SELECT outbox_id FROM platform_outbox_position);
-- statement: params=text
DELETE FROM platform_command_guard WHERE command_id = ?;
