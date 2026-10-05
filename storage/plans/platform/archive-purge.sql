-- plan: platform.archive-purge
-- version: 1
-- access: write
-- statement: params=text,int64
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'platform.archive-purge', CASE WHEN EXISTS (SELECT 1 FROM platform_sequence_stream WHERE stream_key = 'platform:change-archive' AND published_watermark >= CAST(? AS INTEGER)) THEN 1 ELSE 0 END;
-- statement: params=int64,int64
DELETE FROM platform_change_archive WHERE archive_sequence <= MIN(CAST(? AS INTEGER), COALESCE((SELECT published_watermark FROM platform_sequence_stream WHERE stream_key = 'platform:change-archive'), 0)) AND created_at < CAST(? AS INTEGER);
-- statement: params=text
DELETE FROM platform_command_guard WHERE command_id = ?;
