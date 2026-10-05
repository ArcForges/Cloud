-- plan: platform.stream-fence
-- version: 1
-- access: write
-- statement: params=text,scope,int64
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'platform.stream-fence', CASE WHEN EXISTS (SELECT 1 FROM platform_sequence_stream WHERE stream_key = ? AND fence = CAST(? AS INTEGER)) THEN 1 ELSE 0 END;
-- statement: params=int64,scope,int64
UPDATE platform_sequence_stream SET fence = fence + 1, publish_rev = publish_rev + 1, updated_at = CAST(? AS INTEGER)
WHERE stream_key = ? AND fence = CAST(? AS INTEGER);
-- statement: params=text
DELETE FROM platform_command_guard WHERE command_id = ?;
