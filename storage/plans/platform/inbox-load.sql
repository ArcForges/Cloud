-- plan: platform.inbox-load
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=text,text returns=int64?,int64?
SELECT CAST(outcome AS TEXT), CAST(processed_at AS TEXT) FROM platform_inbox WHERE source = ? AND message_id = ?;
