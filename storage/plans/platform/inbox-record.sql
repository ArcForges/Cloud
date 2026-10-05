-- plan: platform.inbox-record
-- version: 1
-- access: write
-- statement: params=text,text,int64,int64,int64,int64
INSERT INTO platform_inbox (source, message_id, received_at, processed_at, outcome, expires_at)
VALUES (?, ?, CAST(? AS INTEGER), CAST(? AS INTEGER), CAST(? AS INTEGER), CAST(? AS INTEGER));
