-- plan: platform.stream-load
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope returns=int64,int64,int64,int64,text?
SELECT CAST(last_sequence AS TEXT), CAST(published_watermark AS TEXT), CAST(publish_rev AS TEXT), CAST(fence AS TEXT), ack_receipt
FROM platform_sequence_stream WHERE stream_key = ?;
