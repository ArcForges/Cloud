-- plan: commerce.catalogue-publish
-- version: 1
-- access: write
-- tail: v1 events=0
-- statement: params=text,scope,int64,text,text,bool,text,int64,text,int64,int64,int64
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'commerce.catalogue-publish', CASE WHEN
COALESCE(o.rev, 0) = c.expected_rev
AND (o.offer_id IS NULL OR (o.kind = c.kind AND o.scope = c.scope AND o.term_profile = c.term_profile))
AND NOT EXISTS (SELECT 1 FROM commerce_price_version WHERE price_version_id = c.price_id)
AND NOT EXISTS (SELECT 1 FROM commerce_price_version WHERE offer_id = c.offer_id AND (version >= c.version OR starts_at >= c.starts_at))
AND (c.starts_at <= c.now OR o.offer_id IS NULL OR (o.name = c.name AND o.active = c.active))
THEN 1 ELSE 0 END
FROM (SELECT ? AS offer_id, CAST(? AS INTEGER) AS kind, ? AS name, ? AS scope, ? AS active, ? AS term_profile,
CAST(? AS INTEGER) AS expected_rev, ? AS price_id, CAST(? AS INTEGER) AS version, CAST(? AS INTEGER) AS starts_at, CAST(? AS INTEGER) AS now) c
LEFT JOIN commerce_offer o ON o.offer_id = c.offer_id;
-- statement: params=scope,int64,text,text,bool,text,int64,int64
INSERT INTO commerce_offer (offer_id, kind, name, scope, active, term_profile, created_at, rev)
VALUES (?, CAST(? AS INTEGER), ?, ?, ?, ?, CAST(? AS INTEGER), CAST(? AS INTEGER) + 1)
ON CONFLICT (offer_id) DO UPDATE SET name = excluded.name, active = excluded.active, rev = excluded.rev;
-- statement: params=text,scope,int64,text,text,text,int64,int64,text
INSERT INTO commerce_price_version (price_version_id, offer_id, version, amount, amount_currency, tax_category, starts_at, ends_at, config_revision_id)
VALUES (?, ?, CAST(? AS INTEGER), ?, ?, ?, CAST(? AS INTEGER), NULLIF(CAST(? AS INTEGER), -1), ?);
-- statement: params=text,text?,text,text,text,text,int64,int64,int64
INSERT INTO platform_command (command_id, workspace_id, actor_ref, operation, request_hash, status, result_payload, result_rev, error_code, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, 2, ?, NULLIF(CAST(? AS INTEGER), -1), NULL, CAST(? AS INTEGER), CAST(? AS INTEGER));
-- statement: params=int64
INSERT INTO platform_sequence_stream (stream_key, last_sequence, published_watermark, publish_rev, fence, ack_receipt, updated_at)
VALUES ('platform:change-archive', 1, 0, 0, 0, NULL, CAST(? AS INTEGER))
ON CONFLICT (stream_key) DO UPDATE SET last_sequence = last_sequence + 1, updated_at = excluded.updated_at;
-- statement: params=text,int64,text,bytes,int64
INSERT INTO platform_change_archive (archive_sequence, command_id, schema_version, record, record_hash, created_at)
VALUES ((SELECT last_sequence FROM platform_sequence_stream WHERE stream_key = 'platform:change-archive'), ?, CAST(? AS INTEGER), ?, ?, CAST(? AS INTEGER));
-- statement: params=text
DELETE FROM platform_command_guard WHERE command_id = ?;
