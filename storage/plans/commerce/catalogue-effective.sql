-- plan: commerce.catalogue-effective
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope,int64,int64 returns=text,int64,text,text,bool,text,int64,text,int64,text,text,text,int64,int64?,text
SELECT o.offer_id, CAST(o.kind AS TEXT), o.name, o.scope, o.active, o.term_profile, CAST(o.rev AS TEXT),
p.price_version_id, CAST(p.version AS TEXT), p.amount, p.amount_currency, p.tax_category, CAST(p.starts_at AS TEXT), CAST(p.ends_at AS TEXT), p.config_revision_id
FROM commerce_offer o JOIN commerce_price_version p ON p.offer_id = o.offer_id
WHERE o.offer_id = ? AND o.active = 1 AND p.price_version_id =
(SELECT price_version_id FROM commerce_price_version WHERE offer_id = o.offer_id AND starts_at <= CAST(? AS INTEGER) ORDER BY starts_at DESC, version DESC LIMIT 1)
AND (p.ends_at IS NULL OR p.ends_at > CAST(? AS INTEGER));
