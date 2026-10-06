-- plan: commerce.catalogue-state
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope returns=text,int64,text,text,bool,text,int64,int64,int64
SELECT o.offer_id, CAST(o.kind AS TEXT), o.name, o.scope, o.active, o.term_profile, CAST(o.rev AS TEXT),
CAST(COALESCE((SELECT MAX(version) FROM commerce_price_version WHERE offer_id = o.offer_id), 0) AS TEXT),
CAST(COALESCE((SELECT MAX(starts_at) FROM commerce_price_version WHERE offer_id = o.offer_id), 0) AS TEXT)
FROM commerce_offer o WHERE o.offer_id = ?;
