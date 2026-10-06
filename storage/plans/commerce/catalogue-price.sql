-- plan: commerce.catalogue-price
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope returns=text,int64,text,text,bool,text,int64,text,int64,text,text,text,int64,int64?,text
SELECT o.offer_id, CAST(o.kind AS TEXT), o.name, o.scope, o.active, o.term_profile, CAST(o.rev AS TEXT),
p.price_version_id, CAST(p.version AS TEXT), p.amount, p.amount_currency, p.tax_category, CAST(p.starts_at AS TEXT), CAST(p.ends_at AS TEXT), p.config_revision_id
FROM commerce_price_version p JOIN commerce_offer o ON o.offer_id = p.offer_id WHERE p.price_version_id = ?;
