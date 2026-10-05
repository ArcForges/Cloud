-- plan: foundation.exact-load
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope,text returns=int64,uint64,decimal,bytes?,int64
SELECT CAST(signed_value AS TEXT), unsigned_text, decimal_text, payload, CAST(revision AS TEXT)
FROM probe_exact WHERE scope = ? AND id = ?;
