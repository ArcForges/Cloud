-- plan: foundation.account-load
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope,text returns=int64,int64
SELECT CAST(balance AS TEXT), CAST(revision AS TEXT) FROM probe_account WHERE scope = ? AND id = ?;
