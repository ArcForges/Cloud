-- plan: foundation.account-seed
-- version: 1
-- access: write
-- statement: params=scope,text,int64
INSERT INTO probe_account (scope, id, balance, revision) VALUES (?, ?, CAST(? AS INTEGER), 1)
ON CONFLICT (scope, id) DO NOTHING;
