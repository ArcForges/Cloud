-- plan: entitlement.revision-load
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope returns=int64
SELECT CAST(rev AS TEXT) FROM entitlement_revision WHERE workspace_id = ?;
