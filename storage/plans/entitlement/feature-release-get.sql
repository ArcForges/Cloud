-- plan: entitlement.feature-release-get
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope returns=int64
SELECT CAST(released_at AS TEXT) FROM entitlement_feature_release WHERE feature_key = ?;
