-- plan: entitlement.feature-releases-load
-- version: 1
-- access: read
-- maxRows: 100
-- statement: params=scope,text returns=text,int64
SELECT feature_key, CAST(released_at AS TEXT) FROM entitlement_feature_release WHERE ? = 'entitlement.global' AND feature_key > ? ORDER BY feature_key LIMIT 100;
