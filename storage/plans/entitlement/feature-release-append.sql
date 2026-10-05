-- plan: entitlement.feature-release-append
-- version: 1
-- access: write
-- tail: none a global feature release changes no workspace row and carries no business receipt
-- statement: params=text,int64
INSERT INTO entitlement_feature_release (feature_key, released_at) VALUES (?, CAST(? AS INTEGER));
