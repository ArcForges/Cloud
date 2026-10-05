-- plan: identity.credential-touch
-- version: 1
-- access: write
-- tail: none usage observation of an already authenticated credential: no business effect, receipt or event, and the instant only moves forward
-- statement: params=int64,text,text,int64
UPDATE identity_auth_identity SET last_used_at = CAST(? AS INTEGER)
WHERE realm_id = ? AND auth_identity_id = ? AND revoked_at IS NULL AND (last_used_at IS NULL OR last_used_at < CAST(? AS INTEGER));
