-- 0003 The name of a passkey that a signed-in account registers (AF-CTR-03 A1b; ArcForges-Design AD-0011 section 4).
--
-- BeginPasskeyRegistration names the new passkey (its display_name, for example "Work laptop"); the registration flow carries
-- that label until CompletePasskeyRegistration stores it on the credential. Only a passkey registration flow (kind 2) has one,
-- bounded like identity.auth_identity.label. Migration 0002 stays as it was applied; this is the only change to its tables, and
-- the runtime role's grants on identity.auth_flow are unchanged.

ALTER TABLE identity.auth_flow ADD COLUMN label text;
ALTER TABLE identity.auth_flow ADD CONSTRAINT auth_flow_label
    CHECK (label IS NULL OR (kind = 2 AND char_length(label) BETWEEN 1 AND 64 AND label !~ '[[:cntrl:]]'));
