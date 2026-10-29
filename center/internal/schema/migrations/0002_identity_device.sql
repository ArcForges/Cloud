-- 0002 Accounts, sessions and devices of the center (AF-CTR-03; ArcForges-Design AD-0011, AD-0021 sections 3 to 7 and 10,
-- data/cloud-store.md sections 2 and 6).
--
-- Applied by `arcforges-center migrate` in one transaction with the migration role; the runner reconciles the runtime role's
-- grants from center/internal/schema/schema.go after every run. The tables derive from the D1 manifests
-- src/ArcForges.Cloud.Storage.D1/Physical/manifest/{identity,device}.json by the section 6 rules (uuid keys, timestamptz instants,
-- smallint enumerations with named CHECK constraints, bounded text). The deviations from the D1 model are listed in
-- docs/postgres-store.md ("Identity and device"):
--   * no realm_id: one center database is one realm;
--   * identity.user gains locale, timezone and the WebAuthn user handle; contract_set_version of device_installation is dropped;
--   * identity.session gains scope, auth_method, authenticated_at, refresh_expires_at and revoke_reason; it keeps no csrf_hash
--     (the CSRF token of a browser session is derived from its cookie handle) and every session names a device and an installation;
--   * identity.auth_flow replaces identity_browser_auth_flow and identity_security_flow for the passkey and e-mail ceremonies;
--   * device.installation.public_key and key_version are nullable (node keys arrive with AF-CTR-04, phone keys with AF-CLD-02), and
--     client_installation_id carries a browser's claimed installation;
--   * the trust level gains 3 = revoked (set by the revocation cascade);
--   * every foreign key is NO ACTION: the D1 cascades of identity_session.user_id and device_installation.device_id are dropped, so a
--     sweep or purge deletes the children first.
--
-- Every credential is stored as a SHA-256 digest (tokens, cookie handles) or a salted PBKDF2 verifier (e-mail codes); no token or code is
-- stored in clear. E-mail addresses are stored in clear only as the subject of an e-mail identity (identity.auth_identity). Flows
-- (identity.auth_flow.email_hash) and rate-limit buckets keep unsalted SHA-256 digests of addresses; such a digest can be reversed by
-- trying addresses, so those rows are personal data, also of people without an account, under their retention. The runtime role has no
-- DELETE: flows, challenges, spent refresh tokens, rate-limit windows and revoked rows are marked, never deleted; the retention sweeps
-- that remove them run with the migration role (AF-PLAT-01).

CREATE SCHEMA identity;
CREATE SCHEMA device;

-- Accounts. A user is never an e-mail address and never a credential; its credentials come and go without changing it.
CREATE TABLE identity.user (
    user_id               uuid        NOT NULL,
    display_name          text        NOT NULL,
    state                 smallint    NOT NULL,
    locale                text        NOT NULL DEFAULT 'en-US',
    timezone              text        NOT NULL DEFAULT 'UTC',
    passkey_user_handle   bytea       NOT NULL,
    created_at            timestamptz NOT NULL,
    deletion_requested_at timestamptz,
    rev                   bigint      NOT NULL,
    CONSTRAINT user_pkey PRIMARY KEY (user_id),
    CONSTRAINT user_passkey_user_handle UNIQUE (passkey_user_handle),
    CONSTRAINT user_display_name CHECK (char_length(display_name) BETWEEN 1 AND 128 AND display_name !~ '[[:cntrl:]]'),
    -- 1 active, 2 restricted, 3 suspended, 4 pending deletion, 5 deleted (identity.user_state)
    CONSTRAINT user_state CHECK (state IN (1, 2, 3, 4, 5)),
    CONSTRAINT user_locale CHECK (locale ~ '^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8}){0,4}$' AND length(locale) <= 35),
    CONSTRAINT user_timezone CHECK (timezone ~ '^[A-Za-z0-9_+/-]{1,64}$'),
    CONSTRAINT user_passkey_user_handle_length CHECK (length(passkey_user_handle) = 32),
    CONSTRAINT user_rev CHECK (rev >= 1)
);

-- Devices: one record per node, per phone and per browser installation (AD-0021 section 7). The cascade of a revocation sets
-- revoked_at, the trust level 3 = revoked and remote_enabled false in one transaction with the revocation of every session bound to
-- the device.
CREATE TABLE device.device (
    device_id       uuid        NOT NULL,
    user_id         uuid        NOT NULL,
    display_name    text        NOT NULL,
    platform        smallint    NOT NULL,
    trust_level     smallint    NOT NULL,
    trust_raised_at timestamptz,
    remote_enabled  boolean     NOT NULL,
    first_seen_at   timestamptz NOT NULL,
    last_seen_at    timestamptz NOT NULL,
    revoked_at      timestamptz,
    revoke_reason   smallint,
    rev             bigint      NOT NULL,
    CONSTRAINT device_pkey PRIMARY KEY (device_id),
    CONSTRAINT device_owner UNIQUE (device_id, user_id),
    CONSTRAINT device_user FOREIGN KEY (user_id) REFERENCES identity.user (user_id),
    CONSTRAINT device_display_name CHECK (char_length(display_name) BETWEEN 1 AND 64 AND display_name !~ '[[:cntrl:]]'),
    -- 1 windows, 2 macos, 3 linux, 4 android, 5 ios, 6 web (device.platform)
    CONSTRAINT device_platform CHECK (platform IN (1, 2, 3, 4, 5, 6)),
    -- 1 untrusted, 2 trusted, 3 revoked (device.trust_level; 3 is set only by the revocation cascade)
    CONSTRAINT device_trust_level CHECK (trust_level IN (1, 2, 3)),
    CONSTRAINT device_revoked_trust CHECK ((trust_level = 3) = (revoked_at IS NOT NULL)),
    CONSTRAINT device_remote_enabled_requires_trusted CHECK (NOT remote_enabled OR trust_level = 2),
    -- 1 revoked by its owner, 2 revoked by an operator (device.revoke_reason)
    CONSTRAINT device_revoke_reason CHECK ((revoke_reason IS NULL) = (revoked_at IS NULL) AND (revoke_reason IS NULL OR revoke_reason IN (1, 2))),
    CONSTRAINT device_seen CHECK (last_seen_at >= first_seen_at),
    CONSTRAINT device_rev CHECK (rev >= 1)
);
CREATE INDEX device_user ON device.device (user_id, revoked_at);

-- Installations: one per device and product. A native installation's ID is the client's (global: a foreign or revoked one is refused);
-- a browser installation's ID is generated by the center and its claimed ID is client_installation_id, unique per account over live
-- rows, so a claim never links two accounts.
CREATE TABLE device.installation (
    installation_id        uuid        NOT NULL,
    device_id              uuid        NOT NULL,
    user_id                uuid        NOT NULL,
    product_id             text        NOT NULL,
    app_version            text        NOT NULL,
    platform               text        NOT NULL,
    client_installation_id uuid,
    public_key             bytea,
    key_version            bigint,
    installed_at           timestamptz NOT NULL,
    last_active_at         timestamptz NOT NULL,
    revoked_at             timestamptz,
    rev                    bigint      NOT NULL,
    CONSTRAINT installation_pkey PRIMARY KEY (installation_id),
    CONSTRAINT installation_device_product UNIQUE (device_id, product_id),
    CONSTRAINT installation_of_device UNIQUE (installation_id, device_id),
    CONSTRAINT installation_device FOREIGN KEY (device_id, user_id) REFERENCES device.device (device_id, user_id),
    CONSTRAINT installation_product_id CHECK (product_id IN ('arcscope', 'companion', 'arcforges-node', 'arcforges-mobile', 'arcforges-web')),
    CONSTRAINT installation_app_version CHECK (app_version ~ '^[A-Za-z0-9._:/-]{1,128}$'),
    CONSTRAINT installation_platform CHECK (platform ~ '^[A-Za-z0-9._:/-]{1,128}$'),
    CONSTRAINT installation_web_claim CHECK ((product_id = 'arcforges-web') = (client_installation_id IS NOT NULL)),
    CONSTRAINT installation_key CHECK ((public_key IS NULL) = (key_version IS NULL)),
    CONSTRAINT installation_public_key_length CHECK (public_key IS NULL OR length(public_key) BETWEEN 32 AND 512),
    CONSTRAINT installation_key_version CHECK (key_version IS NULL OR key_version >= 1),
    CONSTRAINT installation_active CHECK (last_active_at >= installed_at),
    CONSTRAINT installation_rev CHECK (rev >= 1)
);
CREATE INDEX installation_device ON device.installation (device_id);
CREATE UNIQUE INDEX installation_live_web_claim ON device.installation (user_id, client_installation_id)
    WHERE revoked_at IS NULL AND client_installation_id IS NOT NULL;

-- Credentials (authentication identities). Unique by provider and subject, revoked rows included, so a subject never moves from one
-- user to another. Only passkeys (1) and e-mail codes (2) are admitted; the passkey columns are complete for a passkey and absent
-- otherwise. A passkey's subject is the unpadded base64url of its credential ID (at most 1023 bytes, so 1364 characters); an e-mail
-- identity's subject is its normalised address (at most 320 characters). sign_count only ever increases (a regression is refused
-- before any write).
CREATE TABLE identity.auth_identity (
    auth_identity_id   uuid        NOT NULL,
    user_id            uuid        NOT NULL,
    method             smallint    NOT NULL,
    provider_id        text        NOT NULL,
    subject            text        NOT NULL,
    label              text,
    public_key         bytea,
    user_handle        bytea,
    sign_count         bigint,
    backup_eligible    boolean,
    backup_state       boolean,
    transports         text[],
    aaguid             bytea,
    attestation_format text,
    created_at         timestamptz NOT NULL,
    last_used_at       timestamptz,
    revoked_at         timestamptz,
    rev                bigint      NOT NULL,
    CONSTRAINT auth_identity_pkey PRIMARY KEY (auth_identity_id),
    CONSTRAINT auth_identity_provider_subject UNIQUE (provider_id, subject),
    CONSTRAINT auth_identity_user FOREIGN KEY (user_id) REFERENCES identity.user (user_id),
    -- 1 passkey, 2 email code (identity.auth_method; password 3 and OIDC 4 are not admitted on the center)
    CONSTRAINT auth_identity_method CHECK (method IN (1, 2)),
    CONSTRAINT auth_identity_method_provider CHECK ((method = 1 AND provider_id = 'passkey') OR (method = 2 AND provider_id = 'email')),
    CONSTRAINT auth_identity_subject CHECK (subject !~ '[[:cntrl:]]' AND ((method = 1 AND char_length(subject) BETWEEN 1 AND 1364) OR
        (method = 2 AND char_length(subject) BETWEEN 1 AND 320))),
    CONSTRAINT auth_identity_label CHECK (label IS NULL OR (char_length(label) BETWEEN 1 AND 64 AND label !~ '[[:cntrl:]]')),
    CONSTRAINT auth_identity_passkey_material_complete CHECK (method <> 1 OR (public_key IS NOT NULL AND user_handle IS NOT NULL AND
        sign_count IS NOT NULL AND backup_eligible IS NOT NULL AND backup_state IS NOT NULL AND transports IS NOT NULL AND aaguid IS NOT NULL AND
        attestation_format IS NOT NULL)),
    CONSTRAINT auth_identity_passkey_material_only_for_passkey CHECK (method = 1 OR (public_key IS NULL AND user_handle IS NULL AND
        sign_count IS NULL AND backup_eligible IS NULL AND backup_state IS NULL AND transports IS NULL AND aaguid IS NULL AND
        attestation_format IS NULL)),
    CONSTRAINT auth_identity_backup_state_requires_backup_eligible CHECK (NOT backup_state OR backup_eligible),
    CONSTRAINT auth_identity_public_key_length CHECK (public_key IS NULL OR length(public_key) BETWEEN 16 AND 1024),
    CONSTRAINT auth_identity_user_handle_length CHECK (user_handle IS NULL OR length(user_handle) BETWEEN 1 AND 64),
    CONSTRAINT auth_identity_sign_count CHECK (sign_count IS NULL OR sign_count BETWEEN 0 AND 4294967295),
    CONSTRAINT auth_identity_transports CHECK (transports IS NULL OR cardinality(transports) <= 8),
    CONSTRAINT auth_identity_aaguid_length CHECK (aaguid IS NULL OR length(aaguid) = 16),
    CONSTRAINT auth_identity_attestation_format CHECK (attestation_format IS NULL OR attestation_format = 'none'),
    CONSTRAINT auth_identity_used CHECK (last_used_at IS NULL OR last_used_at >= created_at),
    CONSTRAINT auth_identity_rev CHECK (rev >= 1)
);
CREATE INDEX auth_identity_user ON identity.auth_identity (user_id, revoked_at);

-- Sessions: native bearer sessions (access and refresh token digests, rotation per family) and browser cookie sessions (the cookie
-- handle's digest, bound to one origin). Every session names its device and installation. scope is the account-session scope
-- (AD-0011 section 5); the agent scope does not exist here (AF-CTR-07 issues agent grants in their own table).
CREATE TABLE identity.session (
    session_id             uuid        NOT NULL,
    user_id                uuid        NOT NULL,
    device_id              uuid        NOT NULL,
    installation_id        uuid        NOT NULL,
    family_id              uuid,
    credential_kind        smallint    NOT NULL,
    scope                  smallint    NOT NULL,
    product_id             text        NOT NULL,
    purpose                smallint    NOT NULL,
    auth_method            smallint    NOT NULL,
    authenticated_at       timestamptz NOT NULL,
    issued_at              timestamptz NOT NULL,
    expires_at             timestamptz NOT NULL,
    idle_expires_at        timestamptz,
    last_activity_at       timestamptz NOT NULL,
    access_token_hash      bytea,
    access_expires_at      timestamptz,
    refresh_token_hash     bytea,
    refresh_generation     bigint,
    refresh_expires_at     timestamptz,
    browser_handle_hash    bytea,
    browser_origin         text,
    step_up_at             timestamptz,
    auth_epoch             bigint      NOT NULL,
    recovery_generation    bigint      NOT NULL,
    session_policy_version text        NOT NULL,
    revoked_at             timestamptz,
    revoke_reason          smallint,
    rev                    bigint      NOT NULL,
    CONSTRAINT session_pkey PRIMARY KEY (session_id),
    CONSTRAINT session_owner FOREIGN KEY (user_id) REFERENCES identity.user (user_id),
    CONSTRAINT session_device FOREIGN KEY (device_id, user_id) REFERENCES device.device (device_id, user_id),
    CONSTRAINT session_installation FOREIGN KEY (installation_id, device_id) REFERENCES device.installation (installation_id, device_id),
    -- 1 native bearer, 2 browser cookie (identity.credential_kind)
    CONSTRAINT session_credential_kind CHECK (credential_kind IN (1, 2)),
    -- 1 account, 2 mobile.limited, 3 node, 4 push, 5 automation (identity.session_scope)
    CONSTRAINT session_scope CHECK (scope IN (1, 2, 3, 4, 5)),
    CONSTRAINT session_product_id CHECK (product_id IN ('arcscope', 'companion', 'arcforges-node', 'arcforges-mobile', 'arcforges-web')),
    -- 1 authenticate, 2 enroll, 4 recover (AuthPurpose)
    CONSTRAINT session_purpose CHECK (purpose IN (1, 2, 4)),
    -- 1 passkey, 2 email code (identity.auth_method)
    CONSTRAINT session_auth_method CHECK (auth_method IN (1, 2)),
    CONSTRAINT session_native_bearer_shape CHECK (credential_kind <> 1 OR (access_token_hash IS NOT NULL AND access_expires_at IS NOT NULL AND
        refresh_token_hash IS NOT NULL AND refresh_generation IS NOT NULL AND refresh_expires_at IS NOT NULL AND family_id IS NOT NULL AND
        browser_handle_hash IS NULL AND browser_origin IS NULL AND idle_expires_at IS NULL)),
    CONSTRAINT session_browser_cookie_shape CHECK (credential_kind <> 2 OR (browser_handle_hash IS NOT NULL AND browser_origin IS NOT NULL AND
        idle_expires_at IS NOT NULL AND access_token_hash IS NULL AND access_expires_at IS NULL AND refresh_token_hash IS NULL AND
        refresh_generation IS NULL AND refresh_expires_at IS NULL AND family_id IS NULL AND product_id = 'arcforges-web')),
    CONSTRAINT session_hash_lengths CHECK ((access_token_hash IS NULL OR length(access_token_hash) = 32) AND
        (refresh_token_hash IS NULL OR length(refresh_token_hash) = 32) AND (browser_handle_hash IS NULL OR length(browser_handle_hash) = 32)),
    CONSTRAINT session_browser_origin CHECK (browser_origin IS NULL OR length(browser_origin) BETWEEN 1 AND 2048),
    CONSTRAINT session_refresh_generation CHECK (refresh_generation IS NULL OR refresh_generation >= 1),
    CONSTRAINT session_expiry CHECK (expires_at > issued_at AND issued_at >= authenticated_at),
    CONSTRAINT session_idle_expiry_not_after_absolute CHECK (idle_expires_at IS NULL OR idle_expires_at <= expires_at),
    CONSTRAINT session_refresh_expiry_not_after_absolute CHECK (refresh_expires_at IS NULL OR refresh_expires_at <= expires_at),
    CONSTRAINT session_policy_version CHECK (session_policy_version ~ '^[a-z0-9.-]{1,32}$'),
    CONSTRAINT session_epochs CHECK (auth_epoch >= 0 AND recovery_generation >= 0),
    -- 1 signed out, 2 revoked by its account, 3 all sessions revoked, 4 refresh token reused, 5 device revoked, 6 operator
    -- (identity.session_revoke_reason)
    CONSTRAINT session_revoke_reason CHECK ((revoke_reason IS NULL) = (revoked_at IS NULL) AND (revoke_reason IS NULL OR revoke_reason IN (1, 2, 3, 4, 5, 6))),
    CONSTRAINT session_rev CHECK (rev >= 1)
);
CREATE UNIQUE INDEX session_access_token_hash ON identity.session (access_token_hash) WHERE access_token_hash IS NOT NULL;
CREATE UNIQUE INDEX session_refresh_token_hash ON identity.session (refresh_token_hash) WHERE refresh_token_hash IS NOT NULL;
CREATE UNIQUE INDEX session_browser_handle_hash ON identity.session (browser_handle_hash) WHERE browser_handle_hash IS NOT NULL;
CREATE INDEX session_by_user ON identity.session (user_id, revoked_at, expires_at);
CREATE INDEX session_device ON identity.session (device_id);
CREATE INDEX session_installation ON identity.session (installation_id);
CREATE INDEX session_family ON identity.session (family_id) WHERE family_id IS NOT NULL;
CREATE INDEX session_expires_at ON identity.session (expires_at);

-- Spent refresh tokens: the digest of every rotated refresh token, so a second presentation is recognised as reuse and revokes the
-- family. Kept until the family's absolute expiry or with its session, whichever comes first (retention sweep, AF-PLAT-01).
CREATE TABLE identity.spent_refresh (
    token_hash        bytea       NOT NULL,
    session_id        uuid        NOT NULL,
    family_id         uuid        NOT NULL,
    generation        bigint      NOT NULL,
    consumed_at       timestamptz NOT NULL,
    family_expires_at timestamptz NOT NULL,
    CONSTRAINT spent_refresh_pkey PRIMARY KEY (token_hash),
    CONSTRAINT spent_refresh_family_generation UNIQUE (family_id, generation),
    CONSTRAINT spent_refresh_session FOREIGN KEY (session_id) REFERENCES identity.session (session_id),
    CONSTRAINT spent_refresh_token_hash CHECK (length(token_hash) = 32),
    CONSTRAINT spent_refresh_generation CHECK (generation >= 1)
);
CREATE INDEX spent_refresh_session ON identity.spent_refresh (session_id);
CREATE INDEX spent_refresh_family_expires_at ON identity.spent_refresh (family_expires_at);

-- Authentication flows: one row per ceremony (passkey sign-in, passkey registration of a signed-in account, enrollment, e-mail code).
-- A flow is bound to its channel, its kind, its purpose and, for a native flow, its installation claim; a browser flow is bound by its
-- channel, the exact Origin and the secrecy of its 122-bit flow ID. Attempts are counted in their own transaction before a proof is
-- checked, and a consumed flow is never changed again. A passkey registration flow carries the label its new credential gets. An e-mail
-- flow keeps email_hash, the unsalted SHA-256 of the normalised address submitted, whether or not an account has it: it can be reversed
-- by trying addresses, so e-mail flows are personal data, under the flows' retention.
CREATE TABLE identity.auth_flow (
    flow_id                uuid        NOT NULL,
    channel                smallint    NOT NULL,
    kind                   smallint    NOT NULL,
    purpose                smallint    NOT NULL,
    user_id                uuid,
    session_id             uuid,
    label                  text,
    origin                 text,
    challenge              bytea,
    webauthn_user_handle   bytea,
    email_hash             bytea,
    code_hash              bytea,
    code_salt              bytea,
    sends                  smallint    NOT NULL,
    installation_id        uuid,
    installation_product   text,
    installation_platform  text,
    installation_version   text,
    attempts               smallint    NOT NULL,
    max_attempts           smallint    NOT NULL,
    created_at             timestamptz NOT NULL,
    expires_at             timestamptz NOT NULL,
    consumed_at            timestamptz,
    outcome                smallint,
    CONSTRAINT auth_flow_pkey PRIMARY KEY (flow_id),
    CONSTRAINT auth_flow_user FOREIGN KEY (user_id) REFERENCES identity.user (user_id),
    CONSTRAINT auth_flow_session FOREIGN KEY (session_id) REFERENCES identity.session (session_id),
    -- 1 native, 2 browser (identity.flow_channel)
    CONSTRAINT auth_flow_channel CHECK (channel IN (1, 2)),
    -- 1 passkey sign-in, 2 passkey registration, 3 enrollment, 4 e-mail code (identity.flow_kind)
    CONSTRAINT auth_flow_kind CHECK (kind IN (1, 2, 3, 4)),
    -- 1 authenticate, 2 enroll (AuthPurpose)
    CONSTRAINT auth_flow_purpose CHECK (purpose IN (1, 2)),
    CONSTRAINT auth_flow_passkey_challenge CHECK ((kind IN (1, 2, 3)) = (challenge IS NOT NULL) AND (challenge IS NULL OR length(challenge) = 32)),
    CONSTRAINT auth_flow_registration_handle CHECK ((kind IN (2, 3)) = (webauthn_user_handle IS NOT NULL) AND
        (webauthn_user_handle IS NULL OR length(webauthn_user_handle) = 32)),
    CONSTRAINT auth_flow_registration_session CHECK ((kind = 2) = (session_id IS NOT NULL) AND (kind <> 2 OR user_id IS NOT NULL)),
    -- the label rule of identity.auth_identity.label, so a registration flow's label is always a valid credential label
    CONSTRAINT auth_flow_label CHECK ((kind = 2) = (label IS NOT NULL) AND (label IS NULL OR (char_length(label) BETWEEN 1 AND 64 AND
        label !~ '[[:cntrl:]]'))),
    CONSTRAINT auth_flow_email CHECK ((kind = 4) = (email_hash IS NOT NULL) AND (kind = 4) = (code_hash IS NOT NULL) AND
        (kind = 4) = (code_salt IS NOT NULL) AND (email_hash IS NULL OR length(email_hash) = 32) AND (code_hash IS NULL OR length(code_hash) = 32) AND
        (code_salt IS NULL OR length(code_salt) = 16)),
    CONSTRAINT auth_flow_browser_origin CHECK ((channel = 2) = (origin IS NOT NULL) AND (origin IS NULL OR length(origin) BETWEEN 1 AND 2048)),
    CONSTRAINT auth_flow_installation CHECK ((installation_id IS NULL) = (installation_product IS NULL) AND
        (installation_id IS NULL) = (installation_platform IS NULL) AND (installation_id IS NULL) = (installation_version IS NULL)),
    CONSTRAINT auth_flow_installation_product CHECK (installation_product IS NULL OR
        installation_product IN ('arcscope', 'companion', 'arcforges-node', 'arcforges-mobile', 'arcforges-web')),
    CONSTRAINT auth_flow_installation_text CHECK ((installation_platform IS NULL OR installation_platform ~ '^[A-Za-z0-9._:/-]{1,128}$') AND
        (installation_version IS NULL OR installation_version ~ '^[A-Za-z0-9._:/-]{1,128}$')),
    CONSTRAINT auth_flow_sends CHECK (sends BETWEEN 0 AND 3),
    CONSTRAINT auth_flow_attempts CHECK (attempts >= 0 AND attempts <= max_attempts AND max_attempts BETWEEN 1 AND 10),
    CONSTRAINT auth_flow_expiry CHECK (expires_at > created_at),
    -- 1 succeeded, 2 attempts exhausted (identity.flow_outcome). A consumed flow is final (auth_flow_consumed_is_final): presented
    -- again, a succeeded flow is refused CONFLICT/code_reused and an exhausted one STATE/expired; neither is recorded here.
    CONSTRAINT auth_flow_outcome CHECK ((outcome IS NULL) = (consumed_at IS NULL) AND (outcome IS NULL OR outcome IN (1, 2)))
);
CREATE INDEX auth_flow_expires_at ON identity.auth_flow (expires_at);
CREATE INDEX auth_flow_session ON identity.auth_flow (session_id) WHERE session_id IS NOT NULL;
CREATE INDEX auth_flow_user ON identity.auth_flow (user_id) WHERE user_id IS NOT NULL;

CREATE FUNCTION identity.refuse_consumed_flow_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.consumed_at IS NOT NULL THEN
        RAISE EXCEPTION 'a consumed authentication flow is never changed' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER auth_flow_consumed_is_final BEFORE UPDATE ON identity.auth_flow
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_consumed_flow_change();

-- Step-up challenges (the contract's evidence model): one challenge for one operation ID and one target digest of one session, proved
-- at most once and consumed at most once by the sensitive call's own transaction, within five minutes of its proof.
CREATE TABLE identity.step_up_challenge (
    challenge_id        uuid        NOT NULL,
    user_id             uuid        NOT NULL,
    session_id          uuid        NOT NULL,
    operation_id        text        NOT NULL,
    target_hash         bytea       NOT NULL,
    method              smallint    NOT NULL,
    challenge           bytea,
    code_hash           bytea,
    code_salt           bytea,
    state               smallint    NOT NULL,
    attempt_count       smallint    NOT NULL,
    created_at          timestamptz NOT NULL,
    expires_at          timestamptz NOT NULL,
    proved_at           timestamptz,
    consumed_at         timestamptz,
    auth_epoch          bigint      NOT NULL,
    recovery_generation bigint      NOT NULL,
    rev                 bigint      NOT NULL,
    CONSTRAINT step_up_challenge_pkey PRIMARY KEY (challenge_id),
    CONSTRAINT step_up_challenge_user FOREIGN KEY (user_id) REFERENCES identity.user (user_id),
    CONSTRAINT step_up_challenge_session FOREIGN KEY (session_id) REFERENCES identity.session (session_id),
    CONSTRAINT step_up_challenge_operation_id CHECK (operation_id ~ '^[a-z][a-zA-Z]*\.[a-z][a-zA-Z]{0,63}$'),
    CONSTRAINT step_up_challenge_target_hash CHECK (length(target_hash) = 32),
    -- 1 passkey, 2 email code (identity.auth_method)
    CONSTRAINT step_up_challenge_method CHECK (method IN (1, 2)),
    CONSTRAINT step_up_challenge_material CHECK ((method = 1 AND challenge IS NOT NULL AND length(challenge) = 32 AND code_hash IS NULL AND code_salt IS NULL) OR
        (method = 2 AND challenge IS NULL AND code_hash IS NOT NULL AND code_salt IS NOT NULL AND length(code_hash) = 32 AND
        length(code_salt) = 16)),
    -- 1 pending, 2 proved, 3 consumed, 4 expired, 5 denied (identity.step_up_state)
    CONSTRAINT step_up_challenge_state CHECK (state IN (1, 2, 3, 4, 5)),
    CONSTRAINT step_up_challenge_proved CHECK ((state IN (2, 3)) = (proved_at IS NOT NULL)),
    CONSTRAINT step_up_challenge_consumed CHECK ((state = 3) = (consumed_at IS NOT NULL)),
    CONSTRAINT step_up_challenge_attempt_count CHECK (attempt_count BETWEEN 0 AND 5),
    CONSTRAINT step_up_challenge_expiry CHECK (expires_at > created_at),
    CONSTRAINT step_up_challenge_epochs CHECK (auth_epoch >= 0 AND recovery_generation >= 0),
    CONSTRAINT step_up_challenge_rev CHECK (rev >= 1)
);
CREATE INDEX step_up_challenge_session ON identity.step_up_challenge (session_id, expires_at);
CREATE INDEX step_up_challenge_user ON identity.step_up_challenge (user_id);
CREATE INDEX step_up_challenge_expires_at ON identity.step_up_challenge (expires_at);

-- The owner bootstrap (AD-0021 section 6): at most one row ever, so at most one bootstrap per database, enforced by the singleton key.
-- It records the digest of the configured token that was used and the account it created.
CREATE TABLE identity.bootstrap (
    singleton    boolean     NOT NULL,
    token_sha256 bytea       NOT NULL,
    user_id      uuid        NOT NULL,
    consumed_at  timestamptz NOT NULL,
    CONSTRAINT bootstrap_pkey PRIMARY KEY (singleton),
    CONSTRAINT bootstrap_single_row CHECK (singleton),
    CONSTRAINT bootstrap_token_sha256 CHECK (length(token_sha256) = 32),
    CONSTRAINT bootstrap_user FOREIGN KEY (user_id) REFERENCES identity.user (user_id)
);

-- Rate-limit windows (AD-0011 section 7): one row per bucket, the SHA-256 of its kind and key, counting requests in a fixed window that
-- is reset in place. Bucket keys are digests of client IP prefixes, accounts and e-mail addresses; a digest of a short key can be
-- reversed by trying every value, so the rows are personal data with the retention of AF-PLAT-01's sweep.
CREATE TABLE platform.rate_limit (
    bucket_hash  bytea       NOT NULL,
    window_start timestamptz NOT NULL,
    count        integer     NOT NULL,
    CONSTRAINT rate_limit_pkey PRIMARY KEY (bucket_hash),
    CONSTRAINT rate_limit_bucket_hash CHECK (length(bucket_hash) = 32),
    CONSTRAINT rate_limit_count CHECK (count >= 0)
);
CREATE INDEX rate_limit_window_start ON platform.rate_limit (window_start);
