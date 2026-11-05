-- 0006 The mobile native authorization (AF-CTR-04 part M; Contracts public/http/v1/mobile-native.schema.json, MobileNativeAuth v1;
-- ArcForges-Design android.md and data/cloud-store.md section 6).
--
-- Applied by `arcforges-center migrate` in one transaction with the migration role; the runner reconciles the runtime role's grants
-- from center/internal/schema/schema.go after every run (identity.mobile_authorization: SELECT, INSERT, UPDATE). The flow has its own
-- table: fleet.node_sign_in's node columns are NOT NULL and its redirect check admits the loopback forms only, so the mobile flow
-- reuses the one-use code and PKCE functions (package oneuse), not that table. Constraint style follows 0002 and 0004: named
-- constraints, smallint enumerations with their values listed, bounded text, and an index led by the first column of every foreign
-- key.
--
-- One statement changes a 0004 object: identity.session's revoke reasons gain 9 (a one-use mobile authorization code presented
-- again; the session family it delivered is revoked).
--
-- Personal data: the installation claim as the app reports it (its installation ID, platform text and app version), the country and
-- network (ASN) the begin request came from (official-hosted only), and account IDs. No code, verifier, state digest or token is
-- stored in clear: the one-use code only as the SHA-256 of its 32 bytes; the client's state is the app's own random value, returned
-- unchanged in the callback. Retention: no sweep yet (AF-PLAT-01); a flow row is kept at most 7 days after its end once the sweep
-- exists, and until then the table only grows. It is a child of sessions and users (NO ACTION foreign keys): a sweep deletes it
-- first.

ALTER TABLE identity.session DROP CONSTRAINT session_revoke_reason;
-- 1 signed out, 2 revoked by its account, 3 all sessions revoked, 4 refresh token reused, 5 device revoked, 6 operator,
-- 7 superseded by a re-enrollment, 8 enrollment code reused, 9 mobile authorization code reused (identity.session_revoke_reason)
ALTER TABLE identity.session ADD CONSTRAINT session_revoke_reason CHECK ((revoke_reason IS NULL) = (revoked_at IS NULL) AND
    (revoke_reason IS NULL OR revoke_reason IN (1, 2, 3, 4, 5, 6, 7, 8, 9)));

-- Mobile authorization flows: the client and its registered redirect, the PKCE challenge and the client state, the installation
-- claim, the review and the approval (with the approving session and its epochs, so a mobile session never outlives the approver's
-- remediation), the one-use code's digest and the result. A terminal row is final, except that a completed flow becomes REVOKED once
-- when its code is presented again.
CREATE TABLE identity.mobile_authorization (
    flow_id                      uuid        NOT NULL,
    state                        smallint    NOT NULL,
    client_id                    text        NOT NULL,
    redirect_uri                 text        NOT NULL,
    code_challenge               text        NOT NULL,
    client_state                 text        NOT NULL,
    installation_id              uuid        NOT NULL,
    platform                     text        NOT NULL,
    app_version                  text        NOT NULL,
    begin_country                text,
    begin_asn                    bigint,
    created_at                   timestamptz NOT NULL,
    expires_at                   timestamptz NOT NULL,
    viewed_by                    uuid,
    viewed_at                    timestamptz,
    user_id                      uuid,
    decided_at                   timestamptz,
    approver_session_id          uuid,
    approver_auth_method         smallint,
    approver_authenticated_at    timestamptz,
    approver_auth_epoch          bigint,
    approver_recovery_generation bigint,
    code_hash                    bytea,
    code_expires_at              timestamptz,
    code_redeemed_at             timestamptz,
    completed_at                 timestamptz,
    session_id                   uuid,
    rev                          bigint      NOT NULL,
    CONSTRAINT mobile_authorization_pkey PRIMARY KEY (flow_id),
    CONSTRAINT mobile_authorization_viewer FOREIGN KEY (viewed_by) REFERENCES identity.user (user_id),
    CONSTRAINT mobile_authorization_user FOREIGN KEY (user_id) REFERENCES identity.user (user_id),
    CONSTRAINT mobile_authorization_approver_session FOREIGN KEY (approver_session_id) REFERENCES identity.session (session_id),
    CONSTRAINT mobile_authorization_session FOREIGN KEY (session_id) REFERENCES identity.session (session_id),
    -- 1 PENDING, 2 APPROVED, 3 COMPLETED, 4 DENIED, 5 EXPIRED, 6 REVOKED (the fleet.node_sign_in numbering)
    CONSTRAINT mobile_authorization_state CHECK (state IN (1, 2, 3, 4, 5, 6)),
    CONSTRAINT mobile_authorization_client_id CHECK (client_id IN ('arcforges.android', 'arcforges.android.local')),
    -- The release client's verified App Link, or the debug client's private-use scheme (the shapes only; the center admits the exact
    -- value of its own configuration: the origin of its public base URL, or ARCFORGES_CENTER_MOBILE_DEBUG_REDIRECT).
    CONSTRAINT mobile_authorization_redirect_uri CHECK (char_length(redirect_uri) BETWEEN 13 AND 512 AND (
        client_id = 'arcforges.android' AND redirect_uri ~ '^https://[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z][a-z0-9-]*(:[1-9][0-9]{0,4})?/app/callback$' OR
        client_id = 'arcforges.android.local' AND redirect_uri ~ '^[a-z][a-z0-9.+-]*\.[a-z0-9.+-]+:/callback$')),
    CONSTRAINT mobile_authorization_code_challenge CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    CONSTRAINT mobile_authorization_client_state CHECK (client_state ~ '^[A-Za-z0-9._~-]{16,128}$'),
    CONSTRAINT mobile_authorization_installation CHECK (installation_id <> '00000000-0000-0000-0000-000000000000'),
    CONSTRAINT mobile_authorization_platform CHECK (platform ~ '^[A-Za-z0-9._:/-]{1,128}$' AND lower(platform) ~ '^android'),
    CONSTRAINT mobile_authorization_app_version CHECK (app_version ~ '^[A-Za-z0-9._:/-]{1,128}$'),
    CONSTRAINT mobile_authorization_begin_country CHECK (begin_country IS NULL OR begin_country ~ '^[A-Z]{2}$'),
    CONSTRAINT mobile_authorization_begin_asn CHECK (begin_asn IS NULL OR begin_asn BETWEEN 0 AND 4294967295),
    CONSTRAINT mobile_authorization_expiry CHECK (expires_at > created_at),
    CONSTRAINT mobile_authorization_viewed CHECK ((viewed_by IS NULL) = (viewed_at IS NULL)),
    CONSTRAINT mobile_authorization_decided CHECK ((user_id IS NULL) = (decided_at IS NULL)),
    -- 1 passkey, 2 email code (identity.auth_method)
    CONSTRAINT mobile_authorization_approver CHECK ((approver_session_id IS NULL) = (approver_auth_method IS NULL) AND
        (approver_session_id IS NULL) = (approver_authenticated_at IS NULL) AND (approver_session_id IS NULL) = (approver_auth_epoch IS NULL) AND
        (approver_session_id IS NULL) = (approver_recovery_generation IS NULL) AND (approver_session_id IS NULL OR user_id IS NOT NULL) AND
        (approver_auth_method IS NULL OR approver_auth_method IN (1, 2)) AND
        (approver_auth_epoch IS NULL OR (approver_auth_epoch >= 0 AND approver_recovery_generation >= 0))),
    CONSTRAINT mobile_authorization_approved CHECK (state NOT IN (2, 3) OR (approver_session_id IS NOT NULL AND code_hash IS NOT NULL)),
    CONSTRAINT mobile_authorization_code CHECK ((code_hash IS NULL) = (code_expires_at IS NULL) AND (code_hash IS NULL OR length(code_hash) = 32) AND
        (code_expires_at IS NULL OR code_expires_at <= expires_at)),
    -- A redeemed code belongs to a completed flow or to one the redemption revoked.
    CONSTRAINT mobile_authorization_redeemed CHECK (code_redeemed_at IS NULL OR state IN (3, 6)),
    CONSTRAINT mobile_authorization_result CHECK ((state <> 3 OR session_id IS NOT NULL) AND (session_id IS NULL OR state IN (3, 6)) AND
        (completed_at IS NULL) = (session_id IS NULL)),
    CONSTRAINT mobile_authorization_rev CHECK (rev >= 1)
);
CREATE INDEX mobile_authorization_expires_at ON identity.mobile_authorization (expires_at);
CREATE INDEX mobile_authorization_viewer ON identity.mobile_authorization (viewed_by) WHERE viewed_by IS NOT NULL;
CREATE INDEX mobile_authorization_user ON identity.mobile_authorization (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX mobile_authorization_approver_session ON identity.mobile_authorization (approver_session_id) WHERE approver_session_id IS NOT NULL;
CREATE INDEX mobile_authorization_session ON identity.mobile_authorization (session_id) WHERE session_id IS NOT NULL;

CREATE FUNCTION identity.refuse_final_mobile_authorization_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state IN (3, 4, 5, 6) AND NOT (OLD.state = 3 AND NEW.state = 6 AND NEW.rev = OLD.rev + 1 AND
            (to_jsonb(NEW) - 'state' - 'rev') = (to_jsonb(OLD) - 'state' - 'rev')) THEN
        RAISE EXCEPTION 'a final mobile authorization flow is never changed' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER mobile_authorization_final BEFORE UPDATE ON identity.mobile_authorization
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_final_mobile_authorization_change();
