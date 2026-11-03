-- 0004 Node enrollment (AF-CTR-04 part E1a; ArcForges-Design AD-0021 sections 5, 10 and 13a, data/cloud-store.md section 6).
--
-- Applied by `arcforges-center migrate` in one transaction with the migration role; the runner reconciles the runtime role's grants
-- from center/internal/schema/schema.go after every run. The three fleet tables land whole: fleet.node is written by this part
-- (fleet.Enroll, ReportNodeInfo and the device revocation cascade); the sign-in flows are written by the browser sign-in (part E1b)
-- and the device-code sign-in (part E2). Constraint style follows 0002: named constraints, smallint enumerations with their values
-- listed, bounded text, composite foreign keys, and an index led by the first column of every foreign key.
--
-- Two statements change 0002 objects: identity.session's revoke reasons gain 7 (superseded by a re-enrollment of the node) and 8
-- (a one-use enrollment code presented again), and device.installation's public keys become unique over live and revoked rows, so a
-- key is registered once ever and a revoked node's key never returns. A key replaced by a same-account re-enrollment is overwritten
-- and no longer guarded (accepted).
--
-- Node versions are SemVer 2.0.0 without build metadata: the center stores the canonical form, the text before the first '+', which
-- always satisfies 0002's installation_app_version.
--
-- Personal data: the node's name (it can name a person), its version, the country and network (ASN) a sign-in request came from,
-- and account IDs. No token, one-use code, device code or user code is stored in clear: only SHA-256 digests. Retention: the sweeps
-- are AF-PLAT-01's and each period is a maximum (flow rows 7 days after their end; a node row until revoked + 30 days, with its
-- device); until the sweeps exist the fleet tables only grow, and AF-PROD-01's gate for enabling production covers the fleet surface.
-- The flow tables are children of sessions, nodes and users (NO ACTION foreign keys): a sweep deletes them first.

ALTER TABLE identity.session DROP CONSTRAINT session_revoke_reason;
-- 1 signed out, 2 revoked by its account, 3 all sessions revoked, 4 refresh token reused, 5 device revoked, 6 operator,
-- 7 superseded by a re-enrollment, 8 enrollment code reused (identity.session_revoke_reason)
ALTER TABLE identity.session ADD CONSTRAINT session_revoke_reason CHECK ((revoke_reason IS NULL) = (revoked_at IS NULL) AND
    (revoke_reason IS NULL OR revoke_reason IN (1, 2, 3, 4, 5, 6, 7, 8)));

CREATE UNIQUE INDEX installation_public_key ON device.installation (public_key) WHERE public_key IS NOT NULL;

-- Enrolled nodes: one row per enrollment of a node ID in an account, bound to the node's own device and arcforges-node installation.
-- A node ID is live in at most one row; a revoked row is history. display_name is the name the node last reported (the device keeps
-- its own name, which the account may change).
CREATE TABLE fleet.node (
    enrollment_id   uuid        NOT NULL,
    node_id         uuid        NOT NULL,
    user_id         uuid        NOT NULL,
    device_id       uuid        NOT NULL,
    installation_id uuid        NOT NULL,
    display_name    text        NOT NULL,
    os              smallint    NOT NULL,
    arch            smallint    NOT NULL,
    version         text        NOT NULL,
    enrolled_at     timestamptz NOT NULL,
    last_seen_at    timestamptz NOT NULL,
    revoked_at      timestamptz,
    revoke_reason   smallint,
    rev             bigint      NOT NULL,
    CONSTRAINT node_pkey PRIMARY KEY (enrollment_id),
    CONSTRAINT node_installation_once UNIQUE (installation_id),
    CONSTRAINT node_device FOREIGN KEY (device_id, user_id) REFERENCES device.device (device_id, user_id),
    CONSTRAINT node_installation FOREIGN KEY (installation_id, device_id) REFERENCES device.installation (installation_id, device_id),
    CONSTRAINT node_display_name CHECK (char_length(display_name) BETWEEN 1 AND 64 AND display_name !~ '[[:cntrl:]]'),
    -- arcforges.node.v1.OsFamily: 1 windows, 2 linux (fleet.node_os; the device platform maps them by name to 1 and 3)
    CONSTRAINT node_os CHECK (os IN (1, 2)),
    -- arcforges.node.v1.CpuArchitecture: 1 x64, 2 arm64 (fleet.node_arch)
    CONSTRAINT node_arch CHECK (arch IN (1, 2)),
    CONSTRAINT node_version CHECK (char_length(version) <= 128 AND version ~
        '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?$'),
    -- 1 device revoked (fleet.node_revoke_reason)
    CONSTRAINT node_revoke_reason CHECK ((revoke_reason IS NULL) = (revoked_at IS NULL) AND (revoke_reason IS NULL OR revoke_reason = 1)),
    CONSTRAINT node_seen CHECK (last_seen_at >= enrolled_at),
    CONSTRAINT node_rev CHECK (rev >= 1)
);
CREATE UNIQUE INDEX node_live_node_id ON fleet.node (node_id) WHERE revoked_at IS NULL;
CREATE INDEX node_user ON fleet.node (user_id, revoked_at);
CREATE INDEX node_device_id ON fleet.node (device_id);

-- Browser (PKCE loopback) sign-in flows (SM-SIGN-IN): the node as it described itself at Begin, the PKCE challenge, the loopback
-- redirect and the client state, the review and the approval (with the approving session and its epochs, so an enrollment never
-- outlives the approver's remediation), the one-use code's digest and the result. A terminal row is final, except that a completed
-- flow becomes REVOKED once when its code is presented again.
CREATE TABLE fleet.node_sign_in (
    flow_id                      uuid        NOT NULL,
    state                        smallint    NOT NULL,
    node_id                      uuid        NOT NULL,
    node_name                    text        NOT NULL,
    os                           smallint    NOT NULL,
    arch                         smallint    NOT NULL,
    version                      text        NOT NULL,
    node_public_key              bytea       NOT NULL,
    code_challenge               text        NOT NULL,
    redirect_uri                 text        NOT NULL,
    client_state                 text        NOT NULL,
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
    enrollment_id                uuid,
    rev                          bigint      NOT NULL,
    CONSTRAINT node_sign_in_pkey PRIMARY KEY (flow_id),
    CONSTRAINT node_sign_in_viewer FOREIGN KEY (viewed_by) REFERENCES identity.user (user_id),
    CONSTRAINT node_sign_in_user FOREIGN KEY (user_id) REFERENCES identity.user (user_id),
    CONSTRAINT node_sign_in_approver_session FOREIGN KEY (approver_session_id) REFERENCES identity.session (session_id),
    CONSTRAINT node_sign_in_session FOREIGN KEY (session_id) REFERENCES identity.session (session_id),
    CONSTRAINT node_sign_in_enrollment FOREIGN KEY (enrollment_id) REFERENCES fleet.node (enrollment_id),
    -- 1 PENDING, 2 APPROVED, 3 COMPLETED, 4 DENIED, 5 EXPIRED, 6 REVOKED (arcforges.fleet.v1.NodeSignInState)
    CONSTRAINT node_sign_in_state CHECK (state IN (1, 2, 3, 4, 5, 6)),
    CONSTRAINT node_sign_in_node_name CHECK (char_length(node_name) BETWEEN 1 AND 64 AND node_name !~ '[[:cntrl:]]'),
    CONSTRAINT node_sign_in_os CHECK (os IN (1, 2)),
    CONSTRAINT node_sign_in_arch CHECK (arch IN (1, 2)),
    CONSTRAINT node_sign_in_version CHECK (char_length(version) <= 128 AND version ~
        '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?$'),
    CONSTRAINT node_sign_in_public_key CHECK (length(node_public_key) = 91),
    CONSTRAINT node_sign_in_code_challenge CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    -- The loopback shape only; the port range 1024..65535 is the center's rule.
    CONSTRAINT node_sign_in_redirect_uri CHECK (redirect_uri ~ '^http://(127\.0\.0\.1|\[::1\]):[1-9][0-9]{3,4}/callback$'),
    CONSTRAINT node_sign_in_client_state CHECK (client_state ~ '^[A-Za-z0-9._~-]{16,128}$'),
    CONSTRAINT node_sign_in_begin_country CHECK (begin_country IS NULL OR begin_country ~ '^[A-Z]{2}$'),
    CONSTRAINT node_sign_in_begin_asn CHECK (begin_asn IS NULL OR begin_asn BETWEEN 0 AND 4294967295),
    CONSTRAINT node_sign_in_expiry CHECK (expires_at > created_at),
    CONSTRAINT node_sign_in_viewed CHECK ((viewed_by IS NULL) = (viewed_at IS NULL)),
    CONSTRAINT node_sign_in_decided CHECK ((user_id IS NULL) = (decided_at IS NULL)),
    -- 1 passkey, 2 email code (identity.auth_method)
    CONSTRAINT node_sign_in_approver CHECK ((approver_session_id IS NULL) = (approver_auth_method IS NULL) AND
        (approver_session_id IS NULL) = (approver_authenticated_at IS NULL) AND (approver_session_id IS NULL) = (approver_auth_epoch IS NULL) AND
        (approver_session_id IS NULL) = (approver_recovery_generation IS NULL) AND (approver_session_id IS NULL OR user_id IS NOT NULL) AND
        (approver_auth_method IS NULL OR approver_auth_method IN (1, 2)) AND
        (approver_auth_epoch IS NULL OR (approver_auth_epoch >= 0 AND approver_recovery_generation >= 0))),
    CONSTRAINT node_sign_in_approved CHECK (state NOT IN (2, 3) OR (approver_session_id IS NOT NULL AND code_hash IS NOT NULL)),
    CONSTRAINT node_sign_in_code CHECK ((code_hash IS NULL) = (code_expires_at IS NULL) AND (code_hash IS NULL OR length(code_hash) = 32)),
    -- A redeemed code belongs to a completed flow or to one the redemption revoked.
    CONSTRAINT node_sign_in_redeemed CHECK (code_redeemed_at IS NULL OR state IN (3, 6)),
    CONSTRAINT node_sign_in_result CHECK ((session_id IS NULL) = (enrollment_id IS NULL) AND (state <> 3 OR session_id IS NOT NULL) AND
        (session_id IS NULL OR state IN (3, 6)) AND (completed_at IS NULL) = (session_id IS NULL)),
    CONSTRAINT node_sign_in_rev CHECK (rev >= 1)
);
CREATE INDEX node_sign_in_expires_at ON fleet.node_sign_in (expires_at);
CREATE INDEX node_sign_in_pending_node ON fleet.node_sign_in (node_id) WHERE state = 1;
CREATE INDEX node_sign_in_viewer ON fleet.node_sign_in (viewed_by) WHERE viewed_by IS NOT NULL;
CREATE INDEX node_sign_in_user ON fleet.node_sign_in (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX node_sign_in_approver_session ON fleet.node_sign_in (approver_session_id) WHERE approver_session_id IS NOT NULL;
CREATE INDEX node_sign_in_session ON fleet.node_sign_in (session_id) WHERE session_id IS NOT NULL;
CREATE INDEX node_sign_in_enrollment ON fleet.node_sign_in (enrollment_id) WHERE enrollment_id IS NOT NULL;

CREATE FUNCTION fleet.refuse_final_sign_in_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state IN (3, 4, 5, 6) AND NOT (OLD.state = 3 AND NEW.state = 6 AND NEW.rev = OLD.rev + 1 AND
            (to_jsonb(NEW) - 'state' - 'rev') = (to_jsonb(OLD) - 'state' - 'rev')) THEN
        RAISE EXCEPTION 'a final node sign-in flow is never changed' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER node_sign_in_final BEFORE UPDATE ON fleet.node_sign_in
    FOR EACH ROW EXECUTE FUNCTION fleet.refuse_final_sign_in_change();

-- Device-code sign-in authorizations (SM-DEVICE-AUTH): the device code's and the user code's digests, the node as at Start, the
-- poll interval, the lookups of the live user code (five, then refused without ending the authorization), the review and the
-- approval as for the browser flow, and the result. A terminal row is final, except that the first poll after delivery records the
-- reuse once (reused_at).
CREATE TABLE fleet.device_authorization (
    authorization_id             uuid        NOT NULL,
    device_code_hash             bytea       NOT NULL,
    user_code_hash               bytea       NOT NULL,
    state                        smallint    NOT NULL,
    node_id                      uuid        NOT NULL,
    node_name                    text        NOT NULL,
    os                           smallint    NOT NULL,
    arch                         smallint    NOT NULL,
    version                      text        NOT NULL,
    node_public_key              bytea       NOT NULL,
    begin_country                text,
    begin_asn                    bigint,
    interval_ms                  integer     NOT NULL,
    last_poll_at                 timestamptz,
    lookups                      smallint    NOT NULL,
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
    completed_at                 timestamptz,
    reused_at                    timestamptz,
    session_id                   uuid,
    enrollment_id                uuid,
    rev                          bigint      NOT NULL,
    CONSTRAINT device_authorization_pkey PRIMARY KEY (authorization_id),
    CONSTRAINT device_authorization_device_code UNIQUE (device_code_hash),
    CONSTRAINT device_authorization_viewer FOREIGN KEY (viewed_by) REFERENCES identity.user (user_id),
    CONSTRAINT device_authorization_user FOREIGN KEY (user_id) REFERENCES identity.user (user_id),
    CONSTRAINT device_authorization_approver_session FOREIGN KEY (approver_session_id) REFERENCES identity.session (session_id),
    CONSTRAINT device_authorization_session FOREIGN KEY (session_id) REFERENCES identity.session (session_id),
    CONSTRAINT device_authorization_enrollment FOREIGN KEY (enrollment_id) REFERENCES fleet.node (enrollment_id),
    CONSTRAINT device_authorization_hashes CHECK (length(device_code_hash) = 32 AND length(user_code_hash) = 32),
    -- 1 PENDING, 3 APPROVED, 4 DENIED, 5 EXPIRED, 6 COMPLETED (arcforges.fleet.v1.DeviceAuthorizationState; 2 SLOW_DOWN is a
    -- response only)
    CONSTRAINT device_authorization_state CHECK (state IN (1, 3, 4, 5, 6)),
    CONSTRAINT device_authorization_node_name CHECK (char_length(node_name) BETWEEN 1 AND 64 AND node_name !~ '[[:cntrl:]]'),
    CONSTRAINT device_authorization_os CHECK (os IN (1, 2)),
    CONSTRAINT device_authorization_arch CHECK (arch IN (1, 2)),
    CONSTRAINT device_authorization_version CHECK (char_length(version) <= 128 AND version ~
        '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?$'),
    CONSTRAINT device_authorization_public_key CHECK (length(node_public_key) = 91),
    CONSTRAINT device_authorization_begin_country CHECK (begin_country IS NULL OR begin_country ~ '^[A-Z]{2}$'),
    CONSTRAINT device_authorization_begin_asn CHECK (begin_asn IS NULL OR begin_asn BETWEEN 0 AND 4294967295),
    CONSTRAINT device_authorization_interval CHECK (interval_ms BETWEEN 1000 AND 60000),
    CONSTRAINT device_authorization_lookups CHECK (lookups BETWEEN 0 AND 5),
    CONSTRAINT device_authorization_expiry CHECK (expires_at > created_at),
    CONSTRAINT device_authorization_viewed CHECK ((viewed_by IS NULL) = (viewed_at IS NULL)),
    CONSTRAINT device_authorization_decided CHECK ((user_id IS NULL) = (decided_at IS NULL)),
    CONSTRAINT device_authorization_approver CHECK ((approver_session_id IS NULL) = (approver_auth_method IS NULL) AND
        (approver_session_id IS NULL) = (approver_authenticated_at IS NULL) AND (approver_session_id IS NULL) = (approver_auth_epoch IS NULL) AND
        (approver_session_id IS NULL) = (approver_recovery_generation IS NULL) AND (approver_session_id IS NULL OR user_id IS NOT NULL) AND
        (approver_auth_method IS NULL OR approver_auth_method IN (1, 2)) AND
        (approver_auth_epoch IS NULL OR (approver_auth_epoch >= 0 AND approver_recovery_generation >= 0))),
    CONSTRAINT device_authorization_approved CHECK (state NOT IN (3, 6) OR approver_session_id IS NOT NULL),
    CONSTRAINT device_authorization_result CHECK ((session_id IS NULL) = (enrollment_id IS NULL) AND (state = 6) = (session_id IS NOT NULL) AND
        (completed_at IS NULL) = (session_id IS NULL) AND (reused_at IS NULL OR state = 6)),
    CONSTRAINT device_authorization_rev CHECK (rev >= 1)
);
CREATE UNIQUE INDEX device_authorization_live_user_code ON fleet.device_authorization (user_code_hash) WHERE state = 1;
CREATE INDEX device_authorization_expires_at ON fleet.device_authorization (expires_at);
CREATE INDEX device_authorization_pending_node ON fleet.device_authorization (node_id) WHERE state = 1;
CREATE INDEX device_authorization_viewer ON fleet.device_authorization (viewed_by) WHERE viewed_by IS NOT NULL;
CREATE INDEX device_authorization_user ON fleet.device_authorization (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX device_authorization_approver_session ON fleet.device_authorization (approver_session_id) WHERE approver_session_id IS NOT NULL;
CREATE INDEX device_authorization_session ON fleet.device_authorization (session_id) WHERE session_id IS NOT NULL;
CREATE INDEX device_authorization_enrollment ON fleet.device_authorization (enrollment_id) WHERE enrollment_id IS NOT NULL;

CREATE FUNCTION fleet.refuse_final_authorization_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state IN (4, 5, 6) AND NOT (OLD.state = 6 AND NEW.state = 6 AND OLD.reused_at IS NULL AND NEW.reused_at IS NOT NULL AND
            NEW.rev = OLD.rev + 1 AND (to_jsonb(NEW) - 'reused_at' - 'rev') = (to_jsonb(OLD) - 'reused_at' - 'rev')) THEN
        RAISE EXCEPTION 'a final device authorization is never changed' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER device_authorization_final BEFORE UPDATE ON fleet.device_authorization
    FOR EACH ROW EXECUTE FUNCTION fleet.refuse_final_authorization_change();
