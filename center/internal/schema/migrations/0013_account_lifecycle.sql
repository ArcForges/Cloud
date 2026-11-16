-- SPDX-License-Identifier: AGPL-3.0-only
-- AFV2-ID-01: account authority and bounded lifecycle metadata.
-- The finite migration manager fences every earlier writer before this runs.
-- Existing session/proof epochs are facts: a lower snapshot is never promoted.

DO $$ BEGIN
    IF current_setting('arcforges.lifecycle_admitted',true) IS DISTINCT FROM '13' THEN
        RAISE EXCEPTION 'schema 13 needs fenced lifecycle admission' USING ERRCODE = 'check_violation';
    END IF;
END $$;

CREATE TABLE identity.account_security_state (
    user_id uuid NOT NULL REFERENCES identity.user(user_id),
    auth_epoch bigint NOT NULL CHECK (auth_epoch >= 0),
    recovery_generation bigint NOT NULL CHECK (recovery_generation >= 0),
    rev bigint NOT NULL CHECK (rev >= 1),
    changed_at timestamptz NOT NULL,
    CONSTRAINT account_security_state_pkey PRIMARY KEY (user_id)
);

WITH retained AS (
    SELECT user_id, auth_epoch, recovery_generation FROM identity.session
    UNION ALL
    SELECT user_id, auth_epoch, recovery_generation FROM identity.step_up_challenge
    UNION ALL
    SELECT user_id, approver_auth_epoch, approver_recovery_generation
      FROM fleet.node_sign_in WHERE user_id IS NOT NULL AND approver_auth_epoch IS NOT NULL
    UNION ALL
    SELECT user_id, approver_auth_epoch, approver_recovery_generation
      FROM fleet.device_authorization WHERE user_id IS NOT NULL AND approver_auth_epoch IS NOT NULL
    UNION ALL
    SELECT user_id, approver_auth_epoch, approver_recovery_generation
      FROM identity.mobile_authorization WHERE user_id IS NOT NULL AND approver_auth_epoch IS NOT NULL
), maxima AS (
    SELECT user_id, max(auth_epoch) AS auth_epoch, max(recovery_generation) AS recovery_generation
      FROM retained GROUP BY user_id
)
INSERT INTO identity.account_security_state(user_id, auth_epoch, recovery_generation, rev, changed_at)
SELECT u.user_id, coalesce(m.auth_epoch, 0), coalesce(m.recovery_generation, 0), 1, clock_timestamp()
FROM identity.user u LEFT JOIN maxima m ON m.user_id = u.user_id;

-- Keep the original lower epoch values; make their sessions explicitly unusable.
UPDATE identity.session s SET revoked_at = clock_timestamp(), revoke_reason = 6, rev = s.rev + 1
FROM identity.account_security_state a
WHERE a.user_id = s.user_id AND s.revoked_at IS NULL
  AND (s.auth_epoch <> a.auth_epoch OR s.recovery_generation <> a.recovery_generation);

-- Pre-transition uncompleted ceremonies carry no account-epoch snapshot. They
-- are exhausted rather than silently acquiring the new account generation.
UPDATE identity.auth_flow SET consumed_at = clock_timestamp(), outcome = 2
WHERE consumed_at IS NULL;

CREATE FUNCTION identity.initialize_account_security_state() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO identity.account_security_state(user_id, auth_epoch, recovery_generation, rev, changed_at)
    VALUES (NEW.user_id, 0, 0, 1, NEW.created_at);
    RETURN NEW;
END;
$$;
CREATE TRIGGER account_security_state_on_user AFTER INSERT ON identity.user
FOR EACH ROW EXECUTE FUNCTION identity.initialize_account_security_state();

CREATE FUNCTION identity.guard_account_security_state() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'account authority requires a tombstone' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.user_id <> OLD.user_id OR NEW.auth_epoch < OLD.auth_epoch
       OR NEW.recovery_generation < OLD.recovery_generation OR NEW.rev <> OLD.rev + 1
       OR NEW.changed_at < OLD.changed_at THEN
        RAISE EXCEPTION 'account authority cannot move backwards' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER account_security_state_guard BEFORE UPDATE OR DELETE ON identity.account_security_state
FOR EACH ROW EXECUTE FUNCTION identity.guard_account_security_state();

CREATE TABLE identity.lifecycle_operation (
    operation_id uuid NOT NULL,
    user_id uuid NOT NULL REFERENCES identity.user(user_id),
    kind smallint NOT NULL CHECK (kind IN (1, 2, 3)),
    state smallint NOT NULL CHECK (state IN (1, 2, 3, 4, 5, 6, 7)),
    plan_rev bigint NOT NULL CHECK (plan_rev >= 1),
    command_id uuid,
    intent_sha256 bytea NOT NULL CHECK (length(intent_sha256) = 32),
    auth_epoch bigint NOT NULL CHECK (auth_epoch >= 0),
    recovery_generation bigint NOT NULL CHECK (recovery_generation >= 0),
    prior_account_state smallint NOT NULL DEFAULT 1 CHECK (prior_account_state IN (1,2)),
    proof_id uuid,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    confirmed_at timestamptz,
    finished_at timestamptz,
    rev bigint NOT NULL CHECK (rev >= 1),
    export_artifact_id uuid,
    export_sha256 bytea CHECK (export_sha256 IS NULL OR length(export_sha256) = 32),
    export_bytes bigint CHECK (export_bytes IS NULL OR export_bytes BETWEEN 0 AND 2097152),
    active_subscription_count integer NOT NULL DEFAULT 0 CHECK (active_subscription_count >= 0),
    unresolved_operation_count integer NOT NULL DEFAULT 0 CHECK (unresolved_operation_count >= 0),
    -- 0 no blocker; 1 external provider, 2 retention policy, 3 unresolved remote effect.
    blocked_reason smallint NOT NULL DEFAULT 0 CHECK (blocked_reason IN (0, 1, 2, 3)),
    CONSTRAINT lifecycle_operation_pkey PRIMARY KEY (operation_id),
    CONSTRAINT lifecycle_operation_command UNIQUE (user_id, command_id),
    CONSTRAINT lifecycle_operation_expiry CHECK (expires_at > created_at),
    CONSTRAINT lifecycle_operation_export CHECK ((kind = 3) OR
        (export_artifact_id IS NULL AND export_sha256 IS NULL AND export_bytes IS NULL)),
    CONSTRAINT lifecycle_operation_export_material CHECK
        ((export_artifact_id IS NULL) = (export_sha256 IS NULL) AND
         (export_artifact_id IS NULL) = (export_bytes IS NULL)),
    CONSTRAINT lifecycle_operation_confirmation CHECK
        (state NOT IN (2,3,4) OR (command_id IS NOT NULL AND proof_id IS NOT NULL AND confirmed_at IS NOT NULL)),
    CONSTRAINT lifecycle_operation_completed_export CHECK
        (kind <> 3 OR state <> 4 OR export_artifact_id IS NOT NULL)
);
CREATE UNIQUE INDEX lifecycle_operation_live_deletion ON identity.lifecycle_operation(user_id)
WHERE kind = 2 AND state IN (1, 2, 3);
CREATE INDEX lifecycle_operation_user ON identity.lifecycle_operation(user_id, kind, created_at, operation_id);
CREATE INDEX lifecycle_operation_expiry ON identity.lifecycle_operation(expires_at) WHERE state IN (1, 2, 3, 4);

CREATE FUNCTION identity.guard_lifecycle_operation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'lifecycle identities require retained evidence' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.operation_id <> OLD.operation_id OR NEW.user_id <> OLD.user_id OR NEW.kind <> OLD.kind
       OR NEW.created_at <> OLD.created_at OR NEW.intent_sha256 <> OLD.intent_sha256
       OR NEW.auth_epoch <> OLD.auth_epoch OR NEW.recovery_generation <> OLD.recovery_generation
       OR NEW.prior_account_state <> OLD.prior_account_state
       OR NEW.expires_at <> OLD.expires_at OR NEW.plan_rev <> OLD.plan_rev OR NEW.rev <> OLD.rev + 1
       OR (OLD.command_id IS NOT NULL AND NEW.command_id IS DISTINCT FROM OLD.command_id)
       OR (OLD.proof_id IS NOT NULL AND NEW.proof_id IS DISTINCT FROM OLD.proof_id)
       OR (OLD.export_sha256 IS NOT NULL AND
          (NEW.export_sha256 IS DISTINCT FROM OLD.export_sha256 OR NEW.export_bytes IS DISTINCT FROM OLD.export_bytes
           OR NEW.export_artifact_id IS DISTINCT FROM OLD.export_artifact_id)) THEN
        RAISE EXCEPTION 'lifecycle identity is immutable' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state IN (4, 5, 6, 7) AND NEW.state <> OLD.state AND NOT
       (OLD.kind = 3 AND OLD.state = 4 AND NEW.state IN (5, 6, 7)) THEN
        RAISE EXCEPTION 'a terminal lifecycle outcome cannot be reopened' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER lifecycle_operation_guard BEFORE UPDATE OR DELETE ON identity.lifecycle_operation
FOR EACH ROW EXECUTE FUNCTION identity.guard_lifecycle_operation();

ALTER TABLE identity.auth_flow ADD COLUMN lifecycle_operation_id uuid REFERENCES identity.lifecycle_operation(operation_id);
ALTER TABLE identity.auth_flow ADD COLUMN account_auth_epoch bigint;
ALTER TABLE identity.auth_flow ADD COLUMN account_recovery_generation bigint;
ALTER TABLE identity.auth_flow ADD COLUMN delivery_state smallint NOT NULL DEFAULT 0 CHECK (delivery_state IN (0,1,2,3));
ALTER TABLE identity.auth_flow DROP CONSTRAINT auth_flow_kind;
ALTER TABLE identity.auth_flow ADD CONSTRAINT auth_flow_kind CHECK (kind IN (1, 2, 3, 4, 5));
ALTER TABLE identity.auth_flow DROP CONSTRAINT auth_flow_purpose;
ALTER TABLE identity.auth_flow ADD CONSTRAINT auth_flow_purpose CHECK
    (purpose IN (1, 2, 4) AND ((kind = 5) = (purpose = 4)));
ALTER TABLE identity.auth_flow DROP CONSTRAINT auth_flow_passkey_challenge;
ALTER TABLE identity.auth_flow ADD CONSTRAINT auth_flow_passkey_challenge CHECK
    ((kind IN (1, 2, 3, 5)) = (challenge IS NOT NULL) AND (challenge IS NULL OR length(challenge) = 32));
ALTER TABLE identity.auth_flow DROP CONSTRAINT auth_flow_registration_handle;
ALTER TABLE identity.auth_flow ADD CONSTRAINT auth_flow_registration_handle CHECK
    ((kind IN (2, 3, 5)) = (webauthn_user_handle IS NOT NULL) AND
     (webauthn_user_handle IS NULL OR length(webauthn_user_handle) = 32));
ALTER TABLE identity.auth_flow DROP CONSTRAINT auth_flow_email;
ALTER TABLE identity.auth_flow ADD CONSTRAINT auth_flow_email CHECK
    ((kind IN (4, 5)) = (email_hash IS NOT NULL) AND (kind IN (4, 5)) = (code_hash IS NOT NULL) AND
     (kind IN (4, 5)) = (code_salt IS NOT NULL) AND (email_hash IS NULL OR length(email_hash) = 32) AND
     (code_hash IS NULL OR length(code_hash) = 32) AND (code_salt IS NULL OR length(code_salt) = 16));
ALTER TABLE identity.auth_flow ADD CONSTRAINT auth_flow_account_epochs CHECK
    ((account_auth_epoch IS NULL) = (account_recovery_generation IS NULL) AND
     (account_auth_epoch IS NULL OR (account_auth_epoch >= 0 AND account_recovery_generation >= 0)) AND
     (kind <> 5 OR account_auth_epoch IS NOT NULL) AND
     (lifecycle_operation_id IS NULL OR (kind = 5 AND user_id IS NOT NULL)));

-- A finite owner maintenance operation, not runtime DELETE authority. It keeps
-- the account ID and necessary audit/financial/remote outcome references while
-- removing credentials, proof data and personal identity/device labels. The
-- calling maintenance transaction appends its normal chained audit event.
CREATE FUNCTION identity.finish_account_deletion(p_operation_id uuid, p_now timestamptz)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    deletion_user_id uuid;
    account_state smallint;
    operation_state smallint;
    provider_pending boolean;
    unknown_count bigint;
BEGIN
    SELECT user_id INTO deletion_user_id FROM identity.lifecycle_operation
      WHERE operation_id = p_operation_id AND kind = 2;
    IF deletion_user_id IS NULL THEN
        RAISE EXCEPTION 'unknown deletion operation' USING ERRCODE = 'check_violation';
    END IF;
    SELECT state INTO account_state FROM identity.user WHERE user_id = deletion_user_id FOR UPDATE;
    PERFORM 1 FROM identity.account_security_state WHERE user_id = deletion_user_id FOR UPDATE;
    SELECT state INTO operation_state FROM identity.lifecycle_operation WHERE operation_id = p_operation_id FOR UPDATE;
    IF operation_state = 4 AND account_state = 5 THEN RETURN true; END IF;
    IF operation_state <> 3 OR account_state <> 4 THEN
        RAISE EXCEPTION 'account deletion is not confirmed' USING ERRCODE = 'check_violation';
    END IF;
    SELECT EXISTS(SELECT 1 FROM entitlement.service_term WHERE account_id = deletion_user_id AND subscription_ref IS NOT NULL)
        OR coalesce((SELECT auto_renew OR purchase_pending FROM entitlement.account_status_fact
            WHERE account_id = deletion_user_id ORDER BY recorded_at DESC,status_fact_id DESC LIMIT 1), false)
      INTO provider_pending;
    SELECT (SELECT count(*) FROM management.remote_operation WHERE account_id = deletion_user_id AND (final_at IS NULL OR effect = 3))
       + (SELECT count(*) FROM management.legacy_outcome WHERE account_id = deletion_user_id AND (final_at IS NULL OR legacy_state = 7))
      INTO unknown_count;
    IF provider_pending OR unknown_count > 0 THEN
        UPDATE identity.lifecycle_operation SET blocked_reason = CASE WHEN provider_pending THEN 1 ELSE 3 END,
            unresolved_operation_count = unknown_count, rev = rev + 1 WHERE operation_id = p_operation_id;
        RETURN false;
    END IF;
    -- No remote request or Node command is emitted. Existing local Runs and
    -- Sandbox data are outside this Center-only account cleanup.
    UPDATE identity.account_security_state SET auth_epoch = auth_epoch + 1,
        changed_at = greatest(changed_at,p_now), rev = rev + 1 WHERE user_id = deletion_user_id;
    UPDATE identity.session SET revoked_at = p_now,revoke_reason = 2,rev = rev + 1
        WHERE user_id = deletion_user_id AND revoked_at IS NULL;
    UPDATE device.device SET display_name = 'Deleted device',remote_enabled = false,
        revoked_at = coalesce(revoked_at,p_now),revoke_reason = coalesce(revoke_reason,1),trust_level = 3,rev = rev + 1 WHERE user_id = deletion_user_id;
    UPDATE device.installation SET revoked_at = coalesce(revoked_at,p_now),rev = rev + 1 WHERE user_id = deletion_user_id;
    UPDATE fleet.node SET display_name = 'Deleted node',revoked_at = coalesce(revoked_at,p_now),
        revoke_reason = coalesce(revoke_reason,1),rev = rev + 1 WHERE user_id = deletion_user_id;
    DELETE FROM identity.auth_flow WHERE user_id = deletion_user_id OR email_hash IN
        (SELECT sha256(convert_to(subject,'UTF8')) FROM identity.auth_identity WHERE user_id = deletion_user_id AND provider_id = 'email');
    DELETE FROM identity.step_up_challenge WHERE user_id = deletion_user_id;
    DELETE FROM fleet.node_sign_in WHERE user_id = deletion_user_id;
    DELETE FROM fleet.device_authorization WHERE user_id = deletion_user_id;
    DELETE FROM identity.mobile_authorization WHERE user_id = deletion_user_id;
    DELETE FROM identity.auth_identity WHERE user_id = deletion_user_id;
    UPDATE identity.user SET state = 5,display_name = 'Deleted account',locale = 'en-US',timezone = 'UTC',
        passkey_user_handle = sha256(convert_to('deleted:' || deletion_user_id::text,'UTF8')),rev = rev + 1 WHERE user_id = deletion_user_id;
    UPDATE identity.lifecycle_operation SET state = 4,blocked_reason = 0,unresolved_operation_count = 0,
        finished_at = p_now,rev = rev + 1 WHERE operation_id = p_operation_id;
    RETURN true;
END;
$$;
REVOKE ALL ON FUNCTION identity.finish_account_deletion(uuid,timestamptz) FROM PUBLIC;
