-- SPDX-License-Identifier: AGPL-3.0-only

-- The runner holds the source write barrier, proves the rollback archive and
-- fences the old runtime generation before admitting this migration.
DO $$
BEGIN
    IF current_setting('arcforges.contraction_admitted', true) IS DISTINCT FROM '17' THEN
        RAISE EXCEPTION 'V2 contraction requires a checked migration invocation' USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM fleet.hub_lease WHERE expires_at > clock_timestamp()) OR
       EXISTS (SELECT 1 FROM fleet.routed_call WHERE state = 7 OR (final_at IS NULL AND state <> 8)) OR
       EXISTS (SELECT 1 FROM fleet.routed_file_call WHERE state = 7 OR (final_at IS NULL AND state <> 8)) OR
       EXISTS (SELECT 1 FROM management.legacy_outcome WHERE legacy_state = 7 OR (final_at IS NULL AND legacy_state <> 8)) THEN
        RAISE EXCEPTION 'legacy ownership or effects remain unresolved' USING ERRCODE = '55000';
    END IF;

    -- Every archived command retains its original ID and immutable outcome.
    -- A namespace reservation without corresponding evidence also blocks DDL.
    IF EXISTS (
        WITH source AS (
            SELECT account_id, command_id, 1::smallint AS namespace,
                   sha256(convert_to(to_jsonb(r)::text, 'UTF8')) AS digest FROM fleet.routed_call r
            UNION ALL
            SELECT account_id, command_id, 2::smallint AS namespace,
                   sha256(convert_to(to_jsonb(r)::text, 'UTF8')) AS digest FROM fleet.routed_file_call r
        )
        SELECT 1 FROM source
        FULL JOIN management.legacy_outcome o USING (account_id, command_id, namespace)
        FULL JOIN fleet.routed_command_id n
            ON (n.account_id, n.command_id, n.receipt_kind) =
               (source.account_id, source.command_id, source.namespace)
        LEFT JOIN management.command_identity i
            ON (i.account_id, i.command_id) = (source.account_id, source.command_id)
        WHERE source.digest IS DISTINCT FROM o.source_row_sha256
           OR source.namespace IS DISTINCT FROM n.receipt_kind
           OR source.namespace IS DISTINCT FROM i.namespace
    ) THEN
        RAISE EXCEPTION 'the retained legacy command inventory differs' USING ERRCODE = '55000';
    END IF;
END;
$$;

-- The rollback archive retains the original flow IDs and records. Close the
-- still-uncollected authority before withdrawing the live table.
UPDATE identity.mobile_authorization
SET state = CASE WHEN state = 1 THEN 5 ELSE 4 END,
    decided_at = CASE WHEN user_id IS NULL THEN NULL ELSE greatest(decided_at, clock_timestamp()) END,
    rev = rev + 1
WHERE state IN (1, 2);

-- Keep the account finalizer's shared authority, provider, and effect checks.
CREATE OR REPLACE FUNCTION identity.finish_account_deletion(p_operation_id uuid, p_now timestamptz)
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
    SELECT EXISTS(SELECT 1 FROM commerce.provider_cleanup_pending WHERE account_id = deletion_user_id)
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
    UPDATE fleet.node SET display_name = 'Deleted node',reported_name = NULL,named_by_account = false,revoked_at = coalesce(revoked_at,p_now),
        revoke_reason = coalesce(revoke_reason,1),rev = rev + 1 WHERE user_id = deletion_user_id;
    DELETE FROM identity.auth_flow WHERE user_id = deletion_user_id OR email_hash IN
        (SELECT sha256(convert_to(subject,'UTF8')) FROM identity.auth_identity WHERE user_id = deletion_user_id AND provider_id = 'email');
    DELETE FROM identity.step_up_challenge WHERE user_id = deletion_user_id;
    DELETE FROM fleet.node_sign_in WHERE user_id = deletion_user_id;
    DELETE FROM fleet.device_authorization WHERE user_id = deletion_user_id;
    DELETE FROM identity.auth_identity WHERE user_id = deletion_user_id;
    UPDATE identity.user SET state = 5,display_name = 'Deleted account',locale = 'en-US',timezone = 'UTC',
        passkey_user_handle = sha256(convert_to('deleted:' || deletion_user_id::text,'UTF8')),rev = rev + 1 WHERE user_id = deletion_user_id;
    UPDATE identity.lifecycle_operation SET state = 4,blocked_reason = 0,unresolved_operation_count = 0,
        finished_at = p_now,rev = rev + 1 WHERE operation_id = p_operation_id;
    RETURN true;
END;
$$;
REVOKE ALL ON FUNCTION identity.finish_account_deletion(uuid,timestamptz) FROM PUBLIC;

DROP TABLE fleet.routed_call, fleet.routed_file_call, fleet.routed_file_target,
    fleet.routed_command_id, fleet.refusal_code, identity.mobile_authorization RESTRICT;
DROP FUNCTION fleet.routed_call_guarded(), fleet.routed_file_call_guarded(),
    fleet.routed_file_target_fixed(), fleet.routed_command_id_fixed(), fleet.reserve_routed_command_id(),
    fleet.refusal_code_fixed(), identity.refuse_final_mobile_authorization_change(), management.legacy_frozen() RESTRICT;

ALTER TABLE management.cutover_receipt ADD COLUMN contraction_restore_sha256 bytea,
    ADD CONSTRAINT cutover_receipt_contraction_restore CHECK (
        CASE WHEN target_schema = 17 AND source_schema = 16 THEN
            contraction_restore_sha256 IS NOT NULL AND octet_length(contraction_restore_sha256) = 32
        ELSE contraction_restore_sha256 IS NULL END);

-- Runtime checks move off the owner-only original migration ledger. An older
-- executable checking that ledger cannot accept a contracted database.
CREATE VIEW platform.runtime_schema_history AS
    SELECT version, name, sha256, applied_at, applied_by FROM platform.schema_migration;
REVOKE ALL ON platform.runtime_schema_history FROM PUBLIC;
