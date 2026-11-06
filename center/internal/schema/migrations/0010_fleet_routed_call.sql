-- 0010 The routing records of the center-routed task methods (AF-CTR-05 part E2b; Plan CTR5-RTE-03, C.8, PN-6; decisions B-1, B-2, B-3,
-- Q-2, Q-3, Q-4; Cloud docs/center-fleet.md "Routed calls").
--
-- Applied by `arcforges-center migrate` in one transaction with the migration role; the runner reconciles the runtime role's grants
-- from center/internal/schema/schema.go after every run (fleet.routed_call: SELECT, INSERT, UPDATE; fleet.refusal_code: SELECT; never
-- DELETE). Expand only: two new tables that no statement of the previous release names.
--
-- fleet.refusal_code is the fixed, append-only table of the refusal codes a routing record may name (decisions B-2): a smallint value
-- for each CATEGORY/code of the Contracts error catalogue of cohort 1.0.0-ci.437.1 (Contracts e67a6b0), in the catalogue's order, and 0
-- for a code outside it. A value never changes and is never reused; a later catalogue's new code is appended by a later migration with
-- the next value. Its trigger refuses every UPDATE and DELETE.
--
-- fleet.routed_call is the routing record of one SubmitNodeTask or CancelNodeTask command of an account (key: account and command ID):
-- the receipt of the command (PN-6). It holds digests, sizes, the task ID, the states and their instants, and never a request or
-- response byte, a task specification, an argument, a working directory, an environment, output or any text (decisions B-3: a resend
-- routes its own bytes, accepted only when its digest equals the record's). States: 1 ACCEPTED (an attempt was admitted; until its
-- answer is written, or when the answer could not be written, the record counts as one that may have reached the node), 3 SUCCEEDED, 4
-- FAILED (the node's handler refused), 5 REJECTED_BY_NODE, 6 EXPIRED, 7 UNKNOWN (the call may have reached the node without a verified
-- result), 8 NOT_DELIVERED (the hub answered DID_NOT_HAPPEN and no earlier attempt may have reached the node). 2 (DELIVERED) is reserved
-- and never written (Q-2): delivery is known only from the hub's answer, and delivered keeps it. A record is final exactly when final_at
-- is set: SUCCEEDED and FAILED always; REJECTED_BY_NODE and EXPIRED when the node's signed result did not say that the call did not
-- happen. delivered is monotonic: once a record may have reached the node it stays so.
--
-- Personal data: none beyond the account and the IDs. Retention: 90 days by design; the sweep is not delivered (H-24 UNKNOWN, AF-PLAT-01).

CREATE TABLE fleet.refusal_code (
    value    smallint NOT NULL,
    category text     NOT NULL,
    code     text     NOT NULL,
    CONSTRAINT refusal_code_pkey PRIMARY KEY (value),
    CONSTRAINT refusal_code_unique UNIQUE (category, code),
    CONSTRAINT refusal_code_value CHECK (value >= 0),
    CONSTRAINT refusal_code_text CHECK (category ~ '^[a-z]+$' AND code ~ '^[a-z_]+$')
);

INSERT INTO fleet.refusal_code (value, category, code) VALUES
    (0, 'other', 'other'),
    (1, 'authentication', 'credential_revoked'),
    (2, 'authentication', 'signature_invalid'),
    (3, 'authentication', 'step_up_required'),
    (4, 'authentication', 'token_expired'),
    (5, 'authentication', 'unauthenticated'),
    (6, 'authorization', 'account_mismatch'),
    (7, 'authorization', 'approval_required'),
    (8, 'authorization', 'command_pattern_denied'),
    (9, 'authorization', 'peer_policy_denied'),
    (10, 'authorization', 'permission_denied'),
    (11, 'conflict', 'already_exists'),
    (12, 'conflict', 'code_reused'),
    (13, 'conflict', 'command_id_reused'),
    (14, 'conflict', 'digest_mismatch'),
    (15, 'conflict', 'purchase_already_linked'),
    (16, 'conflict', 'revision_conflict'),
    (17, 'entitlement', 'feature_not_entitled'),
    (18, 'entitlement', 'plan_limit_reached'),
    (19, 'execution', 'adopt_not_permitted'),
    (20, 'execution', 'integration_write_failed'),
    (21, 'execution', 'operation_failed'),
    (22, 'execution', 'provider_error'),
    (23, 'internal', 'internal'),
    (24, 'internal', 'store_corrupt'),
    (25, 'resource', 'disk_space'),
    (26, 'resource', 'enforcement_unavailable'),
    (27, 'resource', 'kill_switch_active'),
    (28, 'resource', 'overloaded'),
    (29, 'resource', 'queue_full'),
    (30, 'resource', 'quota_exceeded'),
    (31, 'resource', 'rate_limited'),
    (32, 'resource', 'too_large'),
    (33, 'state', 'cloud_unreachable'),
    (34, 'state', 'dirty_worktree'),
    (35, 'state', 'expired'),
    (36, 'state', 'in_use'),
    (37, 'state', 'invalid_state'),
    (38, 'state', 'link_down'),
    (39, 'state', 'managed_externally'),
    (40, 'state', 'node_offline'),
    (41, 'state', 'node_stopping'),
    (42, 'state', 'node_unreachable'),
    (43, 'state', 'not_activated'),
    (44, 'state', 'not_attached'),
    (45, 'state', 'not_found'),
    (46, 'state', 'not_signed_in'),
    (47, 'state', 'pause_unsupported'),
    (48, 'state', 'peer_blocked'),
    (49, 'state', 'peer_incompatible'),
    (50, 'state', 'peer_unreachable'),
    (51, 'state', 'plan_expired'),
    (52, 'state', 'purchase_pending'),
    (53, 'state', 'sas_mismatch'),
    (54, 'state', 'secrets_unavailable'),
    (55, 'state', 'update_in_progress'),
    (56, 'validation', 'code_invalid'),
    (57, 'validation', 'incompatible_version'),
    (58, 'validation', 'inputs_required'),
    (59, 'validation', 'invalid_argument'),
    (60, 'validation', 'invalid_cursor'),
    (61, 'validation', 'invalid_dependency'),
    (62, 'validation', 'invalid_policy'),
    (63, 'validation', 'path_not_found'),
    (64, 'validation', 'program_not_found'),
    (65, 'validation', 'purchase_invalid'),
    (66, 'validation', 'unsafe_batch_argument'),
    (67, 'validation', 'unsupported_shell');

CREATE FUNCTION fleet.refusal_code_fixed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'fleet.refusal_code is append-only' USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

CREATE TRIGGER refusal_code_fixed BEFORE UPDATE OR DELETE ON fleet.refusal_code FOR EACH ROW EXECUTE FUNCTION fleet.refusal_code_fixed();

CREATE TABLE fleet.routed_call (
    account_id         uuid        NOT NULL,
    command_id         uuid        NOT NULL,
    node_enrollment_id uuid        NOT NULL,
    node_id            uuid        NOT NULL,
    method             smallint    NOT NULL,
    caller_kind        smallint    NOT NULL,
    session_id         uuid,
    relaying_node_id   uuid,
    local_origin       smallint,
    local_session_id   uuid,
    request_digest     bytea       NOT NULL,
    request_size       integer     NOT NULL,
    state              smallint    NOT NULL,
    delivered          boolean     NOT NULL DEFAULT false,
    attempts           integer     NOT NULL,
    task_id            uuid,
    response_sha256    bytea,
    outcome_sha256     bytea,
    response_size      integer,
    executed_at        timestamptz,
    refusal            smallint,
    created_at         timestamptz NOT NULL,
    updated_at         timestamptz NOT NULL,
    final_at           timestamptz,
    CONSTRAINT routed_call_pkey PRIMARY KEY (account_id, command_id),
    CONSTRAINT routed_call_account FOREIGN KEY (account_id) REFERENCES identity.user (user_id),
    CONSTRAINT routed_call_node FOREIGN KEY (node_enrollment_id) REFERENCES fleet.node (enrollment_id),
    CONSTRAINT routed_call_refusal FOREIGN KEY (refusal) REFERENCES fleet.refusal_code (value),
    -- RoutedMethod SUBMIT_NODE_TASK (1) and CANCEL_NODE_TASK (6): the routed mutations; reads have no record.
    CONSTRAINT routed_call_method CHECK (method IN (1, 6)),
    -- 1 an account session (its session), 2 a node relay (the relaying node, its local origin HUMAN, SCRIPT or AGENT, its local session).
    CONSTRAINT routed_call_caller CHECK (
        (caller_kind = 1 AND session_id IS NOT NULL AND relaying_node_id IS NULL AND local_origin IS NULL AND local_session_id IS NULL) OR
        (caller_kind = 2 AND session_id IS NULL AND relaying_node_id IS NOT NULL AND local_origin BETWEEN 1 AND 3 AND local_session_id IS NOT NULL)),
    CONSTRAINT routed_call_request CHECK (octet_length(request_digest) = 32 AND request_size BETWEEN 1 AND 253952),
    CONSTRAINT routed_call_state CHECK (state IN (1, 3, 4, 5, 6, 7, 8)),
    CONSTRAINT routed_call_attempts CHECK (attempts >= 1),
    CONSTRAINT routed_call_digests CHECK ((response_sha256 IS NULL OR octet_length(response_sha256) = 32) AND
        (outcome_sha256 IS NULL OR octet_length(outcome_sha256) = 32) AND (response_size IS NULL OR response_size BETWEEN 1 AND 1040384)),
    -- An executed outcome names its response; SUCCEEDED and FAILED are executed, NOT_DELIVERED never reached the node.
    CONSTRAINT routed_call_executed CHECK ((response_sha256 IS NULL) = (outcome_sha256 IS NULL) AND (response_sha256 IS NULL) = (response_size IS NULL) AND
        (state NOT IN (3, 4) OR response_sha256 IS NOT NULL AND executed_at IS NOT NULL) AND (state <> 8 OR NOT delivered) AND
        (state NOT IN (3, 4, 5, 6, 7) OR delivered) AND (state <> 3 OR refusal IS NULL) AND (state NOT IN (4, 5, 6) OR refusal IS NOT NULL)),
    -- SUCCEEDED and FAILED are always final; REJECTED_BY_NODE and EXPIRED may be; ACCEPTED, UNKNOWN and NOT_DELIVERED never are.
    CONSTRAINT routed_call_final CHECK ((state NOT IN (3, 4) OR final_at IS NOT NULL) AND (final_at IS NULL OR state IN (3, 4, 5, 6))),
    CONSTRAINT routed_call_instants CHECK (updated_at >= created_at AND (final_at IS NULL OR final_at >= created_at))
);

CREATE INDEX routed_call_node_created ON fleet.routed_call (node_enrollment_id, created_at);
CREATE INDEX routed_call_open ON fleet.routed_call (state, updated_at) WHERE state = 1;
CREATE INDEX routed_call_account_created ON fleet.routed_call (account_id, created_at);
CREATE INDEX routed_call_refusal_code ON fleet.routed_call (refusal);

-- The record's identity never changes, a final record keeps its outcome, delivered and attempts never go back, and nothing is
-- deleted at runtime.
CREATE FUNCTION fleet.routed_call_guarded() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'a routing record is never deleted at runtime' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.account_id IS DISTINCT FROM OLD.account_id OR NEW.command_id IS DISTINCT FROM OLD.command_id OR
       NEW.node_enrollment_id IS DISTINCT FROM OLD.node_enrollment_id OR NEW.node_id IS DISTINCT FROM OLD.node_id OR
       NEW.method IS DISTINCT FROM OLD.method OR NEW.caller_kind IS DISTINCT FROM OLD.caller_kind OR
       NEW.relaying_node_id IS DISTINCT FROM OLD.relaying_node_id OR NEW.local_origin IS DISTINCT FROM OLD.local_origin OR
       NEW.request_digest IS DISTINCT FROM OLD.request_digest OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'a routing record keeps its identity' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.delivered AND NOT NEW.delivered OR NEW.attempts < OLD.attempts THEN
        RAISE EXCEPTION 'a routing record never forgets an attempt' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.final_at IS NOT NULL AND (NEW.state IS DISTINCT FROM OLD.state OR NEW.final_at IS DISTINCT FROM OLD.final_at OR
       NEW.task_id IS DISTINCT FROM OLD.task_id OR NEW.response_sha256 IS DISTINCT FROM OLD.response_sha256 OR
       NEW.outcome_sha256 IS DISTINCT FROM OLD.outcome_sha256 OR NEW.response_size IS DISTINCT FROM OLD.response_size OR
       NEW.executed_at IS DISTINCT FROM OLD.executed_at OR NEW.refusal IS DISTINCT FROM OLD.refusal) THEN
        RAISE EXCEPTION 'a final routing record keeps its outcome' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER routed_call_guarded BEFORE UPDATE OR DELETE ON fleet.routed_call FOR EACH ROW EXECUTE FUNCTION fleet.routed_call_guarded();
