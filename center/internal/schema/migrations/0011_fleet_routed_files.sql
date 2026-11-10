-- 0011 AF-CTR-06: file/workspace mutation receipts and the cross-version command namespace.
-- Applied in one migration transaction; 0001..0010 and their checksums remain immutable.
-- Lock the old receipt table before the backfill and trigger installation. This excludes
-- concurrent old-binary INSERT/UPDATE/DELETE until the registry and both guards commit.
-- Reads remain available. New receipt paths cannot exist before this migration commits.
--
-- The registry has only an account/command identity and its immutable receipt kind.
-- Runtime holds SELECT only on it. A narrowly scoped SECURITY DEFINER trigger performs
-- the reservation for INSERTs on the two fixed tables, including from an older center.
-- Duplicate commands within a namespace reach that table's caller/method/digest handling;
-- another namespace is a command_id_reused conflict. No file/request/response bytes here.

LOCK TABLE fleet.routed_call IN SHARE ROW EXCLUSIVE MODE;

-- Append the three reviewed AF-CTR-06 error identities; earlier values never change.
INSERT INTO fleet.refusal_code (value, category, code) VALUES
    (68, 'conflict', 'file_changed'),
    (69, 'conflict', 'occurrence_mismatch'),
    (70, 'state', 'file_access_denied');

CREATE TABLE fleet.routed_file_call (
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
    request_sha256     bytea       NOT NULL,
    request_size       integer     NOT NULL,
    state              smallint    NOT NULL,
    delivered          boolean     NOT NULL DEFAULT false,
    attempts           integer     NOT NULL,
    workspace_id       uuid,
    target_attempt_id  uuid,
    response_sha256    bytea,
    outcome_sha256     bytea,
    response_size      integer,
    executed_at        timestamptz,
    refusal            smallint,
    created_at         timestamptz NOT NULL,
    updated_at         timestamptz NOT NULL,
    final_at           timestamptz,
    CONSTRAINT routed_file_call_pkey PRIMARY KEY (account_id, command_id),
    CONSTRAINT routed_file_call_account FOREIGN KEY (account_id) REFERENCES identity.user (user_id),
    CONSTRAINT routed_file_call_node FOREIGN KEY (node_enrollment_id) REFERENCES fleet.node (enrollment_id),
    CONSTRAINT routed_file_call_refusal FOREIGN KEY (refusal) REFERENCES fleet.refusal_code (value),
    -- Routed file/workspace mutations only; reads have no durable mutation receipt.
    CONSTRAINT routed_file_call_method CHECK (method IN (10, 11, 14, 15, 17, 18)),
    -- 1 an account session (its session), 2 a node relay (the relaying node, its local origin HUMAN, SCRIPT or AGENT, its local session).
    CONSTRAINT routed_file_call_caller CHECK (
        (caller_kind = 1 AND session_id IS NOT NULL AND relaying_node_id IS NULL AND local_origin IS NULL AND local_session_id IS NULL) OR
        (caller_kind = 2 AND session_id IS NULL AND relaying_node_id IS NOT NULL AND local_origin BETWEEN 1 AND 3 AND local_session_id IS NOT NULL)),
    CONSTRAINT routed_file_call_request CHECK (octet_length(request_digest) = 32 AND octet_length(request_sha256) = 32 AND request_size BETWEEN 1 AND 245760),
    CONSTRAINT routed_file_call_state CHECK (state IN (1, 3, 4, 5, 6, 7, 8)),
    CONSTRAINT routed_file_call_attempts CHECK (attempts >= 1),
    CONSTRAINT routed_file_call_digests CHECK ((response_sha256 IS NULL OR octet_length(response_sha256) = 32) AND
        (outcome_sha256 IS NULL OR octet_length(outcome_sha256) = 32) AND (response_size IS NULL OR response_size BETWEEN 1 AND 1040384)),
    -- An executed outcome names its response; SUCCEEDED and FAILED are executed, NOT_DELIVERED never reached the node.
    CONSTRAINT routed_file_call_executed CHECK ((response_sha256 IS NULL) = (outcome_sha256 IS NULL) AND (response_sha256 IS NULL) = (response_size IS NULL) AND
        (state NOT IN (3, 4) OR response_sha256 IS NOT NULL AND executed_at IS NOT NULL) AND (state <> 8 OR NOT delivered) AND
        (state NOT IN (3, 4, 5, 6, 7) OR delivered) AND (state <> 3 OR refusal IS NULL) AND (state NOT IN (4, 5, 6) OR refusal IS NOT NULL)),
    -- SUCCEEDED is always final; FAILED, REJECTED_BY_NODE and EXPIRED may be; ACCEPTED, UNKNOWN and NOT_DELIVERED never are.
    CONSTRAINT routed_file_call_final CHECK ((state <> 3 OR final_at IS NOT NULL) AND (final_at IS NULL OR state IN (3, 4, 5, 6))),
    CONSTRAINT routed_file_call_instants CHECK (updated_at >= created_at AND (final_at IS NULL OR final_at >= created_at))
);

CREATE INDEX routed_file_call_node_created ON fleet.routed_file_call (node_enrollment_id, created_at);
CREATE INDEX routed_file_call_open ON fleet.routed_file_call (state, updated_at) WHERE state = 1;
CREATE INDEX routed_file_call_account_created ON fleet.routed_file_call (account_id, created_at);
CREATE INDEX routed_file_call_refusal_code ON fleet.routed_file_call (refusal);

CREATE FUNCTION fleet.routed_file_call_guarded() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'a routing record is never deleted at runtime' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.account_id IS DISTINCT FROM OLD.account_id OR NEW.command_id IS DISTINCT FROM OLD.command_id OR
       NEW.node_enrollment_id IS DISTINCT FROM OLD.node_enrollment_id OR NEW.node_id IS DISTINCT FROM OLD.node_id OR
       NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.target_attempt_id IS DISTINCT FROM OLD.target_attempt_id OR
       NEW.method IS DISTINCT FROM OLD.method OR NEW.caller_kind IS DISTINCT FROM OLD.caller_kind OR
       NEW.session_id IS DISTINCT FROM OLD.session_id OR NEW.relaying_node_id IS DISTINCT FROM OLD.relaying_node_id OR
       NEW.local_origin IS DISTINCT FROM OLD.local_origin OR NEW.local_session_id IS DISTINCT FROM OLD.local_session_id OR
       NEW.request_digest IS DISTINCT FROM OLD.request_digest OR NEW.request_sha256 IS DISTINCT FROM OLD.request_sha256 OR
       NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'a routing record keeps its identity' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.delivered AND NOT NEW.delivered OR NEW.attempts < OLD.attempts THEN
        RAISE EXCEPTION 'a routing record never forgets an attempt' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.final_at IS NOT NULL AND (NEW.state IS DISTINCT FROM OLD.state OR NEW.final_at IS DISTINCT FROM OLD.final_at OR
       NEW.response_sha256 IS DISTINCT FROM OLD.response_sha256 OR
       NEW.outcome_sha256 IS DISTINCT FROM OLD.outcome_sha256 OR NEW.response_size IS DISTINCT FROM OLD.response_size OR
       NEW.executed_at IS DISTINCT FROM OLD.executed_at OR NEW.refusal IS DISTINCT FROM OLD.refusal) THEN
        RAISE EXCEPTION 'a final routing record keeps its outcome' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER routed_file_call_guarded BEFORE UPDATE OR DELETE ON fleet.routed_file_call FOR EACH ROW EXECUTE FUNCTION fleet.routed_file_call_guarded();

CREATE TABLE fleet.routed_command_id (
    account_id   uuid     NOT NULL,
    command_id   uuid     NOT NULL,
    receipt_kind smallint NOT NULL CHECK (receipt_kind IN (1, 2)),
    CONSTRAINT routed_command_id_pkey PRIMARY KEY (account_id, command_id),
    CONSTRAINT routed_command_id_account FOREIGN KEY (account_id) REFERENCES identity.user (user_id)
);

INSERT INTO fleet.routed_command_id (account_id, command_id, receipt_kind)
    SELECT account_id, command_id, 1 FROM fleet.routed_call ORDER BY account_id, command_id;

-- The UPSERT used by the reservation performs a same-value update to obtain the
-- winning row atomically under concurrent INSERTs. No identity/kind change is allowed.
CREATE FUNCTION fleet.routed_command_id_fixed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'a command namespace is retained' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.account_id IS DISTINCT FROM OLD.account_id OR NEW.command_id IS DISTINCT FROM OLD.command_id OR
       NEW.receipt_kind IS DISTINCT FROM OLD.receipt_kind THEN
        RAISE EXCEPTION 'a command keeps its namespace' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER routed_command_id_fixed BEFORE UPDATE OR DELETE ON fleet.routed_command_id
    FOR EACH ROW EXECUTE FUNCTION fleet.routed_command_id_fixed();

CREATE FUNCTION fleet.reserve_routed_command_id() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    required_kind smallint;
    actual_kind smallint;
BEGIN
    -- Never accept a caller-selected relation or namespace. All data comes from
    -- the row of one of these two migration-owned trigger targets.
    IF TG_TABLE_SCHEMA <> 'fleet' OR TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'invalid command registry trigger' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    CASE TG_TABLE_NAME
        WHEN 'routed_call' THEN required_kind := 1;
        WHEN 'routed_file_call' THEN required_kind := 2;
        ELSE RAISE EXCEPTION 'invalid command registry relation' USING ERRCODE = 'integrity_constraint_violation';
    END CASE;

    INSERT INTO fleet.routed_command_id AS claimed (account_id, command_id, receipt_kind)
        VALUES (NEW.account_id, NEW.command_id, required_kind)
        ON CONFLICT (account_id, command_id) DO UPDATE SET receipt_kind = claimed.receipt_kind
        RETURNING receipt_kind INTO actual_kind;
    IF actual_kind IS DISTINCT FROM required_kind THEN
        RAISE EXCEPTION 'a command belongs to another routing namespace'
            USING ERRCODE = 'unique_violation', CONSTRAINT = 'routed_command_id_namespace';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION fleet.reserve_routed_command_id() FROM PUBLIC;

CREATE TRIGGER routed_call_command_id BEFORE INSERT ON fleet.routed_call
    FOR EACH ROW EXECUTE FUNCTION fleet.reserve_routed_command_id();
CREATE TRIGGER routed_file_call_command_id BEFORE INSERT ON fleet.routed_file_call
    FOR EACH ROW EXECUTE FUNCTION fleet.reserve_routed_command_id();

-- Caller-bound, content-free target associations. A plan identifier is admitted
-- only from a verified signed plan result; an operation association is bound to
-- its admission or a verified signed status of an already bound receipt. Rows
-- never change at runtime; UNKNOWN operation associations remain through human
-- acknowledgment, even if a future retention sweep is introduced.
CREATE TABLE fleet.routed_file_target (
    account_id         uuid        NOT NULL REFERENCES identity.user (user_id),
    node_enrollment_id uuid        NOT NULL REFERENCES fleet.node (enrollment_id),
    node_id            uuid        NOT NULL,
    caller_hash        bytea       NOT NULL CHECK (octet_length(caller_hash) = 32),
    target_kind        smallint    NOT NULL CHECK (target_kind IN (1, 2)),
    lookup_id          uuid        NOT NULL,
    workspace_id       uuid,
    target_attempt_id  uuid,
    target_path        text,
    created_at         timestamptz NOT NULL,
    PRIMARY KEY (account_id, node_id, caller_hash, target_kind, lookup_id),
    CONSTRAINT routed_file_target_shape CHECK (
        (workspace_id IS NOT NULL AND target_attempt_id IS NULL AND target_path IS NOT NULL AND octet_length(target_path) BETWEEN 1 AND 4096) OR
        (workspace_id IS NULL AND target_attempt_id IS NOT NULL AND target_path IS NULL))
);
CREATE INDEX routed_file_target_enrollment ON fleet.routed_file_target (node_enrollment_id);
CREATE FUNCTION fleet.routed_file_target_fixed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'a file target association is immutable' USING ERRCODE = 'integrity_constraint_violation';
END;
$$;
CREATE TRIGGER routed_file_target_fixed BEFORE UPDATE OR DELETE ON fleet.routed_file_target
    FOR EACH ROW EXECUTE FUNCTION fleet.routed_file_target_fixed();

-- The migration owner alone records the credential-generation floor. This is
-- created in the same transaction as the bridge fence, never supplied by an
-- operator flag; ordinary runtime roles cannot read or change it.
CREATE TABLE platform.ctr06_runtime_floor (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    database_oid oid NOT NULL,
    owner_oid oid NOT NULL,
    runtime_role name NOT NULL,
    runtime_role_oid oid NOT NULL,
    legacy_role name,
    legacy_role_oid oid,
    bridge_revision text,
    bridge_image_id text,
    promotion_digest text,
    established_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((legacy_role IS NULL) = (legacy_role_oid IS NULL)),
    CHECK ((bridge_revision IS NULL) = (promotion_digest IS NULL)),
    CHECK (promotion_digest IS NULL OR promotion_digest ~ '^[0-9a-f]{64}$')
);
REVOKE ALL ON platform.ctr06_runtime_floor FROM PUBLIC;

-- Preserve the two old rotation records when the bridge generation is
-- adopted; this table is accessible only to the migration owner.
CREATE TABLE platform.ctr06_legacy_runtime_credential (
    slot text NOT NULL,
    login_role text NOT NULL,
    rotated_at timestamptz NOT NULL,
    rotated_by text NOT NULL,
    promoted_at timestamptz,
    preserved_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON platform.ctr06_legacy_runtime_credential FROM PUBLIC;
