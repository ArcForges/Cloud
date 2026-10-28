-- 0001 The platform store of the center (AF-CTR-02; ArcForges-Design data/cloud-store.md section 6).
--
-- Applied by `arcforges-center migrate` in one transaction with the migration role over the direct connection. The runner
-- creates the platform schema and platform.schema_migration before the first migration. Grants to the runtime role are never
-- written here: the runner reconciles them after every run from center/internal/schema/grants.go.
--
-- Rules (data/cloud-store.md section 6): one schema per module; uuid identifiers; timestamptz instants; enumerations as smallint
-- with named CHECK constraints; text bounded where a contract bounds it. The guarantees of the D1 storage plans (command
-- receipts and guard, inbox, outbox, job lease, audit append) are re-implemented with native transactions, constraints and row
-- locks.

CREATE SCHEMA audit;
CREATE SCHEMA fleet;

-- Command receipts: one row per principal and command ID with the SHA-256 of the transmitted request bytes. A replay with the
-- same digest returns the stored result; a different digest under the same ID is refused. The receipt is written in the same
-- transaction as the command's business changes and outbox rows, so concurrent duplicates execute once.
CREATE TABLE platform.command_receipt (
    principal      text        NOT NULL,
    command_id     uuid        NOT NULL,
    operation      text        NOT NULL,
    request_sha256 bytea       NOT NULL,
    status         smallint    NOT NULL,
    result         bytea,
    error_code     text,
    created_at     timestamptz NOT NULL,
    completed_at   timestamptz,
    expires_at     timestamptz NOT NULL,
    CONSTRAINT command_receipt_pkey PRIMARY KEY (principal, command_id),
    CONSTRAINT command_receipt_principal CHECK (length(principal) BETWEEN 1 AND 256),
    CONSTRAINT command_receipt_operation CHECK (length(operation) BETWEEN 1 AND 256),
    CONSTRAINT command_receipt_request_sha256 CHECK (length(request_sha256) = 32),
    -- 1 in progress, 2 succeeded, 3 failed (platform.command_status)
    CONSTRAINT command_receipt_status CHECK (status IN (1, 2, 3)),
    CONSTRAINT command_receipt_failed_has_error_code CHECK (status <> 3 OR error_code IS NOT NULL),
    CONSTRAINT command_receipt_error_code CHECK (error_code IS NULL OR length(error_code) BETWEEN 1 AND 128),
    CONSTRAINT command_receipt_completion CHECK ((status = 1) = (completed_at IS NULL)),
    CONSTRAINT command_receipt_result_bounded CHECK (result IS NULL OR length(result) <= 262144),
    CONSTRAINT command_receipt_expiry CHECK (expires_at > created_at)
);
CREATE INDEX command_receipt_expires_at ON platform.command_receipt (expires_at);

-- Inbox: one row per provider message, so a redelivered message is recognized and ignored in the transaction that applies it.
CREATE TABLE platform.inbox (
    source       text        NOT NULL,
    message_id   text        NOT NULL,
    received_at  timestamptz NOT NULL,
    processed_at timestamptz,
    outcome      smallint,
    expires_at   timestamptz NOT NULL,
    CONSTRAINT inbox_pkey PRIMARY KEY (source, message_id),
    CONSTRAINT inbox_source CHECK (source ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    CONSTRAINT inbox_message_id CHECK (length(message_id) BETWEEN 1 AND 256),
    -- 1 applied, 2 duplicate ignored, 3 rejected (platform.inbox_outcome)
    CONSTRAINT inbox_outcome CHECK (outcome IS NULL OR outcome IN (1, 2, 3)),
    CONSTRAINT inbox_processed CHECK ((processed_at IS NULL) = (outcome IS NULL)),
    CONSTRAINT inbox_expiry CHECK (expires_at > received_at)
);
CREATE INDEX inbox_expires_at ON platform.inbox (expires_at);

-- Outbox: rows committed with their business change and published at least once by the publisher. The dedup key is unique, so
-- enqueueing the same event twice is a no-op, and consumers deduplicate redeliveries by it.
CREATE TABLE platform.outbox (
    outbox_id      uuid        NOT NULL,
    sequence       bigint      GENERATED ALWAYS AS IDENTITY,
    dedup_key      text        NOT NULL,
    topic          text        NOT NULL,
    aggregate_kind text        NOT NULL,
    aggregate_id   uuid        NOT NULL,
    aggregate_rev  bigint      NOT NULL,
    payload        bytea       NOT NULL,
    correlation_id uuid        NOT NULL,
    causation_id   uuid,
    state          smallint    NOT NULL,
    attempts       integer     NOT NULL,
    available_at   timestamptz NOT NULL,
    created_at     timestamptz NOT NULL,
    dispatched_at  timestamptz,
    last_error     text,
    CONSTRAINT outbox_pkey PRIMARY KEY (outbox_id),
    CONSTRAINT outbox_sequence UNIQUE (sequence),
    CONSTRAINT outbox_dedup_key UNIQUE (dedup_key),
    CONSTRAINT outbox_dedup_key_length CHECK (length(dedup_key) BETWEEN 1 AND 256),
    CONSTRAINT outbox_topic CHECK (topic ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    CONSTRAINT outbox_aggregate_kind CHECK (aggregate_kind ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    CONSTRAINT outbox_aggregate_rev CHECK (aggregate_rev >= 0),
    CONSTRAINT outbox_payload_bounded CHECK (length(payload) <= 262144),
    -- 1 pending, 2 dispatched, 3 dead-lettered (platform.outbox_state)
    CONSTRAINT outbox_state CHECK (state IN (1, 2, 3)),
    CONSTRAINT outbox_attempts CHECK (attempts >= 0),
    CONSTRAINT outbox_dispatched CHECK ((state = 2) = (dispatched_at IS NOT NULL)),
    CONSTRAINT outbox_last_error CHECK (last_error IS NULL OR length(last_error) <= 512)
);
CREATE INDEX outbox_pending ON platform.outbox (available_at, sequence) WHERE state = 1;
CREATE INDEX outbox_aggregate ON platform.outbox (aggregate_kind, aggregate_id, aggregate_rev);

-- Job lease: a claimed job carries its holder, an expiry and a fence that increases with every claim, so a holder whose lease
-- expired cannot complete the job or write under it after another holder claimed it.
CREATE TABLE platform.job_lease (
    job_id       uuid        NOT NULL,
    job_type     text        NOT NULL,
    holder       text,
    leased_until timestamptz,
    attempts     integer     NOT NULL,
    fence        bigint      NOT NULL,
    state        smallint    NOT NULL,
    payload      bytea       NOT NULL,
    available_at timestamptz NOT NULL,
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL,
    last_error   text,
    CONSTRAINT job_lease_pkey PRIMARY KEY (job_id),
    CONSTRAINT job_lease_job_type CHECK (job_type ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    CONSTRAINT job_lease_holder CHECK (holder IS NULL OR length(holder) BETWEEN 1 AND 128),
    -- 1 ready, 2 leased, 3 succeeded, 4 dead-lettered (platform.job_state)
    CONSTRAINT job_lease_state CHECK (state IN (1, 2, 3, 4)),
    CONSTRAINT job_lease_leased_has_holder CHECK (state <> 2 OR (holder IS NOT NULL AND leased_until IS NOT NULL)),
    CONSTRAINT job_lease_attempts CHECK (attempts >= 0),
    CONSTRAINT job_lease_fence CHECK (fence >= 0),
    CONSTRAINT job_lease_payload_bounded CHECK (length(payload) <= 65536),
    CONSTRAINT job_lease_last_error CHECK (last_error IS NULL OR length(last_error) <= 512)
);
CREATE INDEX job_lease_claim ON platform.job_lease (job_type, state, available_at);

-- The two login roles of the runtime credential rotation (written by `arcforges-center admin rotate-runtime-credential` with
-- the migration role; the runtime role has no access).
CREATE TABLE platform.runtime_credential (
    slot       text        NOT NULL,
    login_role text        NOT NULL,
    rotated_at timestamptz NOT NULL,
    rotated_by text        NOT NULL,
    CONSTRAINT runtime_credential_pkey PRIMARY KEY (slot),
    CONSTRAINT runtime_credential_slot CHECK (slot IN ('a', 'b')),
    CONSTRAINT runtime_credential_login_role UNIQUE (login_role),
    CONSTRAINT runtime_credential_rotated_by CHECK (length(rotated_by) BETWEEN 1 AND 128)
);

-- Audit events: an append-only hash chain. Every event's hash covers the previous event's hash and the event's fields, and the
-- single chain head row serializes appends. The runtime role may insert events and read them, never update or delete them; only
-- the approved retention purge of the migration role deletes.
CREATE TABLE audit.audit_event (
    sequence       bigint      NOT NULL,
    event_id       uuid        NOT NULL,
    occurred_at    timestamptz NOT NULL,
    actor_ref      text        NOT NULL,
    event_type     text        NOT NULL,
    reason         text        NOT NULL,
    correlation_id uuid,
    command_id     uuid,
    target_kind    text        NOT NULL,
    target_id      text        NOT NULL,
    payload        bytea       NOT NULL,
    previous_hash  bytea       NOT NULL,
    event_hash     bytea       NOT NULL,
    CONSTRAINT audit_event_pkey PRIMARY KEY (sequence),
    CONSTRAINT audit_event_event_id UNIQUE (event_id),
    CONSTRAINT audit_event_sequence CHECK (sequence >= 1),
    CONSTRAINT audit_event_actor_ref CHECK (length(actor_ref) BETWEEN 1 AND 256),
    CONSTRAINT audit_event_event_type CHECK (event_type ~ '^[a-z][a-z0-9_.]{0,127}$'),
    CONSTRAINT audit_event_reason CHECK (length(reason) <= 128),
    CONSTRAINT audit_event_target_kind CHECK (length(target_kind) <= 64),
    CONSTRAINT audit_event_target_id CHECK (length(target_id) <= 256),
    CONSTRAINT audit_event_payload_bounded CHECK (length(payload) <= 65536),
    CONSTRAINT audit_event_previous_hash CHECK (length(previous_hash) = 32),
    CONSTRAINT audit_event_event_hash CHECK (length(event_hash) = 32)
);
CREATE INDEX audit_event_actor ON audit.audit_event (actor_ref, occurred_at);
CREATE INDEX audit_event_correlation ON audit.audit_event (correlation_id) WHERE correlation_id IS NOT NULL;

CREATE TABLE audit.chain_head (
    singleton     boolean NOT NULL,
    last_sequence bigint  NOT NULL,
    last_hash     bytea   NOT NULL,
    CONSTRAINT chain_head_pkey PRIMARY KEY (singleton),
    CONSTRAINT chain_head_single_row CHECK (singleton),
    CONSTRAINT chain_head_last_sequence CHECK (last_sequence >= 0),
    CONSTRAINT chain_head_last_hash CHECK (length(last_hash) = 32)
);
INSERT INTO audit.chain_head (singleton, last_sequence, last_hash) VALUES (true, 0, decode(repeat('00', 32), 'hex'));

CREATE FUNCTION audit.refuse_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit events are append-only' USING ERRCODE = 'insufficient_privilege';
END;
$$;
CREATE TRIGGER audit_event_append_only BEFORE UPDATE ON audit.audit_event
    FOR EACH ROW EXECUTE FUNCTION audit.refuse_change();

-- Signing-key metadata (fleet.signing_key; AD-0021 section 10): key IDs, purposes, validity and the name of the platform
-- secret that holds the private key. Private keys are never stored here. Rotation overlaps validity windows.
CREATE TABLE fleet.signing_key (
    kid            text        NOT NULL,
    purpose        smallint    NOT NULL,
    algorithm      text        NOT NULL,
    public_key     bytea,
    secret_binding text        NOT NULL,
    not_before     timestamptz NOT NULL,
    not_after      timestamptz NOT NULL,
    retired_at     timestamptz,
    created_at     timestamptz NOT NULL,
    CONSTRAINT signing_key_pkey PRIMARY KEY (kid),
    CONSTRAINT signing_key_kid CHECK (kid ~ '^[A-Za-z0-9_-]{8,64}$'),
    -- 1 command signing (ES256), 2 entitlement token (ES256), 3 relay HMAC (HS256) (fleet.signing_key_purpose)
    CONSTRAINT signing_key_purpose CHECK (purpose IN (1, 2, 3)),
    CONSTRAINT signing_key_algorithm CHECK ((purpose IN (1, 2) AND algorithm = 'ES256') OR (purpose = 3 AND algorithm = 'HS256')),
    CONSTRAINT signing_key_public_key CHECK ((algorithm = 'ES256') = (public_key IS NOT NULL)),
    CONSTRAINT signing_key_public_key_length CHECK (public_key IS NULL OR length(public_key) BETWEEN 32 AND 512),
    CONSTRAINT signing_key_secret_binding CHECK (secret_binding ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    CONSTRAINT signing_key_validity CHECK (not_after > not_before)
);
CREATE INDEX signing_key_purpose_validity ON fleet.signing_key (purpose, not_before, not_after);
