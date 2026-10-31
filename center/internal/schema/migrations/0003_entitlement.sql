-- 0003 Entitlement of the center (AF-CTR-03 part B; ArcForges-Design AD-0021 section 13a, data/cloud-store.md sections 2 and 6).
--
-- Applied by `arcforges-center migrate` in one transaction with the migration role; the runner reconciles the runtime role's grants
-- from center/internal/schema/schema.go after every run. The tables derive from the D1 manifest
-- src/ArcForges.Cloud.Storage.D1/Physical/manifest/entitlement.json (migrations 0006 and 0024) by the section 6 rules (uuid keys,
-- timestamptz instants, 1-based smallint enumerations in the listed order with named CHECK constraints, bounded text). The deviations
-- from the D1 model are listed in docs/postgres-store.md ("Entitlement"):
--   * workspace_id is account_id, a foreign key to identity.user: the center's account is the C# workspace (DC-19);
--   * no realm_id (one center database is one realm), and a service term keeps only the columns the resolver reads: the offer,
--     offer snapshot, supersession and selection-priority columns belong to commerce (AF-CTR-09) and arrive with it by an expand
--     migration;
--   * the snapshot holds the resolver's canonical text (the text that decides equality, version included) in one column, not three
--     json columns;
--   * no capacity or quota tables: the resources they bound are enforced by the tasks whose operations they bound (AF-CTR-04 on);
--   * identity.operator is new: the operator role of decision n2.
--
-- Every record table is append-only: a trigger refuses UPDATE and DELETE (and the runtime role has neither privilege), so the
-- history the resolver replays can only grow. The derived tables, snapshot and revision, are rebuildable and rewritten in place; the
-- revision trigger only lets a row advance by exactly one. The runtime role writes grants, revocations, definitions activations and
-- service terms (the operator grant writes a compensation term and AdminGrant capability grants in one transaction with its audit
-- event); it only reads term actions, account status facts and feature releases, whose writers (commerce, trust and safety,
-- configuration) are later tasks. Operator rows are written and revoked only by the migration role (`arcforges-center admin
-- grant-operator` / `revoke-operator`, audited), never at runtime.
--
-- Personal data. account_id ties every row to a person. issued_by_actor holds an actor reference (account:<uuid>, operator:<uuid>,
-- operator:cli), source_ref an opaque reference (a ticket or incident), reason an operator's free text (up to 512 characters, no
-- control character) and identity.operator.reason the same: the reason texts can name people, so erasure of an account (AF-PLAT-01,
-- AF-ID-02) must decide them. No row holds an e-mail address, a credential or a token. Retention: entitlement records are the audit
-- trail of what an account was entitled to and are kept; the triggers refuse deletion until a retention decision (AF-PLAT-01) adds
-- its own migration. The snapshot may be dropped at any time and is recomputed at the next read.

CREATE SCHEMA entitlement;

-- Operators (decision n2): an account that may issue operator grants, for a bounded time. A row is never edited except to revoke it
-- (revoked_at is set once); the bootstrap owner counts as an operator through identity.bootstrap without a row. Written by the
-- migration role only (PLT-10); the runtime role reads it.
CREATE TABLE identity.operator (
    operator_id uuid        NOT NULL,
    user_id     uuid        NOT NULL,
    granted_at  timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    granted_by  text        NOT NULL,
    reason      text        NOT NULL,
    CONSTRAINT operator_pkey PRIMARY KEY (operator_id),
    CONSTRAINT operator_user FOREIGN KEY (user_id) REFERENCES identity.user (user_id),
    CONSTRAINT operator_expiry CHECK (expires_at > granted_at AND expires_at <= granted_at + interval '400 days'),
    CONSTRAINT operator_revoked CHECK (revoked_at IS NULL OR revoked_at >= granted_at),
    CONSTRAINT operator_granted_by CHECK (char_length(granted_by) BETWEEN 1 AND 128 AND granted_by !~ '[[:cntrl:]]'),
    CONSTRAINT operator_reason CHECK (char_length(reason) BETWEEN 1 AND 512 AND reason !~ '[[:cntrl:]]')
);
CREATE INDEX operator_user ON identity.operator (user_id, expires_at);

CREATE FUNCTION identity.operator_only_revokes() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'operator rows are never deleted' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.operator_id <> OLD.operator_id OR NEW.user_id <> OLD.user_id OR NEW.granted_at <> OLD.granted_at OR NEW.expires_at <> OLD.expires_at
        OR NEW.granted_by <> OLD.granted_by OR NEW.reason <> OLD.reason OR OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'an operator row only changes by being revoked once' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER operator_only_revokes BEFORE UPDATE OR DELETE ON identity.operator
    FOR EACH ROW EXECUTE FUNCTION identity.operator_only_revokes();

CREATE FUNCTION entitlement.refuse_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'entitlement records are append-only' USING ERRCODE = 'check_violation';
END;
$$;

-- The per-account write fence of the Entitlement store: every commit names the revision it read and advances it by one in the same
-- transaction, so two writers never derive a snapshot from a history the other has already changed. Absent is revision zero; the
-- first commit of an account creates the row.
CREATE TABLE entitlement.revision (
    account_id uuid        NOT NULL,
    rev        bigint      NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT revision_pkey PRIMARY KEY (account_id),
    CONSTRAINT revision_account FOREIGN KEY (account_id) REFERENCES identity.user (user_id),
    CONSTRAINT revision_rev CHECK (rev >= 1)
);

CREATE FUNCTION entitlement.revision_advances() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'entitlement revisions are never deleted' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.account_id <> OLD.account_id OR NEW.rev <> OLD.rev + 1 THEN
        RAISE EXCEPTION 'an entitlement revision advances by exactly one' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER revision_advances BEFORE UPDATE OR DELETE ON entitlement.revision
    FOR EACH ROW EXECUTE FUNCTION entitlement.revision_advances();

-- The derived snapshot (EN-02): the version, the instants and the resolver's canonical text, which decides equality (a rebuild from
-- the records alone must reproduce it exactly). Rewritten in place with each commit.
CREATE TABLE entitlement.snapshot (
    account_id          uuid        NOT NULL,
    entitlement_version bigint      NOT NULL,
    computed_at         timestamptz NOT NULL,
    valid_until         timestamptz,
    definitions_version text        NOT NULL,
    content             text        NOT NULL,
    CONSTRAINT snapshot_pkey PRIMARY KEY (account_id),
    CONSTRAINT snapshot_account FOREIGN KEY (account_id) REFERENCES identity.user (user_id),
    CONSTRAINT snapshot_version CHECK (entitlement_version >= 0),
    CONSTRAINT snapshot_validity CHECK (valid_until IS NULL OR valid_until > computed_at),
    CONSTRAINT snapshot_definitions_version CHECK (definitions_version ~ '^[A-Za-z0-9._:-]{1,128}$'),
    CONSTRAINT snapshot_content CHECK (char_length(content) BETWEEN 1 AND 1048576 AND content LIKE 'defs=%')
);

-- Grants (GR-01 to GR-06): immutable; a grant ends by its own end date or by a revocation. kind: 1 capability, 2 quota, 3 allowance
-- (entitlement.grant_kind). source: 1 Subscription, 2 CloudPass, 3 StorageAddOn, 4 PurchasedCredit, 5 AdminGrant, 6 Migration,
-- 7 Compensation (entitlement.grant_source). value is the kind's payload: {} for a capability, {limit, priority} for a quota,
-- {capacityPlanRef, priority} for an allowance. A source reference is unique per account and source, so a replayed issue by the same
-- reference finds its grant.
CREATE TABLE entitlement.grant (
    grant_id        uuid        NOT NULL,
    account_id      uuid        NOT NULL,
    kind            smallint    NOT NULL,
    subject         text        NOT NULL,
    value           jsonb       NOT NULL,
    source          smallint    NOT NULL,
    source_ref      text,
    effective_from  timestamptz NOT NULL,
    effective_until timestamptz,
    issued_by_actor text        NOT NULL,
    created_at      timestamptz NOT NULL,
    reason          text,
    CONSTRAINT grant_pkey PRIMARY KEY (grant_id),
    CONSTRAINT grant_of_account UNIQUE (grant_id, account_id),
    CONSTRAINT grant_account FOREIGN KEY (account_id) REFERENCES identity.user (user_id),
    CONSTRAINT grant_kind CHECK (kind IN (1, 2, 3)),
    CONSTRAINT grant_source CHECK (source IN (1, 2, 3, 4, 5, 6, 7)),
    CONSTRAINT grant_subject CHECK (subject ~ '^[a-z0-9._:-]{1,128}$'),
    CONSTRAINT grant_source_ref CHECK (source_ref IS NULL OR source_ref ~ '^[A-Za-z0-9._:-]{1,128}$'),
    CONSTRAINT grant_actor CHECK (char_length(issued_by_actor) BETWEEN 1 AND 128 AND issued_by_actor !~ '[[:cntrl:]]' AND btrim(issued_by_actor) <> ''),
    CONSTRAINT grant_window CHECK (effective_until IS NULL OR effective_until > effective_from),
    -- COALESCE: a missing key makes the comparisons NULL, and a CHECK admits NULL, so an incomplete payload must read as false.
    CONSTRAINT grant_value_shape CHECK (COALESCE(jsonb_typeof(value) = 'object' AND (
        (kind = 1 AND value = '{}'::jsonb) OR
        (kind = 2 AND (value - 'limit' - 'priority') = '{}'::jsonb AND jsonb_typeof(value -> 'limit') = 'number' AND
            jsonb_typeof(value -> 'priority') = 'number' AND (value ->> 'limit') ~ '^[0-9]{1,15}$' AND (value ->> 'priority') ~ '^[0-9]{1,19}$' AND
            (value ->> 'limit')::numeric <= 100000000000000 AND (value ->> 'priority')::numeric <= 9223372036854775807) OR
        (kind = 3 AND (value - 'capacityPlanRef' - 'priority') = '{}'::jsonb AND jsonb_typeof(value -> 'capacityPlanRef') = 'string' AND
            jsonb_typeof(value -> 'priority') = 'number' AND (value ->> 'capacityPlanRef') ~ '^[A-Za-z0-9._:-]{1,64}$' AND
            (value ->> 'priority') ~ '^[0-9]{1,19}$' AND (value ->> 'priority')::numeric <= 9223372036854775807)), false)),
    -- AdminGrant (5), Migration (6) and Compensation (7) carry the recorded cause (GR-04, GR-05), and no other source does.
    CONSTRAINT grant_reason_required_for_operator_sources CHECK ((source IN (5, 6, 7)) = (reason IS NOT NULL)),
    CONSTRAINT grant_reason_shape CHECK (reason IS NULL OR (char_length(reason) BETWEEN 1 AND 512 AND reason !~ '[[:cntrl:]]' AND btrim(reason) <> ''))
);
CREATE INDEX grant_account ON entitlement.grant (account_id, created_at);
CREATE UNIQUE INDEX grant_source_ref_once ON entitlement.grant (account_id, source, source_ref) WHERE source_ref IS NOT NULL;
CREATE TRIGGER grant_append_only BEFORE UPDATE OR DELETE ON entitlement.grant FOR EACH ROW EXECUTE FUNCTION entitlement.refuse_change();

-- Revocations: immutable; one revocation ends one exact grant of the same account.
CREATE TABLE entitlement.revocation (
    revocation_id   uuid        NOT NULL,
    account_id      uuid        NOT NULL,
    grant_id        uuid        NOT NULL,
    reason_code     text        NOT NULL,
    effective_from  timestamptz NOT NULL,
    issued_by_actor text        NOT NULL,
    created_at      timestamptz NOT NULL,
    CONSTRAINT revocation_pkey PRIMARY KEY (revocation_id),
    CONSTRAINT revocation_grant FOREIGN KEY (grant_id, account_id) REFERENCES entitlement.grant (grant_id, account_id),
    CONSTRAINT revocation_account FOREIGN KEY (account_id) REFERENCES identity.user (user_id),
    CONSTRAINT revocation_reason_code CHECK (reason_code ~ '^[a-z0-9._:-]{1,128}$'),
    CONSTRAINT revocation_actor CHECK (char_length(issued_by_actor) BETWEEN 1 AND 128 AND issued_by_actor !~ '[[:cntrl:]]' AND btrim(issued_by_actor) <> '')
);
CREATE INDEX revocation_grant ON entitlement.revocation (grant_id);
CREATE INDEX revocation_account ON entitlement.revocation (account_id, created_at);
CREATE TRIGGER revocation_append_only BEFORE UPDATE OR DELETE ON entitlement.revocation FOR EACH ROW EXECUTE FUNCTION entitlement.refuse_change();

-- Service terms (SV-01, TM-04): the intervals the resolver reads, immutable; renewal, supersession and revocation are new rows and
-- actions. kind: 1 subscription, 2 pass, 3 compensation, 4 self-host grant (entitlement.service_term_kind). The operator grant writes
-- one compensation term whose period_ref is its source reference, so a replay creates it once.
CREATE TABLE entitlement.service_term (
    term_id          uuid        NOT NULL,
    account_id       uuid        NOT NULL,
    kind             smallint    NOT NULL,
    subscription_ref text,
    period_ref       text        NOT NULL,
    starts_at        timestamptz NOT NULL,
    ends_at          timestamptz NOT NULL,
    grace_ends_at    timestamptz,
    authorized_at    timestamptz NOT NULL,
    created_at       timestamptz NOT NULL,
    CONSTRAINT service_term_pkey PRIMARY KEY (term_id),
    CONSTRAINT service_term_of_account UNIQUE (term_id, account_id),
    CONSTRAINT service_term_account FOREIGN KEY (account_id) REFERENCES identity.user (user_id),
    CONSTRAINT service_term_kind CHECK (kind IN (1, 2, 3, 4)),
    CONSTRAINT service_term_subscription_ref CHECK ((kind = 1 AND subscription_ref IS NOT NULL) OR (kind <> 1 AND subscription_ref IS NULL)),
    CONSTRAINT service_term_subscription_ref_shape CHECK (subscription_ref IS NULL OR subscription_ref ~ '^[A-Za-z0-9._:-]{1,128}$'),
    CONSTRAINT service_term_period_ref CHECK (period_ref ~ '^[A-Za-z0-9._:-]{1,128}$'),
    CONSTRAINT service_term_ends_after_starts CHECK (ends_at > starts_at),
    CONSTRAINT service_term_grace CHECK (grace_ends_at IS NULL OR grace_ends_at >= ends_at)
);
CREATE UNIQUE INDEX service_term_period ON entitlement.service_term (account_id, kind, period_ref);
CREATE TRIGGER service_term_append_only BEFORE UPDATE OR DELETE ON entitlement.service_term FOR EACH ROW EXECUTE FUNCTION entitlement.refuse_change();

-- Term actions (TM-04): an append-only supersede or revoke of a term. kind: 1 supersede, 2 revoke. Read only at runtime.
CREATE TABLE entitlement.service_term_action (
    action_id           uuid        NOT NULL,
    account_id          uuid        NOT NULL,
    term_id             uuid        NOT NULL,
    kind                smallint    NOT NULL,
    effective_at        timestamptz NOT NULL,
    recorded_at         timestamptz NOT NULL,
    source_ref          text        NOT NULL,
    replacement_term_id uuid,
    CONSTRAINT service_term_action_pkey PRIMARY KEY (action_id),
    CONSTRAINT service_term_action_term FOREIGN KEY (term_id, account_id) REFERENCES entitlement.service_term (term_id, account_id),
    CONSTRAINT service_term_action_replacement FOREIGN KEY (replacement_term_id, account_id) REFERENCES entitlement.service_term (term_id, account_id),
    CONSTRAINT service_term_action_account FOREIGN KEY (account_id) REFERENCES identity.user (user_id),
    CONSTRAINT service_term_action_kind CHECK (kind IN (1, 2)),
    CONSTRAINT service_term_action_replacement_matches_kind CHECK ((kind = 1 AND replacement_term_id IS NOT NULL) OR (kind = 2 AND replacement_term_id IS NULL)),
    CONSTRAINT service_term_action_source_ref CHECK (source_ref ~ '^[A-Za-z0-9._:-]{1,128}$')
);
CREATE UNIQUE INDEX service_term_action_source_ref ON entitlement.service_term_action (source_ref);
CREATE INDEX service_term_action_term ON entitlement.service_term_action (term_id, account_id);
CREATE INDEX service_term_action_replacement ON entitlement.service_term_action (replacement_term_id, account_id) WHERE replacement_term_id IS NOT NULL;
CREATE INDEX service_term_action_account ON entitlement.service_term_action (account_id, recorded_at);
CREATE TRIGGER service_term_action_append_only BEFORE UPDATE OR DELETE ON entitlement.service_term_action FOR EACH ROW EXECUTE FUNCTION entitlement.refuse_change();

-- Account status facts (SU-03): append-only; auto_renew and purchase_pending are two independent facts. status: 1 normal,
-- 2 restricted, 3 suspended (entitlement.account_status). The newest fact recorded at or before the evaluated instant applies.
-- Read only at runtime.
CREATE TABLE entitlement.account_status_fact (
    status_fact_id   uuid        NOT NULL,
    account_id       uuid        NOT NULL,
    recorded_at      timestamptz NOT NULL,
    status           smallint    NOT NULL,
    auto_renew       boolean     NOT NULL,
    purchase_pending boolean     NOT NULL,
    source_ref       text        NOT NULL,
    CONSTRAINT account_status_fact_pkey PRIMARY KEY (status_fact_id),
    CONSTRAINT account_status_fact_account FOREIGN KEY (account_id) REFERENCES identity.user (user_id),
    CONSTRAINT account_status_fact_status CHECK (status IN (1, 2, 3)),
    CONSTRAINT account_status_fact_source_ref CHECK (char_length(source_ref) BETWEEN 1 AND 128 AND source_ref ~ '^[A-Za-z0-9._:-]+$')
);
CREATE UNIQUE INDEX account_status_fact_source_ref ON entitlement.account_status_fact (source_ref);
CREATE INDEX account_status_fact_account ON entitlement.account_status_fact (account_id, recorded_at);
CREATE TRIGGER account_status_fact_append_only BEFORE UPDATE OR DELETE ON entitlement.account_status_fact FOR EACH ROW EXECUTE FUNCTION entitlement.refuse_change();

-- Feature releases: global, not per account. A feature is released once from released_at, and a feature with no row is not released.
-- Read only at runtime; a snapshot learns of a release at its next refresh (knowledge time).
CREATE TABLE entitlement.feature_release (
    feature_key text        NOT NULL,
    released_at timestamptz NOT NULL,
    CONSTRAINT feature_release_pkey PRIMARY KEY (feature_key),
    CONSTRAINT feature_release_key CHECK (feature_key ~ '^[a-z0-9._:-]{1,128}$')
);
CREATE TRIGGER feature_release_append_only BEFORE UPDATE OR DELETE ON entitlement.feature_release FOR EACH ROW EXECUTE FUNCTION entitlement.refuse_change();

-- Definitions activations (BN-02, DC-12): the append-only history of the definitions versions applied to an account. The first does
-- not raise the entitlement version; each later one does, once. Written in the same commit as the snapshot it changes.
CREATE TABLE entitlement.definitions_activation (
    account_id          uuid        NOT NULL,
    activated_at        timestamptz NOT NULL,
    definitions_version text        NOT NULL,
    CONSTRAINT definitions_activation_pkey PRIMARY KEY (account_id, activated_at),
    CONSTRAINT definitions_activation_account FOREIGN KEY (account_id) REFERENCES identity.user (user_id),
    CONSTRAINT definitions_activation_version CHECK (definitions_version ~ '^[A-Za-z0-9._:-]{1,128}$')
);
CREATE TRIGGER definitions_activation_append_only BEFORE UPDATE OR DELETE ON entitlement.definitions_activation FOR EACH ROW EXECUTE FUNCTION entitlement.refuse_change();
