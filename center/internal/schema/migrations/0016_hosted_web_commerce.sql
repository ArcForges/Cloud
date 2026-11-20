-- AFV2-HOST-02. The web provider is Paddle (1), with production (1) and
-- sandbox (2) as distinct identity realms. No provider endpoint, price, raw
-- webhook, redirect URL or payment credential is stored by this migration.

CREATE SCHEMA commerce;

-- An empty store has no commerce realm. An admitted configured service
-- writes one value before opening the commerce transaction surface.
CREATE TABLE commerce.provider_environment (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    environment smallint NOT NULL UNIQUE CHECK (environment IN (1, 2))
);

CREATE TABLE commerce.customer (
    account_id uuid NOT NULL REFERENCES identity.user (user_id),
    provider smallint NOT NULL CHECK (provider = 1),
    environment smallint NOT NULL REFERENCES commerce.provider_environment (environment),
    provider_customer_ref text NOT NULL CHECK (provider_customer_ref ~ '^[A-Za-z0-9._:-]{1,128}$'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (account_id, provider, environment),
    UNIQUE (provider, environment, provider_customer_ref),
    UNIQUE (account_id, provider, environment, provider_customer_ref)
);
CREATE INDEX customer_environment ON commerce.customer (environment);

-- Purchase: 1 pending, 2 unknown, 3 completed, 4 expired.
CREATE TABLE commerce.purchase (
    purchase_id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES identity.user (user_id),
    command_id uuid NOT NULL,
    provider smallint NOT NULL CHECK (provider = 1),
    environment smallint NOT NULL REFERENCES commerce.provider_environment (environment),
    catalog_version text NOT NULL CHECK (catalog_version ~ '^[A-Za-z0-9._:-]{1,128}$'),
    offer_ref text NOT NULL CHECK (offer_ref ~ '^[A-Za-z0-9._:-]{1,128}$'),
    product_ref text NOT NULL CHECK (product_ref ~ '^[A-Za-z0-9._:-]{1,128}$'),
    price_ref text NOT NULL CHECK (price_ref ~ '^[A-Za-z0-9._:-]{1,128}$'),
    price_version text NOT NULL CHECK (price_version ~ '^[A-Za-z0-9._:-]{1,128}$'),
    intent_sha256 bytea NOT NULL CHECK (octet_length(intent_sha256) = 32),
    state smallint NOT NULL CHECK (state BETWEEN 1 AND 4),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    rev bigint NOT NULL CHECK (rev >= 1),
    UNIQUE (account_id, command_id),
    UNIQUE (purchase_id, account_id, provider, environment),
    CHECK (expires_at > created_at AND updated_at >= created_at)
);
CREATE INDEX purchase_environment ON commerce.purchase (environment);
CREATE UNIQUE INDEX purchase_unresolved_account
    ON commerce.purchase (account_id, provider, environment) WHERE state IN (1, 2);

-- Checkout: 1 pending, 2 provider-created, 3 completed, 4 expired, 5 unknown.
-- The server binding and an irreversible pre-I/O claim are separate from the
-- caller's attempt identity. Expiry does not retire a possibly sent claim.
CREATE TABLE commerce.checkout (
    checkout_id uuid PRIMARY KEY,
    purchase_id uuid NOT NULL,
    account_id uuid NOT NULL,
    command_id uuid NOT NULL,
    provider smallint NOT NULL CHECK (provider = 1),
    environment smallint NOT NULL CHECK (environment IN (1, 2)),
    intent_sha256 bytea NOT NULL CHECK (octet_length(intent_sha256) = 32),
    return_path text NOT NULL CHECK (
        char_length(return_path) BETWEEN 1 AND 512 AND left(return_path, 1) = '/'
        AND left(return_path, 2) <> '//' AND return_path !~ '[[:cntrl:]]' AND strpos(return_path, chr(92)) = 0
    ),
    provider_intent_id uuid NOT NULL CHECK (provider_intent_id <> '00000000-0000-0000-0000-000000000000'),
    provider_checkout_ref text CHECK (provider_checkout_ref ~ '^[A-Za-z0-9._:-]{1,128}$'),
    provider_customer_ref text CHECK (provider_customer_ref ~ '^[A-Za-z0-9._:-]{1,128}$'),
    state smallint NOT NULL CHECK (state BETWEEN 1 AND 5),
    send_claimed_at timestamptz,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (account_id, command_id),
    UNIQUE (checkout_id, account_id, provider, environment),
    UNIQUE (provider, environment, provider_checkout_ref),
    UNIQUE (provider, environment, provider_intent_id),
    FOREIGN KEY (purchase_id, account_id, provider, environment)
        REFERENCES commerce.purchase (purchase_id, account_id, provider, environment),
    FOREIGN KEY (account_id, provider, environment, provider_customer_ref)
        REFERENCES commerce.customer (account_id, provider, environment, provider_customer_ref),
    CHECK (expires_at > created_at AND updated_at >= created_at),
    CHECK (send_claimed_at IS NULL OR (send_claimed_at >= created_at AND send_claimed_at <= updated_at)),
    CHECK (send_claimed_at IS NOT NULL OR (state IN (1, 4) AND provider_checkout_ref IS NULL AND provider_customer_ref IS NULL)),
    CHECK (state NOT IN (2, 3) OR provider_checkout_ref IS NOT NULL)
);
CREATE INDEX checkout_purchase ON commerce.checkout (purchase_id, account_id, provider, environment);
CREATE UNIQUE INDEX checkout_unexpired_purchase
    ON commerce.checkout (purchase_id) WHERE state <> 4 OR send_claimed_at IS NOT NULL;

-- Subscription states retain the Design's values: pending, active, cancel at
-- term end, payment grace, expired, revoked, and provider unknown.
CREATE TABLE commerce.subscription (
    subscription_id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    provider smallint NOT NULL CHECK (provider = 1),
    environment smallint NOT NULL CHECK (environment IN (1, 2)),
    provider_customer_ref text NOT NULL CHECK (provider_customer_ref ~ '^[A-Za-z0-9._:-]{1,128}$'),
    provider_subscription_ref text NOT NULL CHECK (provider_subscription_ref ~ '^[A-Za-z0-9._:-]{1,128}$'),
    checkout_id uuid,
    catalog_version text NOT NULL CHECK (catalog_version ~ '^[A-Za-z0-9._:-]{1,128}$'),
    product_ref text NOT NULL CHECK (product_ref ~ '^[A-Za-z0-9._:-]{1,128}$'),
    price_ref text NOT NULL CHECK (price_ref ~ '^[A-Za-z0-9._:-]{1,128}$'),
    state smallint NOT NULL CHECK (state BETWEEN 1 AND 7),
    valid_from timestamptz,
    valid_until timestamptz,
    auto_renew boolean NOT NULL,
    provider_revision text CHECK (provider_revision ~ '^[A-Za-z0-9._:-]{1,128}$'),
    provider_updated_at timestamptz NOT NULL,
    provider_snapshot_sha256 bytea NOT NULL CHECK (octet_length(provider_snapshot_sha256) = 32),
    verified_at timestamptz NOT NULL,
    rev bigint NOT NULL CHECK (rev >= 1),
    UNIQUE (provider, environment, provider_subscription_ref),
    UNIQUE (subscription_id, account_id, provider, environment),
    FOREIGN KEY (account_id, provider, environment, provider_customer_ref)
        REFERENCES commerce.customer (account_id, provider, environment, provider_customer_ref),
    FOREIGN KEY (checkout_id, account_id, provider, environment)
        REFERENCES commerce.checkout (checkout_id, account_id, provider, environment),
    CHECK ((valid_from IS NULL) = (valid_until IS NULL)),
    CHECK (state NOT IN (2, 3, 4) OR valid_from IS NOT NULL),
    CHECK (valid_until IS NULL OR valid_until > valid_from)
);
CREATE INDEX subscription_account ON commerce.subscription (account_id, state);
CREATE INDEX subscription_checkout ON commerce.subscription (checkout_id, account_id, provider, environment);

-- Renewal: 1 pending, 2 applied, 3 unknown, 4 rejected.
CREATE TABLE commerce.renewal (
    renewal_id uuid PRIMARY KEY,
    subscription_id uuid NOT NULL,
    account_id uuid NOT NULL,
    command_id uuid NOT NULL,
    provider smallint NOT NULL CHECK (provider = 1),
    environment smallint NOT NULL CHECK (environment IN (1, 2)),
    intent_sha256 bytea NOT NULL CHECK (octet_length(intent_sha256) = 32),
    auto_renew boolean NOT NULL,
    state smallint NOT NULL CHECK (state BETWEEN 1 AND 4),
    send_claimed_at timestamptz,
    result_subscription_rev bigint CHECK (result_subscription_rev >= 1),
    result_valid_from timestamptz,
    result_valid_until timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (account_id, command_id),
    FOREIGN KEY (subscription_id, account_id, provider, environment)
        REFERENCES commerce.subscription (subscription_id, account_id, provider, environment),
    CHECK (updated_at >= created_at),
    CHECK (send_claimed_at IS NULL OR (send_claimed_at >= created_at AND send_claimed_at <= updated_at)),
    CHECK (state <> 3 OR send_claimed_at IS NOT NULL),
    CHECK (
        (state = 2 AND result_subscription_rev IS NOT NULL AND result_valid_from IS NOT NULL
            AND result_valid_until IS NOT NULL AND result_valid_until > result_valid_from)
        OR (state <> 2 AND result_subscription_rev IS NULL AND result_valid_from IS NULL AND result_valid_until IS NULL)
    )
);
CREATE INDEX renewal_subscription ON commerce.renewal (subscription_id, account_id, provider, environment);
CREATE UNIQUE INDEX renewal_unresolved_subscription ON commerce.renewal (subscription_id) WHERE state IN (1, 3);

-- The immutable raw-byte and semantic digests describe the verified event.
-- State 3 with a NULL next check is retained for manual reconciliation.
CREATE TABLE commerce.provider_event (
    provider smallint NOT NULL CHECK (provider = 1),
    environment smallint NOT NULL REFERENCES commerce.provider_environment (environment),
    event_ref text NOT NULL CHECK (event_ref ~ '^[A-Za-z0-9._:-]{1,128}$'),
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
    semantic_sha256 bytea NOT NULL CHECK (octet_length(semantic_sha256) = 32),
    event_kind text NOT NULL CHECK (event_kind ~ '^[a-z][a-z0-9._-]{0,95}$'),
    resource_ref text NOT NULL CHECK (resource_ref ~ '^[A-Za-z0-9._:-]{1,128}$'),
    account_id uuid REFERENCES identity.user (user_id),
    occurred_at timestamptz NOT NULL,
    state smallint NOT NULL CHECK (state BETWEEN 1 AND 5),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    verified_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    processed_at timestamptz,
    next_check_at timestamptz,
    failure_code text CHECK (failure_code ~ '^[a-z][a-z0-9._-]{0,95}$'),
    PRIMARY KEY (provider, environment, event_ref),
    CHECK (processed_at IS NULL OR processed_at >= received_at),
    CHECK ((state IN (2, 4, 5)) = (processed_at IS NOT NULL)),
    CHECK (next_check_at IS NULL OR (state IN (1, 3) AND next_check_at >= received_at))
);
CREATE INDEX provider_event_work ON commerce.provider_event (state, next_check_at)
    WHERE state IN (1, 3) AND next_check_at IS NOT NULL;
CREATE INDEX provider_event_account ON commerce.provider_event (account_id, state);
CREATE INDEX provider_event_environment ON commerce.provider_event (environment);
CREATE INDEX provider_event_resource ON commerce.provider_event (provider, environment, resource_ref, state);

-- The exact immutable term and grants for one verified paid period. An
-- adjustment can affect only these original identities for the same account.
CREATE TABLE commerce.settled_period (
    period_id uuid PRIMARY KEY,
    subscription_id uuid NOT NULL,
    account_id uuid NOT NULL,
    provider smallint NOT NULL CHECK (provider = 1),
    environment smallint NOT NULL CHECK (environment IN (1, 2)),
    provider_transaction_ref text NOT NULL CHECK (provider_transaction_ref ~ '^[A-Za-z0-9._:-]{1,128}$'),
    provider_period_ref text NOT NULL CHECK (provider_period_ref ~ '^[A-Za-z0-9._:-]{1,128}$'),
    term_id uuid NOT NULL,
    nodes_grant_id uuid NOT NULL,
    view_grant_id uuid NOT NULL,
    control_grant_id uuid NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    settled_at timestamptz NOT NULL,
    event_ref text,
    UNIQUE (provider, environment, provider_transaction_ref),
    UNIQUE (subscription_id, provider_period_ref),
    UNIQUE (term_id, account_id),
    FOREIGN KEY (subscription_id, account_id, provider, environment)
        REFERENCES commerce.subscription (subscription_id, account_id, provider, environment),
    FOREIGN KEY (term_id, account_id) REFERENCES entitlement.service_term (term_id, account_id),
    FOREIGN KEY (nodes_grant_id, account_id) REFERENCES entitlement.grant (grant_id, account_id),
    FOREIGN KEY (view_grant_id, account_id) REFERENCES entitlement.grant (grant_id, account_id),
    FOREIGN KEY (control_grant_id, account_id) REFERENCES entitlement.grant (grant_id, account_id),
    FOREIGN KEY (provider, environment, event_ref) REFERENCES commerce.provider_event (provider, environment, event_ref),
    CHECK (valid_until > valid_from),
    CHECK (nodes_grant_id <> view_grant_id AND nodes_grant_id <> control_grant_id AND view_grant_id <> control_grant_id)
);
CREATE INDEX settled_period_nodes_grant ON commerce.settled_period (nodes_grant_id, account_id);
CREATE INDEX settled_period_view_grant ON commerce.settled_period (view_grant_id, account_id);
CREATE INDEX settled_period_control_grant ON commerce.settled_period (control_grant_id, account_id);
CREATE INDEX settled_period_event ON commerce.settled_period (provider, environment, event_ref);

-- Billing kinds: 1 payment, 2 refund, 3 chargeback. Kind carries the
-- direction, and amount_minor is the verified nonnegative magnitude.
CREATE TABLE commerce.billing_entry (
    entry_id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES identity.user (user_id),
    subscription_id uuid,
    provider smallint NOT NULL CHECK (provider = 1),
    environment smallint NOT NULL REFERENCES commerce.provider_environment (environment),
    provider_entry_ref text NOT NULL CHECK (provider_entry_ref ~ '^[A-Za-z0-9._:-]{1,128}$'),
    kind smallint NOT NULL CHECK (kind IN (1, 2, 3)),
    currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    amount_minor numeric(20, 0) NOT NULL CHECK (amount_minor >= 0),
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL,
    event_ref text,
    UNIQUE (provider, environment, provider_entry_ref, kind),
    FOREIGN KEY (subscription_id, account_id, provider, environment)
        REFERENCES commerce.subscription (subscription_id, account_id, provider, environment),
    FOREIGN KEY (provider, environment, event_ref) REFERENCES commerce.provider_event (provider, environment, event_ref)
);
CREATE INDEX billing_entry_account ON commerce.billing_entry (account_id, occurred_at);
CREATE INDEX billing_entry_environment ON commerce.billing_entry (environment);
CREATE INDEX billing_entry_subscription ON commerce.billing_entry (subscription_id, account_id, provider, environment);
CREATE INDEX billing_entry_event ON commerce.billing_entry (provider, environment, event_ref);

CREATE FUNCTION commerce.refuse_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'commerce facts are append-only' USING ERRCODE = 'check_violation';
END;
$$;
CREATE TRIGGER provider_environment_append_only BEFORE UPDATE OR DELETE ON commerce.provider_environment
    FOR EACH ROW EXECUTE FUNCTION commerce.refuse_change();
CREATE TRIGGER customer_append_only BEFORE UPDATE OR DELETE ON commerce.customer
    FOR EACH ROW EXECUTE FUNCTION commerce.refuse_change();
CREATE TRIGGER settled_period_append_only BEFORE UPDATE OR DELETE ON commerce.settled_period
    FOR EACH ROW EXECUTE FUNCTION commerce.refuse_change();
CREATE TRIGGER billing_entry_append_only BEFORE UPDATE OR DELETE ON commerce.billing_entry
    FOR EACH ROW EXECUTE FUNCTION commerce.refuse_change();

CREATE FUNCTION commerce.guard_purchase() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'purchase intent is retained' USING ERRCODE = 'check_violation';
    END IF;
    IF ROW(NEW.purchase_id, NEW.account_id, NEW.command_id, NEW.provider, NEW.environment,
           NEW.catalog_version, NEW.offer_ref, NEW.product_ref, NEW.price_ref, NEW.price_version,
           NEW.intent_sha256, NEW.created_at, NEW.expires_at)
       IS DISTINCT FROM
       ROW(OLD.purchase_id, OLD.account_id, OLD.command_id, OLD.provider, OLD.environment,
           OLD.catalog_version, OLD.offer_ref, OLD.product_ref, OLD.price_ref, OLD.price_version,
           OLD.intent_sha256, OLD.created_at, OLD.expires_at)
       OR NEW.rev <> OLD.rev + 1 OR NEW.updated_at < OLD.updated_at OR OLD.state IN (3, 4)
       OR (OLD.state = 2 AND NEW.state = 1) THEN
        RAISE EXCEPTION 'purchase identity, revision or outcome cannot change' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER purchase_guard BEFORE UPDATE OR DELETE ON commerce.purchase
    FOR EACH ROW EXECUTE FUNCTION commerce.guard_purchase();

CREATE FUNCTION commerce.guard_checkout() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'checkout attempt is retained' USING ERRCODE = 'check_violation';
    END IF;
    IF ROW(NEW.checkout_id, NEW.purchase_id, NEW.account_id, NEW.command_id, NEW.provider, NEW.environment,
           NEW.intent_sha256, NEW.return_path, NEW.provider_intent_id, NEW.created_at, NEW.expires_at)
       IS DISTINCT FROM
       ROW(OLD.checkout_id, OLD.purchase_id, OLD.account_id, OLD.command_id, OLD.provider, OLD.environment,
           OLD.intent_sha256, OLD.return_path, OLD.provider_intent_id, OLD.created_at, OLD.expires_at)
       OR NEW.updated_at < OLD.updated_at OR OLD.state IN (3, 4)
       OR (OLD.send_claimed_at IS NOT NULL AND NEW.send_claimed_at IS DISTINCT FROM OLD.send_claimed_at)
       OR (OLD.send_claimed_at IS NULL AND NEW.send_claimed_at IS NOT NULL
           AND (OLD.state <> 1 OR NEW.state NOT IN (1, 5) OR NEW.provider_checkout_ref IS NOT NULL OR NEW.provider_customer_ref IS NOT NULL))
       OR (OLD.provider_checkout_ref IS NOT NULL AND NEW.provider_checkout_ref IS DISTINCT FROM OLD.provider_checkout_ref)
       OR (OLD.provider_customer_ref IS NOT NULL AND NEW.provider_customer_ref IS DISTINCT FROM OLD.provider_customer_ref)
       OR (OLD.state IN (2, 5) AND NEW.state = 1)
       OR (OLD.state = 5 AND NEW.state = 4 AND NEW.provider_checkout_ref IS NULL) THEN
        RAISE EXCEPTION 'checkout identity, send claim or outcome cannot change' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER checkout_guard BEFORE UPDATE OR DELETE ON commerce.checkout
    FOR EACH ROW EXECUTE FUNCTION commerce.guard_checkout();

CREATE FUNCTION commerce.guard_subscription() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'verified subscription identity is retained' USING ERRCODE = 'check_violation';
    END IF;
    IF ROW(NEW.subscription_id, NEW.account_id, NEW.provider, NEW.environment, NEW.provider_customer_ref,
           NEW.provider_subscription_ref, NEW.checkout_id, NEW.catalog_version, NEW.product_ref, NEW.price_ref)
       IS DISTINCT FROM
       ROW(OLD.subscription_id, OLD.account_id, OLD.provider, OLD.environment, OLD.provider_customer_ref,
           OLD.provider_subscription_ref, OLD.checkout_id, OLD.catalog_version, OLD.product_ref, OLD.price_ref)
       OR NEW.rev <> OLD.rev + 1 OR NEW.verified_at < OLD.verified_at OR NEW.provider_updated_at < OLD.provider_updated_at
       OR (NEW.provider_updated_at = OLD.provider_updated_at AND NEW.provider_snapshot_sha256 <> OLD.provider_snapshot_sha256) THEN
        RAISE EXCEPTION 'subscription binding or verified revision cannot change backward' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER subscription_guard BEFORE UPDATE OR DELETE ON commerce.subscription
    FOR EACH ROW EXECUTE FUNCTION commerce.guard_subscription();

CREATE FUNCTION commerce.guard_renewal() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'renewal command is retained' USING ERRCODE = 'check_violation';
    END IF;
    IF ROW(NEW.renewal_id, NEW.subscription_id, NEW.account_id, NEW.command_id, NEW.provider, NEW.environment,
           NEW.intent_sha256, NEW.auto_renew, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.renewal_id, OLD.subscription_id, OLD.account_id, OLD.command_id, OLD.provider, OLD.environment,
           OLD.intent_sha256, OLD.auto_renew, OLD.created_at)
       OR NEW.updated_at < OLD.updated_at OR OLD.state IN (2, 4)
       OR (OLD.send_claimed_at IS NOT NULL AND NEW.send_claimed_at IS DISTINCT FROM OLD.send_claimed_at)
       OR (OLD.send_claimed_at IS NULL AND NEW.send_claimed_at IS NOT NULL AND (OLD.state <> 1 OR NEW.state NOT IN (1, 3)))
       OR (OLD.state = 3 AND NEW.state = 1) THEN
        RAISE EXCEPTION 'renewal identity, send claim or outcome cannot change' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER renewal_guard BEFORE UPDATE OR DELETE ON commerce.renewal
    FOR EACH ROW EXECUTE FUNCTION commerce.guard_renewal();

CREATE FUNCTION commerce.guard_provider_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'verified provider event identity is retained' USING ERRCODE = 'check_violation';
    END IF;
    IF ROW(NEW.provider, NEW.environment, NEW.event_ref, NEW.payload_sha256, NEW.semantic_sha256,
           NEW.event_kind, NEW.resource_ref, NEW.occurred_at, NEW.verified_at, NEW.received_at)
       IS DISTINCT FROM
       ROW(OLD.provider, OLD.environment, OLD.event_ref, OLD.payload_sha256, OLD.semantic_sha256,
           OLD.event_kind, OLD.resource_ref, OLD.occurred_at, OLD.verified_at, OLD.received_at)
       OR (OLD.account_id IS NOT NULL AND NEW.account_id IS DISTINCT FROM OLD.account_id)
       OR OLD.state IN (2, 4, 5) OR (OLD.state = 3 AND NEW.state = 1)
       OR NEW.attempt_count - OLD.attempt_count NOT IN (0, 1) THEN
        RAISE EXCEPTION 'provider event identity or final outcome cannot change' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER provider_event_guard BEFORE UPDATE OR DELETE ON commerce.provider_event
    FOR EACH ROW EXECUTE FUNCTION commerce.guard_provider_event();

-- The caller holds the account lock for the lifetime of its lifecycle step.
-- The view carries the same narrow provider decision for prepare, confirm and
-- migration-role cleanup without granting runtime execution of a function.
CREATE VIEW commerce.provider_cleanup_pending WITH (security_invoker = true) AS
SELECT u.user_id AS account_id
FROM identity.user u
WHERE EXISTS (
    SELECT 1 FROM commerce.subscription s
    WHERE s.account_id = u.user_id AND (s.state NOT IN (5, 6) OR s.auto_renew)
) OR EXISTS (
    SELECT 1 FROM commerce.purchase p WHERE p.account_id = u.user_id AND p.state IN (1, 2)
) OR EXISTS (
    SELECT 1 FROM commerce.checkout c WHERE c.account_id = u.user_id AND c.state IN (1, 2, 5)
) OR EXISTS (
    SELECT 1 FROM commerce.renewal r WHERE r.account_id = u.user_id AND r.state IN (1, 3)
) OR EXISTS (
    SELECT 1 FROM commerce.provider_event e
    WHERE e.state IN (1, 3) AND (
        e.account_id = u.user_id
        OR (e.account_id IS NULL AND e.event_kind LIKE 'subscription.%' AND EXISTS (
            SELECT 1 FROM commerce.subscription s WHERE s.account_id = u.user_id
              AND (s.provider, s.environment, s.provider_subscription_ref) = (e.provider, e.environment, e.resource_ref)
        ))
        OR (e.account_id IS NULL AND e.event_kind LIKE 'transaction.%' AND EXISTS (
            SELECT 1 FROM commerce.checkout c WHERE c.account_id = u.user_id
              AND (c.provider, c.environment, c.provider_checkout_ref) = (e.provider, e.environment, e.resource_ref)
        ))
    )
) OR EXISTS (
    SELECT 1 FROM entitlement.service_term t
    WHERE t.account_id = u.user_id AND t.subscription_ref IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM commerce.settled_period p WHERE (p.term_id, p.account_id) = (t.term_id, t.account_id)
    )
) OR coalesce((
    SELECT f.auto_renew OR f.purchase_pending
    FROM entitlement.account_status_fact f WHERE f.account_id = u.user_id
    ORDER BY f.recorded_at DESC, f.status_fact_id DESC LIMIT 1
), false);

-- The previous generations' cleanup procedure keeps its original role,
-- account locks, retention rules and remote-effect decision.
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
