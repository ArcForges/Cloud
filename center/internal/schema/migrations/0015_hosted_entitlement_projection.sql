-- AFV2-HOST-01 carries existing canonical subscription facts into the
-- hosted-v2 definition. The projection is migration-owned audit evidence.
-- The resolver still uses the original grants, terms, and their revocations.
-- Opaque source and period references do not imply grant-to-term lineage.

CREATE TABLE entitlement.hosted_projection_migration (
    migration_version  integer     NOT NULL,
    definition_version text        NOT NULL,
    account_id         uuid        NOT NULL,
    source_kind        text        NOT NULL,
    source_id          uuid        NOT NULL,
    source_grant_id    uuid        GENERATED ALWAYS AS (CASE WHEN source_kind = 'grant' THEN source_id END) STORED,
    source_term_id     uuid        GENERATED ALWAYS AS (CASE WHEN source_kind = 'term' THEN source_id END) STORED,
    capability_key     text,
    source_from        timestamptz NOT NULL,
    source_until       timestamptz,
    source_grace_until timestamptz,
    valid_from         timestamptz NOT NULL,
    valid_until        timestamptz,
    recorded_at        timestamptz NOT NULL,
    CONSTRAINT hosted_projection_migration_pkey PRIMARY KEY (migration_version, source_kind, source_id),
    CONSTRAINT hosted_projection_grant FOREIGN KEY (source_grant_id, account_id)
        REFERENCES entitlement.grant (grant_id, account_id),
    CONSTRAINT hosted_projection_term FOREIGN KEY (source_term_id, account_id)
        REFERENCES entitlement.service_term (term_id, account_id),
    CONSTRAINT hosted_projection_definition CHECK (migration_version >= 15 AND definition_version ~ '^[a-z0-9._:-]{1,128}$'),
    CONSTRAINT hosted_projection_source CHECK (
        (source_kind = 'grant' AND capability_key IS NOT NULL
            AND capability_key IN ('center.nodes', 'remote.view', 'remote.control') AND source_grace_until IS NULL)
        OR (source_kind = 'term' AND capability_key IS NULL AND source_until IS NOT NULL
            AND (source_grace_until IS NULL OR source_grace_until >= source_until))
    ),
    CONSTRAINT hosted_projection_validity CHECK (
        valid_from >= source_from AND valid_from <= recorded_at
        AND (valid_until IS NULL OR valid_until > recorded_at)
        AND (source_until IS NULL OR (valid_until IS NOT NULL AND valid_until <= source_until))
    )
);

CREATE TRIGGER hosted_projection_append_only BEFORE UPDATE OR DELETE ON entitlement.hosted_projection_migration
    FOR EACH ROW EXECUTE FUNCTION entitlement.refuse_change();

-- Capture a single statement's view of the known records. A known shortening
-- action limits that interval immediately, even if its effect is still future.
-- Grace remains visible as an original fact without extending paid eligibility.
WITH projection_time AS (
    SELECT statement_timestamp() AS observed_at
), qualified AS (
    SELECT g.account_id, 'grant' AS source_kind, g.grant_id AS source_id, g.subject AS capability_key,
           g.effective_from AS source_from, g.effective_until AS source_until, NULL::timestamptz AS source_grace_until,
           greatest(g.effective_from, g.created_at) AS valid_from,
           least(g.effective_until, (
               SELECT min(r.effective_from) FROM entitlement.revocation r
               WHERE r.grant_id = g.grant_id AND r.account_id = g.account_id AND r.created_at <= p.observed_at
           )) AS valid_until,
           p.observed_at
    FROM entitlement.grant g CROSS JOIN projection_time p
    WHERE g.kind = 1 AND g.source = 1 AND g.subject IN ('center.nodes', 'remote.view', 'remote.control')
    UNION ALL
    SELECT t.account_id, 'term', t.term_id, NULL,
           t.starts_at, t.ends_at, t.grace_ends_at,
           greatest(t.starts_at, t.authorized_at, t.created_at),
           least(t.ends_at, (
               SELECT min(a.effective_at) FROM entitlement.service_term_action a
               WHERE a.term_id = t.term_id AND a.account_id = t.account_id AND a.recorded_at <= p.observed_at
           )),
           p.observed_at
    FROM entitlement.service_term t CROSS JOIN projection_time p
    WHERE t.kind = 1
)
INSERT INTO entitlement.hosted_projection_migration (
    migration_version, definition_version, account_id, source_kind, source_id, capability_key,
    source_from, source_until, source_grace_until, valid_from, valid_until, recorded_at
)
SELECT 15, 'hosted-v2', account_id, source_kind, source_id, capability_key,
       source_from, source_until, source_grace_until, valid_from, valid_until, observed_at
FROM qualified
WHERE valid_from <= observed_at AND (valid_until IS NULL OR observed_at < valid_until);
