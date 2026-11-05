-- 0007 The deploy-level fact of the current definitions version (AF-CTR-05 part E0, store-1; Cloud docs/center-entitlement.md).
--
-- Applied by `arcforges-center migrate` in one transaction with the migration role; the runner reconciles the runtime role's grants
-- from center/internal/schema/schema.go after every run (entitlement.definitions_current: SELECT, INSERT, UPDATE; never DELETE).
--
-- The activation of definitions is per account and keyed by the version of the replica that reads. Two revisions with different
-- definitions versions running side by side (a rolling deploy) would each recompute and append an activation at every read of an
-- account whose last activation is the other's, so the snapshot version would climb by one per read and the 2000-record bound would
-- wedge the account. This table holds one row: the definitions version of the revision that started last, written once by that
-- revision at its start (entitlement.Service.RecordDefinitions). A replica whose version differs from the row neither recomputes an
-- account against its own version nor writes one: it reads a valid snapshot as stored, and answers RESOURCE/overloaded where a
-- recompute is needed (access.gate_failure, definitions_superseded). The number of activations an account gains is so bounded by the
-- starts that change the version, never by its reads.
--
-- The row is written only where it changes: a start with the version already recorded writes nothing, and the trigger refuses an
-- update that keeps the version (the one write per version) or a deletion. Personal data: none (a version text and an instant).
-- Retention: one row, kept.

CREATE TABLE entitlement.definitions_current (
    singleton           boolean     NOT NULL DEFAULT true,
    definitions_version text        NOT NULL,
    recorded_at         timestamptz NOT NULL,
    CONSTRAINT definitions_current_pkey PRIMARY KEY (singleton),
    CONSTRAINT definitions_current_singleton CHECK (singleton),
    CONSTRAINT definitions_current_version CHECK (definitions_version ~ '^[A-Za-z0-9._:-]{1,128}$')
);

CREATE FUNCTION entitlement.definitions_current_once() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'entitlement.definitions_current is never deleted' USING ERRCODE = '55000';
    END IF;
    IF NEW.definitions_version = OLD.definitions_version OR NEW.singleton IS DISTINCT FROM OLD.singleton THEN
        RAISE EXCEPTION 'entitlement.definitions_current is written once per definitions version' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER definitions_current_once BEFORE UPDATE OR DELETE ON entitlement.definitions_current FOR EACH ROW
    EXECUTE FUNCTION entitlement.definitions_current_once();
