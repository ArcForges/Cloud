-- 0008 The node channel's presence and the hub lease (AF-CTR-05 part E1a; Plan CTR5-HUB-05, CTR5-HUB-06, PB-5 and Q22; Cloud
-- docs/center-fleet.md "Node channel").
--
-- Applied by `arcforges-center migrate` in one transaction with the migration role; the runner reconciles the runtime role's grants
-- from center/internal/schema/schema.go after every run (fleet.hub_lease: SELECT, INSERT, UPDATE; never DELETE). Expand only: three
-- nullable columns on fleet.node, which every statement of the previous release names explicitly, and one new table, so the running
-- and the previous release keep working.
--
-- Presence (CTR5-HUB-06). online_since is when the node's current or last channel was accepted (NULL: it never connected),
-- last_heartbeat_at the last heartbeat the hub recorded for it (at accept, at most once a minute from heartbeats, and at close), and
-- connection_id the connection the hub holds for it (NULL while it holds none). The hub of this database is the only writer, and every
-- write is fenced by its lease. A node is ONLINE while its channel is open in the process that holds the lease; the columns are what
-- the hub last wrote, never a proof that a connection is live (a killed process leaves connection_id set until the next hub's start
-- clears the rows of connections it does not hold).
--
-- The hub lease (PB-5, Q22): one row naming the center process that may run the node channel hub on this database, a fencing token
-- that rises with every change of holder, and an expiry. A process takes the lease when there is none, when it has expired or when it
-- was released; it renews it every 10 seconds for 30 seconds; it releases it at a graceful stop; and every hub write names the fence
-- it holds, so a process that lost the lease (a paused or partitioned replica) can no longer write. It never depends on a session
-- advisory lock, which does not survive the transaction-mode pooler the runtime role connects through.
--
-- Personal data: none beyond the instants of a node's connections (the node row is personal data already, 0004). Retention: the
-- presence columns live with their node row; the lease is one row, kept.

ALTER TABLE fleet.node
    ADD COLUMN online_since      timestamptz,
    ADD COLUMN last_heartbeat_at timestamptz,
    ADD COLUMN connection_id     uuid,
    ADD CONSTRAINT node_heartbeat CHECK (last_heartbeat_at IS NULL OR online_since IS NOT NULL AND last_heartbeat_at >= online_since),
    ADD CONSTRAINT node_connection CHECK (connection_id IS NULL OR online_since IS NOT NULL);

CREATE TABLE fleet.hub_lease (
    singleton   boolean     NOT NULL DEFAULT true,
    holder      uuid        NOT NULL,
    fence       bigint      NOT NULL,
    acquired_at timestamptz NOT NULL,
    renewed_at  timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    CONSTRAINT hub_lease_pkey PRIMARY KEY (singleton),
    CONSTRAINT hub_lease_singleton CHECK (singleton),
    CONSTRAINT hub_lease_fence CHECK (fence >= 1),
    CONSTRAINT hub_lease_instants CHECK (renewed_at >= acquired_at AND expires_at >= acquired_at)
);

-- The fence only rises, and it rises with every change of holder; the row is never deleted.
CREATE FUNCTION fleet.hub_lease_fenced() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'fleet.hub_lease is never deleted' USING ERRCODE = '55000';
    END IF;
    IF NEW.singleton IS DISTINCT FROM OLD.singleton OR NEW.fence < OLD.fence OR
       NEW.holder IS DISTINCT FROM OLD.holder AND NEW.fence <= OLD.fence THEN
        RAISE EXCEPTION 'fleet.hub_lease changes holder only with a higher fence' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER hub_lease_fenced BEFORE UPDATE OR DELETE ON fleet.hub_lease FOR EACH ROW EXECUTE FUNCTION fleet.hub_lease_fenced();
