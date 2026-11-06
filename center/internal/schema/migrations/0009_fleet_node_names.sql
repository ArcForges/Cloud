-- 0009 The node registry's names (AF-CTR-05 part E2a; Plan CTR5-API-02, CTR5-API-03 and Q25; Contracts fleet.proto FleetNode name and
-- reported_name, relay.proto ChannelAccepted.node_name; Cloud docs/center-fleet.md "Node registry").
--
-- Applied by `arcforges-center migrate` in one transaction with the migration role; the runner reconciles the runtime role's grants
-- from center/internal/schema/schema.go after every run (fleet.node keeps SELECT, INSERT, UPDATE; never DELETE). Expand only: two new
-- columns on fleet.node, one nullable and one with a constant default, which every statement of the previous release names
-- explicitly or leaves to its default, so the running and the previous release keep working.
--
-- The account's name wins (Q25). display_name is the node's name in the registry: the name it reported until an account renames it
-- (FleetService.RenameNode sets named_by_account), the account's name from then on; the node adopts it at its next accepted channel
-- (ChannelAccepted.node_name). reported_name is the name the node last reported for itself (enrollment, ReportNodeInfo), kept whatever
-- the account calls it. A row of the previous release has no reported_name until its node reports again; until then its display_name
-- is the name it reported (the previous release never renamed a node), and FleetNode.reported_name states it.
--
-- Personal data: a device name the person or the node chose, as display_name already is (0004). Retention: with the node row.

ALTER TABLE fleet.node
    ADD COLUMN reported_name    text,
    ADD COLUMN named_by_account boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT node_reported_name CHECK (reported_name IS NULL OR char_length(reported_name) BETWEEN 1 AND 64 AND reported_name !~ '[[:cntrl:]]');
