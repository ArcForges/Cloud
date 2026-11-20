-- SPDX-License-Identifier: AGPL-3.0-only
-- AFV2-CENTER-03: preserve the original, content-free remote authorization
-- association through reconnection and receipt compaction.
ALTER TABLE management.command_identity
    ADD COLUMN actor_id uuid,
    ADD COLUMN grant_id uuid,
    ADD COLUMN grant_revision bigint,
    ADD CONSTRAINT command_identity_remote_authority CHECK (
       (actor_id IS NULL AND grant_id IS NULL AND grant_revision IS NULL)
       OR (namespace = 3 AND actor_id IS NOT NULL AND grant_id IS NOT NULL
           AND grant_revision IS NOT NULL AND grant_revision > 0)
    );

-- The old constraint was generated without a name. Locate the exact 0012
-- success predicate rather than assuming the database's generated suffix.
DO $$
DECLARE success_constraint name;
BEGIN
    SELECT conname INTO STRICT success_constraint
     FROM pg_constraint
     WHERE conrelid = 'management.remote_operation'::regclass AND contype = 'c'
       AND cardinality(conkey) = 4 AND conkey @> ARRAY(
           SELECT attnum FROM pg_attribute WHERE attrelid = conrelid
           AND attname IN ('state', 'result_sha256', 'effect', 'final_at')
       );
    EXECUTE format('ALTER TABLE management.remote_operation DROP CONSTRAINT %I', success_constraint);
END;
$$;

-- A verified Stop on an already stopped Run succeeds without a new effect.
ALTER TABLE management.remote_operation ADD CONSTRAINT remote_operation_definite_success CHECK (
    state <> 3 OR (result_sha256 IS NOT NULL AND effect IS NOT NULL
    AND (effect = 2 OR (method = 'RunService.Stop' AND effect = 1))
    AND final_at IS NOT NULL)
);

CREATE OR REPLACE FUNCTION management.operation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE i management.command_identity%ROWTYPE;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'routing observations are retained' USING ERRCODE='23000'; END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT i FROM management.command_identity WHERE account_id=NEW.account_id AND command_id=NEW.command_id;
  IF i.namespace<>3 OR i.method<>NEW.method OR i.node_owner_epoch<>NEW.node_owner_epoch OR i.intent_sha256<>NEW.request_sha256 THEN
   RAISE EXCEPTION 'routing identity mismatch' USING ERRCODE='23000'; END IF;
  PERFORM 1 FROM management.node_protocol p JOIN fleet.node n
   ON (n.enrollment_id,n.node_id,n.user_id)=(p.enrollment_id,p.node_id,p.account_id),fleet.hub_lease h
   WHERE p.enrollment_id=i.enrollment_id AND p.account_id=i.account_id AND p.node_id=i.node_id
   AND p.revoked_at IS NULL AND n.revoked_at IS NULL AND n.connection_id=NEW.channel_epoch
   AND h.singleton AND h.fence=NEW.hub_fence AND h.expires_at>clock_timestamp() FOR SHARE OF p,n,h;
  IF NOT FOUND THEN RAISE EXCEPTION 'current protocol and lease required' USING ERRCODE='55000'; END IF;
  IF NEW.state<>1 OR NEW.may_have_delivered OR NEW.delivery_count<>0 OR NEW.final_at IS NOT NULL THEN
   RAISE EXCEPTION 'routing starts at accepted' USING ERRCODE='23000'; END IF;
 ELSE
  IF (NEW.account_id,NEW.command_id,NEW.node_owner_epoch,NEW.method,NEW.request_sha256,NEW.created_at)
   IS DISTINCT FROM (OLD.account_id,OLD.command_id,OLD.node_owner_epoch,OLD.method,OLD.request_sha256,OLD.created_at)
   OR NEW.delivery_count<OLD.delivery_count OR (OLD.may_have_delivered AND NOT NEW.may_have_delivered)
   OR NEW.updated_at<OLD.updated_at OR NEW.hub_fence<OLD.hub_fence THEN
   RAISE EXCEPTION 'routing identity and delivery are monotonic' USING ERRCODE='23000'; END IF;
  IF OLD.final_at IS NOT NULL AND (NEW.state,NEW.result_sha256,NEW.result_kind,NEW.result_id,NEW.effect,NEW.reason,NEW.final_at)
   IS DISTINCT FROM (OLD.state,OLD.result_sha256,OLD.result_kind,OLD.result_id,OLD.effect,OLD.reason,OLD.final_at) THEN
   RAISE EXCEPTION 'a final outcome cannot change' USING ERRCODE='23000'; END IF;
 END IF;
 IF NEW.final_at IS NOT NULL AND (NEW.effect IS NULL OR NEW.effect=3) OR NEW.state=7 AND NOT NEW.may_have_delivered THEN
  RAISE EXCEPTION 'an uncertain outcome remains reconcilable' USING ERRCODE='23000'; END IF;
 IF TG_OP='UPDATE' THEN
  PERFORM 1 FROM fleet.hub_lease h WHERE h.singleton AND h.fence=NEW.hub_fence AND h.expires_at>clock_timestamp() FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'current hub lease required' USING ERRCODE='55000'; END IF;
  -- A channel can disappear before the first pre-send claim. The retained
  -- zero count is authoritative, and recording it grants no delivery right.
  IF NEW.state=8 AND (OLD.state NOT IN (1,8) OR OLD.may_have_delivered OR OLD.delivery_count<>0
    OR NEW.may_have_delivered OR NEW.delivery_count<>0 OR NEW.effect IS DISTINCT FROM 1::smallint
    OR NEW.channel_epoch IS DISTINCT FROM OLD.channel_epoch
    OR NEW.result_sha256 IS NOT NULL OR NEW.result_kind IS NOT NULL OR NEW.result_id IS NOT NULL
    OR NEW.final_at IS NOT NULL) THEN
   RAISE EXCEPTION 'not delivered requires absence of a delivery claim' USING ERRCODE='23000'; END IF;
  -- Retained uncertainty and a definite reconciliation do not authorize a
  -- send or change the channel on which a command may first have run.
  IF NEW.delivery_count>OLD.delivery_count OR NEW.channel_epoch IS DISTINCT FROM OLD.channel_epoch OR
   (NEW.state NOT IN(7,8) AND NOT (OLD.state=7 AND OLD.may_have_delivered AND NEW.state IN(3,4,5,6)
    AND NEW.effect IN(1,2) AND NEW.final_at IS NOT NULL AND NEW.result_sha256 IS NOT NULL
    AND NEW.delivery_count=OLD.delivery_count AND NEW.channel_epoch=OLD.channel_epoch)) THEN
   PERFORM 1 FROM management.command_identity identity_row JOIN management.node_protocol p USING(enrollment_id,node_id,account_id)
    JOIN fleet.node n ON (n.enrollment_id,n.node_id,n.user_id)=(p.enrollment_id,p.node_id,p.account_id)
    WHERE identity_row.account_id=NEW.account_id AND identity_row.command_id=NEW.command_id AND p.revoked_at IS NULL
    AND n.revoked_at IS NULL AND n.connection_id=NEW.channel_epoch FOR SHARE OF p,n;
   IF NOT FOUND THEN RAISE EXCEPTION 'current Node protocol required' USING ERRCODE='55000'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END; $$;
