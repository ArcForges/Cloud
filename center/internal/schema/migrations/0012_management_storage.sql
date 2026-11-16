-- SPDX-License-Identifier: AGPL-3.0-only
-- AFV2-CENTER-01: management-only forward expansion from Design493022fb.
-- Immutable 0001..0011 and account/entitlement facts remain intact.
CREATE SCHEMA management;

-- Enables a database-enforced account/node/enrollment ownership relationship.
ALTER TABLE fleet.node ADD CONSTRAINT node_v2_identity
    UNIQUE (enrollment_id, node_id, user_id);

CREATE TABLE management.node_protocol (
    enrollment_id uuid PRIMARY KEY,
    node_id uuid NOT NULL,
    account_id uuid NOT NULL,
    protocol_major smallint NOT NULL CHECK (protocol_major = 2),
    protocol_epoch uuid NOT NULL UNIQUE,
    initialized_at timestamptz NOT NULL,
    revoked_at timestamptz,
    rev bigint NOT NULL CHECK (rev >= 1),
    FOREIGN KEY (enrollment_id, node_id, account_id)
        REFERENCES fleet.node (enrollment_id, node_id, user_id),
    CHECK (revoked_at IS NULL OR revoked_at >= initialized_at)
);
CREATE INDEX node_protocol_account ON management.node_protocol (account_id);

-- Migration-owned catalogue generated from the closed remote API specification.
-- Runtime cannot insert/update/delete it; terminal attach/input is absent.
CREATE TABLE management.method_catalogue (
    method text PRIMARY KEY CHECK (char_length(method) BETWEEN 1 AND 128),
    permission text NOT NULL CHECK (permission IN
        ('configure', 'run', 'stop', 'resources', 'data', 'delete', 'revoke')),
    contract_major smallint NOT NULL CHECK (contract_major = 2)
);

-- namespace: 1 legacy Task tombstone, 2 legacy file tombstone, 3 V2 management.
-- Global account/command uniqueness prevents reuse across methods/enrollments.
-- Insert-only at runtime. Historical method names are evidence, not dispatch.
CREATE TABLE management.command_identity (
    account_id uuid NOT NULL REFERENCES identity.user (user_id),
    command_id uuid NOT NULL,
    enrollment_id uuid NOT NULL,
    node_id uuid NOT NULL,
    namespace smallint NOT NULL CHECK (namespace IN (1, 2, 3)),
    node_owner_epoch bytea,
    method text NOT NULL CHECK (char_length(method) BETWEEN 1 AND 128),
    intent_sha256 bytea NOT NULL CHECK (octet_length(intent_sha256) = 32),
    created_at timestamptz NOT NULL,
    replay_until timestamptz NOT NULL,
    PRIMARY KEY (account_id, command_id),
    UNIQUE (account_id, command_id, node_owner_epoch),
    FOREIGN KEY (enrollment_id, node_id, account_id)
        REFERENCES fleet.node (enrollment_id, node_id, user_id),
    CHECK (replay_until > created_at),
    CHECK ((namespace = 3) = (node_owner_epoch IS NOT NULL)),
    CHECK (node_owner_epoch IS NULL OR octet_length(node_owner_epoch) = 16)
);
-- Node store owner epoch is distinct from enrollment/protocol/channel epochs.
-- Legacy namespaces have no such epoch; they are non-executable tombstones.
CREATE INDEX command_identity_enrollment
    ON management.command_identity (enrollment_id, created_at);

-- Routing states: 1 accepted; 2 reserved; 3 succeeded; 4 failed; 5 rejected;
-- 6 expired; 7 unknown; 8 not_delivered. These are not process/Run states.
-- A migration guard verifies namespace=3, same method/enrollment as identity,
-- and current node_protocol/lease fence when admitting a new V2 operation.
CREATE TABLE management.remote_operation (
    account_id uuid NOT NULL,
    command_id uuid NOT NULL,
    node_owner_epoch bytea NOT NULL CHECK (octet_length(node_owner_epoch) = 16),
    method text NOT NULL REFERENCES management.method_catalogue (method),
    state smallint NOT NULL CHECK (state IN (1, 3, 4, 5, 6, 7, 8)),
    may_have_delivered boolean NOT NULL DEFAULT false,
    delivery_count integer NOT NULL CHECK (delivery_count >= 0),
    hub_fence bigint NOT NULL CHECK (hub_fence >= 1),
    channel_epoch uuid NOT NULL,
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    result_sha256 bytea,
    result_kind text CHECK (result_kind IN ('sandbox', 'run', 'transfer', 'policy', 'operation')),
    result_id uuid,
    effect smallint CHECK (effect IN (1, 2, 3)),
    reason text CHECK (char_length(reason) BETWEEN 1 AND 96),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    final_at timestamptz,
    PRIMARY KEY (account_id, command_id),
    FOREIGN KEY (account_id, command_id, node_owner_epoch)
        REFERENCES management.command_identity (account_id, command_id, node_owner_epoch),
    CHECK (result_sha256 IS NULL OR octet_length(result_sha256) = 32),
    CHECK ((result_kind IS NULL) = (result_id IS NULL)),
    CHECK (state <> 8 OR NOT may_have_delivered),
    CHECK (state <> 3 OR (result_sha256 IS NOT NULL AND effect = 2 AND final_at IS NOT NULL)),
    CHECK (state NOT IN (3, 4) OR may_have_delivered),
    CHECK (final_at IS NULL OR state IN (3, 4, 5, 6)),
    CHECK (updated_at >= created_at),
    CHECK (final_at IS NULL OR final_at >= created_at)
);
-- foundation.v1 EffectCertainty: 1 did_not_happen, 2 happened, 3 unknown.
CREATE INDEX remote_operation_open
    ON management.remote_operation (state, updated_at) WHERE final_at IS NULL;

-- Migration-role only: exact artifact/backup/cutover proof identity, no secrets.
CREATE TABLE management.cutover_receipt (
    cutover_id uuid PRIMARY KEY,
    source_schema integer NOT NULL CHECK (source_schema >= 0),
    target_schema integer NOT NULL CHECK (target_schema > source_schema),
    database_identity_sha256 bytea NOT NULL CHECK (octet_length(database_identity_sha256) = 32),
    artifact_manifest_sha256 bytea NOT NULL CHECK (octet_length(artifact_manifest_sha256) = 32),
    backup_manifest_sha256 bytea NOT NULL CHECK (octet_length(backup_manifest_sha256) = 32),
    retired_writer_set_sha256 bytea NOT NULL CHECK (octet_length(retired_writer_set_sha256) = 32),
    phase smallint NOT NULL CHECK (phase IN (1, 2, 3, 4)),
    recorded_at timestamptz NOT NULL,
    ready_at timestamptz,
    CHECK ((phase = 4) = (ready_at IS NOT NULL))
);
-- phase: 1 prepared, 2 writers_fenced, 3 schema_verified, 4 ready.
-- Restore creates a target-specific receipt; source readiness is not copied.


-- Preserve old receipt identity and uncertainty without a V2 dispatch target.
CREATE TABLE management.legacy_outcome (
 account_id uuid NOT NULL, command_id uuid NOT NULL, namespace smallint NOT NULL CHECK(namespace IN(1,2)),
 legacy_method smallint NOT NULL, legacy_state smallint NOT NULL,
 may_have_delivered boolean NOT NULL, delivery_count integer NOT NULL CHECK(delivery_count>=1),
 response_sha256 bytea, outcome_sha256 bytea, final_at timestamptz, updated_at timestamptz NOT NULL,
 source_row_sha256 bytea NOT NULL CHECK(octet_length(source_row_sha256)=32),
 PRIMARY KEY(account_id,command_id),
 FOREIGN KEY(account_id,command_id) REFERENCES management.command_identity(account_id,command_id)
);
INSERT INTO management.command_identity(account_id,command_id,enrollment_id,node_id,namespace,method,intent_sha256,created_at,replay_until)
 SELECT account_id,command_id,node_enrollment_id,node_id,1,'legacy.task.'||method,request_digest,created_at,created_at+interval '90 days' FROM fleet.routed_call;
INSERT INTO management.command_identity(account_id,command_id,enrollment_id,node_id,namespace,method,intent_sha256,created_at,replay_until)
 SELECT account_id,command_id,node_enrollment_id,node_id,2,'legacy.file.'||method,request_digest,created_at,created_at+interval '90 days' FROM fleet.routed_file_call;
INSERT INTO management.legacy_outcome
 SELECT account_id,command_id,1,method,state,delivered OR state IN(1,7),attempts,response_sha256,outcome_sha256,final_at,updated_at,sha256(convert_to(to_jsonb(r)::text,'UTF8')) FROM fleet.routed_call r;
INSERT INTO management.legacy_outcome
 SELECT account_id,command_id,2,method,state,delivered OR state IN(1,7),attempts,response_sha256,outcome_sha256,final_at,updated_at,sha256(convert_to(to_jsonb(r)::text,'UTF8')) FROM fleet.routed_file_call r;

-- Closed remotely callable durable mutations only. Pure reads and transient
-- terminal input/resize/lease operations cannot reserve durable identities.
INSERT INTO management.method_catalogue(method,permission,contract_major) VALUES
 ('NodeService.RevokeRemoteGrant','revoke',2),
 ('SandboxService.Create','configure',2),('SandboxService.Configure','configure',2),('SandboxService.Delete','delete',2),
 ('RunService.Start','run',2),('RunService.Stop','stop',2),('ResourceService.SetPolicy','resources',2),
 ('DataService.BeginImport','data',2),('DataService.WriteImport','data',2),('DataService.CommitImport','data',2),
 ('DataService.BeginExport','data',2),('DataService.CloseTransfer','data',2);

CREATE FUNCTION management.identity_admitted() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.namespace=3 AND NOT EXISTS(SELECT 1 FROM management.method_catalogue WHERE method=NEW.method) THEN
  RAISE EXCEPTION 'method is not a durable remote mutation' USING ERRCODE='23000'; END IF;
 IF NEW.namespace<>3 AND current_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid=TG_RELID) THEN
  RAISE EXCEPTION 'legacy import is migration owned' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER command_identity_admitted BEFORE INSERT ON management.command_identity FOR EACH ROW EXECUTE FUNCTION management.identity_admitted();

CREATE FUNCTION management.identity_fixed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'a retained command identity is immutable' USING ERRCODE='23000'; END; $$;
CREATE TRIGGER command_identity_fixed BEFORE UPDATE OR DELETE ON management.command_identity FOR EACH ROW EXECUTE FUNCTION management.identity_fixed();
CREATE TRIGGER legacy_outcome_fixed BEFORE UPDATE OR DELETE ON management.legacy_outcome FOR EACH ROW EXECUTE FUNCTION management.identity_fixed();
CREATE TRIGGER method_catalogue_fixed BEFORE UPDATE OR DELETE ON management.method_catalogue FOR EACH ROW EXECUTE FUNCTION management.identity_fixed();
CREATE TRIGGER cutover_receipt_fixed BEFORE UPDATE OR DELETE ON management.cutover_receipt FOR EACH ROW EXECUTE FUNCTION management.identity_fixed();
CREATE FUNCTION management.protocol_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'protocol history is retained' USING ERRCODE='23000'; END IF;
 IF (NEW.enrollment_id,NEW.node_id,NEW.account_id,NEW.protocol_major,NEW.protocol_epoch,NEW.initialized_at)
  IS DISTINCT FROM (OLD.enrollment_id,OLD.node_id,OLD.account_id,OLD.protocol_major,OLD.protocol_epoch,OLD.initialized_at)
  OR NEW.rev<=OLD.rev OR OLD.revoked_at IS NOT NULL THEN
  RAISE EXCEPTION 'protocol identity cannot be replaced or reactivated' USING ERRCODE='23000'; END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER node_protocol_guard BEFORE UPDATE OR DELETE ON management.node_protocol FOR EACH ROW EXECUTE FUNCTION management.protocol_guard();
CREATE FUNCTION management.operation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
  IF NEW.state<>7 THEN
   PERFORM 1 FROM management.command_identity identity_row JOIN management.node_protocol p USING(enrollment_id,node_id,account_id)
    JOIN fleet.node n ON (n.enrollment_id,n.node_id,n.user_id)=(p.enrollment_id,p.node_id,p.account_id)
    WHERE identity_row.account_id=NEW.account_id AND identity_row.command_id=NEW.command_id AND p.revoked_at IS NULL
    AND n.revoked_at IS NULL AND n.connection_id=NEW.channel_epoch FOR SHARE OF p,n;
   IF NOT FOUND THEN RAISE EXCEPTION 'current Node protocol required' USING ERRCODE='55000'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER remote_operation_guard BEFORE INSERT OR UPDATE OR DELETE ON management.remote_operation FOR EACH ROW EXECUTE FUNCTION management.operation_guard();

-- This expansion is a frozen V1 submission boundary, not a Task-to-Run adapter.
-- Existing outcomes remain readable exactly as recorded and are never dispatched.
CREATE FUNCTION management.legacy_frozen() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'legacy remote routing is in maintenance after V2 expansion' USING ERRCODE='55000'; END; $$;
CREATE TRIGGER legacy_task_frozen BEFORE INSERT OR UPDATE OR DELETE ON fleet.routed_call FOR EACH ROW EXECUTE FUNCTION management.legacy_frozen();
CREATE TRIGGER legacy_file_frozen BEFORE INSERT OR UPDATE OR DELETE ON fleet.routed_file_call FOR EACH ROW EXECUTE FUNCTION management.legacy_frozen();
CREATE TRIGGER legacy_target_frozen BEFORE INSERT OR UPDATE OR DELETE ON fleet.routed_file_target FOR EACH ROW EXECUTE FUNCTION management.legacy_frozen();
