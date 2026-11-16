// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/jackc/pgx/v5"
)

// The source10 archive has no floor to exclude or trust. It first restores in
// the independently isolated target, verifies the complete original snapshot,
// then runs the canonical 0011/0012 transactions with the same private cap.
func restoreManagementSchema10(ctx context.Context, conn *pgx.Conn, cfg config.Migration, meta ctr06BackupMetadata, metadataDigest, runner, tool string, childEnv []string, archive *os.File, listPath string, c *restoreCapability) (report RestoreReport, finalErr error) {
	committed, ready := false, false
	defer func() {
		if finalErr != nil && committed && !ready {
			finalErr = fmt.Errorf("the schema10 archive transaction committed; target admission UNKNOWN and quarantined; preserve it: %w", finalErr)
		}
	}()
	build, err := Load(schema.Migrations())
	if err != nil || len(build) != 12 || build[11].Name != "0012_management_storage.sql" {
		return report, ErrManagementTransitionRequired
	}
	options := Options{Runner: runner, RuntimeRole: cfg.RuntimeRole, LockTimeout: cfg.LockTimeout, localRestore: c}
	options.defaults()
	if err := lock(ctx, conn, options); err != nil {
		return report, err
	}
	defer unlock(conn)
	var owner string
	if err := conn.QueryRow(ctx, "SELECT current_user").Scan(&owner); err != nil || owner == "" {
		return report, ErrManagementTransitionRequired
	}
	if _, err := runRestoreTool(ctx, tool, childEnv, archive, "--single-transaction", "--exit-on-error", "--no-owner", "--no-acl", "--role="+owner, "--use-list="+listPath, "--dbname="+cfg.Database); err != nil {
		return report, ctr06RestoreChildFailure(conn, "quarantined")
	}
	committed = true
	verification, err := ctr06VerifyRestoredData(ctx, conn, meta, build[:10])
	if err != nil {
		return report, err
	}
	artifact, err := readManagementArtifact(runner, build[11])
	if err != nil {
		return report, err
	}
	identity, err := managementDatabaseIdentity(ctx, conn)
	if err != nil {
		return report, err
	}
	a := &managementAdmission{conn: conn, source: 10, oldRole: meta.SourceRuntimeRole, backup: &meta,
		backupDigest: metadataDigest, artifactDigest: artifact.Digest, executableDigest: artifact.Executable,
		sourceLabel: artifact.Source, databaseIdentity: identity, targetRole: cfg.RuntimeRole, active: true, recovery: c}
	defer func() { a.active = false }()
	options.management = a
	c.managementArtifact, c.managementSource = artifact.Digest, 10
	expanded, err := Apply(ctx, conn, build, options)
	if err != nil || expanded.Version != 12 || expanded.Grants != "" {
		return report, errors.New("the restored schema10 target could not complete its finite maintenance expansion; preserve its quarantine")
	}
	if err := verifyManagementSchema10Expansion(ctx, conn, meta, build); err != nil {
		return report, err
	}
	if err := managementPendingRestore(ctx, conn, conn, cfg.RuntimeRole, c); err != nil {
		return report, err
	}
	floor, _, err := restoreSecuritySnapshot(ctx, conn)
	if err != nil {
		return report, err
	}
	receipt, err := finalizeCTR06Restore(ctx, conn, cfg.RuntimeRole, meta.SourceRuntimeRole, verification, c)
	if err != nil {
		return report, errors.New("the restored schema10 target could not commit checked readiness; preserve its quarantine")
	}
	ready = true
	status, err := Inspect(ctx, conn, build)
	if err != nil || status.State != StateCurrent || status.RuntimeRole != cfg.RuntimeRole || status.RestoreReceipt != receipt {
		return report, errors.New("target readiness committed but its checked status is unavailable; inspect the receipt")
	}
	options.localRestore, options.management = nil, nil
	reconciled, err := Apply(ctx, conn, build, options)
	if err != nil || reconciled.State != StateCurrent || len(reconciled.Ran) != 0 || reconciled.Grants != "reconciled" {
		return report, errors.New("target readiness committed but its grants could not reconcile; inspect the receipt")
	}
	if err := checkRestoreIsolation(ctx, conn, cfg.RuntimeRole); err != nil {
		return report, err
	}
	return RestoreReport{Database: cfg.Database, RuntimeRole: cfg.RuntimeRole, SourceBackupSHA256: c.archiveSHA256,
		TargetFloorSHA256: ctr06SHA([]byte(floor)), SchemaVersion: 12, RestoreReceipt: receipt}, nil
}

// New roles are created by this transaction, never adopted from source names.
// The source generation remains excluded by the target's no-ACL restore; this
// deliberately does not revoke roles that may still serve the source database.
func managementRestoreWriterClosure(ctx context.Context, q Querier, role string, a *managementAdmission) (string, error) {
	c := a.recovery
	if c == nil || !c.active || c.conn != a.conn || requireCTR06RestoreIsolation(ctx, q) != nil {
		return "", ErrManagementTransitionRequired
	}
	identity, err := managementDatabaseIdentity(ctx, q)
	if err != nil || identity != a.databaseIdentity {
		return "", ErrManagementTransitionRequired
	}
	var oids []uint32
	for _, name := range []string{role, role + "_a", role + "_b"} {
		if err := RequirePlainRole(ctx, q, name, false); err != nil {
			return "", err
		}
		var oid uint32
		if err := q.QueryRow(ctx, "SELECT oid FROM pg_roles WHERE rolname=$1", name).Scan(&oid); err != nil || oid == 0 {
			return "", ErrManagementTransitionRequired
		}
		oids = append(oids, oid)
	}
	var unsafe bool
	err = q.QueryRow(ctx, `WITH RECURSIVE reach(actor,memberof) AS (
 SELECT oid,oid FROM pg_roles UNION SELECT reach.actor,m.roleid FROM reach JOIN pg_auth_members m ON m.member=reach.memberof)
 SELECT EXISTS(SELECT 1 FROM platform.runtime_credential WHERE login_role<>$3::text||'_'||slot OR slot NOT IN('a','b'))
 OR EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND usesysid NOT IN(SELECT oid FROM pg_roles WHERE rolsuper))
 OR EXISTS(SELECT 1 FROM pg_database d,aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) acl WHERE d.datname=current_database() AND acl.grantee=0 AND acl.privilege_type IN('CONNECT','TEMPORARY'))
 OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member=ANY($1::oid[]) OR (roleid=ANY($1::oid[]) AND member<>(SELECT oid FROM pg_roles WHERE rolname=current_user)))
 OR EXISTS(SELECT 1 FROM reach JOIN pg_roles actor ON actor.oid=reach.actor JOIN pg_roles reachable ON reachable.oid=reach.memberof
 WHERE actor.rolname<>current_user AND actor.rolname !~ '^pg_' AND NOT actor.rolsuper AND NOT actor.oid=ANY($1::oid[])
 AND (reachable.rolsuper OR reachable.rolname=current_user OR reachable.oid=ANY($1::oid[]) OR EXISTS(
 SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=ANY($2::text[])
 AND t.relkind IN('r','p') AND (has_table_privilege(reachable.oid,t.oid,'INSERT,UPDATE,DELETE,TRUNCATE') OR has_any_column_privilege(reachable.oid,t.oid,'INSERT,UPDATE')))))`,
		oids, []string{"platform", "audit", "fleet", "identity", "device", "entitlement"}, a.oldRole).Scan(&unsafe)
	if err != nil || unsafe {
		return "", ErrManagementTransitionRequired
	}
	raw, _ := json.Marshal(struct {
		Database, SourceExcluded, Runtime, Archive, Metadata string
		OIDs                                                 []uint32
	}{identity, a.oldRole, role, c.archiveSHA256, c.metadataSHA256, oids})
	return ctr06SHA(raw), nil
}

func managementPendingRestore(ctx context.Context, q Querier, conn *pgx.Conn, role string, c *restoreCapability) error {
	if c == nil || !c.active || c.conn != conn || requireCTR06RestoreIsolation(ctx, q) != nil || checkRestoreIsolation(ctx, q, role) != nil {
		return ErrManagementTransitionRequired
	}
	var matches bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform.ctr06_runtime_floor f
 JOIN platform.ctr06_restore_admission a ON a.singleton=f.singleton
 JOIN pg_database d ON d.datname=current_database() AND d.oid=f.database_oid AND d.datdba=f.owner_oid
 JOIN pg_roles r ON r.rolname=$1 AND r.oid=f.runtime_role_oid
 WHERE f.singleton AND f.runtime_role=$1 AND f.cluster_system_identifier=$2
 AND f.cluster_system_identifier=(SELECT system_identifier::text FROM pg_control_system())
 AND f.database_oid=$3::oid AND f.owner_oid=$4::oid AND f.owner_oid=(SELECT oid FROM pg_roles WHERE rolname=current_user)
 AND a.kind='restore' AND a.state='PENDING' AND a.receipt_sha256 IS NULL
 AND a.cluster_system_identifier=f.cluster_system_identifier AND a.database_oid=f.database_oid AND a.owner_oid=f.owner_oid AND a.runtime_role_oid=f.runtime_role_oid
 AND a.archive_sha256=$5 AND a.metadata_sha256=$6 AND a.capability_sha256=$7)`, role, c.cluster, c.databaseOID, c.ownerOID, c.archiveSHA256, c.metadataSHA256, c.tokenDigest()).Scan(&matches)
	if err != nil || !matches {
		return ErrManagementTransitionRequired
	}
	return nil
}

// Complete source rows were checked before expansion. Recheck every unchanged
// table and the sequence/LOB closure afterwards; only the canonical history,
// credential archival and three additive refusal rows may differ. The final
// closed catalogue and exact applied checksums qualify the transformed schema.
func verifyManagementSchema10Expansion(ctx context.Context, conn *pgx.Conn, meta ctr06BackupMetadata, build []Migration) error {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return ErrManagementTransitionRequired
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, "SET LOCAL search_path=pg_catalog; SET LOCAL TIME ZONE 'UTC'"); err != nil {
		return err
	}
	applied, exists, err := ReadApplied(ctx, tx)
	if err != nil || !exists || len(applied) != 12 || len(Compare(build, applied).Problems) != 0 {
		return ErrManagementTransitionRequired
	}
	if err := ctr06CheckSchemaOwnership(ctx, tx); err != nil {
		return err
	}
	_, expected, err := backupDefinition(12)
	catalogue, catalogueErr := ctr06CatalogueSHA(ctx, tx)
	if err != nil || catalogueErr != nil || catalogue != expected {
		return ErrManagementTransitionRequired
	}
	var names []string
	var expectedRows []ctr06BackupTable
	for _, table := range meta.Tables {
		switch table.Name {
		case "platform.schema_migration", "platform.runtime_credential", "fleet.refusal_code":
			continue
		}
		names = append(names, table.Name)
		expectedRows = append(expectedRows, table)
	}
	rows, err := ctr06SnapshotData(ctx, tx, names)
	if err != nil || !reflect.DeepEqual(rows, expectedRows) {
		return ErrManagementTransitionRequired
	}
	sequences, err := ctr06SnapshotSequences(ctx, tx)
	if err != nil || !reflect.DeepEqual(sequences, meta.Sequences) {
		return ErrManagementTransitionRequired
	}
	objects, err := ctr06SnapshotLargeObjects(ctx, tx)
	if err != nil || !reflect.DeepEqual(objects, meta.LargeObjects) {
		return ErrManagementTransitionRequired
	}
	var wrong bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM fleet.routed_call r FULL JOIN management.legacy_outcome l USING(account_id,command_id)
 WHERE r.command_id IS NULL OR l.command_id IS NULL OR l.namespace<>1 OR l.source_row_sha256 IS DISTINCT FROM sha256(convert_to(to_jsonb(r)::text,'UTF8')))
 OR EXISTS(SELECT 1 FROM fleet.routed_call r FULL JOIN management.command_identity i USING(account_id,command_id)
 WHERE r.command_id IS NULL OR i.command_id IS NULL OR i.namespace<>1 OR i.node_owner_epoch IS NOT NULL
 OR (i.enrollment_id,i.node_id,i.method,i.intent_sha256,i.created_at,i.replay_until) IS DISTINCT FROM
 (r.node_enrollment_id,r.node_id,'legacy.task.'||r.method,r.request_digest,r.created_at,r.created_at+interval '90 days'))
 OR EXISTS(SELECT 1 FROM management.remote_operation)
 OR EXISTS(SELECT 1 FROM management.node_protocol)
 OR EXISTS(SELECT 1 FROM management.cutover_receipt)
 OR EXISTS(SELECT 1 FROM platform.runtime_credential)`).Scan(&wrong)
	if err != nil || wrong {
		return ErrManagementTransitionRequired
	}
	return tx.Commit(ctx)
}
