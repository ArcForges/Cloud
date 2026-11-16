// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"

	"github.com/jackc/pgx/v5"
)

func managementDatabaseIdentity(ctx context.Context, q Querier) (string, error) {
	var identity string
	err := q.QueryRow(ctx, `SELECT encode(sha256(convert_to((SELECT system_identifier::text FROM pg_control_system())||':'||d.oid||':'||d.datdba,'UTF8')),'hex')
 FROM pg_database d WHERE d.datname=current_database() AND d.datdba=(SELECT oid FROM pg_roles WHERE rolname=current_user)`).Scan(&identity)
	if err != nil || !restoreDigest.MatchString(identity) {
		return "", ErrManagementTransitionRequired
	}
	return identity, nil
}

func requireManagementSchema10Source(ctx context.Context, q Querier, role string) error {
	if ValidRoleName(role) != nil {
		return ErrManagementTransitionRequired
	}
	var database string
	if q.QueryRow(ctx, "SELECT current_database()").Scan(&database) != nil || RequireOrdinaryDatabase(ctx, q, database) != nil {
		return ErrManagementTransitionRequired
	}
	if _, err := managementDatabaseIdentity(ctx, q); err != nil {
		return err
	}
	return RequirePlainRole(ctx, q, role, false)
}

// checkManagementSnapshot runs before any credential or schema mutation, under
// the full source write barrier and the outer session migration lock.
func checkManagementSnapshot(ctx context.Context, tx pgx.Tx, conn *pgx.Conn, a *managementAdmission) error {
	if a == nil || !a.active || a.conn != conn || a.backup == nil || a.backup.SourceSchemaVersion != a.source {
		return ErrManagementTransitionRequired
	}
	identity, err := managementDatabaseIdentity(ctx, tx)
	if err != nil || identity != a.databaseIdentity {
		return ErrManagementTransitionRequired
	}
	if _, err := tx.Exec(ctx, "SET LOCAL search_path=pg_catalog; SET LOCAL TIME ZONE 'UTC'"); err != nil {
		return ErrManagementTransitionRequired
	}
	inventory, expected, err := backupDefinition(a.source)
	if err != nil {
		return err
	}
	tables, err := ctr06RequiredTablesFrom(inventory)
	if err != nil {
		return err
	}
	quoted := make([]string, 0, len(tables))
	for _, table := range tables {
		quoted = append(quoted, pgx.Identifier(strings.Split(table, ".")).Sanitize())
	}
	if _, err := tx.Exec(ctx, "LOCK TABLE "+strings.Join(quoted, ",")+" IN ACCESS EXCLUSIVE MODE"); err != nil {
		return err
	}
	if err := ctr06CheckSchemaOwnership(ctx, tx); err != nil {
		return err
	}
	catalogue, err := ctr06CatalogueSHA(ctx, tx)
	if err != nil || catalogue != expected || catalogue != a.backup.SourceCatalogueSHA256 {
		return ErrManagementTransitionRequired
	}
	data, err := ctr06SnapshotData(ctx, tx, tables)
	if err != nil || !reflect.DeepEqual(data, a.backup.Tables) {
		return ErrManagementTransitionRequired
	}
	sequences, err := ctr06SnapshotSequences(ctx, tx)
	if err != nil || !reflect.DeepEqual(sequences, a.backup.Sequences) {
		return ErrManagementTransitionRequired
	}
	objects, err := ctr06SnapshotLargeObjects(ctx, tx)
	if err != nil || !reflect.DeepEqual(objects, a.backup.LargeObjects) {
		return ErrManagementTransitionRequired
	}
	return nil
}

func createManagementRoles(ctx context.Context, tx pgx.Tx, role string) error {
	if ValidRoleName(role) != nil {
		return ErrManagementTransitionRequired
	}
	for _, name := range []string{role, role + "_a", role + "_b"} {
		if _, err := tx.Exec(ctx, "CREATE ROLE "+pgx.Identifier{name}.Sanitize()+" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
			return err
		}
	}
	return nil
}

// guardManagementSchema11 is a finite maintenance admission, not a replacement
// promotion boolean. Only the active manager that captured and rechecked the
// actual source, executable and writer graph can enter it on this connection.
func guardManagementSchema11(ctx context.Context, tx pgx.Tx, conn *pgx.Conn, role string, a *managementAdmission) error {
	if a == nil || a.source != 10 || a.targetRole != role || a.floorEstablished || a.artifactDigest == "" || a.executableDigest == "" {
		return ErrManagementTransitionRequired
	}
	if err := checkManagementSnapshot(ctx, tx, conn, a); err != nil {
		return err
	}
	if err := requireManagementSchema10Source(ctx, tx, a.oldRole); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, "SELECT oid FROM pg_roles WHERE rolname=$1", a.oldRole).Scan(&a.legacyRoleOID); err != nil {
		return ErrManagementTransitionRequired
	}
	retired, err := fenceManagementWriters(ctx, tx, a.oldRole)
	if err != nil {
		return err
	}
	a.retiredDigest = retired
	return createManagementRoles(ctx, tx, role)
}

func recordManagementSchema11Floor(ctx context.Context, tx pgx.Tx, conn *pgx.Conn, role string, a *managementAdmission, recovery *restoreCapability) error {
	if a == nil || !a.active || a.conn != conn || a.source != 10 || a.targetRole != role || a.retiredDigest == "" || a.legacyRoleOID == 0 {
		return ErrManagementTransitionRequired
	}
	identity, err := managementDatabaseIdentity(ctx, tx)
	if err != nil || identity != a.databaseIdentity {
		return ErrManagementTransitionRequired
	}
	if err := RequirePlainRole(ctx, tx, role, false); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO platform.ctr06_legacy_runtime_credential(slot,login_role,rotated_at,rotated_by,promoted_at)
 SELECT slot,login_role,rotated_at,rotated_by,promoted_at FROM platform.runtime_credential;
 DELETE FROM platform.runtime_credential;`); err != nil {
		return err
	}
	proof, _ := json.Marshal(struct{ Kind, Database, Artifact, Backup, Writers, Runtime string }{"same-invocation finite maintenance v2", identity, a.artifactDigest, a.backupDigest, a.retiredDigest, role})
	tag, err := tx.Exec(ctx, `INSERT INTO platform.ctr06_runtime_floor
 (singleton,cluster_system_identifier,database_oid,owner_oid,runtime_role,runtime_role_oid,legacy_role,legacy_role_oid,bridge_revision,bridge_image_id,promotion_digest)
 SELECT true,(SELECT system_identifier::text FROM pg_control_system()),d.oid,d.datdba,r.rolname,r.oid,$2,$3,$4,$5,$6
 FROM pg_database d,pg_roles r WHERE d.datname=current_database() AND r.rolname=$1 AND d.datdba=(SELECT oid FROM pg_roles WHERE rolname=current_user)`,
		role, a.oldRole, a.legacyRoleOID, "afv2-maintenance/"+a.sourceLabel, "native-sha256:"+a.executableDigest, ctr06SHA(proof))
	if err != nil || tag.RowsAffected() != 1 {
		return ErrManagementTransitionRequired
	}
	if err := recordCTR06Admission(ctx, tx, conn, role, recovery); err != nil {
		return err
	}
	a.floorEstablished = true
	return nil
}

func guardManagementAfterSchema11(ctx context.Context, tx pgx.Tx, conn *pgx.Conn, options Options, a *managementAdmission) error {
	if a == nil || !a.active || a.conn != conn || a.source != 10 || !a.floorEstablished || a.targetRole != options.RuntimeRole {
		return ErrManagementTransitionRequired
	}
	identity, err := managementDatabaseIdentity(ctx, tx)
	if err != nil || identity != a.databaseIdentity {
		return ErrManagementTransitionRequired
	}
	_, _, err = readyCTR06Admission(ctx, tx, options.RuntimeRole)
	return err
}
