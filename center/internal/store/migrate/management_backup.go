// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/jackc/pgx/v5"
)

// backupDefinition selects a closed reviewed schema, never the inventory of the
// archive being admitted. The original 0011 format and oracle remain unchanged.
func backupDefinition(version int) (inventory, catalogue string, err error) {
	switch version {
	case 10:
		return ctr06Schema10Inventory, ctr06Schema10CatalogueSHA, nil
	case 11:
		return ctr06Schema11Inventory, ctr06Schema11CatalogueSHA, nil
	case 12:
		build, err := Load(schema.Migrations())
		if err != nil || len(build) < 12 || build[11].SHA256 != managementSchema12MigrationSHA {
			return "", "", errors.New("schema12 backup catalogue qualification does not match this migration build")
		}
		return managementSchema12Inventory, managementSchema12CatalogueSHA, nil
	case 13:
		return lifecycleBackupDefinition()
	case 14:
		return remoteObservationBackupDefinition()
	case 15:
		return hostedEntitlementBackupDefinition()
	default:
		return "", "", errors.New("unsupported logical backup schema")
	}
}

// managementRestoreList retains all non-authority source facts. Only the source
// ready receipt's DATA is excluded: the canonical table/constraints/trigger still
// restore, and the destination will write its own receipt under its private cap.
func managementRestoreList(raw []byte) ([]byte, error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), restoreTOCMax)
	var output bytes.Buffer
	omitted := 0
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 8 && strings.Join(fields[3:len(fields)-1], " ") == "TABLE DATA management cutover_receipt" {
			omitted++
			continue
		}
		output.WriteString(line)
		output.WriteByte('\n')
	}
	if scanner.Err() != nil || omitted != 1 {
		return nil, errors.New("source cutover authority is missing or ambiguous")
	}
	return output.Bytes(), nil
}

func finishManagementRestore(ctx context.Context, tx pgx.Tx, conn *pgx.Conn, runtimeRole, sourceRole string, c *restoreCapability) error {
	if c == nil || !c.active || c.conn != conn || c.managementArtifact == "" || requireCTR06RestoreIsolation(ctx, tx) != nil {
		return ErrManagementTransitionRequired
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE management.node_protocol,management.command_identity,management.remote_operation,
 management.legacy_outcome,management.method_catalogue,management.cutover_receipt IN ACCESS EXCLUSIVE MODE`); err != nil {
		return err
	}
	var receipts int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM management.cutover_receipt").Scan(&receipts); err != nil || receipts != 0 {
		return ErrManagementTransitionRequired
	}
	// Old channel/protocol authority is not replayable after a database restore.
	// Retain every command/result identity and do not invent a Node outcome.
	if _, err := tx.Exec(ctx, `UPDATE management.node_protocol SET revoked_at=greatest(clock_timestamp(),initialized_at),rev=rev+1 WHERE revoked_at IS NULL;
 UPDATE fleet.node SET connection_id=NULL;`); err != nil {
		return err
	}
	a := &managementAdmission{conn: conn, source: c.managementSource, backupDigest: c.metadataSHA256, artifactDigest: c.managementArtifact,
		retiredDigest: ctr06SHA([]byte("V2 restored target excludes source runtime generation:" + sourceRole + ":" + runtimeRole)), active: true}
	defer func() { a.active = false }()
	return recordManagement(ctx, tx, conn, Options{RuntimeRole: runtimeRole, management: a})
}
