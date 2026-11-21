// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"

	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/jackc/pgx/v5"
)

// The complete source data is verified before this transaction. Restoration
// renews account authority only; old sessions/proofs keep their lower snapshots
// and are explicitly revoked. Lifecycle/command/UNKNOWN identities survive.
func finishLifecycleRestore(ctx context.Context, tx pgx.Tx, conn *pgx.Conn, runtimeRole, sourceRole string, c *restoreCapability) error {
	if c == nil || !c.active || c.conn != conn || c.lifecycleArtifact == "" || requireCTR06RestoreIsolation(ctx, tx) != nil ||
		checkRestoreIsolationAtVersion(ctx, tx, runtimeRole, c.schemaVersion) != nil {
		return ErrLifecycleTransitionRequired
	}
	tables := "identity.user,identity.account_security_state,identity.session,identity.step_up_challenge," +
		"identity.auth_flow,identity.lifecycle_operation"
	if c.schemaVersion < schema.ContractionVersion {
		tables += ",identity.mobile_authorization"
	}
	tables += ",fleet.node_sign_in,fleet.device_authorization"
	if _, err := tx.Exec(ctx, "LOCK TABLE "+tables+" IN ACCESS EXCLUSIVE MODE"); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE identity.account_security_state SET auth_epoch=auth_epoch+1,recovery_generation=recovery_generation+1,
 rev=rev+1,changed_at=greatest(changed_at,clock_timestamp());
 UPDATE identity.session SET revoked_at=greatest(issued_at,clock_timestamp()),revoke_reason=6,rev=rev+1 WHERE revoked_at IS NULL;
 UPDATE identity.step_up_challenge SET state=5,rev=rev+1 WHERE state=1;
 UPDATE identity.step_up_challenge SET state=3,consumed_at=greatest(proved_at,clock_timestamp()),rev=rev+1 WHERE state=2;
 UPDATE identity.auth_flow SET consumed_at=greatest(created_at,clock_timestamp()),outcome=2 WHERE consumed_at IS NULL;
 UPDATE identity.lifecycle_operation SET state=7,finished_at=greatest(created_at,clock_timestamp()),rev=rev+1
 WHERE kind IN(1,3) AND (state IN(1,2,3) OR kind=3 AND state=4);`); err != nil {
		return err
	}
	// Pending enrollment approvals are bound to old account/session epochs.
	// Their snapshots remain untouched, so ApprovalStands cannot revive them.
	a := &managementAdmission{conn: conn, source: 0, backupDigest: c.metadataSHA256, artifactDigest: c.lifecycleArtifact,
		retiredDigest: ctr06SHA([]byte("account lifecycle restored target excludes source authority:" + sourceRole + ":" + runtimeRole)), active: true}
	defer func() { a.active = false }()
	return recordLifecycle(ctx, tx, conn, Options{RuntimeRole: runtimeRole, lifecycle: a})
}
