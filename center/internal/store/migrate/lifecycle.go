// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"errors"
	"strings"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/jackc/pgx/v5"
)

// ErrLifecycleTransitionRequired refuses schema13 without the current
// invocation's complete backup, writer fence and new runtime generation.
var ErrLifecycleTransitionRequired = errors.New("account lifecycle storage requires a checked schema12 backup and same-invocation writer-fenced transition")

func requireLifecycleReady(ctx context.Context, q Querier) error {
	var ready bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM management.cutover_receipt c,pg_database d
 WHERE d.datname=current_database() AND c.phase=4 AND c.target_schema=13
 AND c.database_identity_sha256=sha256(convert_to((SELECT system_identifier::text FROM pg_control_system())||':'||d.oid||':'||d.datdba,'UTF8')))`).Scan(&ready)
	if err != nil || !ready {
		return ErrLifecycleTransitionRequired
	}
	return nil
}

// ApplyLifecycle is the finite schema12 -> schema13 transition. The schema12
// manager remains a separate finite operation for old schema10/11 databases;
// each phase has its own actual source backup, credential generation and proof.
func ApplyLifecycle(ctx context.Context, conn *pgx.Conn, build []Migration, options Options, cfg config.Migration, archivePath, metadataPath string) (Result, error) {
	if options.BridgeProof != nil || cfg.CTR06BridgeExecutable != "" || cfg.CTR06ProofFile != "" {
		return Result{State: StateRefused}, ErrManagementSuccessorUnqualified
	}
	if len(build) < 13 || build[11].Name != "0012_management_storage.sql" || build[12].Name != "0013_account_lifecycle.sql" {
		return Result{State: StateRefused}, ErrRefused
	}
	// This finite admission proves only its original schema12 to schema13
	// transition. A later append runs through the ordinary migration entry.
	build = build[:13]
	options.defaults()
	if err := lock(ctx, conn, options); err != nil {
		return Result{}, err
	}
	defer unlock(conn)
	applied, exists, err := ReadApplied(ctx, conn)
	if err != nil || !exists || len(applied) != 12 || len(Compare(build[:12], applied).Problems) != 0 || requireManagementReady(ctx, conn) != nil {
		return Result{State: StateRefused}, ErrLifecycleTransitionRequired
	}
	oldRole, _, err := readyCTR06Admission(ctx, conn, cfg.RuntimeRole)
	if err != nil {
		return Result{State: StateRefused}, err
	}
	parsed, err := pgx.ParseConfig(cfg.URL)
	if err != nil || parsed.Database != conn.Config().Database || parsed.User != conn.Config().User || parsed.Host != conn.Config().Host || parsed.Port != conn.Config().Port {
		return Result{State: StateRefused}, ErrLifecycleTransitionRequired
	}
	report, err := CaptureLogical(ctx, cfg, archivePath, metadataPath)
	if err != nil {
		return Result{State: StateRefused}, err
	}
	meta, err := ctr06ReadMetadata(metadataPath, report.MetadataSHA256)
	if err != nil || report.SchemaVersion != 12 {
		return Result{State: StateRefused}, ErrLifecycleTransitionRequired
	}
	artifact, err := readManagementArtifact(options.Runner, build[12])
	if err != nil {
		return Result{State: StateRefused}, err
	}
	role := oldRole
	if len(role) > 19 {
		role = role[:19]
	}
	role += "_id_" + strings.ReplaceAll(newManagementID(), "-", "")[:16]
	identity, err := managementDatabaseIdentity(ctx, conn)
	if err != nil {
		return Result{State: StateRefused}, err
	}
	a := &managementAdmission{conn: conn, source: 12, oldRole: oldRole, backup: &meta, backupDigest: report.MetadataSHA256,
		artifactDigest: artifact.Digest, executableDigest: artifact.Executable, sourceLabel: artifact.Source,
		databaseIdentity: identity, targetRole: role, active: true}
	defer func() { a.active = false }()
	options.RuntimeRole, options.lifecycle = role, a
	return Apply(ctx, conn, build, options)
}

func guardLifecycle(ctx context.Context, tx pgx.Tx, conn *pgx.Conn, options Options) error {
	a := options.lifecycle
	if a == nil || !a.active || a.conn != conn || a.artifactDigest == "" {
		return ErrLifecycleTransitionRequired
	}
	if a.source == 12 {
		if a.targetRole != options.RuntimeRole || a.oldRole == options.RuntimeRole || a.executableDigest == "" {
			return ErrLifecycleTransitionRequired
		}
		if err := checkManagementSnapshot(ctx, tx, conn, a); err != nil {
			return err
		}
		if _, _, err := readyCTR06Admission(ctx, tx, a.oldRole); err != nil || requireManagementReady(ctx, tx) != nil {
			return ErrLifecycleTransitionRequired
		}
		retired, err := fenceManagementWritersIn(ctx, tx, a.oldRole, schema.Schemas)
		if err != nil {
			return err
		}
		a.retiredDigest = retired
		if err := createManagementRoles(ctx, tx, options.RuntimeRole); err != nil {
			return err
		}
	} else if a.source == 0 {
		// The private cap was minted only for a genuinely absent migration
		// history. 0011 already reserved all three previously absent roles.
		// Check all seven schemas again before deriving account authority.
		if c := options.localRestore; c != nil {
			if err := managementPendingRestore(ctx, tx, conn, options.RuntimeRole, c); err != nil {
				return err
			}
		} else if _, _, err := readyCTR06Admission(ctx, tx, options.RuntimeRole); err != nil || requireManagementReady(ctx, tx) != nil {
			return ErrLifecycleTransitionRequired
		}
		retired, err := fenceManagementWritersIn(ctx, tx, options.RuntimeRole, schema.Schemas)
		if err != nil {
			return err
		}
		a.retiredDigest = retired
	} else {
		return ErrLifecycleTransitionRequired
	}
	_, err := tx.Exec(ctx, "SELECT set_config('arcforges.lifecycle_admitted','13',true)")
	return err
}

func recordLifecycle(ctx context.Context, tx pgx.Tx, conn *pgx.Conn, options Options) error {
	if options.localRestore != nil {
		return nil // destination-specific readiness is committed after checking the restored data
	}
	a := options.lifecycle
	if a == nil || !a.active || a.conn != conn || a.artifactDigest == "" || a.retiredDigest == "" {
		return ErrLifecycleTransitionRequired
	}
	if a.source == 12 {
		if _, err := tx.Exec(ctx, `INSERT INTO platform.ctr06_legacy_runtime_credential(slot,login_role,rotated_at,rotated_by,promoted_at)
 SELECT slot,login_role,rotated_at,rotated_by,promoted_at FROM platform.runtime_credential;
 DELETE FROM platform.runtime_credential;`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `WITH floor AS (UPDATE platform.ctr06_runtime_floor SET runtime_role=$1,runtime_role_oid=(SELECT oid FROM pg_roles WHERE rolname=$1) RETURNING runtime_role_oid)
 UPDATE platform.ctr06_restore_admission SET runtime_role_oid=floor.runtime_role_oid FROM floor;`, options.RuntimeRole); err != nil {
			return err
		}
	}
	backup := a.backupDigest
	if backup == "" {
		backup = ctr06SHA([]byte("genuinely fresh account lifecycle store: no predecessor backup"))
	}
	tag, err := tx.Exec(ctx, `INSERT INTO management.cutover_receipt
 (cutover_id,source_schema,target_schema,database_identity_sha256,artifact_manifest_sha256,backup_manifest_sha256,retired_writer_set_sha256,phase,recorded_at,ready_at)
 SELECT gen_random_uuid(),$1,13,sha256(convert_to((SELECT system_identifier::text FROM pg_control_system())||':'||d.oid||':'||d.datdba,'UTF8')),
 decode($2,'hex'),decode($3,'hex'),decode($4,'hex'),4,clock_timestamp(),clock_timestamp()
 FROM pg_database d WHERE d.datname=current_database() AND d.datdba=(SELECT oid FROM pg_roles WHERE rolname=current_user)`, a.source, a.artifactDigest, backup, a.retiredDigest)
	if err != nil || tag.RowsAffected() != 1 {
		return ErrLifecycleTransitionRequired
	}
	return nil
}
