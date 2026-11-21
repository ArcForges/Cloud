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

// ErrContractionRequired means the source is still on its rollback schema or
// the current database cannot prove its contraction admission.
var ErrContractionRequired = errors.New("schema contraction requires a verified backup, isolated restore, and drained predecessor")

const contractionName = "0017_retire_legacy_routing.sql"

type contractionAdmission struct {
	snapshot       managementAdmission
	restoreReceipt string
}

func isContraction(migration Migration) bool {
	return migration.Version == schema.ContractionVersion && migration.Name == contractionName
}

func requireContractionReady(ctx context.Context, q Querier) error {
	var ready bool
	err := q.QueryRow(ctx, "SELECT platform.runtime_contraction_ready()").Scan(&ready)
	if err != nil || !ready {
		return ErrContractionRequired
	}
	return nil
}

// ApplyContraction takes and restores the exact predecessor backup before
// entering the destructive transaction. Witness configuration names a new,
// separately isolated database and runtime group.
func ApplyContraction(ctx context.Context, conn *pgx.Conn, build []Migration, options Options, cfg, witness config.Migration, archivePath, metadataPath string) (Result, error) {
	target := schema.ContractionVersion
	predecessor := target - 1
	refused := Result{State: StateRefused}
	if len(build) != target || !isContraction(build[predecessor]) || options.BridgeProof != nil ||
		cfg.CTR06ProofFile != "" || cfg.CTR06BridgeExecutable != "" || cfg.Database == witness.Database ||
		cfg.RuntimeRole == witness.RuntimeRole || options.RuntimeRole != cfg.RuntimeRole {
		return refused, ErrContractionRequired
	}
	parsed, err := pgx.ParseConfig(cfg.URL)
	if err != nil || parsed.Database != cfg.Database || parsed.Database != conn.Config().Database ||
		parsed.User != conn.Config().User || parsed.Host != conn.Config().Host || parsed.Port != conn.Config().Port {
		return refused, ErrContractionRequired
	}
	options.defaults()
	if err := lock(ctx, conn, options); err != nil {
		return refused, err
	}
	defer unlock(conn)
	status, err := Inspect(ctx, conn, build)
	if err != nil || status.Version != predecessor || status.State != StatePending || status.RuntimeRole != cfg.RuntimeRole {
		return refused, ErrContractionRequired
	}
	if err := refuseRetiredReaders(ctx, conn, cfg.RuntimeRole); err != nil {
		return refused, err
	}
	report, err := CaptureLogical(ctx, cfg, archivePath, metadataPath)
	if err != nil {
		return refused, err
	}
	meta, err := ctr06ReadMetadata(metadataPath, report.MetadataSHA256)
	if err != nil || meta.SourceSchemaVersion != predecessor || report.SchemaVersion != predecessor {
		return refused, ErrContractionRequired
	}
	restored, err := RestoreLogical(ctx, witness, archivePath, report.ArchiveSHA256, metadataPath, report.MetadataSHA256, options.Runner)
	if err != nil {
		return refused, err
	}
	if restored.Database != witness.Database || restored.RuntimeRole != witness.RuntimeRole ||
		restored.SchemaVersion != predecessor || restored.SourceBackupSHA256 != report.ArchiveSHA256 ||
		!restoreDigest.MatchString(restored.RestoreReceipt) {
		return refused, ErrContractionRequired
	}
	artifact, err := readManagementArtifact(options.Runner, build[predecessor])
	if err != nil {
		return refused, err
	}
	identity, err := managementDatabaseIdentity(ctx, conn)
	if err != nil {
		return refused, err
	}
	role := cfg.RuntimeRole
	if len(role) > 19 {
		role = role[:19]
	}
	role += "_v2_" + strings.ReplaceAll(newManagementID(), "-", "")[:16]

	a := &contractionAdmission{
		snapshot: managementAdmission{
			conn: conn, source: predecessor, oldRole: cfg.RuntimeRole, targetRole: role, backup: &meta,
			backupDigest: report.MetadataSHA256, artifactDigest: artifact.Digest,
			executableDigest: artifact.Executable, databaseIdentity: identity, active: true,
		},
		restoreReceipt: restored.RestoreReceipt,
	}
	defer func() { a.snapshot.active = false }()
	options.RuntimeRole, options.contraction = role, a
	options.Schemas, options.Grants = schema.AtVersion(target)
	return Apply(ctx, conn, build, options)
}

func guardContraction(ctx context.Context, tx pgx.Tx, conn *pgx.Conn, options Options) error {
	a := options.contraction
	if a == nil || !a.snapshot.active || a.snapshot.conn != conn || a.snapshot.artifactDigest == "" {
		return ErrContractionRequired
	}
	predecessor := schema.ContractionVersion - 1
	schemas, _ := schema.AtVersion(predecessor)
	switch a.snapshot.source {
	case predecessor:
		if a.snapshot.targetRole != options.RuntimeRole || a.snapshot.oldRole == options.RuntimeRole ||
			a.snapshot.executableDigest == "" || !restoreDigest.MatchString(a.restoreReceipt) {
			return ErrContractionRequired
		}
		if err := checkManagementSnapshot(ctx, tx, conn, &a.snapshot); err != nil {
			return err
		}
		if _, _, err := readyCTR06Admission(ctx, tx, a.snapshot.oldRole); err != nil ||
			requireManagementReady(ctx, tx) != nil || requireLifecycleReady(ctx, tx) != nil {
			return ErrContractionRequired
		}
		retired, err := fenceManagementWritersIn(ctx, tx, a.snapshot.oldRole, schemas)
		if err != nil {
			return err
		}
		a.snapshot.retiredDigest = retired
		if err := createManagementRoles(ctx, tx, options.RuntimeRole); err != nil {
			return err
		}
	case 0:
		if c := options.localRestore; c != nil {
			if !c.active || c.conn != conn || c.contractionArtifact != a.snapshot.artifactDigest ||
				managementPendingRestore(ctx, tx, conn, options.RuntimeRole, c) != nil {
				return ErrContractionRequired
			}
		} else if _, _, err := readyCTR06Admission(ctx, tx, options.RuntimeRole); err != nil ||
			requireManagementReady(ctx, tx) != nil || requireLifecycleReady(ctx, tx) != nil {
			return ErrContractionRequired
		}
		retired, err := fenceManagementWritersIn(ctx, tx, options.RuntimeRole, schemas)
		if err != nil {
			return err
		}
		a.snapshot.retiredDigest = retired
	default:
		return ErrContractionRequired
	}
	if err := refuseRetiredReaders(ctx, tx, ""); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "SET LOCAL TIME ZONE 'UTC'; SELECT set_config('arcforges.contraction_admitted','17',true)")
	return err
}

func refuseRetiredReaders(ctx context.Context, q Querier, predecessor string) error {
	var accessible bool
	err := q.QueryRow(ctx, `WITH RECURSIVE retired AS (
 SELECT c.oid, c.relowner, c.relacl FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE (n.nspname,c.relname) IN (('fleet','routed_call'),('fleet','routed_file_call'),
 ('fleet','routed_file_target'),('fleet','routed_command_id'),('fleet','refusal_code'),('identity','mobile_authorization'))
), reach(actor, effective) AS (
 SELECT oid,oid FROM pg_roles
 UNION
 SELECT reach.actor,m.roleid FROM reach JOIN pg_auth_members m ON m.member=reach.effective WHERE m.set_option
)
 SELECT EXISTS(SELECT 1 FROM retired c,LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
  WHERE a.grantee=0 AND a.privilege_type='SELECT')
 OR EXISTS(SELECT 1 FROM retired c CROSS JOIN reach JOIN pg_roles r ON r.oid=reach.actor
  WHERE r.oid<>c.relowner AND NOT r.rolsuper AND r.rolname !~ '^pg_'
    AND ($1::text='' OR r.rolname NOT IN ($1::text,$1::text||'_a',$1::text||'_b'))
    AND (has_database_privilege(r.oid,current_database(),'CONNECT') OR EXISTS(
      SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database() AND a.usesysid=r.oid))
    AND (has_table_privilege(reach.effective,c.oid,'SELECT') OR has_any_column_privilege(reach.effective,c.oid,'SELECT')))`, predecessor).Scan(&accessible)
	if err != nil || accessible {
		return ErrContractionRequired
	}
	return nil
}

func recordContraction(ctx context.Context, tx pgx.Tx, conn *pgx.Conn, options Options) error {
	if options.localRestore != nil {
		return nil
	}
	a := options.contraction
	if a == nil || !a.snapshot.active || a.snapshot.conn != conn || a.snapshot.retiredDigest == "" {
		return ErrContractionRequired
	}
	if a.snapshot.source != 0 {
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
	return appendContractionReceipt(ctx, tx, a.snapshot.source, a.snapshot.artifactDigest,
		a.snapshot.backupDigest, a.snapshot.retiredDigest, a.restoreReceipt)
}

func appendContractionReceipt(ctx context.Context, tx pgx.Tx, source int, artifact, backup, retired, witness string) error {
	if backup == "" {
		backup = ctr06SHA([]byte("genuinely fresh contracted store: no predecessor backup"))
	}
	tag, err := tx.Exec(ctx, `INSERT INTO management.cutover_receipt
 (cutover_id,source_schema,target_schema,database_identity_sha256,artifact_manifest_sha256,backup_manifest_sha256,retired_writer_set_sha256,phase,recorded_at,ready_at,contraction_restore_sha256)
 SELECT gen_random_uuid(),$1,$2,sha256(convert_to((SELECT system_identifier::text FROM pg_control_system())||':'||d.oid||':'||d.datdba,'UTF8')),
 decode($3,'hex'),decode($4,'hex'),decode($5,'hex'),4,clock_timestamp(),clock_timestamp(),decode(nullif($6,''),'hex')
 FROM pg_database d WHERE d.datname=current_database() AND d.datdba=(SELECT oid FROM pg_roles WHERE rolname=current_user)`,
		source, schema.ContractionVersion, artifact, backup, retired, witness)
	if err != nil || tag.RowsAffected() != 1 {
		return ErrContractionRequired
	}
	return nil
}

func finishContractionRestore(ctx context.Context, tx pgx.Tx, conn *pgx.Conn, runtimeRole, sourceRole string, c *restoreCapability) error {
	if c == nil || !c.active || c.conn != conn || c.contractionArtifact == "" || requireCTR06RestoreIsolation(ctx, tx) != nil {
		return ErrContractionRequired
	}
	retired := ctr06SHA([]byte("contracted restore excludes source runtime generation:" + sourceRole + ":" + runtimeRole))
	return appendContractionReceipt(ctx, tx, 0, c.contractionArtifact, c.metadataSHA256, retired, "")
}
