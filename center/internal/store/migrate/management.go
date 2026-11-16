// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/ArcForges/Cloud/center/internal/buildinfo"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/jackc/pgx/v5"
)

// ErrManagementTransitionRequired refuses a naked 0012 on an existing database.
var ErrManagementTransitionRequired = errors.New("V2 storage requires a checked backup and same-invocation writer-fenced maintenance transition")

// ErrManagementSuccessorUnqualified keeps the obsolete published bridge and
// hosted proof from becoming a maintenance admission. This path accepts neither.
var ErrManagementSuccessorUnqualified = errors.New("the obsolete bridge or publisher proof cannot qualify the finite V2 maintenance transition")

type managementAdmission struct {
	conn             *pgx.Conn
	source           int
	oldRole          string
	backup           *ctr06BackupMetadata
	backupDigest     string
	artifactDigest   string
	retiredDigest    string
	active           bool
	databaseIdentity string
	targetRole       string
	executableDigest string
	sourceLabel      string
	legacyRoleOID    uint32
	floorEstablished bool
}

func requireManagementReady(ctx context.Context, q Querier) error {
	var ready bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM management.cutover_receipt c,pg_database d
 WHERE d.datname=current_database() AND c.phase=4 AND c.target_schema=12
 AND c.database_identity_sha256=sha256(convert_to((SELECT system_identifier::text FROM pg_control_system())||':'||d.oid||':'||d.datdba,'UTF8')))`).Scan(&ready)
	if err != nil || !ready {
		return ErrManagementTransitionRequired
	}
	return nil
}

// loadCTR06Build keeps historical backup/restore mechanics on their exact
// supported 0001..0011 prefix. Appending V2 must not silently alter that format.
func loadCTR06Build() ([]Migration, error) {
	build, err := Load(schema.Migrations())
	if err != nil || len(build) < 11 || build[10].Name != "0011_fleet_routed_files.sql" {
		return nil, ErrRefused
	}
	return build[:11], nil
}

func ctr06Schemas() []string { schemas, _ := schema.AtVersion(11); return schemas }

type managementArtifactIdentity struct{ Digest, Executable, Source string }

func managementArtifact(runner string, migration Migration) (string, error) {
	identity, err := readManagementArtifact(runner, migration)
	return identity.Digest, err
}

func readManagementArtifact(runner string, migration Migration) (managementArtifactIdentity, error) {
	path, err := os.Executable()
	if err != nil {
		return managementArtifactIdentity{}, ErrManagementTransitionRequired
	}
	file, err := os.Open(path)
	if err != nil {
		return managementArtifactIdentity{}, ErrManagementTransitionRequired
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 256<<20 {
		return managementArtifactIdentity{}, ErrManagementTransitionRequired
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(file, 256<<20+1))
	if err != nil || n != info.Size() {
		return managementArtifactIdentity{}, ErrManagementTransitionRequired
	}
	// This binds actual local bytes and the supplied build label. It is an
	// identity receipt, not a signature or claim of protected publication.
	executable := hex.EncodeToString(h.Sum(nil))
	document, err := buildinfo.Document("not-probed", buildinfo.Center{})
	if err != nil {
		return managementArtifactIdentity{}, ErrManagementTransitionRequired
	}
	source := document.Revision
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" && document.Build.SourceCommit == "local" {
				source = setting.Value
				if document.Build.Dirty {
					source += "-dirty"
				}
			}
		}
	}
	raw, _ := json.Marshal(struct{ Executable, Source, Compiler, OS, Arch, Runner, Migration string }{executable, source, runtime.Version(), runtime.GOOS, runtime.GOARCH, runner, migration.SHA256})
	return managementArtifactIdentity{ctr06SHA(raw), executable, source}, nil
}

// ApplyManagement expands a checked schema10/11 in finite offline maintenance.
// CaptureLogical produces the real snapshot/archive before writer fencing; its
// full data/sequence/object assertions are rechecked under the writer locks.
// No old bridge is started, and the old publisher proof is never accepted. A
// schema10 floor is established only by its same-call complete writer fence.
func ApplyManagement(ctx context.Context, conn *pgx.Conn, build []Migration, options Options, cfg config.Migration, archivePath, metadataPath string) (Result, error) {
	if options.BridgeProof != nil || cfg.CTR06BridgeExecutable != "" || cfg.CTR06ProofFile != "" {
		return Result{State: StateRefused}, ErrManagementSuccessorUnqualified
	}
	if len(build) != 12 || build[11].Name != "0012_management_storage.sql" {
		return Result{State: StateRefused}, ErrRefused
	}
	options.defaults()
	if err := lock(ctx, conn, options); err != nil {
		return Result{}, err
	}
	defer unlock(conn)
	applied, exists, err := ReadApplied(ctx, conn)
	if err != nil || !exists {
		return Result{State: StateRefused}, ErrManagementTransitionRequired
	}
	sourceVersion := len(applied)
	if (sourceVersion != 10 && sourceVersion != 11) || len(Compare(build[:sourceVersion], applied).Problems) != 0 {
		return Result{State: StateRefused}, ErrRefused
	}
	oldRole := cfg.RuntimeRole
	if sourceVersion == 11 {
		oldRole, _, err = readyCTR06Admission(ctx, conn, cfg.RuntimeRole)
	} else {
		err = requireManagementSchema10Source(ctx, conn, cfg.RuntimeRole)
	}
	if err != nil {
		return Result{State: StateRefused}, err
	}
	parsed, err := pgx.ParseConfig(cfg.URL)
	if err != nil || parsed.Database != conn.Config().Database || parsed.User != conn.Config().User || parsed.Host != conn.Config().Host || parsed.Port != conn.Config().Port {
		return Result{State: StateRefused}, ErrManagementTransitionRequired
	}
	report, err := CaptureLogical(ctx, cfg, archivePath, metadataPath)
	if err != nil {
		return Result{State: StateRefused}, err
	}
	meta, err := ctr06ReadMetadata(metadataPath, report.MetadataSHA256)
	if err != nil {
		return Result{State: StateRefused}, err
	}
	artifact, err := readManagementArtifact(options.Runner, build[11])
	if err != nil {
		return Result{State: StateRefused}, err
	}
	role := oldRole
	if len(role) > 19 {
		role = role[:19]
	}
	role += "_v2_" + strings.ReplaceAll(newManagementID(), "-", "")[:16]
	databaseIdentity, err := managementDatabaseIdentity(ctx, conn)
	if err != nil {
		return Result{State: StateRefused}, err
	}
	if report.SchemaVersion != sourceVersion {
		return Result{State: StateRefused}, ErrManagementTransitionRequired
	}
	a := &managementAdmission{conn: conn, source: sourceVersion, oldRole: oldRole, backup: &meta, backupDigest: report.MetadataSHA256, artifactDigest: artifact.Digest, executableDigest: artifact.Executable, sourceLabel: artifact.Source, databaseIdentity: databaseIdentity, targetRole: role, active: true}
	defer func() { a.active = false }()
	options.RuntimeRole = role
	options.management = a
	result, applyErr := Apply(ctx, conn, build, options)
	if applyErr != nil {
		// 0011 and 0012 remain distinct forward transactions. Report a committed
		// floor honestly; never re-enable the old generation after a later fault.
		if current, exists, readErr := ReadApplied(ctx, conn); readErr == nil && exists {
			result.describe(build, current, true)
		}
	}
	return result, applyErr
}

func newManagementID() string {
	// gen_random_uuid is not needed for the local role nonce.
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(id[:])
}

func guardManagement(ctx context.Context, tx pgx.Tx, conn *pgx.Conn, options Options) error {
	a := options.management
	if a == nil || !a.active || a.conn != conn || a.artifactDigest == "" {
		return ErrManagementTransitionRequired
	}
	if a.source == 0 {
		if c := options.localRestore; c != nil {
			if !c.active || c.conn != conn || requireCTR06RestoreIsolation(ctx, tx) != nil {
				return ErrManagementTransitionRequired
			}
			return nil
		}
		_, _, err := readyCTR06Admission(ctx, tx, options.RuntimeRole)
		return err
	}
	if a.source == 10 {
		return guardManagementAfterSchema11(ctx, tx, conn, options, a)
	}
	if a.source != 11 || a.backup == nil {
		return ErrManagementTransitionRequired
	}
	if _, err := tx.Exec(ctx, "SET LOCAL search_path=pg_catalog; SET LOCAL TIME ZONE 'UTC'"); err != nil {
		return ErrManagementTransitionRequired
	}
	// Drain all legacy application writers, not just receipt writers. The
	// trusted owner/superuser boundary is retained from the existing migrator.
	tables, err := ctr06RequiredTables()
	if err != nil {
		return err
	}
	quoted := make([]string, 0, len(tables))
	for _, table := range tables {
		quoted = append(quoted, pgx.Identifier(strings.Split(table, ".")).Sanitize())
	}
	if _, err = tx.Exec(ctx, "LOCK TABLE "+strings.Join(quoted, ",")+" IN ACCESS EXCLUSIVE MODE"); err != nil {
		return err
	}
	if _, _, err = readyCTR06Admission(ctx, tx, a.oldRole); err != nil {
		return err
	}
	if err = ctr06CheckSchemaOwnership(ctx, tx); err != nil {
		return err
	}
	catalogue, err := ctr06CatalogueSHA(ctx, tx)
	if err != nil || catalogue != a.backup.SourceCatalogueSHA256 {
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
	retired, err := fenceManagementWriters(ctx, tx, a.oldRole)
	if err != nil {
		return err
	}
	a.retiredDigest = retired
	for _, role := range []string{options.RuntimeRole, options.RuntimeRole + "_a", options.RuntimeRole + "_b"} {
		if _, err = tx.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
			return err
		}
	}
	return nil
}

func recordManagement(ctx context.Context, tx pgx.Tx, conn *pgx.Conn, options Options) error {
	if options.localRestore != nil {
		return nil
	} // Source readiness is never copied; final target proof is atomic with restore admission.
	a := options.management
	if a == nil || !a.active || a.conn != conn {
		return ErrManagementTransitionRequired
	}
	if a.source == 11 {
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
		backup = ctr06SHA([]byte("genuinely fresh V2 store: no predecessor backup"))
	}
	retired := a.retiredDigest
	if retired == "" {
		retired = ctr06SHA([]byte("genuinely fresh V2 store: no legacy writers"))
	}
	_, err := tx.Exec(ctx, `INSERT INTO management.cutover_receipt
 (cutover_id,source_schema,target_schema,database_identity_sha256,artifact_manifest_sha256,backup_manifest_sha256,retired_writer_set_sha256,phase,recorded_at,ready_at)
 SELECT gen_random_uuid(),$1,12,sha256(convert_to((SELECT system_identifier::text FROM pg_control_system())||':'||d.oid||':'||d.datdba,'UTF8')),
 decode($2,'hex'),decode($3,'hex'),decode($4,'hex'),4,clock_timestamp(),clock_timestamp()
 FROM pg_database d WHERE d.datname=current_database() AND d.datdba=(SELECT oid FROM pg_roles WHERE rolname=current_user)`, a.source, a.artifactDigest, backup, retired)
	return err
}

func fenceManagementWriters(ctx context.Context, tx pgx.Tx, group string) (string, error) {
	if err := RequirePlainRole(ctx, tx, group, false); err != nil {
		return "", err
	}
	candidates := []string{group, group + "_a", group + "_b"}
	type roleIdentity struct {
		Name string
		OID  uint32
	}
	var identities []roleIdentity
	var oids []uint32
	var names []string
	var groupOID uint32
	for _, name := range candidates {
		var oid uint32
		var login bool
		err := tx.QueryRow(ctx, "SELECT oid,rolcanlogin FROM pg_roles WHERE rolname=$1", name).Scan(&oid, &login)
		if errors.Is(err, pgx.ErrNoRows) && name != group {
			continue
		}
		if err != nil {
			return "", ErrManagementTransitionRequired
		}
		if err := RequirePlainRole(ctx, tx, name, login); err != nil {
			return "", err
		}
		if name == group {
			groupOID = oid
		} else {
			var member, reserved bool
			err := tx.QueryRow(ctx, `SELECT pg_has_role($1::oid,$2::oid,'MEMBER'),
    NOT $3::boolean AND EXISTS(SELECT 1 FROM pg_auth_members WHERE roleid=$1::oid
     AND member=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND admin_option)
    AND NOT EXISTS(SELECT 1 FROM platform.runtime_credential WHERE login_role=$4)`, oid, groupOID, login, name).Scan(&member, &reserved)
			if err != nil || (!member && !reserved) {
				return "", ErrManagementTransitionRequired
			}
		}
		identities = append(identities, roleIdentity{name, oid})
		oids = append(oids, oid)
		names = append(names, name)
	}
	var unsafe bool
	err := tx.QueryRow(ctx, `WITH RECURSIVE reach(actor,memberof) AS (
 SELECT oid,oid FROM pg_roles UNION SELECT reach.actor,m.roleid FROM reach JOIN pg_auth_members m ON m.member=reach.memberof)
 SELECT EXISTS(SELECT 1 FROM platform.runtime_credential WHERE login_role<>ALL($1::text[]))
 OR EXISTS(SELECT 1 FROM pg_stat_activity WHERE usesysid=ANY($2::oid[]) AND pid<>pg_backend_pid())
 OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member=ANY($2::oid[]) AND NOT(member<>$4::oid AND roleid=$4::oid))
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace,
 LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) acl
 WHERE n.nspname=ANY($3::text[]) AND acl.grantee=0 AND acl.privilege_type IN('INSERT','UPDATE','DELETE','TRUNCATE'))
 OR EXISTS(SELECT 1 FROM reach JOIN pg_roles actor ON actor.oid=reach.actor JOIN pg_roles reachable ON reachable.oid=reach.memberof
 WHERE actor.rolname<>current_user AND actor.rolname !~ '^pg_' AND NOT actor.rolsuper AND NOT actor.oid=ANY($2::oid[])
 AND (reachable.rolsuper OR reachable.rolname=current_user OR reachable.oid=ANY($2::oid[]) OR EXISTS(
 SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=ANY($3::text[])
 AND c.relkind IN('r','p') AND (has_table_privilege(reachable.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE') OR has_any_column_privilege(reachable.oid,c.oid,'INSERT,UPDATE')))))`, names[1:], oids, []string{"platform", "audit", "fleet", "identity", "device", "entitlement"}, groupOID).Scan(&unsafe)
	if err != nil || unsafe {
		return "", ErrManagementTransitionRequired
	}
	for _, name := range names {
		quoted := pgx.Identifier{name}.Sanitize()
		for _, s := range []string{"platform", "audit", "fleet", "identity", "device", "entitlement"} {
			schemaName := pgx.Identifier{s}.Sanitize()
			for _, statement := range []string{"REVOKE ALL ON ALL TABLES IN SCHEMA " + schemaName + " FROM " + quoted, "REVOKE ALL ON ALL SEQUENCES IN SCHEMA " + schemaName + " FROM " + quoted, "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA " + schemaName + " FROM " + quoted, "REVOKE ALL ON SCHEMA " + schemaName + " FROM " + quoted} {
				if _, err := tx.Exec(ctx, statement); err != nil {
					return "", err
				}
			}
		}
		if _, err := tx.Exec(ctx, "ALTER ROLE "+quoted+" NOLOGIN PASSWORD NULL"); err != nil {
			return "", err
		}
		if name != group {
			if _, err := tx.Exec(ctx, "REVOKE "+pgx.Identifier{group}.Sanitize()+" FROM "+quoted); err != nil {
				return "", err
			}
		}
	}
	var database string
	if err := tx.QueryRow(ctx, "SELECT current_database()").Scan(&database); err != nil {
		return "", err
	}
	for _, name := range names {
		if _, err := tx.Exec(ctx, "REVOKE CONNECT,TEMPORARY ON DATABASE "+pgx.Identifier{database}.Sanitize()+" FROM "+pgx.Identifier{name}.Sanitize()); err != nil {
			return "", err
		}
	}
	raw, _ := json.Marshal(identities)
	return ctr06SHA(raw), nil
}
