// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/jackc/pgx/v5"
)

const restoreTOCMax = 16 * 1024 * 1024

var restoreDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var restoreTOCID = regexp.MustCompile(`^[0-9]+;$`)

// restoreList preserves the input order and every unrelated archive entry. The
// fresh destination already owns the six schemas and its protected floor; the
// exact floor and admission tables, data and primary keys are the only object exclusions.
func restoreList(raw []byte, schemas []string) ([]byte, error) {
	if len(raw) == 0 || len(raw) > restoreTOCMax {
		return nil, errors.New("restore archive table of contents is unavailable or too large")
	}
	expected := make(map[string]int, len(schemas)+6)
	for _, name := range schemas {
		if _, duplicate := expected["schema:"+name]; duplicate || name == "" {
			return nil, errors.New("invalid restore schema inventory")
		}
		expected["schema:"+name] = 0
	}
	for _, key := range []string{"floor:table", "floor:data", "floor:primary-key", "admission:table", "admission:data", "admission:primary-key"} {
		expected[key] = 0
	}
	seenIDs := map[string]bool{}
	var output bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), restoreTOCMax)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, ";") || strings.TrimSpace(line) == "" {
			fmt.Fprintln(&output, line)
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 || !restoreTOCID.MatchString(fields[0]) || seenIDs[fields[0]] {
			return nil, errors.New("invalid or duplicate restore archive entry")
		}
		seenIDs[fields[0]] = true
		item := fields[3:]
		key := ""
		if len(item) == 4 && item[0] == "SCHEMA" && item[1] == "-" {
			if _, ok := expected["schema:"+item[2]]; ok {
				key = "schema:" + item[2]
			}
		} else {
			for name, prefix := range map[string]string{"ctr06_runtime_floor": "floor", "ctr06_restore_admission": "admission"} {
				switch {
				case len(item) == 4 && item[0] == "TABLE" && item[1] == "platform" && item[2] == name:
					key = prefix + ":table"
				case len(item) == 5 && item[0] == "TABLE" && item[1] == "DATA" && item[2] == "platform" && item[3] == name:
					key = prefix + ":data"
				case len(item) == 5 && item[0] == "CONSTRAINT" && item[1] == "platform" && item[2] == name && item[3] == name+"_pkey":
					key = prefix + ":primary-key"
				}
			}
		}
		if key != "" {
			expected[key]++
			if expected[key] != 1 {
				return nil, errors.New("duplicate protected restore object")
			}
			continue
		}
		for _, token := range item {
			if token == "ctr06_runtime_floor" || token == "ctr06_runtime_floor_pkey" ||
				token == "ctr06_restore_admission" || token == "ctr06_restore_admission_pkey" {
				return nil, errors.New("unexpected protected restore object")
			}
		}
		fmt.Fprintln(&output, line)
	}
	if scanner.Err() != nil {
		return nil, errors.New("restore archive table of contents cannot be read")
	}
	for _, count := range expected {
		if count != 1 {
			return nil, errors.New("restore archive is missing a protected object")
		}
	}
	return output.Bytes(), nil
}

// A backup is an administrator-selected privileged input. Its expected digest
// is required; only the verified private copy is ever given to pg_restore.
func copyRestoreBackup(path, expected, dir string) (*os.File, error) {
	if !filepath.IsAbs(path) || !restoreDigest.MatchString(expected) {
		return nil, errors.New("an absolute backup path and its SHA-256 are required")
	}
	input, err := os.Open(path)
	if err != nil {
		return nil, errors.New("the backup could not be opened")
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("the backup is not a regular file")
	}
	copyFile, err := os.OpenFile(filepath.Join(dir, "archive"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, errors.New("the private backup could not be created")
	}
	failed := true
	defer func() {
		if failed {
			_ = copyFile.Close()
		}
	}()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(copyFile, hash), input)
	if err != nil || n == 0 || hex.EncodeToString(hash.Sum(nil)) != expected {
		return nil, errors.New("the private backup does not match its expected SHA-256")
	}
	if err := copyFile.Sync(); err != nil {
		return nil, errors.New("the private backup could not be synchronized")
	}
	if _, err := copyFile.Seek(0, io.SeekStart); err != nil {
		return nil, errors.New("the private backup could not be rewound")
	}
	failed = false
	return copyFile, nil
}

// The connection URL is never put in command arguments or output. libpq gets
// only explicitly constructed PG settings and the credential in its private
// child environment; inherited PGOPTIONS/PGSERVICE cannot change the target.
func restorePGEnvironment(raw string) ([]string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil || u.Hostname() == "" || len(u.Path) < 2 {
		return nil, errors.New("the restore database connection is invalid")
	}
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	password, _ := u.User.Password()
	env := []string{}
	for _, key := range []string{"PATH", "SYSTEMROOT", "WINDIR", "HOME", "TMPDIR", "TEMP", "TMP"} {
		if value := os.Getenv(key); value != "" {
			env = append(env, key+"="+value)
		}
	}
	env = append(env, "PGHOST="+u.Hostname(), "PGPORT="+port, "PGUSER="+u.User.Username(),
		"PGPASSWORD="+password, "PGDATABASE="+u.Path[1:], "PGSSLMODE="+u.Query().Get("sslmode"))
	if u.Query().Get("sslmode") == "verify-full" {
		env = append(env, "PGSSLROOTCERT=system")
	}
	if value := u.Query().Get("channel_binding"); value != "" {
		env = append(env, "PGCHANNELBINDING="+value)
	}
	if value := u.Query().Get("connect_timeout"); value != "" {
		env = append(env, "PGCONNECT_TIMEOUT="+value)
	}
	return env, nil
}

type boundedRestoreOutput struct{ data bytes.Buffer }

func (w *boundedRestoreOutput) Write(p []byte) (int, error) {
	if w.data.Len()+len(p) > restoreTOCMax {
		return 0, errors.New("restore table of contents exceeds the limit")
	}
	return w.data.Write(p)
}

func runRestoreTool(ctx context.Context, tool string, env []string, archive *os.File, args ...string) ([]byte, error) {
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return nil, errors.New("the verified backup cannot be rewound")
	}
	command := exec.CommandContext(ctx, tool, args...)
	command.Env, command.Stdin, command.Stderr = env, archive, io.Discard
	command.WaitDelay = 5 * time.Second
	var output boundedRestoreOutput
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return nil, errors.New("pg_restore did not complete")
	}
	return output.data.Bytes(), nil
}

// Decompress and read the complete protected archive without executing its
// SQL. Output and stderr are discarded because the archive is privileged.
func ctr06ArchiveIntegrity(ctx context.Context, tool string, env []string, archive *os.File) error {
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return errors.New("the protected backup cannot be rewound")
	}
	command := exec.CommandContext(ctx, tool, "--file=-", "--no-owner", "--no-acl")
	command.Env, command.Stdin, command.Stdout, command.Stderr = env, archive, io.Discard, io.Discard
	command.WaitDelay = 5 * time.Second
	if err := command.Run(); err != nil {
		return errors.New("the complete backup archive is corrupt or unreadable")
	}
	return nil
}

// The owned child has returned from Wait (or could not start). Its database
// session can outlive a lost client or a delayed COMMIT, so account for all
// non-superuser target connections with a bounded independent context. Never
// terminate an unknown backend or infer rollback from the child exit alone.
func ctr06RestoreChildFailure(conn *pgx.Conn, targetState string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		var remaining bool
		err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity a JOIN pg_roles r ON r.oid=a.usesysid
 WHERE a.datname=current_database() AND a.pid<>pg_backend_pid() AND NOT r.rolsuper)`).Scan(&remaining)
		if err == nil && !remaining {
			return fmt.Errorf("restore child did not complete; remaining target connections were not observed; target outcome UNKNOWN and remains %s; preserve it", targetState)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("restore child did not complete; target connections are unresolved; target outcome UNKNOWN and remains %s; preserve it", targetState)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// The same connection observes the fresh floor, triggers and definer routines
// before and after the restore. OIDs in a logical archive are never authority.
func restoreSecuritySnapshot(ctx context.Context, conn *pgx.Conn) (string, string, error) {
	var floor, security string
	err := conn.QueryRow(ctx, `SELECT jsonb_build_array(to_jsonb(f),to_jsonb(a))::text
 FROM platform.ctr06_runtime_floor f JOIN platform.ctr06_restore_admission a ON a.singleton=f.singleton WHERE f.singleton`).Scan(&floor)
	if err != nil {
		return "", "", errors.New("the destination runtime floor is unavailable")
	}
	err = conn.QueryRow(ctx, `SELECT jsonb_build_object(
 'definers', coalesce((SELECT jsonb_agg(jsonb_build_array(n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),
          pg_get_userbyid(p.proowner),pg_get_functiondef(p.oid)) ORDER BY n.nspname,p.proname,pg_get_function_identity_arguments(p.oid))
  FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE p.prosecdef AND n.nspname !~ '^pg_' AND n.nspname<>'information_schema'),'[]'::jsonb),
 'triggers', coalesce((SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,t.tgname,pg_get_triggerdef(t.oid))
          ORDER BY n.nspname,c.relname,t.tgname)
  FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE NOT t.tgisinternal AND n.nspname=ANY($1)),'[]'::jsonb))::text`, schema.Schemas).Scan(&security)
	if err != nil {
		return "", "", errors.New("the destination security schema is unavailable")
	}
	return floor, security, nil
}

// Reject additional roles, inherited/SET ROLE paths and live non-owner sessions
// even when CONNECT is currently revoked. Only the newly created group and
// its passwordless slots may receive target privileges after reconciliation.
func checkRestoreIsolation(ctx context.Context, conn Querier, role string) error {
	for _, name := range []string{role, role + "_a", role + "_b"} {
		if err := RequirePlainRole(ctx, conn, name, false); err != nil {
			return errors.New("a destination runtime role is not a fresh passwordless group")
		}
	}
	var unsafe bool
	err := conn.QueryRow(ctx, `WITH RECURSIVE reach(actor, memberof) AS (
 SELECT oid,oid FROM pg_roles UNION SELECT reach.actor,m.roleid FROM reach JOIN pg_auth_members m ON m.member=reach.memberof
), owner AS (SELECT oid FROM pg_roles WHERE rolname=current_user)
SELECT
 EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid,owner
   WHERE parent.rolname IN ($1::text,$1::text||'_a',$1::text||'_b') AND m.member<>owner.oid)
 OR EXISTS(SELECT 1 FROM pg_stat_activity a JOIN pg_roles r ON r.oid=a.usesysid,owner
   WHERE a.datname=current_database() AND a.pid<>pg_backend_pid() AND NOT r.rolsuper)
 OR EXISTS(SELECT 1 FROM pg_database d,aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a
   WHERE d.datname=current_database() AND a.grantee=0 AND a.privilege_type IN ('CONNECT','TEMPORARY'))
 OR EXISTS(SELECT 1 FROM pg_roles actor JOIN reach r ON r.actor=actor.oid JOIN pg_roles reachable ON reachable.oid=r.memberof,owner
   WHERE actor.oid<>owner.oid AND NOT actor.rolsuper AND actor.rolname !~ '^pg_' AND actor.rolname NOT IN ($1::text,$1::text||'_a',$1::text||'_b')
   AND (has_table_privilege(reachable.oid,'fleet.routed_call','INSERT,UPDATE,DELETE,TRUNCATE') OR
        has_table_privilege(reachable.oid,'fleet.routed_file_call','INSERT,UPDATE,DELETE,TRUNCATE') OR
        has_table_privilege(reachable.oid,'fleet.routed_command_id','INSERT,UPDATE,DELETE,TRUNCATE') OR
        has_table_privilege(reachable.oid,'fleet.routed_file_target','INSERT,UPDATE,DELETE,TRUNCATE') OR
        has_table_privilege(reachable.oid,'fleet.hub_lease','INSERT,UPDATE,DELETE,TRUNCATE')))`, role).Scan(&unsafe)
	if err != nil || unsafe {
		return errors.New("the destination has an unknown writer, membership or connection")
	}
	return nil
}

type RestoreReport struct {
	Database           string `json:"database"`
	RuntimeRole        string `json:"runtimeRole"`
	SourceBackupSHA256 string `json:"sourceBackupSha256"`
	TargetFloorSHA256  string `json:"targetFloorSha256"`
	SchemaVersion      int    `json:"schemaVersion"`
	RestoreReceipt     string `json:"restoreReceipt"`
}

// RestoreLogical admits only a supported 0011 backup with its protected
// same-snapshot metadata. The original archive is never modified, and a
// destination is created only after the complete preflight checks succeed.
func RestoreLogical(ctx context.Context, cfg config.Migration, archivePath, expected, metadataPath, metadataDigest, runner string) (report RestoreReport, finalErr error) {
	archiveCommitted, admissionReady := false, false
	defer func() {
		if finalErr != nil && archiveCommitted && !admissionReady {
			finalErr = fmt.Errorf("the archive transaction committed; destination admission outcome UNKNOWN; preserve and inspect it: %w", finalErr)
		}
	}()
	if cfg.CTR06BridgeExecutable != "" || cfg.CTR06ProofFile != "" {
		return report, errors.New("a restore cannot use a bridge promotion proof")
	}
	if err := ValidRoleName(cfg.RuntimeRole); err != nil {
		return report, err
	}
	if !filepath.IsAbs(metadataPath) {
		return report, errors.New("an absolute trusted backup metadata path is required")
	}
	maintenanceURL, err := url.Parse(cfg.Maintenance)
	if err != nil || strings.TrimPrefix(maintenanceURL.Path, "/") == cfg.Database {
		return report, errors.New("a distinct maintenance database and fresh destination are required")
	}
	build, err := Load(schema.Migrations())
	if err != nil || len(build) != 11 || build[10].Name != "0011_fleet_routed_files.sql" {
		return report, errors.New("the supported migration build is unavailable")
	}
	metadata, err := ctr06ReadMetadata(metadataPath, metadataDigest)
	if err != nil {
		return report, err
	}
	if err := ctr06ValidateMetadata(metadata, build); err != nil || metadata.ArchiveSHA256 != expected {
		return report, errors.New("the trusted metadata does not admit this supported backup")
	}
	tool, err := ctr06NativeTool("pg_restore")
	if err != nil {
		return report, err
	}
	dir, closeDir, err := restoreScratch()
	if err != nil {
		return report, errors.New("a private restore workspace is unavailable")
	}
	defer func() {
		if err := closeDir(); err != nil {
			finalErr = errors.Join(finalErr, errors.New("private restore workspace cleanup failed"))
		}
	}()
	archive, err := copyRestoreBackup(archivePath, expected, dir)
	if err != nil {
		return report, err
	}
	defer archive.Close()
	info, err := archive.Stat()
	if err != nil || info.Size() != metadata.ArchiveLength {
		return report, errors.New("the backup length does not match its trusted metadata")
	}
	childEnv, err := restorePGEnvironment(cfg.URL)
	if err != nil {
		return report, err
	}
	raw, err := runRestoreTool(ctx, tool, childEnv, archive, "--list")
	if err != nil || ctr06SHA(raw) != metadata.ArchiveTOCSHA256 {
		return report, errors.New("the backup inventory does not match its trusted metadata")
	}
	if err := ctr06ArchiveInventory(raw, metadata.LargeObjects); err != nil {
		return report, err
	}
	selected, err := restoreList(raw, schema.Schemas)
	if err != nil {
		return report, err
	}
	sequences, err := ctr06ArchiveFacts(ctx, tool, childEnv, archive, build)
	if err != nil || !reflect.DeepEqual(sequences, metadata.Sequences) {
		return report, errors.New("the archive history or sequence assertions do not match")
	}
	if err := ctr06ArchiveIntegrity(ctx, tool, childEnv, archive); err != nil {
		return report, err
	}
	listPath := filepath.Join(dir, "restore-list")
	if err := os.WriteFile(listPath, selected, 0o600); err != nil {
		return report, errors.New("the private restore list could not be written")
	}
	conn, err := createRestoreTarget(ctx, cfg)
	if err != nil {
		return report, err
	}
	defer conn.Close(context.Background())
	capability, err := newRestoreCapability(ctx, conn, expected, metadataDigest)
	if err != nil {
		return report, errors.New("the destination recovery identity could not be established")
	}
	defer capability.destroy()
	options := Options{Runner: runner, RuntimeRole: cfg.RuntimeRole, LockTimeout: cfg.LockTimeout, localRestore: capability}
	initial, err := Apply(ctx, conn, build, options)
	if err != nil || initial.State != StateCurrent || initial.Grants != "" {
		return report, errors.New("the fresh destination 0011 admission outcome is UNKNOWN; preserve it for investigation")
	}
	if err := checkRestoreIsolation(ctx, conn, cfg.RuntimeRole); err != nil {
		return report, err
	}
	floor, security, err := restoreSecuritySnapshot(ctx, conn)
	if err != nil {
		return report, err
	}
	var owner string
	if err := conn.QueryRow(ctx, "SELECT current_user").Scan(&owner); err != nil || owner == "" {
		return report, errors.New("the destination owner is unavailable")
	}
	if _, err := runRestoreTool(ctx, tool, childEnv, archive, "--single-transaction", "--exit-on-error", "--no-owner", "--no-acl", "--role="+owner, "--clean", "--if-exists", "--use-list="+listPath, "--dbname="+cfg.Database); err != nil {
		return report, ctr06RestoreChildFailure(conn, "quarantined")
	}
	archiveCommitted = true
	newFloor, newSecurity, err := restoreSecuritySnapshot(ctx, conn)
	if err != nil || floor != newFloor || security != newSecurity {
		return report, errors.New("the restored security schema or quarantined destination floor differs; preserve the target")
	}
	if err := checkRestoreIsolation(ctx, conn, cfg.RuntimeRole); err != nil {
		return report, err
	}
	verification, err := ctr06VerifyRestoredData(ctx, conn, metadata, build)
	if err != nil {
		return report, err
	}
	receipt, err := finalizeCTR06Restore(ctx, conn, cfg.RuntimeRole, metadata.SourceRuntimeRole, verification, capability)
	if err != nil {
		return report, errors.New("the verified restore could not commit readiness; target outcome UNKNOWN; preserve it for investigation")
	}
	admissionReady = true
	status, err := Inspect(ctx, conn, build)
	if err != nil || status.State != StateCurrent || len(status.Pending) != 0 || status.RuntimeRole != cfg.RuntimeRole || status.RestoreReceipt != receipt {
		return report, errors.New("restore readiness committed, but its checked status could not be confirmed; inspect the receipt")
	}
	options.localRestore = nil
	reconciled, err := Apply(ctx, conn, build, options)
	if err != nil || reconciled.State != StateCurrent || len(reconciled.Ran) != 0 || reconciled.Grants != "reconciled" {
		return report, errors.New("restore readiness committed, but destination grants could not be reconciled; inspect the receipt")
	}
	if err := checkRestoreIsolation(ctx, conn, cfg.RuntimeRole); err != nil {
		return report, err
	}
	digest := sha256.Sum256([]byte(floor))
	return RestoreReport{Database: cfg.Database, RuntimeRole: cfg.RuntimeRole, SourceBackupSHA256: expected,
		TargetFloorSHA256: hex.EncodeToString(digest[:]), SchemaVersion: status.Version, RestoreReceipt: receipt}, nil
}

// createRestoreTarget owns only a previously absent target. It verifies the
// complete effective connection ACL while connections are disabled and never
// adopts or removes resources left by another invocation.
func createRestoreTarget(ctx context.Context, cfg config.Migration) (*pgx.Conn, error) {
	maintenance, err := restoreConnect(ctx, cfg.Maintenance)
	if err != nil {
		return nil, errors.New("the maintenance database could not be reached")
	}
	defer maintenance.Close(context.Background())
	var occupied, ownerShared bool
	err = maintenance.QueryRow(ctx, `WITH RECURSIVE reach(actor,memberof) AS (
 SELECT oid,oid FROM pg_roles UNION SELECT reach.actor,m.roleid FROM reach JOIN pg_auth_members m ON m.member=reach.memberof
), owner AS (SELECT oid FROM pg_roles WHERE rolname=current_user)
SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1) OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN ($2::text,$2::text||'_a',$2::text||'_b')),
 EXISTS(SELECT 1 FROM reach JOIN pg_roles actor ON actor.oid=reach.actor,owner
  WHERE reach.memberof=owner.oid AND actor.oid<>owner.oid AND NOT actor.rolsuper AND actor.rolname !~ '^pg_')`, cfg.Database, cfg.RuntimeRole).Scan(&occupied, &ownerShared)
	if err != nil {
		return nil, Sanitize("check the destination role graph", err)
	}
	if occupied {
		return nil, errors.New("the destination or a runtime role already exists")
	}
	if ownerShared {
		return nil, errors.New("the migration owner has unknown members")
	}
	db := pgx.Identifier{cfg.Database}.Sanitize()
	for _, statement := range []string{
		"CREATE DATABASE " + db + " ALLOW_CONNECTIONS false",
		// The database is still closed if the process dies before this comment.
		// The marker only refuses ordinary tools; it never authorizes resumption.
		"COMMENT ON DATABASE " + db + " IS '" + ctr06RestoreIsolationMarker + "'",
		"REVOKE CONNECT, TEMPORARY ON DATABASE " + db + " FROM PUBLIC",
	} {
		if _, err := maintenance.Exec(ctx, statement); err != nil {
			return nil, errors.New("the fresh destination could not be created and isolated; preserve it for investigation")
		}
	}
	// Examine inherited access before allowing the first connection. The
	// owner and PostgreSQL superusers are the administrative trust boundary.
	var targetSafe bool
	err = maintenance.QueryRow(ctx, `SELECT NOT d.datallowconn
 AND pg_catalog.shobj_description(d.oid,'pg_database')=$2
 AND d.datdba=(SELECT oid FROM pg_roles WHERE rolname=current_user)
 AND NOT EXISTS (SELECT 1 FROM aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a
   WHERE a.grantee=0 AND a.privilege_type IN ('CONNECT','TEMPORARY'))
 AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.oid<>d.datdba AND NOT r.rolsuper
   AND (has_database_privilege(r.oid,d.oid,'CONNECT') OR has_database_privilege(r.oid,d.oid,'TEMPORARY')))
 FROM pg_database d WHERE d.datname=$1`, cfg.Database, ctr06RestoreIsolationMarker).Scan(&targetSafe)
	if err != nil || !targetSafe {
		return nil, errors.New("the destination ACL is not isolated; preserve it for investigation")
	}
	if _, err := maintenance.Exec(ctx, "ALTER DATABASE "+db+" ALLOW_CONNECTIONS true"); err != nil {
		return nil, errors.New("the isolated destination could not be enabled; preserve it for investigation")
	}
	conn, err := restoreConnect(ctx, cfg.URL)
	if err != nil {
		return nil, errors.New("the fresh destination could not be reached; preserve it for investigation")
	}
	return conn, nil
}

// restoreConnect opens only the already validated direct migration endpoint.
func restoreConnect(ctx context.Context, raw string) (*pgx.Conn, error) {
	c, err := pgx.ParseConfig(raw)
	if err != nil {
		return nil, errors.New("invalid restore connection")
	}
	c.RuntimeParams["application_name"] = "arcforges-center-restore-manager"
	conn, err := pgx.ConnectConfig(ctx, c)
	if err != nil {
		return nil, errors.New("restore connection unavailable")
	}
	return conn, nil
}
