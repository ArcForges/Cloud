// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/provision"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/ArcForges/Cloud/center/internal/store/migrate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func localBridgeFixture(t *testing.T) (string, string, *pgx.Conn, []migrate.Migration, string, *pgx.Conn) {
	t.Helper()
	binary := os.Getenv("ARCFORGES_TEST_CTR06_BRIDGE_BINARY")
	if binary == "" {
		t.Skip("requires the exact independently verified native bridge executable")
	}
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	build, err := migrate.Load(schema.Migrations())
	if err != nil {
		t.Fatal(err)
	}
	var grants []schema.Grant
	for _, grant := range schema.RuntimeGrants {
		if grant.Schema == "fleet" && (grant.Table == "routed_file_call" || grant.Table == "routed_command_id" || grant.Table == "routed_file_target") {
			continue
		}
		grants = append(grants, grant)
	}
	legacy := name + "_runtime"
	if _, err := migrate.Apply(context.Background(), owner, build[:10], migrate.Options{RuntimeRole: legacy, Grants: grants, Schemas: schema.Schemas}); err != nil {
		t.Fatal(err)
	}
	old, err := provision.Rotate(context.Background(), owner, provision.Options{Group: legacy, DirectURL: url, Runner: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provision.Confirm(context.Background(), owner, legacy, old.Slot); err != nil {
		t.Fatal(err)
	}
	oldConn := pgtest.Connect(t, old.RuntimeURL)
	holder := platform.NewID()
	if _, err := oldConn.Exec(context.Background(), `INSERT INTO fleet.hub_lease(singleton,holder,fence,acquired_at,renewed_at,expires_at)
VALUES(true,$1,1,clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '1 hour')`, holder); err != nil {
		t.Fatal(err)
	}
	return url, legacy, owner, build, binary, oldConn
}

func TestCTR06SelfHostedNativeBridgeUpgradeAndRollback(t *testing.T) {
	url, legacy, owner, build, bridge, old := localBridgeFixture(t)
	ctx := context.Background()
	values := map[string]string{
		config.EnvMode: "self-hosted", config.EnvMigrationDatabaseURL: url,
		config.EnvRuntimeRole: legacy, config.EnvCTR06BridgeExecutable: bridge,
	}
	lookup := func(k string) (string, bool) { v, ok := values[k]; return v, ok }
	var stdout, stderr bytes.Buffer
	if code := migration("apply", lookup, &stdout, &stderr); code != exitOK {
		t.Fatalf("self-hosted migration exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var applied migrate.Result
	if err := json.Unmarshal(stdout.Bytes(), &applied); err != nil || applied.Version != 11 || applied.RuntimeRole == legacy {
		t.Fatalf("upgrade result: %+v %v", applied, err)
	}
	finalRole := applied.RuntimeRole
	marker := strings.LastIndex(finalRole, "_n06_")
	if marker < 0 {
		t.Fatalf("unexpected final group %q", finalRole)
	}
	temporaryRole := finalRole[:marker] + "_c06_" + finalRole[marker+len("_n06_"):]
	var preserved, floor, noLiveSlot, temporaryDisabled, finalClean, leaseExpired, noTemporaryBackends bool
	err := owner.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM platform.ctr06_legacy_runtime_credential WHERE login_role=$1||'_a' AND promoted_at IS NOT NULL),
 EXISTS(SELECT 1 FROM platform.ctr06_runtime_floor WHERE runtime_role=$2 AND legacy_role=$1 AND promotion_digest IS NOT NULL),
 NOT EXISTS(SELECT 1 FROM platform.runtime_credential),
 EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$3||'_a' AND NOT rolcanlogin)
   AND NOT has_table_privilege($3,'fleet.routed_call','INSERT')
   AND NOT has_table_privilege($3,'fleet.hub_lease','UPDATE'),
 EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$2 AND NOT rolcanlogin)
   AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$2||'_a' AND NOT rolcanlogin)
   AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$2||'_b' AND NOT rolcanlogin)
   AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE roleid=(SELECT oid FROM pg_roles WHERE rolname=$2) AND member<>(SELECT oid FROM pg_roles WHERE rolname=current_user)),
 EXISTS(SELECT 1 FROM fleet.hub_lease WHERE expires_at<=clock_timestamp()),
 NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$3||'_a')`, legacy, finalRole, temporaryRole).
		Scan(&preserved, &floor, &noLiveSlot, &temporaryDisabled, &finalClean, &leaseExpired, &noTemporaryBackends)
	if err != nil || !preserved || !floor || !noLiveSlot || !temporaryDisabled || !finalClean || !leaseExpired || !noTemporaryBackends {
		t.Fatalf("floor/history/retirement: %v %v %v %v %v %v %v %v", preserved, floor, noLiveSlot, temporaryDisabled, finalClean, leaseExpired, noTemporaryBackends, err)
	}
	_, err = old.Exec(ctx, "UPDATE fleet.hub_lease SET expires_at=clock_timestamp()+interval '1 hour' WHERE singleton")
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("old open connection renewed the lease: %v", err)
	}
	if _, err := provision.Rotate(ctx, owner, provision.Options{Group: legacy, DirectURL: url}); !errors.Is(err, migrate.ErrCTR06RetirementUnproven) {
		t.Fatalf("old admin rotation was not refused: %v", err)
	}
	rotation, err := provision.Rotate(ctx, owner, provision.Options{Group: finalRole, DirectURL: url, Runner: "selfhost-current"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provision.Confirm(ctx, owner, finalRole, rotation.Slot); err != nil {
		t.Fatal(err)
	}
	if result, err := migrate.Apply(ctx, owner, build, migrate.Options{RuntimeRole: finalRole}); err != nil || result.Version != 11 {
		t.Fatalf("current admin reconciliation: %+v %v", result, err)
	}
	current := pgtest.Connect(t, rotation.RuntimeURL)
	newHolder := platform.NewID()
	tag, err := current.Exec(ctx, `UPDATE fleet.hub_lease SET holder=$1,fence=fence+1,acquired_at=clock_timestamp(),
renewed_at=clock_timestamp(),expires_at=clock_timestamp()+interval '1 minute' WHERE singleton AND expires_at<=clock_timestamp()`, newHolder)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("new floor could not take the lease: %v", err)
	}

	// Run the actual current source and then the same verified bridge as the
	// supported server rollback, both with the new floor credential. This does
	// not run an old privileged admin tool or publish anything.
	candidateName := "current-center"
	if runtime.GOOS == "windows" {
		candidateName += ".exe"
	}
	candidate := filepath.Join(t.TempDir(), candidateName)
	compile := exec.Command("go", "build", "-trimpath", "-o", candidate, "./cmd/arcforges-center")
	compile.Dir = filepath.Join("..", "..")
	if raw, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("build current source: %s", raw)
	}
	for _, executable := range []string{candidate, bridge} {
		testActualLocalService(t, executable, rotation.RuntimeURL)
	}
	if _, err := provision.Rotate(ctx, owner, provision.Options{Group: legacy, DirectURL: url}); !errors.Is(err, migrate.ErrCTR06RetirementUnproven) {
		t.Fatalf("old privileged rotation revived after rollback: %v", err)
	}
}

func testActualLocalService(t *testing.T, executable, runtimeURL string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	cmd := exec.Command(executable, "serve")
	cmd.Env = []string{config.EnvMode + "=self-hosted", config.EnvPublicBaseURL + "=http://127.0.0.1:1",
		config.EnvDatabaseURL + "=" + runtimeURL, config.EnvHTTPAddress + "=127.0.0.1:0", config.EnvGRPCAddress + "=off",
		config.EnvAdminAddress + "=" + address, config.EnvSurfaces + "=none", config.EnvMetricsLogInterval + "=0"}
	if root := os.Getenv("SystemRoot"); root != "" {
		cmd.Env = append(cmd.Env, "SystemRoot="+root)
	}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get("http://" + address + "/readyz")
		if err == nil {
			var status struct {
				Status     string            `json:"status"`
				Components map[string]string `json:"components"`
			}
			err = json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&status)
			_ = response.Body.Close()
			if err == nil && response.StatusCode == 200 && status.Status == "ready" &&
				status.Components["database"] == "ready" && status.Components["databaseSchema"] == "ready" {
				_ = cmd.Process.Kill()
				_, _ = cmd.Process.Wait()
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("actual server did not become ready")
}

func TestCTR06SelfHostedRejectsAdditionalTemporaryConnection(t *testing.T) {
	url, legacy, owner, build, bridge, old := localBridgeFixture(t)
	ctx := context.Background()
	var leaked *pgx.Conn
	var temporary migrate.PreparedBridgeRoles
	result, err := migrate.ApplySelfHostedCTR06(ctx, owner, build, migrate.Options{RuntimeRole: legacy}, bridge,
		func(ctx context.Context, roles migrate.PreparedBridgeRoles) (string, error) {
			temporary = roles
			prepared, err := provision.CompleteIssuedCTR06Bridge(ctx, owner, build, provision.Options{Group: legacy, DirectURL: url}, roles)
			if err != nil {
				return "", err
			}
			leaked, err = pgx.Connect(ctx, prepared.RuntimeURL)
			if err != nil {
				return "", err
			}
			return prepared.RuntimeURL, nil
		})
	if leaked != nil {
		defer func() { _ = leaked.Close(context.Background()) }()
	}
	if !errors.Is(err, migrate.ErrCTR06RetirementUnproven) || !strings.Contains(err.Error(), "before local bridge start") {
		t.Fatalf("remaining bridge backend did not refuse at the pre-start check: %+v %v", result, err)
	}
	var unchanged, disabled bool
	if err := owner.QueryRow(ctx, `SELECT
 (SELECT max(version)=10 FROM platform.schema_migration) AND to_regclass('fleet.routed_file_call') IS NULL,
 EXISTS(SELECT 1 FROM pg_roles WHERE oid=$1 AND NOT rolcanlogin)
   AND NOT has_table_privilege($2,'fleet.hub_lease','UPDATE')`, temporary.BridgeLoginOID, temporary.BridgeRole).Scan(&unchanged, &disabled); err != nil || !unchanged || !disabled {
		t.Fatalf("failed call cleanup: unchanged=%v disabled=%v err=%v", unchanged, disabled, err)
	}
	if leaked != nil {
		_, err = leaked.Exec(ctx, "UPDATE fleet.hub_lease SET expires_at=clock_timestamp() WHERE singleton")
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Fatalf("already open temporary backend kept write privilege: %v", err)
		}
	}
	if _, err := old.Exec(ctx, "UPDATE fleet.hub_lease SET expires_at=clock_timestamp()+interval '1 hour' WHERE singleton"); err != nil {
		t.Fatalf("refused migration changed legacy permissions: %v", err)
	}
}

// TestCTR06SelfHostedObserveNativeBridgeBackend checks the real PG activity
// visible to the migration owner during the managed bridge's ready response.
func TestCTR06SelfHostedObserveNativeBridgeBackend(t *testing.T) {
	url, legacy, owner, build, binary, _ := localBridgeFixture(t)
	ctx := context.Background()
	prepared, err := provision.PrepareCTR06Bridge(ctx, owner, build, provision.Options{Group: legacy, DirectURL: url})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	cmd := exec.Command(binary, "serve")
	cmd.Env = []string{config.EnvMode + "=self-hosted", config.EnvPublicBaseURL + "=http://127.0.0.1:1", config.EnvDatabaseURL + "=" + prepared.RuntimeURL,
		config.EnvDatabaseMaxConns + "=1", config.EnvHTTPAddress + "=127.0.0.1:0", config.EnvGRPCAddress + "=off",
		config.EnvAdminAddress + "=" + address, config.EnvSurfaces + "=none", config.EnvMetricsLogInterval + "=0"}
	if root := os.Getenv("SystemRoot"); root != "" {
		cmd.Env = append(cmd.Env, "SystemRoot="+root)
	}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(15 * time.Second)
	var ready bool
	for time.Now().Before(deadline) {
		response, e := client.Get("http://" + address + "/readyz")
		if e == nil {
			var status struct {
				Status     string            `json:"status"`
				Components map[string]string `json:"components"`
			}
			e = json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&status)
			_ = response.Body.Close()
			if e == nil && status.Status == "ready" && status.Components["database"] == "ready" && status.Components["databaseSchema"] == "ready" {
				ready = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("bridge not ready")
	}
	admin := pgtest.Admin(t)
	for name, conn := range map[string]*pgx.Conn{"owner": owner, "administrator": admin} {
		rows, e := conn.Query(ctx, "SELECT usename,usesysid::bigint,backend_type,state FROM pg_stat_activity WHERE datname=$1 ORDER BY pid", prepared.DatabaseName)
		if e != nil {
			t.Fatal(e)
		}
		for rows.Next() {
			var user string
			var kind, state *string
			var oid int64
			if e = rows.Scan(&user, &oid, &kind, &state); e != nil {
				t.Fatal(e)
			}
			t.Logf("%s sees user=%s oid=%d backend-type-visible=%v state-visible=%v; bridge oid=%d", name, user, oid, kind != nil, state != nil, prepared.BridgeLoginOID)
		}
		if e = rows.Err(); e != nil {
			t.Fatal(e)
		}
		rows.Close()
	}
}

// The test invokes the actual newly built CLI, including its normal private
// secret-file and admin commands. No source-level migration callback is used.
func TestCTR06SelfHostedRealCLIAndFailure(t *testing.T) {
	url, legacy, owner, _, bridge, old := localBridgeFixture(t)
	ctx := context.Background()
	candidateName := "current-center"
	if runtime.GOOS == "windows" {
		candidateName += ".exe"
	}
	candidate := filepath.Join(t.TempDir(), candidateName)
	compile := exec.Command("go", "build", "-trimpath", "-o", candidate, "./cmd/arcforges-center")
	compile.Dir = filepath.Join("..", "..")
	if raw, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("build current CLI: %s", raw)
	}
	baseEnv := []string{config.EnvMode + "=self-hosted", config.EnvMigrationDatabaseURL + "=" + url}
	if root := os.Getenv("SystemRoot"); root != "" {
		baseEnv = append(baseEnv, "SystemRoot="+root)
	}
	run := func(env []string, args ...string) (string, string, error) {
		cmd := exec.Command(candidate, args...)
		cmd.Env = append(append([]string(nil), baseEnv...), env...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}
	wrong := filepath.Join(t.TempDir(), "wrong-bridge")
	if err := os.WriteFile(wrong, []byte("not a bridge"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := run([]string{config.EnvRuntimeRole + "=" + legacy, config.EnvCTR06BridgeExecutable + "=" + wrong}, "migrate", "apply")
	if err == nil {
		t.Fatal("CLI accepted a non-bridge executable")
	}
	var intact bool
	if err := owner.QueryRow(ctx, "SELECT (SELECT max(version)=10 FROM platform.schema_migration) AND to_regclass('fleet.routed_file_call') IS NULL").Scan(&intact); err != nil || !intact {
		t.Fatalf("wrong executable changed the database: %v %v", intact, err)
	}
	if _, err := old.Exec(ctx, "UPDATE fleet.hub_lease SET expires_at=clock_timestamp()+interval '1 hour' WHERE singleton"); err != nil {
		t.Fatalf("refused CLI changed old permissions: %v", err)
	}
	stdout, stderr, err := run([]string{config.EnvRuntimeRole + "=" + legacy, config.EnvCTR06BridgeExecutable + "=" + bridge}, "migrate", "apply")
	if err != nil {
		t.Fatalf("actual CLI migration failed: %s", stderr)
	}
	var result migrate.Result
	if err := json.Unmarshal([]byte(stdout), &result); err != nil || result.Version != 11 || result.RuntimeRole == legacy {
		t.Fatalf("actual CLI migration result: %+v %v", result, err)
	}
	secret := filepath.Join(t.TempDir(), "runtime.json")
	stdout, stderr, err = run([]string{config.EnvRuntimeRole + "=" + result.RuntimeRole, config.EnvRuntimeSecretFile + "=" + secret},
		"admin", "rotate-runtime-credential")
	if err != nil {
		t.Fatalf("actual CLI rotation failed: %s", stderr)
	}
	var rotated struct {
		Slot string `json:"slot"`
	}
	if err := json.Unmarshal([]byte(stdout), &rotated); err != nil || (rotated.Slot != "a" && rotated.Slot != "b") {
		t.Fatalf("actual CLI rotation returned an invalid slot: %v", err)
	}
	if _, stderr, err := run([]string{config.EnvRuntimeRole + "=" + result.RuntimeRole}, "admin", "confirm-runtime-credential", "--slot", rotated.Slot); err != nil {
		t.Fatalf("actual CLI confirmation failed: %s", stderr)
	}
	if _, stderr, err := run([]string{config.EnvRuntimeRole + "=" + result.RuntimeRole}, "migrate", "apply"); err != nil {
		t.Fatalf("actual CLI reconciliation failed: %s", stderr)
	}
	raw, err := os.ReadFile(secret)
	if err != nil {
		t.Fatal(err)
	}
	var material map[string]string
	if err := json.Unmarshal(raw, &material); err != nil || material[config.EnvDatabaseURL] == "" {
		t.Fatal("actual CLI did not create its private runtime secret")
	}
	testActualLocalService(t, candidate, material[config.EnvDatabaseURL])
	testActualLocalService(t, bridge, material[config.EnvDatabaseURL])
	deniedSecret := filepath.Join(t.TempDir(), "old-runtime.json")
	if _, _, err := run([]string{config.EnvRuntimeRole + "=" + legacy, config.EnvRuntimeSecretFile + "=" + deniedSecret},
		"admin", "rotate-runtime-credential"); err == nil {
		t.Fatal("current CLI revived the old generation")
	}
	if _, err := os.Lstat(deniedSecret); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused old rotation wrote a secret file")
	}
}

// A hard stop after the bridge has finished but while 0011 waits for the
// database write lock leaves an unconfirmed issued generation. A later run
// must not adopt it from its public marker or change its permissions.
func TestCTR06SelfHostedHardInterruptedCallFailsClosed(t *testing.T) {
	url, legacy, owner, _, bridge, old := localBridgeFixture(t)
	ctx := context.Background()
	name := "current-center"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	candidate := filepath.Join(t.TempDir(), name)
	compile := exec.Command("go", "build", "-trimpath", "-o", candidate, "./cmd/arcforges-center")
	compile.Dir = filepath.Join("..", "..")
	if raw, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("build current CLI: %s", raw)
	}
	blocker := pgtest.Connect(t, url)
	tx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "LOCK TABLE fleet.hub_lease IN ACCESS SHARE MODE"); err != nil {
		t.Fatal(err)
	}
	env := []string{config.EnvMode + "=self-hosted", config.EnvMigrationDatabaseURL + "=" + url,
		config.EnvRuntimeRole + "=" + legacy, config.EnvCTR06BridgeExecutable + "=" + bridge}
	if root := os.Getenv("SystemRoot"); root != "" {
		env = append(env, "SystemRoot="+root)
	}
	cmd := exec.Command(candidate, "migrate", "apply")
	cmd.Env, cmd.Stdout, cmd.Stderr = env, io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	defer func() {
		if !stopped {
			_ = cmd.Process.Kill()
			<-done
		}
	}()
	deadline := time.Now().Add(20 * time.Second)
	waiting := false
	for time.Now().Before(deadline) {
		select {
		case <-done:
			stopped = true
			t.Fatal("migration exited before the controlled lock wait")
		default:
		}
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
WHERE datname=current_database() AND usename=current_user AND pid<>pg_backend_pid()
AND wait_event_type='Lock' AND query LIKE 'LOCK TABLE fleet.routed_call,%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("migration did not reach its 0011 lock")
	}
	prefix := strings.TrimSuffix(legacy, "_runtime") + "_c06_%"
	var abandoned string
	err = owner.QueryRow(ctx, `SELECT rolname FROM pg_roles WHERE rolname LIKE $1 AND NOT rolcanlogin
AND has_table_privilege(oid,'fleet.routed_call','INSERT')`, prefix).Scan(&abandoned)
	if err != nil || abandoned == "" {
		t.Fatalf("issued temporary generation not found: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-done
	stopped = true
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	retry := exec.Command(candidate, "migrate", "apply")
	retry.Env, retry.Stdout, retry.Stderr = env, io.Discard, io.Discard
	if err := retry.Run(); err == nil {
		t.Fatal("retry accepted an unexplained temporary writer")
	}
	var schemaUnchanged, stillWriter, loginEnabled bool
	err = owner.QueryRow(ctx, `SELECT
 (SELECT max(version)=10 FROM platform.schema_migration) AND to_regclass('fleet.routed_file_call') IS NULL,
 has_table_privilege($1,'fleet.routed_call','INSERT'),
 EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1||'_a' AND rolcanlogin)`, abandoned).
		Scan(&schemaUnchanged, &stillWriter, &loginEnabled)
	if err != nil || !schemaUnchanged || !stillWriter || !loginEnabled {
		t.Fatalf("retry modified unknown prior issuance: schema=%v writer=%v login=%v err=%v", schemaUnchanged, stillWriter, loginEnabled, err)
	}
	if _, err := old.Exec(ctx, "UPDATE fleet.hub_lease SET expires_at=clock_timestamp()+interval '1 hour' WHERE singleton"); err != nil {
		t.Fatalf("hard interruption changed legacy rights: %v", err)
	}
}
