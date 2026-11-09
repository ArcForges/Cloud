// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"errors"
	"io/fs"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/ArcForges/Cloud/center/internal/store"
)

const migration0011SHA256 = "ecc0de1fcb39b08462a0d0bb3d72b7df09693a7eae9f180c4baef9d4b1dde8e3"

type namespaceFixture struct {
	account, enrollment, node, session platform.ID
}

type namespaceWriter interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func seedNamespaceFixture(t *testing.T, conn *pgx.Conn) namespaceFixture {
	t.Helper()
	ctx := context.Background()
	f := namespaceFixture{platform.NewID(), platform.NewID(), platform.NewID(), platform.NewID()}
	device, installation := platform.NewID(), platform.NewID()
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev)
VALUES ($1, 'Owner', 1, sha256(convert_to($2, 'UTF8')), now(), 1)`, []any{f.account, f.account.String()}},
		{`INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev)
VALUES ($1, $2, 'test node', 3, 1, false, now(), now(), 1)`, []any{device, f.account}},
		{`INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, installed_at, last_active_at, rev)
VALUES ($1, $2, $3, 'arcforges-node', '0.1.0', 'linux', now(), now(), 1)`, []any{installation, device, f.account}},
		{`INSERT INTO fleet.node (enrollment_id, node_id, user_id, device_id, installation_id, display_name, os, arch, version, enrolled_at, last_seen_at, rev)
VALUES ($1, $2, $3, $4, $5, 'test node', 2, 1, '0.1.0', now(), now(), 1)`, []any{f.enrollment, f.node, f.account, device, installation}},
	}
	for _, statement := range statements {
		if _, err := conn.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed namespace fixture: %v", store.Sanitize("seed namespace fixture", err))
		}
	}
	return f
}

func insertNamespace(ctx context.Context, q namespaceWriter, f namespaceFixture, command platform.ID, file bool, method, size int, ignore bool) error {
	table := "routed_call"
	if file {
		table = "routed_file_call"
	}
	statement := "INSERT INTO " + pgx.Identifier{"fleet", table}.Sanitize() + `
(account_id, command_id, node_enrollment_id, node_id, method, caller_kind, session_id, request_digest, request_size,
 state, delivered, attempts, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, 1, $6, $7, $8, 1, false, 1, now(), now())`
	if ignore {
		statement += " ON CONFLICT (account_id, command_id) DO NOTHING"
	}
	_, err := q.Exec(ctx, statement, f.account, command, f.enrollment, f.node, method, f.session, make([]byte, 32), size)
	return err
}

func requireNamespaceCode(t *testing.T, err error, code, constraint string) {
	t.Helper()
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) || pgError.Code != code || constraint != "" && pgError.ConstraintName != constraint {
		t.Fatalf("wanted SQLSTATE %s constraint %s, got %v", code, constraint, store.Sanitize("namespace assertion", err))
	}
}

func TestMigration0011SharedCommandNamespace(t *testing.T) {
	build := centerBuild(t)
	if len(build) < 11 || build[10].Name != "0011_fleet_routed_files.sql" || build[10].SHA256 != migration0011SHA256 {
		t.Fatal("missing or changed 0011 migration")
	}
	ctx := context.Background()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	schemas10, grants10 := schemasAndGrantsAt(10)
	options10 := Options{Runner: "test", RuntimeRole: name + "_runtime", Schemas: schemas10, Grants: grants10}
	if result, err := apply(t, url, build[:10], options10); err != nil || result.Version != 10 {
		t.Fatalf("version10: %+v %v", result, err)
	}
	f := seedNamespaceFixture(t, owner)
	existing := platform.NewID()
	if err := insertNamespace(ctx, owner, f, existing, false, 1, 10, false); err != nil {
		t.Fatal(store.Sanitize("seed old receipt", err))
	}

	// A failure after all new objects/triggers/backfill rolls everything back.
	brokenFS := fstest.MapFS{}
	entries, err := fs.ReadDir(schema.Migrations(), ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, readErr := fs.ReadFile(schema.Migrations(), entry.Name())
		if readErr != nil {
			t.Fatal(readErr)
		}
		if entry.Name() == build[10].Name {
			data = append(data, []byte("\nSELECT 1 / 0;\n")...)
		}
		brokenFS[entry.Name()] = &fstest.MapFile{Data: data}
	}
	broken, err := Load(brokenFS)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Runner: "test", RuntimeRole: name + "_runtime"}
	if _, err = apply(t, url, broken, options); err == nil {
		t.Fatal("failed migration was accepted")
	}
	var absent bool
	if err = owner.QueryRow(ctx, "SELECT to_regclass('fleet.routed_command_id') IS NULL AND to_regclass('fleet.routed_file_call') IS NULL").Scan(&absent); err != nil || !absent {
		t.Fatalf("failed migration left new objects: %v %v", absent, err)
	}
	if result, applyErr := apply(t, url, build, options); applyErr != nil || result.Version != 11 || len(result.Ran) != 1 {
		t.Fatalf("version11: %+v %v", result, applyErr)
	}
	if version, compatibilityErr := CheckCompatible(ctx, owner, build[:10]); compatibilityErr != nil || version != 11 {
		t.Fatalf("previous runtime schema compatibility: %d %v", version, compatibilityErr)
	}
	var kind int
	if err = owner.QueryRow(ctx, "SELECT receipt_kind FROM fleet.routed_command_id WHERE account_id=$1 AND command_id=$2", f.account, existing).Scan(&kind); err != nil || kind != 1 {
		t.Fatalf("old receipt backfill: %d %v", kind, err)
	}

	login, password := name+"_namespace_login", pgtest.Secret()
	if _, err = owner.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN PASSWORD '"+password+"' IN ROLE "+pgx.Identifier{name + "_runtime"}.Sanitize()); err != nil {
		t.Fatal(store.Sanitize("create isolated runtime login", err))
	}
	runtimeURL := pgtest.WithUser(t, url, login, password)
	runtime := pgtest.Connect(t, runtimeURL)
	// Runtime cannot reserve/spoof the registry directly, and cannot call the definer helper.
	for _, statement := range []string{
		"INSERT INTO fleet.routed_command_id VALUES (gen_random_uuid(),gen_random_uuid(),1)",
		"UPDATE fleet.routed_command_id SET receipt_kind=receipt_kind",
		"DELETE FROM fleet.routed_command_id",
		"SELECT fleet.reserve_routed_command_id()",
	} {
		_, denied := runtime.Exec(ctx, statement)
		requireNamespaceCode(t, denied, "42501", "")
	}
	requireNamespaceCode(t, insertNamespace(ctx, runtime, f, existing, true, 10, 10, false), "23505", "routed_command_id_namespace")
	requireNamespaceCode(t, insertNamespace(ctx, runtime, f, existing, true, 10, 10, true), "23505", "routed_command_id_namespace")
	fresh := platform.NewID()
	if err = insertNamespace(ctx, runtime, f, fresh, true, 10, 10, false); err != nil {
		t.Fatal(store.Sanitize("new runtime receipt through trigger", err))
	}
	// The old INSERT path is still protected even after a rollback to old runtime SQL.
	requireNamespaceCode(t, insertNamespace(ctx, runtime, f, fresh, false, 1, 10, true), "23505", "routed_command_id_namespace")
	if err = insertNamespace(ctx, runtime, f, existing, false, 1, 10, true); err != nil {
		t.Fatal(store.Sanitize("same old namespace replay", err))
	}
	if err = insertNamespace(ctx, runtime, f, fresh, true, 10, 10, true); err != nil {
		t.Fatal(store.Sanitize("same file namespace replay", err))
	}

	// Reconcile the previous release's exact privilege set: new tables become
	// unreadable, but old INSERTs must still pass the migration-owned trigger.
	if err = reconcile(ctx, owner, Options{RuntimeRole: name + "_runtime", Schemas: schemas10, Grants: grants10}); err != nil {
		t.Fatal(err)
	}
	var canReadRegistry bool
	if err = owner.QueryRow(ctx, "SELECT has_table_privilege($1, 'fleet.routed_command_id', 'SELECT')", login).Scan(&canReadRegistry); err != nil || canReadRegistry {
		t.Fatalf("old runtime unexpectedly has registry SELECT: %v %v", canReadRegistry, err)
	}
	requireNamespaceCode(t, insertNamespace(ctx, runtime, f, fresh, false, 1, 10, true), "23505", "routed_command_id_namespace")
	if err = insertNamespace(ctx, runtime, f, platform.NewID(), false, 1, 10, false); err != nil {
		t.Fatal(store.Sanitize("old runtime writes with old grants", err))
	}
	if err = reconcile(ctx, owner, Options{RuntimeRole: name + "_runtime", Schemas: schema.Schemas, Grants: schema.RuntimeGrants}); err != nil {
		t.Fatal(err)
	}

	invalid := platform.NewID()
	requireNamespaceCode(t, insertNamespace(ctx, runtime, f, invalid, true, 9, 10, false), "23514", "routed_file_call_method")
	var count int
	if err = owner.QueryRow(ctx, "SELECT count(*) FROM fleet.routed_command_id WHERE account_id=$1 AND command_id=$2", f.account, invalid).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected insert leaked namespace: %d %v", count, err)
	}
	requireNamespaceCode(t, insertNamespace(ctx, runtime, f, platform.NewID(), true, 10, 245761, false), "23514", "routed_file_call_request")
	for _, statement := range []string{
		"UPDATE fleet.routed_file_call SET command_id=gen_random_uuid()",
		"UPDATE fleet.routed_file_call SET workspace_id=gen_random_uuid()",
		"DELETE FROM fleet.routed_file_call",
		"UPDATE fleet.routed_command_id SET receipt_kind=3",
		"DELETE FROM fleet.routed_command_id",
	} {
		_, guarded := owner.Exec(ctx, statement)
		requireNamespaceCode(t, guarded, "23000", "")
	}

	// Distinct accounts are distinct namespaces, even when command bytes match.
	other := seedNamespaceFixture(t, owner)
	if err = insertNamespace(ctx, runtime, other, existing, true, 10, 10, false); err != nil {
		t.Fatal(store.Sanitize("other account namespace", err))
	}
	pool := pgtest.Pool(t, runtimeURL, 4)
	database := store.New(pool)
	for _, isolation := range []pgx.TxIsoLevel{pgx.ReadCommitted, pgx.Serializable} {
		command := platform.NewID()
		var results [2]error
		var wait sync.WaitGroup
		start := make(chan struct{})
		for index := range 2 {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				method := 1
				if index == 1 {
					method = 10
				}
				results[index] = database.InTx(ctx, "race command namespaces", store.TxOptions{Isolation: isolation},
					func(ctx context.Context, tx pgx.Tx) error {
						return insertNamespace(ctx, tx, f, command, index == 1, method, 10, false)
					})
			}()
		}
		close(start)
		wait.Wait()
		successes := 0
		for _, raceErr := range results {
			if raceErr == nil {
				successes++
			} else if !errors.Is(raceErr, store.ErrConflict) {
				t.Fatalf("unexpected concurrent namespace error: %v", raceErr)
			}
		}
		if successes != 1 {
			t.Fatalf("%s: successes=%d", isolation, successes)
		}
		if err = owner.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM fleet.routed_call WHERE account_id=$1 AND command_id=$2) +
 (SELECT count(*) FROM fleet.routed_file_call WHERE account_id=$1 AND command_id=$2),
 (SELECT count(*) FROM fleet.routed_command_id WHERE account_id=$1 AND command_id=$2)`,
			f.account, command).Scan(&count, &kind); err != nil || count != 1 || kind != 1 {
			t.Fatalf("one winner/one registry: %d %d %v", count, kind, err)
		}
	}
	if err = runtime.Close(ctx); err != nil {
		t.Fatal(store.Sanitize("close runtime", err))
	}
	restarted := pgtest.Connect(t, runtimeURL)
	requireNamespaceCode(t, insertNamespace(ctx, restarted, f, fresh, false, 1, 10, false), "23505", "routed_command_id_namespace")
}

func TestMigration0011WaitsForAnOldWriterAndBackfillsItsCommit(t *testing.T) {
	build := centerBuild(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	url, name := pgtest.Database(t)
	schemas10, grants10 := schemasAndGrantsAt(10)
	if _, err := apply(t, url, build[:10], Options{Runner: "test", RuntimeRole: name + "_runtime", Schemas: schemas10, Grants: grants10}); err != nil {
		t.Fatal(err)
	}
	observer := pgtest.Connect(t, url)
	f := seedNamespaceFixture(t, observer)
	oldConnection := pgtest.Connect(t, url)
	oldWriter, err := oldConnection.Begin(ctx)
	if err != nil {
		t.Fatal(store.Sanitize("begin old writer", err))
	}
	defer func() { _ = oldWriter.Rollback(context.Background()) }()
	command := platform.NewID()
	if err = insertNamespace(ctx, oldWriter, f, command, false, 1, 10, false); err != nil {
		t.Fatal(store.Sanitize("old writer insert before migration", err))
	}
	migration := pgtest.Connect(t, url)
	type outcome struct {
		result Result
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, failure := Apply(ctx, migration, build, Options{Runner: "test", RuntimeRole: name + "_runtime"})
		done <- outcome{result, failure}
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	waiting := false
	for !waiting {
		if err = observer.QueryRow(ctx, `SELECT EXISTS (
SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='relation'
AND relation='fleet.routed_call'::regclass AND NOT granted)`, migration.PgConn().PID()).Scan(&waiting); err != nil {
			t.Fatal(store.Sanitize("observe actual migration lock wait", err))
		}
		if waiting {
			break
		}
		select {
		case premature := <-done:
			t.Fatalf("migration did not wait for the old writer: version%d %v", premature.result.Version, premature.err)
		case <-ctx.Done():
			t.Fatal("migration did not reach its guarded table lock before the test deadline")
		case <-ticker.C:
		}
	}
	if err = oldWriter.Commit(ctx); err != nil {
		t.Fatal(store.Sanitize("commit old writer", err))
	}
	select {
	case completed := <-done:
		if completed.err != nil || completed.result.Version != 11 {
			t.Fatalf("migration after old writer commit: version%d %v", completed.result.Version, completed.err)
		}
	case <-ctx.Done():
		t.Fatal("migration did not finish after the old writer committed")
	}
	var kind int
	if err = observer.QueryRow(ctx, "SELECT receipt_kind FROM fleet.routed_command_id WHERE account_id=$1 AND command_id=$2", f.account, command).Scan(&kind); err != nil || kind != 1 {
		t.Fatalf("old commit was not included in the migration backfill: kind%d %v", kind, store.Sanitize("backfill assertion", err))
	}
}
