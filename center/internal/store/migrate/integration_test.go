// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/schema"
)

func apply(t *testing.T, url string, build []Migration, options Options) (Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	conn := pgtest.Connect(t, url)
	return Apply(ctx, conn, build, options)
}

func centerBuild(t *testing.T) []Migration {
	t.Helper()
	build, err := Load(schema.Migrations())
	if err != nil {
		t.Fatal(err)
	}
	return build
}

func TestApplyThenRepeatIsANoOp(t *testing.T) {
	url, name := pgtest.Database(t)
	build := centerBuild(t)
	first, err := apply(t, url, build, Options{Runner: "test", RuntimeRole: name + "_runtime"})
	if err != nil {
		t.Fatal(err)
	}
	if first.State != StateCurrent || len(first.Ran) != len(build) || first.Version != len(build) || first.Grants != "reconciled" {
		t.Fatalf("first run: %+v", first)
	}
	second, err := apply(t, url, build, Options{Runner: "test", RuntimeRole: name + "_runtime"})
	if err != nil {
		t.Fatal(err)
	}
	if second.State != StateCurrent || len(second.Ran) != 0 || second.Version != len(build) {
		t.Fatalf("second run: %+v", second)
	}
	ctx := context.Background()
	status, err := Inspect(ctx, pgtest.Connect(t, url), build)
	if err != nil || status.State != StateCurrent || len(status.Pending) != 0 {
		t.Fatalf("status: %+v %v", status, err)
	}
	if status.Applied[0].SHA256 != build[0].SHA256 || status.Database != name {
		t.Fatalf("record: %+v", status)
	}
	// Every run records the server's major and minor (the tests pin PostgreSQL 18).
	var version int
	if err = pgtest.Connect(t, url).QueryRow(ctx, "SELECT current_setting('server_version_num')::int").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if first.ServerVersionNum != version || second.ServerVersionNum != version || status.ServerVersionNum != version || version < 180000 {
		t.Fatalf("server version %d: %d %d %d", version, first.ServerVersionNum, second.ServerVersionNum, status.ServerVersionNum)
	}
	if first.TestedMajor != TestedMajor || !first.ServerMajorMatchesTested || !status.ServerMajorMatchesTested {
		t.Fatalf("tested major: %+v", first)
	}
	if first.Logging.LogStatement == "" || first.Logging.LogMinDurationStatement == "" || first.Logging.PgStatStatementsTrack == "" ||
		status.Logging != first.Logging {
		t.Fatalf("logging: %+v %+v", first.Logging, status.Logging)
	}
}

func TestStatusOfAnEmptyDatabase(t *testing.T) {
	url, _ := pgtest.Database(t)
	status, err := Inspect(context.Background(), pgtest.Connect(t, url), centerBuild(t))
	if err != nil || status.State != StateUninitialized || len(status.Pending) != len(centerBuild(t)) {
		t.Fatalf("status: %+v %v", status, err)
	}
}

func TestConcurrentRunsSerialize(t *testing.T) {
	url, name := pgtest.Database(t)
	build := centerBuild(t)
	const runs = 6
	results := make([]Result, runs)
	failures := make([]error, runs)
	conns := make([]*pgx.Conn, runs)
	for index := range conns {
		conns[index] = pgtest.Connect(t, url)
	}
	var group sync.WaitGroup
	start := make(chan struct{})
	for index := range runs {
		group.Go(func() {
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			results[index], failures[index] = Apply(ctx, conns[index], build, Options{Runner: fmt.Sprintf("run-%d", index), RuntimeRole: name + "_runtime"})
		})
	}
	close(start)
	group.Wait()
	ran := 0
	for index := range runs {
		if failures[index] != nil {
			t.Fatalf("run %d: %v", index, failures[index])
		}
		if results[index].State != StateCurrent {
			t.Fatalf("run %d: %+v", index, results[index])
		}
		ran += len(results[index].Ran)
	}
	if ran != len(build) {
		t.Fatalf("%d migrations ran across %d concurrent runs; each must run once", ran, runs)
	}
}

func TestAnEditedAppliedMigrationIsRefused(t *testing.T) {
	url, _ := pgtest.Database(t)
	original, _ := Load(files("CREATE TABLE platform.t1 (x int);", "CREATE TABLE platform.t2 (x int);"))
	if _, err := apply(t, url, original[:1], Options{Runner: "test"}); err != nil {
		t.Fatal(err)
	}
	edited, _ := Load(files("CREATE TABLE platform.t1 (x bigint);", "CREATE TABLE platform.t2 (x int);"))
	result, err := apply(t, url, edited, Options{Runner: "test"})
	if !errors.Is(err, ErrRefused) || result.State != StateRefused || !strings.Contains(strings.Join(result.Problems, " "), "was edited") {
		t.Fatalf("edited: %+v %v", result, err)
	}
	var exists bool
	if err = pgtest.Connect(t, url).QueryRow(context.Background(), "SELECT to_regclass('platform.t2') IS NOT NULL").Scan(&exists); err != nil || exists {
		t.Fatalf("a refused run applied the next migration: %v %v", exists, err)
	}
}

func TestARemovedAppliedMigrationIsRefused(t *testing.T) {
	url, _ := pgtest.Database(t)
	build, _ := Load(files("CREATE TABLE platform.t1 (x int);", "CREATE TABLE platform.t2 (x int);"))
	if _, err := apply(t, url, build, Options{Runner: "test"}); err != nil {
		t.Fatal(err)
	}
	result, err := apply(t, url, build[:1], Options{Runner: "test"})
	if !errors.Is(err, ErrRefused) || !strings.Contains(strings.Join(result.Problems, " "), "ahead") {
		t.Fatalf("removed last: %+v %v", result, err)
	}
	renamed, _ := Load(fstestRename(files("CREATE TABLE platform.t1 (x int);", "CREATE TABLE platform.t3 (x int);"), "0002_second.sql", "0002_other.sql"))
	result, err = apply(t, url, renamed, Options{Runner: "test"})
	if !errors.Is(err, ErrRefused) || !strings.Contains(strings.Join(result.Problems, " "), "renamed or removed") {
		t.Fatalf("replaced: %+v %v", result, err)
	}
}

func TestAFailingMigrationRollsBackCompletely(t *testing.T) {
	url, _ := pgtest.Database(t)
	failing, _ := Load(files("CREATE TABLE platform.t1 (x int);", "CREATE TABLE platform.t2 (x int); INSERT INTO platform.t1 VALUES (1); SELECT 1 / 0;"))
	_, err := apply(t, url, failing, Options{Runner: "test"})
	var failure *Failure
	if !errors.As(err, &failure) || failure.Name != "0002_second.sql" || failure.SQLState != "22012" {
		t.Fatalf("failure: %v", err)
	}
	conn := pgtest.Connect(t, url)
	var t2 bool
	var rows, version int
	if err = conn.QueryRow(context.Background(), "SELECT to_regclass('platform.t2') IS NOT NULL, (SELECT count(*) FROM platform.t1), (SELECT max(version) FROM platform.schema_migration)").Scan(&t2, &rows, &version); err != nil {
		t.Fatal(err)
	}
	if t2 || rows != 0 || version != 1 {
		t.Fatalf("partial state after a failed migration: t2=%v rows=%d version=%d", t2, rows, version)
	}
	fixed, _ := Load(files("CREATE TABLE platform.t1 (x int);", "CREATE TABLE platform.t2 (x int); INSERT INTO platform.t1 VALUES (1);"))
	if result, err := apply(t, url, fixed, Options{Runner: "test"}); err != nil || len(result.Ran) != 1 {
		t.Fatalf("fixed run: %+v %v", result, err)
	}
}

// A data error quotes the offending value in the server's primary message (22P02 here); the run's output, its log lines and the
// error the command logs name the SQLSTATE, the class and the objects only.
func TestAFailingMigrationNeverQuotesAValue(t *testing.T) {
	url, _ := pgtest.Database(t)
	const value = "fixture-value-7319"
	failing, _ := Load(files("CREATE TABLE platform.t1 (x text);",
		"INSERT INTO platform.t1 VALUES ('"+value+"'); ALTER TABLE platform.t1 ALTER COLUMN x TYPE integer USING x::integer;"))
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	result, err := apply(t, url, failing, Options{Runner: "test", Logger: logger})
	var failure *Failure
	if !errors.As(err, &failure) || failure.SQLState != "22P02" || failure.Message != "data exception" {
		t.Fatalf("failure: %#v %v", failure, err)
	}
	document, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	// The command prints the result and logs the error with the same logger (cmd/arcforges-center).
	logger.Error("the migration failed", "error", err.Error())
	for name, text := range map[string]string{"output": string(document), "log": logs.String(), "error": err.Error()} {
		if strings.Contains(text, value) {
			t.Fatalf("the %s quotes the row value: %s", name, text)
		}
	}
	if !strings.Contains(err.Error(), "22P02") || !strings.Contains(logs.String(), "0002_second.sql") {
		t.Fatalf("the failure does not name its SQLSTATE and migration: %v %s", err, logs.String())
	}
	// A constraint violation names its constraint and table, never the duplicated value.
	unique, _ := Load(files("CREATE TABLE platform.t2 (x text CONSTRAINT t2_x UNIQUE);",
		"INSERT INTO platform.t2 VALUES ('"+value+"'), ('"+value+"');"))
	other, _ := pgtest.Database(t)
	_, err = apply(t, other, unique, Options{Runner: "test"})
	if !errors.As(err, &failure) || failure.SQLState != "23505" || strings.Contains(err.Error(), value) ||
		failure.Message != "integrity constraint violation (constraint t2_x, table platform.t2)" {
		t.Fatalf("unique failure: %#v %v", failure, err)
	}
	// Errors of class 42 keep the server's message, which names objects of the migration's own text.
	missing, _ := Load(files("CREATE TABLE platform.t3 (x int);", "SELECT * FROM platform.absent;"))
	third, _ := pgtest.Database(t)
	_, err = apply(t, third, missing, Options{Runner: "test"})
	if !errors.As(err, &failure) || failure.SQLState != "42P01" || !strings.Contains(failure.Message, "platform.absent") {
		t.Fatalf("42P01 failure: %#v %v", failure, err)
	}
}

func TestACrashedRunRollsBackAndReleasesTheLock(t *testing.T) {
	url, _ := pgtest.Database(t)
	slow, _ := Load(files("CREATE TABLE platform.t1 (x int);", "CREATE TABLE platform.t2 (x int); SELECT pg_sleep(60);"))
	conn := pgtest.Connect(t, url)
	var pid uint32
	if err := conn.QueryRow(context.Background(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_, err := Apply(ctx, conn, slow, Options{Runner: "crashing"})
		done <- err
	}()
	admin := pgtest.Admin(t)
	deadline := time.Now().Add(30 * time.Second)
	for {
		var running bool
		if err := admin.QueryRow(context.Background(), "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = $1 AND query LIKE '%pg_sleep%')", pid).Scan(&running); err != nil {
			t.Fatal(err)
		}
		if running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the slow migration never started")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// The process dies mid-migration: the server ends the session.
	if _, err := admin.Exec(context.Background(), "SELECT pg_terminate_backend($1)", pid); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("the crashed run reported success")
	}
	fixed, _ := Load(files("CREATE TABLE platform.t1 (x int);", "CREATE TABLE platform.t2 (x int);"))
	result, err := apply(t, url, fixed, Options{Runner: "after-crash", LockTimeout: 5 * time.Second})
	if err != nil || len(result.Ran) != 1 || result.Ran[0].Name != "0002_second.sql" {
		t.Fatalf("the run after the crash: %+v %v", result, err)
	}
}

func TestALockHeldByAnotherRunTimesOut(t *testing.T) {
	url, _ := pgtest.Database(t)
	holder := pgtest.Connect(t, url)
	if _, err := holder.Exec(context.Background(), "SELECT pg_advisory_lock($1)", LockKey); err != nil {
		t.Fatal(err)
	}
	_, err := apply(t, url, centerBuild(t), Options{Runner: "test", LockTimeout: time.Second})
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("expected the lock timeout, got %v", err)
	}
}

func TestTheRuntimeRoleHasExactlyItsGrants(t *testing.T) {
	url, name := pgtest.Database(t)
	group := name + "_runtime"
	migration := pgtest.Connect(t, url)
	ctx := context.Background()
	// An unrelated schema of another module that the runtime role was never granted.
	if _, err := migration.Exec(ctx, "CREATE SCHEMA other; CREATE TABLE other.secret (x int); INSERT INTO other.secret VALUES (1)"); err != nil {
		t.Fatal(err)
	}
	if _, err := apply(t, url, centerBuild(t), Options{Runner: "test", RuntimeRole: group}); err != nil {
		t.Fatal(err)
	}
	// An extra privilege granted by hand is revoked by the next run.
	if _, err := migration.Exec(ctx, "GRANT DELETE ON platform.outbox TO "+group); err != nil {
		t.Fatal(err)
	}
	if _, err := apply(t, url, centerBuild(t), Options{Runner: "test", RuntimeRole: group}); err != nil {
		t.Fatal(err)
	}
	login, password := group+"_a", pgtest.Secret()
	if _, err := migration.Exec(ctx, "CREATE ROLE "+login+" LOGIN PASSWORD '"+password+"' IN ROLE "+group); err != nil {
		t.Fatal(err)
	}
	runtime := pgtest.Connect(t, pgtest.WithUser(t, url, login, password))
	allowed := []string{
		"SELECT count(*) FROM platform.schema_migration",
		"INSERT INTO platform.inbox (source, message_id, received_at, expires_at) VALUES ('test', 'm1', now(), now() + interval '1 day')",
		"UPDATE platform.inbox SET processed_at = now(), outcome = 1 WHERE source = 'test'",
		"SELECT count(*) FROM fleet.signing_key",
		"SELECT last_sequence FROM audit.chain_head",
		"SELECT count(*) FROM identity.user",
		"SELECT count(*) FROM identity.session",
		"SELECT count(*) FROM device.installation",
		"SELECT count(*) FROM platform.rate_limit",
		"INSERT INTO platform.rate_limit (bucket_hash, window_start, count) VALUES (decode(repeat('ab', 32), 'hex'), now(), 1)",
		"UPDATE platform.rate_limit SET count = count + 1",
	}
	for _, statement := range allowed {
		if _, err := runtime.Exec(ctx, statement); err != nil {
			t.Errorf("the runtime role cannot run %q: %v", statement, err)
		}
	}
	refused := []string{
		"CREATE TABLE platform.extra (x int)",
		"CREATE TABLE public.extra (x int)",
		"CREATE SCHEMA extra",
		"ALTER TABLE platform.outbox ADD COLUMN extra int",
		"DROP TABLE platform.inbox",
		"DELETE FROM platform.outbox",
		"DELETE FROM platform.inbox",
		"TRUNCATE platform.command_receipt",
		"UPDATE audit.audit_event SET reason = 'x'",
		"DELETE FROM audit.audit_event",
		"INSERT INTO fleet.signing_key (kid) VALUES ('kid-00001')",
		"SELECT * FROM platform.runtime_credential",
		"INSERT INTO platform.schema_migration (version, name, sha256, duration_ms, runner) VALUES (99, '0099_x.sql', repeat('0', 64), 0, 'x')",
		"SELECT * FROM other.secret",
		"CREATE INDEX extra ON platform.outbox (topic)",
		"CREATE TEMP TABLE extra_temporary (x int)",
		// AF-CTR-03: nothing of the identity and device store is deleted at runtime, and the append-only rows stay so.
		"DELETE FROM identity.session",
		"DELETE FROM identity.auth_flow",
		"DELETE FROM device.device",
		"DELETE FROM platform.rate_limit",
		"UPDATE identity.spent_refresh SET generation = 2",
		"UPDATE identity.bootstrap SET consumed_at = now()",
		"TRUNCATE identity.user",
		"ALTER TABLE identity.session ADD COLUMN extra int",
	}
	for _, statement := range refused {
		_, err := runtime.Exec(ctx, statement)
		if !pgtest.IsCode(err, "42501") {
			t.Errorf("the runtime role ran %q (or failed otherwise: %v)", statement, err)
		}
	}
}

// Production and acceptance share one cluster: a runtime role connects to its own database only.
func TestTheRuntimeRoleConnectsOnlyToItsOwnDatabase(t *testing.T) {
	ctx := context.Background()
	type center struct{ url, login, password string }
	centers := make([]center, 2)
	for index := range centers {
		url, name := pgtest.Database(t)
		group := name + "_runtime"
		for range 2 { // a repeated run keeps the database privileges
			if _, err := apply(t, url, centerBuild(t), Options{Runner: "test", RuntimeRole: group}); err != nil {
				t.Fatal(err)
			}
		}
		login, password := group+"_a", pgtest.Secret()
		if _, err := pgtest.Connect(t, url).Exec(ctx, "CREATE ROLE "+login+" LOGIN PASSWORD '"+password+"' IN ROLE "+group); err != nil {
			t.Fatal(err)
		}
		centers[index] = center{url: url, login: login, password: password}
	}
	for index, own := range centers {
		other := centers[1-index]
		if conn, err := pgx.Connect(ctx, pgtest.WithUser(t, own.url, own.login, own.password)); err != nil {
			t.Fatalf("center %d: its runtime role cannot connect to its own database: %v", index, err)
		} else {
			_ = conn.Close(ctx)
		}
		conn, err := pgx.Connect(ctx, pgtest.WithUser(t, other.url, own.login, own.password))
		if err == nil {
			_ = conn.Close(ctx)
			t.Fatalf("center %d: its runtime role connected to another center's database", index)
		}
		if !pgtest.IsCode(err, "42501") {
			t.Fatalf("center %d: unexpected refusal: %v", index, err)
		}
		// The owner keeps its rights.
		if conn, err := pgx.Connect(ctx, own.url); err != nil {
			t.Fatalf("center %d: the migration role cannot connect: %v", index, err)
		} else {
			_ = conn.Close(ctx)
		}
	}
}

func TestEveryTableHasAGrantDecision(t *testing.T) {
	url, name := pgtest.Database(t)
	if _, err := apply(t, url, centerBuild(t), Options{Runner: "test", RuntimeRole: name + "_runtime"}); err != nil {
		t.Fatal(err)
	}
	rows, err := pgtest.Connect(t, url).Query(context.Background(), "SELECT table_schema || '.' || table_name FROM information_schema.tables WHERE table_schema = ANY($1) ORDER BY 1", schema.Schemas)
	if err != nil {
		t.Fatal(err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	decided := slices.Clone(schema.MigrationOnly)
	for _, grant := range schema.RuntimeGrants {
		decided = append(decided, grant.Schema+"."+grant.Table)
	}
	slices.Sort(decided)
	if !slices.Equal(tables, decided) {
		t.Fatalf("tables %v; decided %v (add each new table to schema.RuntimeGrants or schema.MigrationOnly)", tables, decided)
	}
}

func TestTheRuntimeRoleMustNotBeTheMigrationRoleOrElevated(t *testing.T) {
	url, name := pgtest.Database(t)
	if _, err := apply(t, url, centerBuild(t), Options{Runner: "test", RuntimeRole: name + "_owner"}); err == nil {
		t.Fatal("the migration role was accepted as the runtime role")
	}
	elevated := name + "_elevated"
	if _, err := pgtest.Admin(t).Exec(context.Background(), "CREATE ROLE "+elevated+" NOLOGIN CREATEDB"); err != nil {
		t.Fatal(err)
	}
	if _, err := apply(t, url, centerBuild(t), Options{Runner: "test", RuntimeRole: elevated}); err == nil || !strings.Contains(err.Error(), "elevated") {
		t.Fatalf("an elevated runtime role was accepted: %v", err)
	}
}

func fstestRename(directory fstest.MapFS, from, to string) fstest.MapFS {
	directory[to] = directory[from]
	delete(directory, from)
	return directory
}

func TestTheRuntimeChecksSchemaCompatibility(t *testing.T) {
	url, _ := pgtest.Database(t)
	conn := pgtest.Connect(t, url)
	ctx := context.Background()
	build, _ := Load(files("CREATE TABLE platform.t1 (x int);", "CREATE TABLE platform.t2 (x int);"))
	if _, err := CheckCompatible(ctx, conn, build); !errors.Is(err, ErrIncompatible) {
		t.Fatalf("an unmigrated database: %v", err)
	}
	if _, err := apply(t, url, build[:1], Options{Runner: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckCompatible(ctx, conn, build); !errors.Is(err, ErrIncompatible) {
		t.Fatalf("a pending migration: %v", err)
	}
	if _, err := apply(t, url, build, Options{Runner: "test"}); err != nil {
		t.Fatal(err)
	}
	if version, err := CheckCompatible(ctx, conn, build); err != nil || version != 2 {
		t.Fatalf("current: %d %v", version, err)
	}
	// The previous revision stays compatible with a database one migration ahead (expand and contract).
	if version, err := CheckCompatible(ctx, conn, build[:1]); err != nil || version != 2 {
		t.Fatalf("ahead: %d %v", version, err)
	}
	edited, _ := Load(files("CREATE TABLE platform.t1 (x bigint);", "CREATE TABLE platform.t2 (x int);"))
	if _, err := CheckCompatible(ctx, conn, edited); !errors.Is(err, ErrIncompatible) {
		t.Fatalf("edited: %v", err)
	}
}
