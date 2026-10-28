// SPDX-License-Identifier: AGPL-3.0-only

package provision

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
)

// The vector was computed independently with Python's hashlib.pbkdf2_hmac and hmac (phrase Abc-def_123-XYZ, salt 00..0f).
func TestTheScramVerifierVector(t *testing.T) {
	salt := make([]byte, 16)
	for index := range salt {
		salt[index] = byte(index)
	}
	verifier, err := ScramVerifier("Abc-def_123-XYZ", salt, 4096)
	expected := "SCRAM-SHA-256$4096:AAECAwQFBgcICQoLDA0ODw==$AhgSG6CVHQYNB2J3NwfqEH4VNJeckG8zG1beC/AUjE8=:wOAWkAdsV5DYBC1zpc+AiHCkfxHf+XmjNwqBjZyqnAA="
	if err != nil || verifier != expected {
		t.Fatalf("%s %v", verifier, err)
	}
	for _, bad := range []string{"", "pass word", "pässword", "a'b", `a\b`} {
		if _, err = ScramVerifier(bad, salt, 4096); err == nil {
			t.Errorf("%q accepted: SASLprep is the identity only on the generated alphabet", bad)
		}
	}
	if _, err = ScramVerifier("abc", salt[:8], 4096); err == nil {
		t.Error("a short salt was accepted")
	}
}

func TestOnePredicateDecidesNeon(t *testing.T) {
	cases := map[string]bool{
		"ep-cool-darkness-123456.us-east-2.aws.neon.tech":        true,
		"ep-cool-darkness-123456-pooler.us-east-2.aws.neon.tech": true,
		"EP-Cool-1.eu-central-1.aws.neon.tech":                   true,
		"ep-x.evilneon.tech":                                     false,
		"db.example.org":                                         false,
		"127.0.0.1":                                              false,
		"ep-x":                                                   false,
	}
	for host, neon := range cases {
		if NeonHost(host) != neon {
			t.Errorf("%s: %v", host, !neon)
		}
		if derived := PooledHost(host); (derived != host) != (neon && !strings.Contains(host, "-pooler")) {
			t.Errorf("%s: the pooled host %s disagrees with the predicate", host, derived)
		}
	}
}

func TestTheSecretForms(t *testing.T) {
	const phrase = "Abc-def_123-XYZ"
	secret, form, err := passwordSecret(phrase, true)
	if err != nil || form != FormNeonPlaintext || secret != phrase {
		t.Fatalf("neon: %s %v", form, err)
	}
	secret, form, err = passwordSecret(phrase, false)
	if err != nil || form != FormVerifier || strings.Contains(secret, phrase) || !strings.HasPrefix(secret, "SCRAM-SHA-256$4096:") {
		t.Fatalf("verifier: %s %v", form, err)
	}
	if again, _, _ := passwordSecret(phrase, false); again == secret {
		t.Fatal("two verifiers share a salt")
	}
	if _, _, err = passwordSecret("it's", true); err == nil {
		t.Fatal("a value outside the alphabet was accepted")
	}
	// No statement the center sends carries a secret: it travels by COPY only.
	for _, statement := range []string{secretTable, setLoginSource, setLoginCall, setLoginDrop} {
		if strings.Contains(statement, "PASSWORD '") {
			t.Fatalf("a statement embeds a password: %s", statement)
		}
	}
}

// tracer records every statement and argument the migration connection sends, and the COPY statements.
type tracer struct {
	mu   sync.Mutex
	sent []string
}

func (r *tracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, data.SQL)
	for _, argument := range data.Args {
		r.sent = append(r.sent, fmt.Sprint(argument))
	}
	return ctx
}

func (r *tracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func traced(t *testing.T, url string) (*pgx.Conn, *tracer) {
	t.Helper()
	config, err := pgx.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &tracer{}
	config.Tracer = recorder
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn, recorder
}

func storedSecret(t *testing.T, role string) string {
	t.Helper()
	var secret string
	if err := pgtest.Admin(t).QueryRow(context.Background(), "SELECT rolpassword FROM pg_authid WHERE rolname = $1", role).Scan(&secret); err != nil {
		t.Fatal(err)
	}
	return secret
}

// recompute derives the verifier of phrase with the iterations and salt of a stored verifier.
func recompute(t *testing.T, stored, phrase string) string {
	t.Helper()
	header, _, found := strings.Cut(strings.TrimPrefix(stored, "SCRAM-SHA-256$"), "$")
	iterationsText, saltText, ok := strings.Cut(header, ":")
	if !strings.HasPrefix(stored, "SCRAM-SHA-256$") || !found || !ok {
		t.Fatal("the stored secret is not a SCRAM verifier")
	}
	iterations, _ := strconv.Atoi(iterationsText)
	salt, err := base64.StdEncoding.DecodeString(saltText)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := ScramVerifier(phrase, salt, iterations)
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

// On a self-hosted PostgreSQL only a verifier reaches the server, and only by COPY: PostgreSQL stores it as it is, the SCRAM
// login with the password succeeds (the probe), and no statement text or bind argument the center sent holds the password or
// the verifier.
func TestARotationSendsOnlyAVerifier(t *testing.T) {
	url, group := migrated(t)
	conn, recorder := traced(t, url)
	rotation, err := Rotate(context.Background(), conn, Options{Group: group, DirectURL: url, PooledHost: pgtest.Host(t), Runner: "test", ProbeTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if rotation.PasswordForm != FormVerifier || rotation.ServerVersionNum < 160000 || !rotation.Probe.ConnectsUnpooled || !rotation.Probe.ConnectedAsLogin {
		t.Fatalf("rotation %+v", rotation)
	}
	phrase := passwordOf(rotation.RuntimeURL)
	stored := storedSecret(t, rotation.LoginRole)
	if len(phrase) != 40 || recompute(t, stored, phrase) != stored {
		t.Fatal("the stored verifier is not the runtime password's")
	}
	for _, text := range recorder.sent {
		if strings.Contains(text, phrase) || strings.Contains(text, stored) {
			t.Fatal("a statement or argument sent to the server contains the password or its verifier")
		}
	}
}

// The center's verifier equals PostgreSQL's own for the same password, salt and iterations.
func TestTheVerifierMatchesPostgreSQLs(t *testing.T) {
	role, phrase := pgtest.Name("scram"), "Zyx-987_abc-DEF"
	admin := pgtest.Admin(t)
	ctx := context.Background()
	if _, err := admin.Exec(ctx, "SET password_encryption = 'scram-sha-256'"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE ROLE "+role+" LOGIN PASSWORD '"+phrase+"'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pgtest.Admin(t).Exec(context.Background(), "DROP ROLE IF EXISTS "+role) })
	stored := storedSecret(t, role)
	if recompute(t, stored, phrase) != stored {
		t.Fatal("the center's verifier differs from PostgreSQL's")
	}
}

// fields are every text of a server error, the context included.
func fields(err error) string {
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) {
		return err.Error()
	}
	return strings.Join([]string{err.Error(), pgError.Message, pgError.Detail, pgError.Hint, pgError.Where, pgError.InternalQuery,
		pgError.SchemaName, pgError.TableName, pgError.ColumnName, pgError.DataTypeName, pgError.ConstraintName, pgError.Routine}, "\n")
}

// withSecret runs the login function's preparation in a transaction that is always rolled back: the secret table with value, the
// function source, then call. It returns the call's error.
func withSecret(t *testing.T, conn *pgx.Conn, value, source string, before func(tx pgx.Tx), call func(tx pgx.Tx) error) error {
	t.Helper()
	ctx := context.Background()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if before != nil {
		before(tx)
	}
	if _, err = tx.Exec(ctx, secretTable); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.CopyFrom(ctx, pgx.Identifier{"pg_temp", "arcforges_login_secret"}, []string{"secret"}, pgx.CopyFromRows([][]any{{value}})); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, source); err != nil {
		t.Fatal(err)
	}
	return call(tx)
}

func unhandledSource(t *testing.T) string {
	t.Helper()
	unhandled := strings.Replace(setLoginSource, "EXCEPTION WHEN OTHERS OR query_canceled THEN\n    RAISE EXCEPTION USING ERRCODE = SQLSTATE, MESSAGE = 'login role update failed';\n", "", 1)
	if unhandled == setLoginSource {
		t.Fatal("the control did not remove the handler")
	}
	return unhandled
}

// A failing password statement reports its SQLSTATE and a fixed message: neither the error nor its context quotes the dynamic
// statement, which holds the secret. Without the handler the context would (the control below).
func TestTheLoginRoleFunctionHidesItsStatement(t *testing.T) {
	url, _ := migrated(t)
	conn := pgtest.Connect(t, url)
	ctx := context.Background()
	const phrase = "Hidden-value_0123456789-abcdefghijklmnop"
	absent := func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, setLoginCall, "arcforges_absent_role") // 42704 inside the function
		return err
	}
	err := withSecret(t, conn, phrase, setLoginSource, nil, absent)
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) || pgError.Code != "42704" || pgError.Message != "login role update failed" {
		t.Fatalf("the failure: %v", err)
	}
	if strings.Contains(fields(err), phrase) || strings.Contains(fields(err), "PASSWORD") {
		t.Fatalf("the error or its context quotes the role statement: %s", fields(err))
	}
	if err = withSecret(t, conn, phrase, unhandledSource(t), nil, absent); !strings.Contains(fields(err), phrase) {
		t.Fatalf("the control's context does not quote the statement, so the test proves nothing: %s", fields(err))
	}
}

// knownPassword makes the next rotations use a password the test knows, so it can look for it in errors and logs.
func knownPassword(t *testing.T) string {
	t.Helper()
	phrase, err := Password()
	if err != nil {
		t.Fatal(err)
	}
	previous := newPassword
	newPassword = func() (string, error) { return phrase, nil }
	t.Cleanup(func() { newPassword = previous })
	return phrase
}

// serverLog reads the test server's log, or skips the log part where it cannot be read.
func serverLog(t *testing.T) (string, bool) {
	t.Helper()
	log, ok := pgtest.ServerLog(t)
	if !ok && os.Getenv(pgtest.EnvRequired) == "1" && os.Getenv(pgtest.EnvContainer) == "" {
		t.Log("the test server's log cannot be read here; the log checks are skipped")
	}
	return log, ok
}

// debug_print_parse and debug_print_rewritten are user-settable; the function switches them off for its own execution, so no
// parse dump of the nested password statement reaches the log. The control function without the SET clauses leaks.
func TestDebugPrintSettingsLogNoSecret(t *testing.T) {
	url, group := migrated(t)
	ctx := context.Background()
	conn := pgtest.Connect(t, url)
	var database string
	if err := conn.QueryRow(ctx, "SELECT current_database()").Scan(&database); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "ALTER DATABASE "+pgx.Identifier{database}.Sanitize()+" SET debug_print_parse = on"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "ALTER DATABASE "+pgx.Identifier{database}.Sanitize()+" SET debug_print_rewritten = on"); err != nil {
		t.Fatal(err)
	}
	phrase := knownPassword(t)
	rotation := rotator{t: t, url: url, group: group}.rotate()
	if rotation.Logging.DebugPrintParse != "on" || rotation.Logging.DebugPrintRewritten != "on" {
		t.Fatalf("logging %+v", rotation.Logging)
	}
	// The control: without the function's SET clauses, the parse dump carries a value from the secret table.
	const control = "Control-value_0123456789-abcdefghijklmn"
	fresh := pgtest.Connect(t, url)
	_ = withSecret(t, fresh, control, strings.Replace(setLoginSource, "SET debug_print_parse = off SET debug_print_rewritten = off SET debug_print_plan = off\n", "", 1), nil,
		func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, setLoginCall, rotation.LoginRole)
			return err
		})
	log, ok := serverLog(t)
	if !ok {
		return
	}
	if strings.Contains(log, phrase) || strings.Contains(log, storedSecret(t, rotation.LoginRole)) {
		t.Fatal("a parse dump in the server log holds the secret")
	}
	if !strings.Contains(log, control) || !strings.Contains(log, "{QUERY") {
		t.Fatal("the control did not leak into the parse dump, so the test proves nothing")
	}
}

// A session holding the login role's row makes the rotation fail cleanly on the secret-free statement, before any secret is
// involved; the lock-wait message names only that statement.
func TestABlockedRoleRowFailsTheRotationCleanly(t *testing.T) {
	url, group := migrated(t)
	ctx := context.Background()
	r := rotator{t: t, url: url, group: group}
	r.confirm(r.rotate().Slot) // a
	r.confirm(r.rotate().Slot) // b: the next rotation takes a again
	var database string
	if err := pgtest.Connect(t, url).QueryRow(ctx, "SELECT current_database()").Scan(&database); err != nil {
		t.Fatal(err)
	}
	admin := pgtest.Connect(t, pgtest.WithDatabase(t, pgtest.ServerURL(t), database))
	for _, setting := range []string{"log_lock_waits = on", "deadlock_timeout = '100ms'"} {
		if _, err := admin.Exec(ctx, "ALTER DATABASE "+pgx.Identifier{database}.Sanitize()+" SET "+setting); err != nil {
			t.Fatal(err)
		}
	}
	holder, err := pgtest.Connect(t, url).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(ctx) }()
	if _, err = holder.Exec(ctx, "ALTER ROLE "+group+"_a CONNECTION LIMIT 5"); err != nil {
		t.Fatal(err)
	}
	phrase := knownPassword(t)
	_, err = Rotate(ctx, pgtest.Connect(t, url), Options{Group: group, DirectURL: url, PooledHost: pgtest.Host(t), Runner: "test",
		ProbeTimeout: 10 * time.Second, RoleLockTimeout: 400 * time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "take the login role") || !strings.Contains(err.Error(), "55P03") {
		t.Fatalf("the blocked rotation: %v", err)
	}
	if strings.Contains(fields(err), phrase) {
		t.Fatal("the error holds the secret")
	}
	log, ok := serverLog(t)
	if !ok {
		return
	}
	if strings.Contains(log, phrase) {
		t.Fatal("the server log holds the secret")
	}
	if !strings.Contains(log, "still waiting for") {
		t.Fatal("no lock wait was logged, so the test proves nothing")
	}
}

// The residual path: were the password statement itself to wait (bypassing the secret-free statement) and be cancelled by
// statement_timeout, the handler catches the cancellation too, so neither the error nor the log carries the statement.
func TestACancelledPasswordStatementLogsNoSecret(t *testing.T) {
	url, group := migrated(t)
	ctx := context.Background()
	r := rotator{t: t, url: url, group: group}
	login := r.rotate().LoginRole
	holder, err := pgtest.Connect(t, url).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(ctx) }()
	if _, err = holder.Exec(ctx, "ALTER ROLE "+login+" CONNECTION LIMIT 5"); err != nil {
		t.Fatal(err)
	}
	const phrase = "Cancelled-value_0123456789-abcdefghijkl"
	err = withSecret(t, pgtest.Connect(t, url), phrase, setLoginSource,
		func(tx pgx.Tx) {
			if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = 300"); err != nil {
				t.Fatal(err)
			}
		},
		func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, setLoginCall, login)
			return err
		})
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) || pgError.Code != "57014" || pgError.Message != "login role update failed" {
		t.Fatalf("the cancelled call: %v", err)
	}
	if strings.Contains(fields(err), phrase) || strings.Contains(fields(err), "PASSWORD") {
		t.Fatalf("the error quotes the statement: %s", fields(err))
	}
	if log, ok := serverLog(t); ok && strings.Contains(log, phrase) {
		t.Fatal("the server log holds the secret")
	}
}

// The secret appears in no pg_stat_statements row and, where the test server's log can be read (the Linux leg: log_statement
// 'all', log_min_duration_statement 0), in no log line; pg_stat_statements.track = 'all' and log_parser_stats = on refuse the
// rotation.
func TestTheSecretReachesNoStatementRecordOrLog(t *testing.T) {
	url, group := migrated(t)
	ctx := context.Background()
	var database string
	if err := pgtest.Connect(t, url).QueryRow(ctx, "SELECT current_database()").Scan(&database); err != nil {
		t.Fatal(err)
	}
	admin := pgtest.Connect(t, pgtest.WithDatabase(t, pgtest.ServerURL(t), database))
	var track *string
	if err := admin.QueryRow(ctx, "SELECT current_setting('pg_stat_statements.track', true)").Scan(&track); err != nil {
		t.Fatal(err)
	}
	if track == nil {
		if os.Getenv(pgtest.EnvRequired) == "1" {
			t.Fatal("the test server does not preload pg_stat_statements")
		}
		t.Skip("the test server does not preload pg_stat_statements")
	}
	if _, err := admin.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS pg_stat_statements"); err != nil {
		t.Fatal(err)
	}
	r := rotator{t: t, url: url, group: group}
	rotation := r.rotate()
	if rotation.Logging.PgStatStatementsTrack != *track || rotation.Logging.LogStatement == "" || rotation.Logging.LogMinDurationStatement == "" {
		t.Fatalf("logging %+v", rotation.Logging)
	}
	phrase := passwordOf(rotation.RuntimeURL)
	stored := storedSecret(t, rotation.LoginRole)
	rows, err := admin.Query(ctx, "SELECT query FROM pg_stat_statements")
	if err != nil {
		t.Fatal(err)
	}
	queries, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	called := false
	for _, query := range queries {
		if strings.Contains(query, phrase) || strings.Contains(query, stored) {
			t.Fatal("pg_stat_statements recorded the secret")
		}
		called = called || strings.Contains(query, "arcforges_set_login($1)")
	}
	if !called {
		t.Fatal("pg_stat_statements did not record the call, so the test proves nothing")
	}
	if log, ok := pgtest.ServerLog(t); ok {
		if strings.Contains(log, phrase) || strings.Contains(log, stored) {
			t.Fatal("the server log holds the secret")
		}
		if !strings.Contains(log, "arcforges_set_login") || !strings.Contains(log, "duration:") {
			t.Fatal("the server log does not show the rotation's statements and durations, so the test proves nothing")
		}
	}
	if _, err = admin.Exec(ctx, "ALTER DATABASE "+pgx.Identifier{database}.Sanitize()+" SET pg_stat_statements.track = 'all'"); err != nil {
		t.Fatal(err)
	}
	_, err = Rotate(ctx, pgtest.Connect(t, url), Options{Group: group, DirectURL: url, PooledHost: pgtest.Host(t), Runner: "test", ProbeTimeout: 10 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "pg_stat_statements.track") {
		t.Fatalf("track = 'all' was not refused: %v", err)
	}
	// log_parser_stats logs parser statistics with the nested statement as context, and only a superuser can switch it off.
	for _, statement := range []string{"RESET pg_stat_statements.track", "SET log_parser_stats = on"} {
		if _, err = admin.Exec(ctx, "ALTER DATABASE "+pgx.Identifier{database}.Sanitize()+" "+statement); err != nil {
			t.Fatal(err)
		}
	}
	_, err = Rotate(ctx, pgtest.Connect(t, url), Options{Group: group, DirectURL: url, PooledHost: pgtest.Host(t), Runner: "test", ProbeTimeout: 10 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "log_parser_stats") {
		t.Fatalf("log_parser_stats = on was not refused: %v", err)
	}
}
