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

// A failing role statement reports its SQLSTATE and a fixed message: neither the error nor its context quotes the dynamic
// statement, which holds the secret. Without the handler the context would (the control below).
func TestTheLoginRoleFunctionHidesItsStatement(t *testing.T) {
	url, group := migrated(t)
	conn := pgtest.Connect(t, url)
	ctx := context.Background()
	const phrase = "Hidden-value_0123456789-abcdefghijklmnop"
	call := func(source string) error {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err = tx.Exec(ctx, secretTable); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.CopyFrom(ctx, pgx.Identifier{"pg_temp", "arcforges_login_secret"}, []string{"secret"}, pgx.CopyFromRows([][]any{{phrase}})); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, source); err != nil {
			t.Fatal(err)
		}
		// Creating the existing group role again fails (42710) inside the function.
		_, err = tx.Exec(ctx, setLoginCall, group, 4, true)
		return err
	}
	err := call(setLoginSource)
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) || pgError.Code != "42710" || pgError.Message != "login role update failed" {
		t.Fatalf("the failure: %v", err)
	}
	if strings.Contains(fields(err), phrase) || strings.Contains(fields(err), "PASSWORD") {
		t.Fatalf("the error or its context quotes the role statement: %s", fields(err))
	}
	// The control: the same function without the handler puts the statement, secret included, into the error's context.
	unhandled := strings.Replace(setLoginSource, "EXCEPTION WHEN OTHERS THEN\n    RAISE EXCEPTION USING ERRCODE = SQLSTATE, MESSAGE = 'login role update failed';\n", "", 1)
	if unhandled == setLoginSource {
		t.Fatal("the control did not remove the handler")
	}
	if err = call(unhandled); !strings.Contains(fields(err), phrase) {
		t.Fatalf("the control's context does not quote the statement, so the test proves nothing: %s", fields(err))
	}
}

// The secret appears in no pg_stat_statements row and, where the test server's log can be read (the Linux leg: log_statement
// 'all', log_min_duration_statement 0), in no log line; pg_stat_statements.track = 'all' refuses the rotation.
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
		called = called || strings.Contains(query, "arcforges_set_login($1, $2, $3)")
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
}
