// SPDX-License-Identifier: AGPL-3.0-only

// Package pgtest gives integration tests an isolated database on a real PostgreSQL server. The server is named by
// ARCFORGES_TEST_POSTGRES_URL (an administrative URL; `python eng/center.py check` starts a PostgreSQL container pinned by digest
// on a loopback port and sets it on the Linux leg). Without it the integration tests skip, unless
// ARCFORGES_TEST_POSTGRES_REQUIRED=1, which turns the skip into a failure: the Linux leg sets both, so it can never pass without
// running them. Every test gets its own database and roles with random names, dropped when the test ends.
package pgtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The environment of the integration server.
const (
	EnvServer   = "ARCFORGES_TEST_POSTGRES_URL"
	EnvRequired = "ARCFORGES_TEST_POSTGRES_REQUIRED"
)

// ServerURL is the administrative URL of the integration server, or skips (fails when required).
func ServerURL(t testing.TB) string {
	t.Helper()
	value := os.Getenv(EnvServer)
	if value == "" {
		if os.Getenv(EnvRequired) == "1" {
			t.Fatalf("%s is required on this leg but not set", EnvServer)
		}
		t.Skipf("integration test: set %s to run it against a real PostgreSQL", EnvServer)
	}
	return value
}

// Name returns a random lowercase identifier with a prefix.
func Name(prefix string) string {
	var random [6]byte
	if _, err := rand.Read(random[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(random[:])
}

// Secret returns a random password.
func Secret() string {
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(random[:])
}

// Admin connects to the server's administrative database.
func Admin(t testing.TB) *pgx.Conn {
	t.Helper()
	return Connect(t, ServerURL(t))
}

// Connect opens a connection that the test closes at cleanup.
func Connect(t testing.TB, value string) *pgx.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, value)
	if err != nil {
		t.Fatalf("connect to the integration server: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// Pool opens a pool in exec mode (no session state, as behind the Neon pooler) that the test closes at cleanup.
func Pool(t testing.TB, value string, maxConns int32) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(value)
	if err != nil {
		t.Fatalf("parse the pool URL: %v", err)
	}
	config.MaxConns = maxConns
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("open the pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// Database creates an isolated database owned by a fresh migration role with CREATEROLE and CREATEDB (as the Neon owner role has) and returns
// the migration role's URL of it. The database and every role created by the test with the prefix are dropped at cleanup.
func Database(t testing.TB) (migrationURL string, name string) {
	t.Helper()
	admin := Admin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	name = Name("center")
	owner, password := name+"_owner", Secret()
	statements := []string{
		"CREATE ROLE " + owner + " LOGIN CREATEROLE CREATEDB PASSWORD '" + password + "'",
		"CREATE DATABASE " + name + " OWNER " + owner,
	}
	for _, statement := range statements {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatalf("create the test database: %v", err)
		}
	}
	t.Cleanup(func() { Drop(t, name) })
	return WithDatabase(t, WithUser(t, ServerURL(t), owner, password), name), name
}

// Drop removes a test database and every role whose name starts with it.
func Drop(t testing.TB, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, ServerURL(t))
	if err != nil {
		t.Errorf("connect to drop %s: %v", name, err)
		return
	}
	defer func() { _ = admin.Close(context.Background()) }()
	if _, err = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
		t.Errorf("drop database %s: %v", name, err)
	}
	rows, err := admin.Query(ctx, "SELECT rolname FROM pg_roles WHERE rolname LIKE $1 ORDER BY length(rolname) DESC", name+"%")
	if err != nil {
		t.Errorf("list the roles of %s: %v", name, err)
		return
	}
	roles, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Errorf("list the roles of %s: %v", name, err)
		return
	}
	for _, role := range roles {
		quoted := pgx.Identifier{role}.Sanitize()
		_, _ = admin.Exec(ctx, "DROP OWNED BY "+quoted+" CASCADE")
		if _, err = admin.Exec(ctx, "DROP ROLE IF EXISTS "+quoted); err != nil {
			t.Errorf("drop role %s: %v", role, err)
		}
	}
}

// WithUser replaces the user and password of a URL.
func WithUser(t testing.TB, value, user, password string) string {
	t.Helper()
	uri, err := url.Parse(value)
	if err != nil {
		t.Fatalf("parse the server URL: %v", err)
	}
	uri.User = url.UserPassword(user, password)
	return uri.String()
}

// WithDatabase replaces the database of a URL.
func WithDatabase(t testing.TB, value, database string) string {
	t.Helper()
	uri, err := url.Parse(value)
	if err != nil {
		t.Fatalf("parse the server URL: %v", err)
	}
	uri.Path = "/" + database
	return uri.String()
}

// Host returns the host:port of the server URL.
func Host(t testing.TB) string {
	t.Helper()
	uri, err := url.Parse(ServerURL(t))
	if err != nil {
		t.Fatalf("parse the server URL: %v", err)
	}
	return uri.Host
}

// IsCode reports whether err is a PostgreSQL error with the SQLSTATE, or a sanitized error that names it.
func IsCode(err error, code string) bool {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		return pgError.Code == code
	}
	return err != nil && strings.Contains(err.Error(), "SQLSTATE "+code)
}
