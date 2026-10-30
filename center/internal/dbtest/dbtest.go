// SPDX-License-Identifier: AGPL-3.0-only

// Package dbtest gives the tests of the packages above the store one migrated PostgreSQL database with the runtime role's store on it
// and a few helpers to seed and count rows (EVIDENCE: REAL PostgreSQL, the pinned image of the Linux leg). It is linked into test
// binaries only and imports no package that builds on the store, so any of their tests may use it.
package dbtest

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/provision"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/ArcForges/Cloud/center/internal/store"
	"github.com/ArcForges/Cloud/center/internal/store/migrate"
)

// Database is a migrated test database.
type Database struct {
	T *testing.T
	// Migration is a connection of the migration role (the owner): it seeds what the runtime role may not write.
	Migration *pgx.Conn
	// Runtime is the runtime role's store: exactly the privileges of a deployed center.
	Runtime *store.DB
	// URL is the migration role's URL, RuntimeURL the runtime role's.
	URL        string
	RuntimeURL string
	Name       string
}

// New creates an isolated database, applies every migration with the center's own runner and connects the runtime role.
func New(t *testing.T) *Database {
	t.Helper()
	url, name := pgtest.Database(t)
	group := name + "_runtime"
	build, err := migrate.Load(schema.Migrations())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	migration := pgtest.Connect(t, url)
	if _, err = migrate.Apply(ctx, migration, build, migrate.Options{Runner: "test", RuntimeRole: group}); err != nil {
		t.Fatal(err)
	}
	rotation, err := provision.Rotate(ctx, pgtest.Connect(t, url), provision.Options{Group: group, DirectURL: url, PooledHost: pgtest.Host(t), Runner: "test", ProbeTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return &Database{T: t, Migration: migration, Runtime: store.New(pgtest.Pool(t, rotation.RuntimeURL, 8)), URL: url, RuntimeURL: rotation.RuntimeURL, Name: name}
}

// Exec runs statements as the migration role.
func (d *Database) Exec(statements ...string) {
	d.T.Helper()
	for _, statement := range statements {
		if _, err := d.Migration.Exec(context.Background(), statement); err != nil {
			d.T.Fatalf("%s: %v", statement, err)
		}
	}
}

// Count runs a query that returns one integer as the migration role.
func (d *Database) Count(query string, arguments ...any) int {
	d.T.Helper()
	var count int
	if err := d.Migration.QueryRow(context.Background(), query, arguments...).Scan(&count); err != nil {
		d.T.Fatalf("%s: %v", query, err)
	}
	return count
}

var accounts int

// Account creates an account (a user row, as the bootstrap or an enrolment would) in the given state (1 active, 2 restricted, 3
// suspended) and returns its ID.
func (d *Database) Account(state int16) platform.ID {
	d.T.Helper()
	id := platform.NewID()
	handle := make([]byte, 32)
	copy(handle, id[:])
	accounts++
	handle[31] = byte(accounts)
	if _, err := d.Migration.Exec(context.Background(), `INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev)
VALUES ($1, 'Test', $2, $3, now(), 1)`, id, state, handle); err != nil {
		d.T.Fatal(err)
	}
	return id
}
