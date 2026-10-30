// SPDX-License-Identifier: AGPL-3.0-only

// Package dbtest gives the tests of the packages above the store one migrated PostgreSQL database with the runtime role's store on it
// and a few helpers to seed and count rows (EVIDENCE: REAL PostgreSQL, the pinned image of the Linux leg). It is linked into test
// binaries only and imports no package that builds on the store, so any of their tests may use it.
package dbtest

import (
	"context"
	"crypto/sha256"
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

// Session is a browser cookie session of an account, seeded by the migration role.
type Session struct {
	ID       platform.ID
	DeviceID platform.ID
	User     platform.ID
	// Handle is the cookie handle's raw bytes; the stored digest is of these.
	Handle []byte
}

// Session seeds a browser session of an account: its web device and installation and a live cookie session of the scope (1 account,
// 2 mobile.limited). The session is at epochs zero, the state every new session starts in.
func (d *Database) Session(user platform.ID, scope int16) Session {
	d.T.Helper()
	device, installation, id := platform.NewID(), platform.NewID(), platform.NewID()
	handle := make([]byte, 32)
	copy(handle, id[:])
	digest := sha256sum(handle)
	ctx := context.Background()
	statements := []struct {
		sql       string
		arguments []any
	}{
		{`INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev)
VALUES ($1, $2, 'Browser', 6, 1, false, now(), now(), 1)`, []any{device, user}},
		{`INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, client_installation_id, installed_at, last_active_at, rev)
VALUES ($1, $2, $3, 'arcforges-web', 'web', 'web', $4, now(), now(), 1)`, []any{installation, device, user, platform.NewID()}},
		{`INSERT INTO identity.session (session_id, user_id, device_id, installation_id, credential_kind, scope, product_id, purpose, auth_method, authenticated_at,
    issued_at, expires_at, idle_expires_at, last_activity_at, browser_handle_hash, browser_origin, auth_epoch, recovery_generation, session_policy_version, rev)
VALUES ($1, $2, $3, $4, 2, $5, 'arcforges-web', 1, 1, now(), now(), now() + interval '12 hours', now() + interval '30 minutes', now(), $6,
    'https://center.example', 0, 0, 'v1', 1)`, []any{id, user, device, installation, scope, digest[:]}},
	}
	for _, statement := range statements {
		if _, err := d.Migration.Exec(ctx, statement.sql, statement.arguments...); err != nil {
			d.T.Fatal(err)
		}
	}
	return Session{ID: id, DeviceID: device, User: user, Handle: handle}
}

// ProveStepUp seeds a proved, unconsumed passkey step-up challenge of a session for an operation class and target hash, proved at the
// given instant and valid for the five minutes the evidence lasts.
func (d *Database) ProveStepUp(session Session, class string, target []byte, proved time.Time) platform.ID {
	d.T.Helper()
	id := platform.NewID()
	if _, err := d.Migration.Exec(context.Background(), `INSERT INTO identity.step_up_challenge (challenge_id, user_id, session_id, operation_id, target_hash, method, challenge,
    state, attempt_count, created_at, expires_at, proved_at, auth_epoch, recovery_generation, rev)
VALUES ($1, $2, $3, $4, $5, 1, decode(repeat('c1', 32), 'hex'), 2, 0, $6, $7, $6, 0, 0, 1)`, id, session.User, session.ID, class, target, proved.UTC(), proved.UTC().Add(5*time.Minute)); err != nil {
		d.T.Fatal(err)
	}
	return id
}

func sha256sum(data []byte) [32]byte { return sha256.Sum256(data) }
