// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// migration0008SHA256 pins the applied form of 0008_fleet_channel.sql (immutable once applied).
const migration0008SHA256 = "d791661faeec2a1ee6f999e0799165b2be88737f966d89e97297e84c9683bcda"

// TestMigration0008LandsOverVersion7 is E1-22 (AF-CTR-05 part E1a; Plan C.8 as amended by PB-5; EVIDENCE: REAL PostgreSQL, REAL
// runner): a database at version 7 with an enrolled node row, owned by a migration role that is not a superuser, receives 0008 from the
// center's own runner. Its checksum is the pinned one; the node row keeps its values and gains the three presence columns empty (the
// expand step: the previous release's statements name their columns); the runtime role holds exactly select, insert and update on
// fleet.hub_lease; the presence checks refuse a heartbeat or a connection without online_since and a heartbeat before it; the lease is
// one row whose fence only rises, which changes holder only with a higher fence and which is never deleted.
func TestMigration0008LandsOverVersion7(t *testing.T) {
	build := centerBuild(t)
	if len(build) < 8 || build[7].Name != "0008_fleet_channel.sql" {
		t.Fatalf("the build has no 0008 as its eighth migration: %d migrations", len(build))
	}
	if build[7].SHA256 != migration0008SHA256 {
		t.Fatalf("0008_fleet_channel.sql has the checksum %s, pinned %s", build[7].SHA256, migration0008SHA256)
	}
	ctx := context.Background()
	url, name := pgtest.Database(t)
	conn := pgtest.Connect(t, url)
	schemas7, grants7 := schemasAndGrantsAt(7)
	if seventh, err := apply(t, url, build[:7], Options{Runner: "test", RuntimeRole: name + "_runtime", Schemas: schemas7, Grants: grants7}); err != nil ||
		seventh.Version != 7 {
		t.Fatalf("version 7: %+v %v", seventh, err)
	}
	exec := func(statement string, arguments ...any) error {
		_, err := conn.Exec(ctx, statement, arguments...)
		return err
	}
	// An enrolled node of the previous release.
	user, device, installation, enrollment, node := platform.NewID(), platform.NewID(), platform.NewID(), platform.NewID(), platform.NewID()
	for _, statement := range []struct {
		sql       string
		arguments []any
	}{
		{`INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev) VALUES ($1, 'Owner', 1, sha256(convert_to($2, 'UTF8')), now(), 1)`,
			[]any{user, user.String()}},
		{`INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev)
VALUES ($1, $2, 'buildbox', 3, 1, false, now(), now(), 1)`, []any{device, user}},
		{`INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, installed_at, last_active_at, rev)
VALUES ($1, $2, $3, 'arcforges-node', '0.1.0', 'linux', now(), now(), 1)`, []any{installation, device, user}},
		{`INSERT INTO fleet.node (enrollment_id, node_id, user_id, device_id, installation_id, display_name, os, arch, version, enrolled_at, last_seen_at, rev)
VALUES ($1, $2, $3, $4, $5, 'buildbox', 2, 1, '0.1.0', now() - interval '1 hour', now() - interval '1 hour', 1)`, []any{enrollment, node, user, device, installation}},
	} {
		if err := exec(statement.sql, statement.arguments...); err != nil {
			t.Fatalf("seeding the previous release's node: %v", err)
		}
	}
	schemas8, grants8 := schemasAndGrantsAt(8)
	result, err := apply(t, url, build[:8], Options{Runner: "test", RuntimeRole: name + "_runtime", Schemas: schemas8, Grants: grants8})
	if err != nil || result.Version != 8 || len(result.Ran) != 1 || result.Ran[0].SHA256 != migration0008SHA256 || result.Grants != "reconciled" {
		t.Fatalf("0008 over version 7: %+v %v", result, err)
	}
	var onlineSince, lastHeartbeat *time.Time
	var connection *[16]byte
	var display string
	if err = conn.QueryRow(ctx, "SELECT online_since, last_heartbeat_at, connection_id, display_name FROM fleet.node WHERE enrollment_id = $1", enrollment).
		Scan(&onlineSince, &lastHeartbeat, &connection, &display); err != nil || onlineSince != nil || lastHeartbeat != nil || connection != nil || display != "buildbox" {
		t.Fatalf("the previous release's node after 0008: %v %v %v %q %v", onlineSince, lastHeartbeat, connection, display, err)
	}
	for kind, want := range map[string]bool{"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": false, "TRUNCATE": false} {
		var has bool
		if err = conn.QueryRow(ctx, "SELECT has_table_privilege($1, 'fleet.hub_lease', $2)", name+"_runtime", kind).Scan(&has); err != nil || has != want {
			t.Errorf("the runtime role's %s on fleet.hub_lease: %v %v", kind, has, err)
		}
	}
	refusedBy := func(t *testing.T, code, constraint, statement string, arguments ...any) {
		t.Helper()
		err := exec(statement, arguments...)
		var pgError *pgconn.PgError
		if !errors.As(err, &pgError) || pgError.Code != code || constraint != "" && pgError.ConstraintName != constraint {
			t.Errorf("not refused with %s %s (%v): %s", code, constraint, err, statement)
		}
	}
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	// Presence: a heartbeat or a connection needs online_since, and a heartbeat comes after it.
	refusedBy(t, "23514", "node_heartbeat", "UPDATE fleet.node SET last_heartbeat_at = $2 WHERE enrollment_id = $1", enrollment, at)
	refusedBy(t, "23514", "node_connection", "UPDATE fleet.node SET connection_id = $2 WHERE enrollment_id = $1", enrollment, platform.NewID())
	refusedBy(t, "23514", "node_heartbeat", "UPDATE fleet.node SET online_since = $2, last_heartbeat_at = $3 WHERE enrollment_id = $1", enrollment, at,
		at.Add(-time.Second))
	if err = exec("UPDATE fleet.node SET online_since = $2, last_heartbeat_at = $2, connection_id = $3 WHERE enrollment_id = $1", enrollment, at,
		platform.NewID()); err != nil {
		t.Fatalf("an accepted channel: %v", err)
	}
	// The lease.
	holder, other := platform.NewID(), platform.NewID()
	refusedBy(t, "23514", "hub_lease_singleton", `INSERT INTO fleet.hub_lease (singleton, holder, fence, acquired_at, renewed_at, expires_at)
VALUES (false, $1, 1, $2, $2, $2)`, holder, at)
	refusedBy(t, "23514", "hub_lease_fence", `INSERT INTO fleet.hub_lease (holder, fence, acquired_at, renewed_at, expires_at) VALUES ($1, 0, $2, $2, $2)`, holder, at)
	refusedBy(t, "23514", "hub_lease_instants", `INSERT INTO fleet.hub_lease (holder, fence, acquired_at, renewed_at, expires_at) VALUES ($1, 1, $2, $3, $2)`,
		holder, at, at.Add(-time.Second))
	if err = exec(`INSERT INTO fleet.hub_lease (holder, fence, acquired_at, renewed_at, expires_at) VALUES ($1, 1, $2, $2, $3)`, holder, at,
		at.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	refusedBy(t, "23505", "hub_lease_pkey", `INSERT INTO fleet.hub_lease (holder, fence, acquired_at, renewed_at, expires_at) VALUES ($1, 1, $2, $2, $2)`, other, at)
	refusedBy(t, "55000", "", "UPDATE fleet.hub_lease SET fence = 0")
	refusedBy(t, "55000", "", "UPDATE fleet.hub_lease SET holder = $1", other)
	refusedBy(t, "55000", "", "DELETE FROM fleet.hub_lease")
	if err = exec("UPDATE fleet.hub_lease SET renewed_at = $1, expires_at = $2", at.Add(10*time.Second), at.Add(40*time.Second)); err != nil {
		t.Fatalf("a renewal: %v", err)
	}
	if err = exec("UPDATE fleet.hub_lease SET holder = $1, fence = fence + 1, acquired_at = $2, renewed_at = $2, expires_at = $3", other, at.Add(time.Minute),
		at.Add(90*time.Second)); err != nil {
		t.Fatalf("a takeover: %v", err)
	}
}
