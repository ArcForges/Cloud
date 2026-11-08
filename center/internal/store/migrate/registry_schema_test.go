// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// migration0009SHA256 pins the applied form of 0009_fleet_node_names.sql (immutable once applied).
const migration0009SHA256 = "35d2fcd03470e8638c5a840c9bf3609eab1f476c61a7b30dbd7302d9873a0586"

// TestMigration0009LandsOverVersion8 (AF-CTR-05 part E2a; Plan CTR5-API-03, Q25; EVIDENCE: REAL PostgreSQL, REAL runner): a database at
// version 8 with an enrolled node row, owned by a migration role that is not a superuser, receives 0009 from the center's own runner. Its
// checksum is the pinned one; the node row keeps its values and gains reported_name empty and named_by_account false (the expand step);
// the previous release's insert, which names neither column, still lands; the runtime role keeps exactly select, insert and update on
// fleet.node; a reported name is 1 to 64 characters without control characters, and named_by_account is never NULL.
func TestMigration0009LandsOverVersion8(t *testing.T) {
	build := centerBuild(t)
	if len(build) < 9 || build[8].Name != "0009_fleet_node_names.sql" {
		t.Fatalf("the build has no 0009 as its ninth migration: %d migrations", len(build))
	}
	if build[8].SHA256 != migration0009SHA256 {
		t.Fatalf("0009_fleet_node_names.sql has the checksum %s, pinned %s", build[8].SHA256, migration0009SHA256)
	}
	ctx := context.Background()
	url, name := pgtest.Database(t)
	conn := pgtest.Connect(t, url)
	schemas8, grants8 := schemasAndGrantsAt(8)
	if eighth, err := apply(t, url, build[:8], Options{Runner: "test", RuntimeRole: name + "_runtime", Schemas: schemas8, Grants: grants8}); err != nil ||
		eighth.Version != 8 {
		t.Fatalf("version 8: %+v %v", eighth, err)
	}
	exec := func(statement string, arguments ...any) error {
		_, err := conn.Exec(ctx, statement, arguments...)
		return err
	}
	user, device, installation, enrollment, node := platform.NewID(), platform.NewID(), platform.NewID(), platform.NewID(), platform.NewID()
	seed := []struct {
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
	}
	for _, statement := range seed {
		if err := exec(statement.sql, statement.arguments...); err != nil {
			t.Fatalf("seeding the previous release's node: %v", err)
		}
	}
	schemas9, grants9 := schemasAndGrantsAt(9)
	result, err := apply(t, url, build[:9], Options{Runner: "test", RuntimeRole: name + "_runtime", Schemas: schemas9, Grants: grants9})
	if err != nil || result.Version != 9 || len(result.Ran) != 1 || result.Ran[0].SHA256 != migration0009SHA256 || result.Grants != "reconciled" {
		t.Fatalf("0009 over version 8: %+v %v", result, err)
	}
	var reported *string
	var named bool
	var display string
	if err = conn.QueryRow(ctx, "SELECT reported_name, named_by_account, display_name FROM fleet.node WHERE enrollment_id = $1", enrollment).
		Scan(&reported, &named, &display); err != nil || reported != nil || named || display != "buildbox" {
		t.Fatalf("the previous release's node after 0009: %v %v %q %v", reported, named, display, err)
	}
	// The previous release's enrollment insert names neither new column.
	device2, installation2 := platform.NewID(), platform.NewID()
	for _, statement := range []struct {
		sql       string
		arguments []any
	}{
		{`INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev)
VALUES ($1, $2, 'laptop', 3, 1, false, now(), now(), 1)`, []any{device2, user}},
		{`INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, installed_at, last_active_at, rev)
VALUES ($1, $2, $3, 'arcforges-node', '0.1.0', 'linux', now(), now(), 1)`, []any{installation2, device2, user}},
		{`INSERT INTO fleet.node (enrollment_id, node_id, user_id, device_id, installation_id, display_name, os, arch, version, enrolled_at, last_seen_at, rev)
VALUES ($1, $2, $3, $4, $5, 'laptop', 2, 1, '0.1.0', now(), now(), 1)`, []any{platform.NewID(), platform.NewID(), user, device2, installation2}},
	} {
		if err := exec(statement.sql, statement.arguments...); err != nil {
			t.Fatalf("the previous release's enrollment after 0009: %v", err)
		}
	}
	for kind, want := range map[string]bool{"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": false, "TRUNCATE": false} {
		var has bool
		if err = conn.QueryRow(ctx, "SELECT has_table_privilege($1, 'fleet.node', $2)", name+"_runtime", kind).Scan(&has); err != nil || has != want {
			t.Errorf("the runtime role's %s on fleet.node: %v %v", kind, has, err)
		}
	}
	refusedBy := func(code, constraint, statement string, arguments ...any) {
		t.Helper()
		err := exec(statement, arguments...)
		var pgError *pgconn.PgError
		if !errors.As(err, &pgError) || pgError.Code != code || constraint != "" && pgError.ConstraintName != constraint {
			t.Errorf("not refused with %s %s (%v): %s %v", code, constraint, err, statement, arguments)
		}
	}
	for _, bad := range []string{"", strings.Repeat("n", 65), "build\nbox", "build\tbox"} {
		refusedBy("23514", "node_reported_name", "UPDATE fleet.node SET reported_name = $2 WHERE enrollment_id = $1", enrollment, bad)
	}
	refusedBy("23502", "", "UPDATE fleet.node SET named_by_account = NULL WHERE enrollment_id = $1", enrollment)
	if err = exec("UPDATE fleet.node SET reported_name = $2, named_by_account = true WHERE enrollment_id = $1", enrollment, strings.Repeat("n", 64)); err != nil {
		t.Fatalf("a 64-character reported name: %v", err)
	}
}
