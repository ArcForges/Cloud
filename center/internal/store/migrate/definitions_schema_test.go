// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
)

// migration0007SHA256 pins the applied form of 0007_entitlement_definitions_current.sql (immutable once applied).
const migration0007SHA256 = "5fa106a23788c7f5600c538177e5bbbcc8f549e7df47bfcfff53ca9aa1ed7530"

// TestMigration0007LandsOverVersion6 is E0-8 (AF-CTR-05 part E0, store-1; EVIDENCE: REAL PostgreSQL, REAL runner): a database at
// version 6, owned by a migration role that is not a superuser, receives 0007 from the center's own runner; its checksum is the pinned
// one; the runtime role holds exactly select, insert and update on entitlement.definitions_current (no delete); the table holds one
// row with a well-formed version; and the row is written once per version: an update that keeps the version and any deletion are
// refused by its trigger, while an update to another version is the one change it admits.
func TestMigration0007LandsOverVersion6(t *testing.T) {
	build := centerBuild(t)
	if len(build) < 7 || build[6].Name != "0007_entitlement_definitions_current.sql" {
		t.Fatalf("the build has no 0007 as its seventh migration: %d migrations", len(build))
	}
	if build[6].SHA256 != migration0007SHA256 {
		t.Fatalf("0007_entitlement_definitions_current.sql has the checksum %s, pinned %s", build[6].SHA256, migration0007SHA256)
	}
	ctx := context.Background()
	url, name := pgtest.Database(t)
	conn := pgtest.Connect(t, url)
	schemas6, grants6 := schemasAndGrantsAt(6)
	if sixth, err := apply(t, url, build[:6], Options{Runner: "test", RuntimeRole: name + "_runtime", Schemas: schemas6, Grants: grants6}); err != nil || sixth.Version != 6 {
		t.Fatalf("version 6: %+v %v", sixth, err)
	}
	result, err := apply(t, url, build[:7], Options{Runner: "test", RuntimeRole: name + "_runtime"})
	if err != nil || result.Version != 7 || len(result.Ran) != 1 || result.Ran[0].SHA256 != migration0007SHA256 || result.Grants != "reconciled" {
		t.Fatalf("0007 over version 6: %+v %v", result, err)
	}
	for kind, want := range map[string]bool{"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": false, "TRUNCATE": false} {
		var has bool
		if err = conn.QueryRow(ctx, "SELECT has_table_privilege($1, 'entitlement.definitions_current', $2)", name+"_runtime", kind).Scan(&has); err != nil || has != want {
			t.Errorf("the runtime role's %s: %v %v", kind, has, err)
		}
	}
	exec := func(statement string, arguments ...any) error {
		_, err := conn.Exec(ctx, statement, arguments...)
		return err
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
	refusedBy(t, "23514", "definitions_current_singleton", "INSERT INTO entitlement.definitions_current (singleton, definitions_version, recorded_at) VALUES (false, 'v1', $1)", at)
	refusedBy(t, "23514", "definitions_current_version", "INSERT INTO entitlement.definitions_current (definitions_version, recorded_at) VALUES ('a version', $1)", at)
	refusedBy(t, "23514", "definitions_current_version", "INSERT INTO entitlement.definitions_current (definitions_version, recorded_at) VALUES ('', $1)", at)
	if err = exec("INSERT INTO entitlement.definitions_current (definitions_version, recorded_at) VALUES ('dev-1', $1)", at); err != nil {
		t.Fatal(err)
	}
	refusedBy(t, "23505", "definitions_current_pkey", "INSERT INTO entitlement.definitions_current (definitions_version, recorded_at) VALUES ('dev-2', $1)", at)
	// The one write per version: rewriting the same version (even its instant alone) and deleting the row are refused.
	refusedBy(t, "55000", "", "UPDATE entitlement.definitions_current SET recorded_at = $1", at.Add(time.Hour))
	refusedBy(t, "55000", "", "DELETE FROM entitlement.definitions_current")
	if err = exec("UPDATE entitlement.definitions_current SET definitions_version = 'dev-2', recorded_at = $1", at.Add(time.Hour)); err != nil {
		t.Fatalf("a start with another version: %v", err)
	}
	var version string
	var recorded time.Time
	if err = conn.QueryRow(ctx, "SELECT definitions_version, recorded_at FROM entitlement.definitions_current").Scan(&version, &recorded); err != nil ||
		version != "dev-2" || !recorded.Equal(at.Add(time.Hour)) {
		t.Fatalf("the fact after a change: %q %v %v", version, recorded, err)
	}
	var rows int
	if err = conn.QueryRow(ctx, "SELECT count(*) FROM entitlement.definitions_current").Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("%d rows %v", rows, err)
	}
}
