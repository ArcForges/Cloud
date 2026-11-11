// SPDX-License-Identifier: AGPL-3.0-only

package provision

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/ArcForges/Cloud/center/internal/store/migrate"
	"github.com/jackc/pgx/v5"
)

func TestCTR06SelectorEmptyUnconfirmedAndApplicablePromotion(t *testing.T) {
	url, group := migrated(t)
	r := rotator{t: t, url: url, group: group}
	first := r.rotate()
	unconfirmed := r.rotate()
	if first.Slot != "a" || unconfirmed.Slot != "a" {
		t.Fatalf("empty and unconfirmed history selected %s and %s", first.Slot, unconfirmed.Slot)
	}
	r.confirm(unconfirmed.Slot)
	next := r.rotate()
	if next.Slot != "b" {
		t.Fatalf("the checked promoted a history selected %s", next.Slot)
	}
	r.confirm(next.Slot)
}

func TestCTR06SelectorRejectsForeignAmbiguousAndUnreadableHistory(t *testing.T) {
	for _, kind := range []string{"foreign", "ambiguous", "rls", "unreadable"} {
		t.Run(kind, func(t *testing.T) {
			url, group := migrated(t)
			ctx := context.Background()
			conn := pgtest.Connect(t, url)
			switch kind {
			case "foreign":
				_, err := conn.Exec(ctx, `INSERT INTO platform.runtime_credential(slot,login_role,rotated_at,rotated_by,promoted_at)
 VALUES('a',$1,clock_timestamp(),'test',clock_timestamp())`, group+"_foreign_a")
				if err != nil {
					t.Fatal(err)
				}
			case "ambiguous":
				_, err := conn.Exec(ctx, `INSERT INTO platform.runtime_credential(slot,login_role,rotated_at,rotated_by,promoted_at)
 SELECT slot,$1::text||'_'||slot,t,t::text,t FROM (VALUES('a'),('b')) s(slot) CROSS JOIN (SELECT clock_timestamp() AS t) x`, group)
				if err != nil {
					t.Fatal(err)
				}
			case "rls":
				if _, err := conn.Exec(ctx, "ALTER TABLE platform.runtime_credential ENABLE ROW LEVEL SECURITY; ALTER TABLE platform.runtime_credential FORCE ROW LEVEL SECURITY"); err != nil {
					t.Fatal(err)
				}
			case "unreadable":
				var owner string
				if err := conn.QueryRow(ctx, "SELECT current_user").Scan(&owner); err != nil {
					t.Fatal(err)
				}
				if _, err := conn.Exec(ctx, "REVOKE SELECT ON platform.runtime_credential FROM "+pgx.Identifier{owner}.Sanitize()); err != nil {
					t.Fatal(err)
				}
			}
			before := make([]bool, 2)
			if err := conn.QueryRow(ctx, "SELECT (SELECT rolcanlogin FROM pg_roles WHERE rolname=$1),(SELECT rolcanlogin FROM pg_roles WHERE rolname=$2)", group+"_a", group+"_b").Scan(&before[0], &before[1]); err != nil {
				t.Fatal(err)
			}
			_, err := Rotate(ctx, conn, Options{Group: group, DirectURL: url, PooledHost: pgtest.Host(t), Runner: "test", ProbeTimeout: 10 * time.Second})
			want := map[string]string{"foreign": "does not match the checked generation", "ambiguous": "promotion history is ambiguous", "rls": "cannot be read completely", "unreadable": "read the runtime credentials"}[kind]
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("%s history was not specifically refused: %v", kind, err)
			}
			after := make([]bool, 2)
			if err := conn.QueryRow(ctx, "SELECT (SELECT rolcanlogin FROM pg_roles WHERE rolname=$1),(SELECT rolcanlogin FROM pg_roles WHERE rolname=$2)", group+"_a", group+"_b").Scan(&after[0], &after[1]); err != nil || before[0] != after[0] || before[1] != after[1] {
				t.Fatalf("%s refusal changed login availability: %v %v %v", kind, before, after, err)
			}
		})
	}
}

func TestCTR06FloorIdentityMismatchAndUnreadableClusterRefuseAdministration(t *testing.T) {
	for _, kind := range []string{"different-cluster", "missing-admission", "unreadable-cluster"} {
		t.Run(kind, func(t *testing.T) {
			url, group := migrated(t)
			ctx := context.Background()
			conn := pgtest.Connect(t, url)
			build, err := migrate.Load(schema.Migrations())
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "different-cluster":
				if _, err := conn.Exec(ctx, "UPDATE platform.ctr06_runtime_floor SET cluster_system_identifier='0'"); err != nil {
					t.Fatal(err)
				}
			case "missing-admission":
				if _, err := conn.Exec(ctx, "DELETE FROM platform.ctr06_restore_admission"); err != nil {
					t.Fatal(err)
				}
			case "unreadable-cluster":
				database := strings.TrimSuffix(group, "_runtime")
				admin := pgtest.Connect(t, pgtest.WithDatabase(t, pgtest.ServerURL(t), database))
				if _, err := admin.Exec(ctx, "REVOKE EXECUTE ON FUNCTION pg_catalog.pg_control_system() FROM PUBLIC"); err != nil {
					t.Fatal(err)
				}
				var unused string
				if err := conn.QueryRow(ctx, "SELECT system_identifier::text FROM pg_catalog.pg_control_system()").Scan(&unused); !pgtest.IsCode(err, "42501") {
					t.Fatalf("identity was still readable after the isolated database revoke: %v", err)
				}
			}
			status, err := migrate.Inspect(ctx, conn, build)
			if !errors.Is(err, migrate.ErrCTR06RetirementUnproven) || status.State != migrate.StateRefused {
				t.Fatalf("%s status trusted: %+v %v", kind, status, err)
			}
			if result, err := migrate.Apply(ctx, conn, build, migrate.Options{RuntimeRole: group}); !errors.Is(err, migrate.ErrCTR06RetirementUnproven) || result.State != migrate.StateRefused {
				t.Fatalf("%s reconciliation trusted: %+v %v", kind, result, err)
			}
			if _, err := Rotate(ctx, conn, Options{Group: group, DirectURL: url}); !errors.Is(err, migrate.ErrCTR06RetirementUnproven) {
				t.Fatalf("%s rotation trusted: %v", kind, err)
			}
			if _, err := Confirm(ctx, conn, group, "a"); !errors.Is(err, migrate.ErrCTR06RetirementUnproven) {
				t.Fatalf("%s confirmation trusted: %v", kind, err)
			}
		})
	}
}
