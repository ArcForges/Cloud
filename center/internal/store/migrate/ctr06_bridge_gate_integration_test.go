// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

func legacyGateFixture(t *testing.T) (string, string, *pgx.Conn, []Migration) {
	t.Helper()
	url, name := pgtest.Database(t)
	build := centerBuild(t)
	if _, err := apply(t, url, build[:10], Options{Runner: "ctr06-gate-test"}); err != nil {
		t.Fatal(err)
	}
	return url, name, pgtest.Connect(t, url), build
}

func requireCTR06Blocked(t *testing.T, url, name string, conn *pgx.Conn, build []Migration) {
	t.Helper()
	if _, err := apply(t, url, build, Options{Runner: "ctr06-gate-test", RuntimeRole: name + "_runtime"}); !errors.Is(err, ErrCTR06RetirementUnproven) {
		t.Fatalf("expected unproven retirement, got %v", err)
	}
	var version int
	var absent bool
	if err := conn.QueryRow(context.Background(), "SELECT max(version), to_regclass('fleet.routed_file_call') IS NULL FROM platform.schema_migration").Scan(&version, &absent); err != nil || version != 10 || !absent {
		t.Fatalf("blocked migration changed schema: version=%d absent=%v err=%v", version, absent, err)
	}
}

func TestCTR06GateRejectsLegacyRowsAndForgedPromotion(t *testing.T) {
	t.Run("existing receipt", func(t *testing.T) {
		url, name, owner, build := legacyGateFixture(t)
		fixture := seedNamespaceFixture(t, owner)
		command := platform.NewID()
		if err := insertNamespace(context.Background(), owner, fixture, command, false, 1, 10, false); err != nil {
			t.Fatal(store.Sanitize("seed old receipt", err))
		}
		requireCTR06Blocked(t, url, name, owner, build)
		var count int
		if err := owner.QueryRow(context.Background(), "SELECT count(*) FROM fleet.routed_call WHERE command_id=$1", command).Scan(&count); err != nil || count != 1 {
			t.Fatalf("old receipt lost: %d %v", count, err)
		}
	})
	t.Run("untrusted slot record", func(t *testing.T) {
		url, name, owner, build := legacyGateFixture(t)
		if _, err := owner.Exec(context.Background(), `INSERT INTO platform.runtime_credential(slot,login_role,rotated_at,rotated_by,promoted_at)
VALUES ('a',$1,now(),'8e5f6e26aa97b123d9f60b91f780364a094e74cd',now())`, name+"_runtime_a"); err != nil {
			t.Fatal(store.Sanitize("seed stale slot", err))
		}
		requireCTR06Blocked(t, url, name, owner, build)
	})
}

func TestCTR06GateRejectsIndirectWriterWithoutConnect(t *testing.T) {
	url, name, owner, build := legacyGateFixture(t)
	ctx := context.Background()
	group, login := name+"_oldgroup", name+"_oldlogin"
	statements := []string{
		"CREATE ROLE " + pgx.Identifier{group}.Sanitize() + " NOLOGIN",
		"CREATE ROLE " + pgx.Identifier{login}.Sanitize() + " LOGIN NOINHERIT",
		"GRANT " + pgx.Identifier{group}.Sanitize() + " TO " + pgx.Identifier{login}.Sanitize(),
		"GRANT USAGE ON SCHEMA fleet TO " + pgx.Identifier{group}.Sanitize(),
		"GRANT INSERT ON fleet.routed_call TO " + pgx.Identifier{group}.Sanitize(),
		"REVOKE CONNECT ON DATABASE " + pgx.Identifier{name}.Sanitize() + " FROM PUBLIC, " + pgx.Identifier{login}.Sanitize(),
	}
	for _, statement := range statements {
		if _, err := owner.Exec(ctx, statement); err != nil {
			t.Fatal(store.Sanitize("prepare indirect old writer", err))
		}
	}
	var connect, member bool
	if err := owner.QueryRow(ctx, "SELECT has_database_privilege($1,current_database(),'CONNECT'), pg_has_role($1,$2,'MEMBER')", login, group).Scan(&connect, &member); err != nil || connect || !member {
		t.Fatalf("fixture connect=%v member=%v %v", connect, member, err)
	}
	requireCTR06Blocked(t, url, name, owner, build)
}

func TestCTR06GateRejectsExistingConnectionAndOldLeaseRenewal(t *testing.T) {
	url, name, owner, build := legacyGateFixture(t)
	ctx := context.Background()
	login := name + "_oldlogin"
	password := pgtest.Secret()
	if _, err := owner.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN PASSWORD '"+password+"'"); err != nil {
		t.Fatal(store.Sanitize("create old login", err))
	}
	for _, statement := range []string{"GRANT USAGE ON SCHEMA fleet TO " + pgx.Identifier{login}.Sanitize(), "GRANT SELECT,INSERT,UPDATE ON fleet.hub_lease TO " + pgx.Identifier{login}.Sanitize()} {
		if _, err := owner.Exec(ctx, statement); err != nil {
			t.Fatal(store.Sanitize("grant old lease access", err))
		}
	}
	old := pgtest.Connect(t, pgtest.WithUser(t, url, login, password))
	if _, err := owner.Exec(ctx, "REVOKE CONNECT ON DATABASE "+pgx.Identifier{name}.Sanitize()+" FROM PUBLIC, "+pgx.Identifier{login}.Sanitize()); err != nil {
		t.Fatal(store.Sanitize("revoke old login connect", err))
	}
	var connected bool
	if err := owner.QueryRow(ctx, "SELECT has_database_privilege($1,current_database(),'CONNECT')", login).Scan(&connected); err != nil || connected {
		t.Fatalf("old role still CONNECT=%v %v", connected, err)
	}
	requireCTR06Blocked(t, url, name, owner, build)
	// CONNECT removal did not end this authenticated session: it can still take
	// and renew the old lease, so the failed gate must not be mistaken for retirement.
	holder := platform.NewID()
	if _, err := old.Exec(ctx, `INSERT INTO fleet.hub_lease(singleton,holder,fence,acquired_at,renewed_at,expires_at)
VALUES(true,$1,1,clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '30 seconds')`, holder); err != nil {
		t.Fatal(store.Sanitize("old session acquires lease", err))
	}
	if tag, err := old.Exec(ctx, "UPDATE fleet.hub_lease SET renewed_at=clock_timestamp(),expires_at=clock_timestamp()+interval '30 seconds' WHERE holder=$1", holder); err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("old session could not renew: %v", store.Sanitize("old lease renewal", err))
	}
}

func TestCTR06GateDrainsOldWriteBeforeSchema(t *testing.T) {
	url, name, owner, build := legacyGateFixture(t)
	ctx := context.Background()
	fixture := seedNamespaceFixture(t, owner)
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err = insertNamespace(ctx, tx, fixture, platform.NewID(), false, 1, 10, false); err != nil {
		t.Fatal(store.Sanitize("hold old write", err))
	}
	// The guard's ACCESS EXCLUSIVE lock must wait for the open old writer;
	// a bounded lock timeout rolls 0011 back instead of bypassing that writer.
	_, err = apply(t, url, build, Options{Runner: "ctr06-gate-test", RuntimeRole: name + "_runtime", LockWait: 200 * time.Millisecond})
	var failure *Failure
	if !errors.As(err, &failure) || failure.SQLState != "55P03" {
		t.Fatalf("old write lock did not stop migration: %v", err)
	}
	probe := pgtest.Connect(t, url)
	var absent bool
	if err = probe.QueryRow(ctx, "SELECT to_regclass('fleet.routed_file_call') IS NULL").Scan(&absent); err != nil || !absent {
		t.Fatalf("partial schema: %v %v", absent, err)
	}
}
