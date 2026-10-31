// SPDX-License-Identifier: AGPL-3.0-only

package entitlement_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The operator role on real PostgreSQL (EVIDENCE: REAL). The command line around it is tested in cmd/arcforges-center.

func inMigrationTx(t *testing.T, db *dbtest.Database, work func(pgx.Tx) error) error {
	t.Helper()
	return pgx.BeginFunc(context.Background(), db.Migration, work)
}

func TestTheOperatorRoleIsGrantedForABoundedTimeAndAuditedWithTheRow(t *testing.T) {
	db := dbtest.New(t)
	account := db.Account(1)
	now := time.Date(2026, 11, 2, 9, 30, 0, 123456789, time.UTC)
	reason := "support rota for the launch"
	for _, days := range []int{0, -1, entitlement.MaxOperatorDays + 1} {
		err := inMigrationTx(t, db, func(tx pgx.Tx) error {
			_, err := entitlement.GrantOperatorRole(context.Background(), tx, account, days, reason, now)
			return err
		})
		if !errors.Is(err, entitlement.ErrRoleDays) {
			t.Fatalf("%d days: %v", days, err)
		}
	}
	for _, bad := range []string{"", "   ", "a\nb", strings.Repeat("r", 513)} {
		err := inMigrationTx(t, db, func(tx pgx.Tx) error {
			_, err := entitlement.GrantOperatorRole(context.Background(), tx, account, 30, bad, now)
			return err
		})
		if !errors.Is(err, entitlement.ErrRoleReason) {
			t.Fatalf("reason %q: %v", bad, err)
		}
	}
	if db.Count("SELECT count(*) FROM identity.operator") != 0 {
		t.Fatal("a refused grant wrote")
	}
	var role entitlement.OperatorRole
	err := inMigrationTx(t, db, func(tx pgx.Tx) (err error) {
		role, err = entitlement.GrantOperatorRole(context.Background(), tx, account, entitlement.MaxOperatorDays, reason, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 11, 2, 9, 30, 0, 123456000, time.UTC); !role.GrantedAt.Equal(want) || !role.ExpiresAt.Equal(want.Add(90*24*time.Hour)) {
		t.Fatalf("the role: %+v", role)
	}
	operator := func(at time.Time) bool {
		var is bool
		if err := inMigrationTx(t, db, func(tx pgx.Tx) (err error) {
			is, err = entitlement.IsOperator(context.Background(), tx, account, at)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return is
	}
	if !operator(now.Add(time.Hour)) || !operator(role.ExpiresAt.Add(-time.Second)) {
		t.Fatal("the role is not live inside its time")
	}
	if operator(role.ExpiresAt) || operator(now.Add(-time.Hour)) {
		t.Fatal("the role is live outside its time")
	}
	if db.Count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1 AND actor_ref = 'operator:cli' AND target_id = $2", entitlement.AuditOperatorRoleGranted, account.String()) != 1 {
		t.Fatal("the grant is not audited")
	}
	// A live role is not granted again.
	err = inMigrationTx(t, db, func(tx pgx.Tx) error {
		_, err := entitlement.GrantOperatorRole(context.Background(), tx, account, 5, reason, now.Add(time.Hour))
		return err
	})
	if !errors.Is(err, entitlement.ErrRoleAlreadyLive) {
		t.Fatalf("a second grant: %v", err)
	}
	// An audit that fails undoes the row: the two are one transaction.
	other := db.Account(1)
	db.Exec("CREATE SCHEMA testfault",
		"CREATE FUNCTION testfault.refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type = 'identity.operator.granted' THEN RAISE EXCEPTION 'the audit is refused (test)' USING ERRCODE = '57P01'; END IF; RETURN NEW; END; $$",
		"CREATE TRIGGER test_refuse BEFORE INSERT ON audit.audit_event FOR EACH ROW EXECUTE FUNCTION testfault.refuse()")
	err = inMigrationTx(t, db, func(tx pgx.Tx) error {
		_, err := entitlement.GrantOperatorRole(context.Background(), tx, other, 5, reason, now)
		return err
	})
	if err == nil || db.Count("SELECT count(*) FROM identity.operator WHERE user_id = $1", other) != 0 {
		t.Fatalf("a grant whose audit failed: %v", err)
	}
}

func TestOnlyAnActiveAccountThatExistsBecomesAnOperator(t *testing.T) {
	db := dbtest.New(t)
	now := time.Now()
	for name, account := range map[string]platform.ID{"restricted": db.Account(2), "suspended": db.Account(3), "deleted": db.Account(5)} {
		err := inMigrationTx(t, db, func(tx pgx.Tx) error {
			_, err := entitlement.GrantOperatorRole(context.Background(), tx, account, 5, "reason", now)
			return err
		})
		if !errors.Is(err, entitlement.ErrRoleAccountState) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	err := inMigrationTx(t, db, func(tx pgx.Tx) error {
		_, err := entitlement.GrantOperatorRole(context.Background(), tx, platform.NewID(), 5, "reason", now)
		return err
	})
	if !errors.Is(err, entitlement.ErrRoleNoAccount) {
		t.Fatalf("an unknown account: %v", err)
	}
	if db.Count("SELECT count(*) FROM identity.operator") != 0 || db.Count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1", entitlement.AuditOperatorRoleGranted) != 0 {
		t.Fatal("a refused grant wrote")
	}
}

func TestRevokingTheRoleEndsOnlyTheLiveRowsOfThatAccountOnce(t *testing.T) {
	db := dbtest.New(t)
	account, other := db.Account(1), db.Account(1)
	now := time.Now()
	db.Exec("INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason) VALUES (gen_random_uuid(), '"+account.String()+"', now() - interval '2 days', now() + interval '10 days', 'operator:cli', 'live')",
		"INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason) VALUES (gen_random_uuid(), '"+account.String()+"', now() - interval '20 days', now() - interval '1 day', 'operator:cli', 'expired')",
		"INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, revoked_at, granted_by, reason) VALUES (gen_random_uuid(), '"+account.String()+"', now() - interval '5 days', now() + interval '20 days', now() - interval '4 days', 'operator:cli', 'revoked')",
		"INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason) VALUES (gen_random_uuid(), '"+other.String()+"', now() - interval '2 days', now() + interval '10 days', 'operator:cli', 'another account')")
	var ended int64
	if err := inMigrationTx(t, db, func(tx pgx.Tx) (err error) {
		ended, err = entitlement.RevokeOperatorRole(context.Background(), tx, account, now)
		return err
	}); err != nil || ended != 1 {
		t.Fatalf("%d %v", ended, err)
	}
	if db.Count("SELECT count(*) FROM identity.operator WHERE user_id = $1 AND revoked_at IS NOT NULL", account) != 2 ||
		db.Count("SELECT count(*) FROM identity.operator WHERE user_id = $1 AND revoked_at IS NULL", other) != 1 {
		t.Fatal("the revocation touched the wrong rows")
	}
	// The expired row keeps the end it had; the revoked row keeps its first revocation.
	if db.Count("SELECT count(*) FROM identity.operator WHERE user_id = $1 AND reason = 'expired' AND revoked_at IS NULL", account) != 1 {
		t.Fatal("an expired row was rewritten")
	}
	if err := inMigrationTx(t, db, func(tx pgx.Tx) (err error) {
		ended, err = entitlement.RevokeOperatorRole(context.Background(), tx, account, now)
		return err
	}); err != nil || ended != 0 {
		t.Fatalf("a second revocation: %d %v", ended, err)
	}
	if db.Count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1 AND actor_ref = 'operator:cli' AND target_id = $2", entitlement.AuditOperatorRoleRevoked, account.String()) != 2 {
		t.Fatal("each revocation is audited")
	}
	if db.Count(`SELECT count(*) FROM audit.audit_event WHERE convert_from(payload, 'UTF8') LIKE '%"rowsEnded":%'`) != 2 {
		t.Fatal("the audit does not say how many rows ended")
	}
}

func TestTheRuntimeRoleCannotWriteTheOperatorRole(t *testing.T) {
	db := dbtest.New(t)
	account := db.Account(1)
	_, err := db.Runtime.Pool().Exec(context.Background(), "INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason) VALUES (gen_random_uuid(), $1, now(), now() + interval '1 day', 'operator:cli', 'x')", account)
	if err == nil {
		t.Fatal("the runtime role wrote an operator row")
	}
	db.Exec("INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason) VALUES (gen_random_uuid(), '" + account.String() + "', now() - interval '1 day', now() + interval '1 day', 'operator:cli', 'x')")
	if _, err = db.Runtime.Pool().Exec(context.Background(), "UPDATE identity.operator SET revoked_at = now() WHERE user_id = $1", account); err == nil {
		t.Fatal("the runtime role revoked an operator row")
	}
}

// TestTwoConcurrentRoleGrantsMakeOneLiveRow: the second command waits at the account's lock and then finds the first one's row, so
// an account never holds two live operator rows (a share lock admits both commands and the check is a read before the insert).
func TestTwoConcurrentRoleGrantsMakeOneLiveRow(t *testing.T) {
	db := dbtest.New(t)
	account := db.Account(1)
	ctx := context.Background()
	// The first command runs on a connection of its own: one connection runs one transaction at a time.
	first, err := pgtest.Connect(t, db.URL).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = entitlement.GrantOperatorRole(ctx, first, account, 10, "first command", time.Now()); err != nil {
		t.Fatal(err)
	}
	second := make(chan error, 1)
	go func() {
		second <- inMigrationTx(t, db, func(tx pgx.Tx) error {
			_, err := entitlement.GrantOperatorRole(ctx, tx, account, 10, "second command", time.Now())
			return err
		})
	}()
	select {
	case err := <-second:
		_ = first.Rollback(ctx)
		t.Fatalf("the second command did not wait for the first: %v", err)
	case <-time.After(400 * time.Millisecond):
	}
	if err = first.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-second:
		if !errors.Is(err, entitlement.ErrRoleAlreadyLive) {
			t.Fatalf("the second command: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the second command never finished")
	}
	if db.Count("SELECT count(*) FROM identity.operator WHERE user_id = $1 AND revoked_at IS NULL", account) != 1 {
		t.Fatal("two live operator rows")
	}
}

func TestAReasonThatIsNotValidUTF8IsRefusedForTheRole(t *testing.T) {
	db := dbtest.New(t)
	account := db.Account(1)
	err := inMigrationTx(t, db, func(tx pgx.Tx) error {
		_, err := entitlement.GrantOperatorRole(context.Background(), tx, account, 5, "bad \xff byte", time.Now())
		return err
	})
	if !errors.Is(err, entitlement.ErrRoleReason) || db.Count("SELECT count(*) FROM identity.operator") != 0 {
		t.Fatalf("%v", err)
	}
}
