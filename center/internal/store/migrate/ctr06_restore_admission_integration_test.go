// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/jackc/pgx/v5"
)

func TestCTR06FreshAdmissionIsAtomicAndRequired(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	conn := pgtest.Connect(t, url)
	build := centerBuild(t)
	role := name + "_runtime"
	result, err := Apply(ctx, conn, build, Options{Runner: "test", RuntimeRole: role})
	if err != nil || result.Version != 11 || result.Grants != "reconciled" {
		t.Fatalf("fresh migration: %+v %v", result, err)
	}
	var kind, state string
	var bound bool
	if err := conn.QueryRow(ctx, `SELECT a.kind,a.state,a.database_oid=f.database_oid AND a.owner_oid=f.owner_oid AND
 a.runtime_role_oid=f.runtime_role_oid AND a.cluster_system_identifier=f.cluster_system_identifier
 FROM platform.ctr06_restore_admission a JOIN platform.ctr06_runtime_floor f USING (singleton)`).Scan(&kind, &state, &bound); err != nil || kind != "fresh" || state != "READY" || !bound {
		t.Fatalf("fresh admission: %s %s %v %v", kind, state, bound, err)
	}
	if status, err := Inspect(ctx, conn, build); err != nil || status.State != StateCurrent || status.RuntimeRole != role {
		t.Fatalf("fresh checked status: %+v %v", status, err)
	}
	if _, err := conn.Exec(ctx, "DELETE FROM platform.ctr06_restore_admission"); err != nil {
		t.Fatal(err)
	}
	if status, err := Inspect(ctx, conn, build); !errors.Is(err, ErrCTR06RetirementUnproven) || status.State != StateRefused {
		t.Fatalf("missing admission trusted: %+v %v", status, err)
	}
	if _, err := Apply(ctx, conn, build, Options{Runner: "test", RuntimeRole: role}); !errors.Is(err, ErrCTR06RetirementUnproven) {
		t.Fatalf("missing admission reconciled: %v", err)
	}
}

func TestCTR06PendingAdmissionCannotBeAdoptedOrUsed(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	conn := pgtest.Connect(t, url)
	if _, err := conn.Exec(ctx, "REVOKE CONNECT, TEMPORARY ON DATABASE "+pgx.Identifier{name}.Sanitize()+" FROM PUBLIC"); err != nil {
		t.Fatal(err)
	}
	build := centerBuild(t)
	role := name + "_runtime"
	if _, err := conn.Exec(ctx, "COMMENT ON DATABASE "+pgx.Identifier{name}.Sanitize()+" IS '"+ctr06RestoreIsolationMarker+"'"); err != nil {
		t.Fatal(err)
	}
	capability, err := newRestoreCapability(ctx, conn, strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	result, err := Apply(ctx, conn, build, Options{Runner: "test", RuntimeRole: role, localRestore: capability})
	if err != nil || result.Version != 11 || result.Grants != "" {
		t.Fatalf("pending migration: %+v %v", result, err)
	}
	var kind, state string
	var roleLogin, slotALogin, slotBLogin bool
	if err := conn.QueryRow(ctx, `SELECT a.kind,a.state,
 (SELECT rolcanlogin FROM pg_roles WHERE rolname=$1::text),
 (SELECT rolcanlogin FROM pg_roles WHERE rolname=$1::text||'_a'),
 (SELECT rolcanlogin FROM pg_roles WHERE rolname=$1::text||'_b')
 FROM platform.ctr06_restore_admission a WHERE singleton`, role).Scan(&kind, &state, &roleLogin, &slotALogin, &slotBLogin); err != nil || kind != "restore" || state != "PENDING" || roleLogin || slotALogin || slotBLogin {
		t.Fatalf("pending roles/admission: %s %s %v %v %v %v", kind, state, roleLogin, slotALogin, slotBLogin, err)
	}
	if status, err := Inspect(ctx, conn, build); !errors.Is(err, ErrCTR06RetirementUnproven) || status.State != StateRefused {
		t.Fatalf("pending status trusted: %+v %v", status, err)
	}
	if _, err := Apply(ctx, conn, build, Options{Runner: "test", RuntimeRole: role}); !errors.Is(err, ErrCTR06RetirementUnproven) {
		t.Fatalf("pending grants reconciled: %v", err)
	}
	if state, err := Apply(ctx, conn, build, Options{Runner: "test"}); !errors.Is(err, ErrCTR06RetirementUnproven) || state.State != StateRefused {
		t.Fatalf("schema-only application trusted a pending destination: %+v %v", state, err)
	}
	other := pgtest.Connect(t, url)
	if _, err := finalizeCTR06Restore(ctx, other, role, role, strings.Repeat("c", 64), capability); !errors.Is(err, ErrCTR06RetirementUnproven) {
		t.Fatalf("capability accepted on another connection: %v", err)
	}
	if err := other.Close(ctx); err != nil {
		t.Fatal(err)
	}
	fake, err := newRestoreCapability(ctx, conn, strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finalizeCTR06Restore(ctx, conn, role, role, strings.Repeat("c", 64), fake); !errors.Is(err, ErrCTR06RetirementUnproven) {
		t.Fatalf("new invocation adopted pending admission: %v", err)
	}
	if err := conn.QueryRow(ctx, "SELECT state FROM platform.ctr06_restore_admission WHERE singleton").Scan(&state); err != nil || state != "PENDING" {
		t.Fatalf("refused finalization changed admission: %s %v", state, err)
	}
}

func TestCTR06AdmissionMismatchRollsBackEntire0011(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	conn := pgtest.Connect(t, url)
	build := centerBuild(t)
	if _, err := conn.Exec(ctx, "COMMENT ON DATABASE "+pgx.Identifier{name}.Sanitize()+" IS '"+ctr06RestoreIsolationMarker+"'"); err != nil {
		t.Fatal(err)
	}
	capability, err := newRestoreCapability(ctx, conn, strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	capability.databaseOID++ // a test-only mismatch, never a caller flag
	_, err = Apply(ctx, conn, build, Options{Runner: "test", RuntimeRole: name + "_runtime", localRestore: capability})
	if !errors.Is(err, ErrCTR06RetirementUnproven) {
		t.Fatalf("mismatched target accepted: %v", err)
	}
	var version int
	var floorAbsent, admissionAbsent, roleAbsent bool
	if err := conn.QueryRow(ctx, `SELECT max(version),to_regclass('platform.ctr06_runtime_floor') IS NULL,
 to_regclass('platform.ctr06_restore_admission') IS NULL,NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)
 FROM platform.schema_migration`, name+"_runtime").Scan(&version, &floorAbsent, &admissionAbsent, &roleAbsent); err != nil || version != 10 || !floorAbsent || !admissionAbsent || !roleAbsent {
		t.Fatalf("0011 was partially committed: version=%d floor=%v admission=%v role=%v err=%v", version, floorAbsent, admissionAbsent, roleAbsent, err)
	}
}

// Compile-time assurance that both checked transaction and connection provide
// the same read interface used by the isolation and admission checks.
var _ Querier = (pgx.Tx)(nil)

func TestCTR06BackupCatalogueOnFreshSchema(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	conn := pgtest.Connect(t, url)
	build := centerBuild(t)
	if _, err := Apply(ctx, conn, build, Options{Runner: "test", RuntimeRole: name + "_runtime"}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "SET search_path=pg_catalog; SET TIME ZONE 'UTC'"); err != nil {
		t.Fatal(err)
	}
	digest, err := ctr06CatalogueSHA(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	if digest != ctr06Schema11CatalogueSHA {
		t.Fatalf("supported 0011 catalogue drift: %s", digest)
	}
}

func TestCTR06BackupCatalogueOnLegacySchema(t *testing.T) {
	ctx := context.Background()
	url, _ := pgtest.Database(t)
	conn := pgtest.Connect(t, url)
	build := centerBuild(t)
	if _, err := Apply(ctx, conn, build[:10], Options{Runner: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "SET search_path=pg_catalog; SET TIME ZONE 'UTC'"); err != nil {
		t.Fatal(err)
	}
	digest, err := ctr06CatalogueSHA(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	if digest != ctr06Schema10CatalogueSHA {
		t.Fatalf("supported schema10 catalogue drift: %s", digest)
	}
}

func TestCTR06CanonicalMigrationWithoutFloorNeverCommits(t *testing.T) {
	ctx := context.Background()
	url, _ := pgtest.Database(t)
	conn := pgtest.Connect(t, url)
	build := centerBuild(t)
	if _, err := Apply(ctx, conn, build, Options{Runner: "test"}); !errors.Is(err, ErrCTR06RetirementUnproven) {
		t.Fatalf("canonical 0011 committed without a runtime floor: %v", err)
	}
	var version int
	var floor, admission bool
	if err := conn.QueryRow(ctx, `SELECT max(version),to_regclass('platform.ctr06_runtime_floor') IS NULL,
 to_regclass('platform.ctr06_restore_admission') IS NULL FROM platform.schema_migration`).Scan(&version, &floor, &admission); err != nil || version != 10 || !floor || !admission {
		t.Fatalf("floorless failure was partially committed: %d %v %v %v", version, floor, admission, err)
	}
}

func TestCTR06BackupCatalogueRefusesDisabledTriggerAndRowSecurity(t *testing.T) {
	for _, mutation := range []string{
		"ALTER TABLE fleet.routed_file_call DISABLE TRIGGER routed_file_call_guarded",
		"ALTER TABLE platform.outbox ENABLE ROW LEVEL SECURITY",
	} {
		t.Run(mutation, func(t *testing.T) {
			ctx := context.Background()
			url, name := pgtest.Database(t)
			conn := pgtest.Connect(t, url)
			build := centerBuild(t)
			if _, err := Apply(ctx, conn, build, Options{Runner: "test", RuntimeRole: name + "_runtime"}); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Exec(ctx, "SET search_path=pg_catalog; SET TIME ZONE 'UTC'"); err != nil {
				t.Fatal(err)
			}
			if err := ctr06CheckSchemaOwnership(ctx, conn); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Exec(ctx, mutation); err != nil {
				t.Fatal(err)
			}
			digest, err := ctr06CatalogueSHA(ctx, conn)
			if err != nil || digest == ctr06Schema11CatalogueSHA {
				t.Fatalf("changed security definition was accepted: digest=%s err=%v", digest, err)
			}
		})
	}
}

func TestCTR06RestoreIsolationMarkerOnlyRefusesAndRequiresExactPrivateBinding(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	conn := pgtest.Connect(t, url)
	if _, err := newRestoreCapability(ctx, conn, strings.Repeat("a", 64), strings.Repeat("b", 64)); !errors.Is(err, ErrCTR06RetirementUnproven) {
		t.Fatalf("missing restore isolation accepted: %v", err)
	}
	comment := func(value string) {
		t.Helper()
		if _, err := conn.Exec(ctx, "COMMENT ON DATABASE "+pgx.Identifier{name}.Sanitize()+" IS '"+value+"'"); err != nil {
			t.Fatal(err)
		}
	}
	comment(ctr06RestoreIsolationPrefix + "malformed")
	if err := RequireOrdinaryDatabase(ctx, conn, name); !errors.Is(err, ErrCTR06RetirementUnproven) {
		t.Fatalf("malformed reserved marker accepted by ordinary administration: %v", err)
	}
	if _, err := newRestoreCapability(ctx, conn, strings.Repeat("a", 64), strings.Repeat("b", 64)); !errors.Is(err, ErrCTR06RetirementUnproven) {
		t.Fatalf("malformed marker accepted as private binding: %v", err)
	}
	comment(ctr06RestoreIsolationMarker)
	capability, err := newRestoreCapability(ctx, conn, strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	defer capability.destroy()
	comment(ctr06RestoreIsolationPrefix + "changed")
	result, err := Apply(ctx, conn, centerBuild(t), Options{Runner: "test", RuntimeRole: name + "_runtime", localRestore: capability})
	if !errors.Is(err, ErrCTR06RetirementUnproven) || result.State != StateRefused {
		t.Fatalf("changed marker accepted by an existing capability: %+v %v", result, err)
	}
	var migrationExists bool
	if err := conn.QueryRow(ctx, "SELECT to_regclass('platform.schema_migration') IS NOT NULL").Scan(&migrationExists); err != nil || migrationExists {
		t.Fatalf("changed marker caused a migration effect: %v %v", migrationExists, err)
	}
	comment("an unrelated administrator note")
	if err := RequireOrdinaryDatabase(ctx, conn, name); err != nil {
		t.Fatalf("unrelated ordinary database comment was rejected: %v", err)
	}
}

func TestCTR06LegacyRestoreGrantRequiresLiveSameInvocationCapability(t *testing.T) {
	ctx := context.Background()
	url, name := pgtest.Database(t)
	conn := pgtest.Connect(t, url)
	build := centerBuild(t)
	legacy := name + "_runtime"
	grants := make([]schema.Grant, 0, len(schema.RuntimeGrants))
	for _, item := range schema.RuntimeGrants {
		if item.Schema == "fleet" && (item.Table == "routed_file_call" || item.Table == "routed_command_id" || item.Table == "routed_file_target") {
			continue
		}
		grants = append(grants, item)
	}
	if _, err := Apply(ctx, conn, build[:10], Options{Runner: "test", RuntimeRole: legacy, Grants: grants}); err != nil {
		t.Fatalf("prepare real schema-10 source: %v", err)
	}
	if _, err := conn.Exec(ctx, "COMMENT ON DATABASE "+pgx.Identifier{name}.Sanitize()+" IS '"+ctr06RestoreIsolationMarker+"'"); err != nil {
		t.Fatal(err)
	}
	capability, err := newRestoreCapability(ctx, conn, strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	defer capability.destroy()
	roles, err := prepareCTR06Roles(ctx, conn, legacy, capability)
	if err != nil {
		t.Fatal(err)
	}
	grant := &ctr06RestoreBridgeGrant{restore: capability, roles: roles, active: true}
	options := Options{Runner: "test", RuntimeRole: roles.BridgeRole, Grants: grants, Schemas: schema.Schemas}
	if _, err := Apply(ctx, conn, build[:10], options); !errors.Is(err, ErrCTR06RetirementUnproven) {
		t.Fatalf("ordinary pre-11 apply accepted a restore marker: %v", err)
	}
	admitted := context.WithValue(ctx, ctr06RestoreBridgeGrantKey{}, grant)
	other := pgtest.Connect(t, url)
	if _, err := Apply(admitted, other, build[:10], options); !errors.Is(err, ErrCTR06RetirementUnproven) {
		t.Fatalf("grant was usable on another connection: %v", err)
	}
	if err := other.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(admitted, conn, build[:9], options); !errors.Is(err, ErrCTR06RetirementUnproven) {
		t.Fatalf("grant accepted a different schema build: %v", err)
	}
	forged := *grant
	forged.roles.Nonce = strings.Repeat("f", len(roles.Nonce))
	if _, err := Apply(context.WithValue(ctx, ctr06RestoreBridgeGrantKey{}, &forged), conn, build[:10], options); !errors.Is(err, ErrCTR06RetirementUnproven) {
		t.Fatalf("forged issuance nonce authorized grants: %v", err)
	}
	forged = *grant
	forged.roles.BridgeRoleOID++
	if _, err := Apply(context.WithValue(ctx, ctr06RestoreBridgeGrantKey{}, &forged), conn, build[:10], options); !errors.Is(err, ErrCTR06RetirementUnproven) {
		t.Fatalf("forged bridge role OID authorized grants: %v", err)
	}
	var hasInsert bool
	if err := conn.QueryRow(ctx, "SELECT has_table_privilege($1,'fleet.routed_call','INSERT')", roles.BridgeRole).Scan(&hasInsert); err != nil || hasInsert {
		t.Fatalf("failed admission changed bridge privileges: %v %v", hasInsert, err)
	}
	result, err := Apply(admitted, conn, build[:10], options)
	if err != nil || result.Version != 10 || result.Grants != "reconciled" {
		t.Fatalf("same invocation pre-11 bridge grant failed: %+v %v", result, err)
	}
	if err := conn.QueryRow(ctx, "SELECT has_table_privilege($1,'fleet.routed_call','INSERT')", roles.BridgeRole).Scan(&hasInsert); err != nil || !hasInsert {
		t.Fatalf("bridge did not receive its real legacy grant: %v %v", hasInsert, err)
	}
	grant.active = false
	if _, err := Apply(admitted, conn, build[:10], options); !errors.Is(err, ErrCTR06RetirementUnproven) {
		t.Fatalf("expired invocation capability was accepted: %v", err)
	}
}
