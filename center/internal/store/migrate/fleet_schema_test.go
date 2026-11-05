// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/schema"
)

// migration0004SHA256 pins the applied form of 0004_fleet_enrollment.sql: an applied migration is immutable, so this value only
// changes before the migration is merged. The successor provenance record of this part pins the same file by its hash.
const migration0004SHA256 = "babcd36d812138e688183501c0e9bd87aee9d9d0bcb6c6158a7b03c1226fe101"

// TestMigration0004LandsWholeOverVersion3 rehearses the production step of 0004 as the 0002 and 0003 rehearsals do: a database at
// version 3, owned by a migration role that is not a superuser, receives 0004 from the center's own runner. A copy of 0004 that fails
// at its last statement leaves version 3 with nothing of 0004 (no fleet table, no changed revoke-reason constraint, no key index);
// the real 0004 then lands with its pinned checksum, and the runtime role holds exactly select, insert and update on the three tables.
func TestMigration0004LandsWholeOverVersion3(t *testing.T) {
	build := centerBuild(t)
	if len(build) < 4 || build[3].Name != "0004_fleet_enrollment.sql" {
		t.Fatalf("the build has no 0004 as its fourth migration: %d migrations", len(build))
	}
	if build[3].SHA256 != migration0004SHA256 {
		t.Fatalf("0004_fleet_enrollment.sql has the checksum %s, pinned %s", build[3].SHA256, migration0004SHA256)
	}
	ctx := context.Background()
	schemas3, grants3 := schemasAndGrantsAt(3)
	for _, failing := range []bool{true, false} {
		url, name := pgtest.Database(t)
		conn := pgtest.Connect(t, url)
		if third, err := apply(t, url, build[:3], Options{Runner: "test", RuntimeRole: name + "_runtime", Schemas: schemas3, Grants: grants3}); err != nil || third.Version != 3 {
			t.Fatalf("version 3: %+v %v", third, err)
		}
		schemas4, grants4 := schemasAndGrantsAt(4)
		options := Options{Runner: "test", RuntimeRole: name + "_runtime", Schemas: schemas4, Grants: grants4}
		if failing {
			broken := fstest.MapFS{}
			entries, err := fs.ReadDir(schema.Migrations(), ".")
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				data, err := fs.ReadFile(schema.Migrations(), entry.Name())
				if err != nil {
					t.Fatal(err)
				}
				if entry.Name() == "0004_fleet_enrollment.sql" {
					data = append(data, []byte("\nSELECT 1 / 0;\n")...)
				}
				broken[entry.Name()] = &fstest.MapFile{Data: data}
			}
			failingBuild, err := Load(broken)
			if err != nil {
				t.Fatal(err)
			}
			_, err = apply(t, url, failingBuild[:4], options)
			var failure *Failure
			if !errors.As(err, &failure) || failure.Name != "0004_fleet_enrollment.sql" || failure.SQLState != "22012" {
				t.Fatalf("the failing 0004: %v", err)
			}
			status, err := Inspect(ctx, conn, build[:4])
			var objects, reasons string
			if err == nil {
				err = conn.QueryRow(ctx, `SELECT coalesce(string_agg(name, ', ' ORDER BY name), '') FROM (
    SELECT 'table fleet.' || relname AS name FROM pg_class WHERE relnamespace = 'fleet'::regnamespace AND relname <> 'signing_key' AND relkind = 'r'
    UNION ALL SELECT 'index ' || relname FROM pg_class WHERE relname = 'installation_public_key'
    UNION ALL SELECT 'function ' || proname FROM pg_proc WHERE pronamespace = 'fleet'::regnamespace) found`).Scan(&objects)
			}
			if err == nil {
				err = conn.QueryRow(ctx, "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'session_revoke_reason'").Scan(&reasons)
			}
			if err != nil || status.Version != 3 || status.State != StatePending || len(status.Pending) != 1 || objects != "" || strings.Contains(reasons, "7") {
				t.Fatalf("after the failed 0004: %+v objects=%q reasons=%q %v", status, objects, reasons, err)
			}
			continue
		}
		result, err := apply(t, url, build[:4], options)
		if err != nil || result.Version != 4 || len(result.Ran) != 1 || result.Ran[0].Name != "0004_fleet_enrollment.sql" ||
			result.Ran[0].SHA256 != migration0004SHA256 || result.Grants != "reconciled" || result.State != StateCurrent {
			t.Fatalf("0004 over version 3: %+v %v", result, err)
		}
		t.Logf("0004 applied over version 3 by a non-superuser owner in %d ms, sha256 %s", result.Ran[0].DurationMS, result.Ran[0].SHA256)
		privilege := func(table, kind string) bool {
			var has bool
			if err := conn.QueryRow(ctx, "SELECT has_table_privilege($1, $2, $3)", name+"_runtime", table, kind).Scan(&has); err != nil {
				t.Fatal(err)
			}
			return has
		}
		for table, want := range map[string]string{"fleet.node": "SIU", "fleet.node_sign_in": "SIU", "fleet.device_authorization": "SIU", "fleet.signing_key": "S"} {
			for letter, kind := range map[string]string{"S": "SELECT", "I": "INSERT", "U": "UPDATE"} {
				if got := privilege(table, kind); got != strings.Contains(want, letter) {
					t.Errorf("the runtime role's %s on %s is %v, declared %q", kind, table, got, want)
				}
			}
			if privilege(table, "DELETE") || privilege(table, "TRUNCATE") {
				t.Errorf("the runtime role may delete from %s", table)
			}
		}
	}
}

// TestEveryFleetForeignKeyHasAnIndex holds migration 0004 to the index decision of 0002 (E8, cloud-10): the first referencing column
// of every foreign key of the fleet schema leads an index, so the retention sweeps and an account purge check each reference through
// an index.
func TestEveryFleetForeignKeyHasAnIndex(t *testing.T) {
	url, name := pgtest.Database(t)
	if _, err := apply(t, url, centerBuild(t), Options{Runner: "test", RuntimeRole: name + "_runtime"}); err != nil {
		t.Fatal(err)
	}
	var missing []string
	var count int
	rows, err := pgtest.Connect(t, url).Query(context.Background(), `SELECT c.conname,
    EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.conrelid AND i.indkey[0] = c.conkey[1])
FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
WHERE c.contype = 'f' AND n.nspname = 'fleet' ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var constraint string
		var indexed bool
		if err = rows.Scan(&constraint, &indexed); err != nil {
			t.Fatal(err)
		}
		count++
		if !indexed {
			missing = append(missing, constraint)
		}
	}
	// node: device and installation; each flow table: viewer, approver, approver session, session and enrollment.
	if err = rows.Err(); err != nil || len(missing) > 0 || count != 12 {
		t.Fatalf("fleet foreign keys %d, without a leading index: %v %v", count, missing, err)
	}
}

// TestTheFleetStoreConstraints holds migration 0004 to its invariants with the migration role, independently of the code that writes
// the rows: the node row's shape (the SemVer-without-metadata version, the OsFamily numbering, one live row per node ID), a key
// registered once over live and revoked installations, the two new revoke reasons, the flow shapes (91-byte keys, the PKCE challenge,
// the loopback redirect, the client state, the country and ASN, the approver's complete record, a redeemed code only on a completed or
// revoked flow, five lookups), and the final-state triggers. Each refused case names the constraint that must refuse it.
func TestTheFleetStoreConstraints(t *testing.T) {
	url, name := pgtest.Database(t)
	if _, err := apply(t, url, centerBuild(t), Options{Runner: "test", RuntimeRole: name + "_runtime"}); err != nil {
		t.Fatal(err)
	}
	conn := pgtest.Connect(t, url)
	ctx := context.Background()
	exec := func(statement string) error {
		_, err := conn.Exec(ctx, statement)
		return err
	}
	must := func(t *testing.T, statement string) {
		t.Helper()
		if err := exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	const (
		user         = "00000000-0000-4000-8000-000000000001"
		browserDev   = "00000000-0000-4000-8000-000000000011"
		nodeDev      = "00000000-0000-4000-8000-000000000012"
		web          = "00000000-0000-4000-8000-000000000021"
		nodeInst     = "00000000-0000-4000-8000-000000000022"
		secondDev    = "00000000-0000-4000-8000-000000000013"
		secondInst   = "00000000-0000-4000-8000-000000000023"
		browser      = "00000000-0000-4000-8000-000000000051"
		nodeSession  = "00000000-0000-4000-8000-000000000052"
		nodeID       = "00000000-0000-4000-8000-000000000071"
		enrollment   = "00000000-0000-4000-8000-000000000081"
		denied       = "00000000-0000-4000-8000-000000000091"
		completed    = "00000000-0000-4000-8000-000000000092"
		delivered    = "00000000-0000-4000-8000-000000000093"
		key          = "decode(repeat('04', 91), 'hex')"
		otherKey     = "decode(repeat('05', 91), 'hex')"
		challenge    = "repeat('A', 43)"
		redirect     = "'http://127.0.0.1:49152/callback'"
		clientState  = "repeat('s', 16)"
		approverCols = ", user_id, decided_at, approver_session_id, approver_auth_method, approver_authenticated_at, approver_auth_epoch, approver_recovery_generation"
		approverVals = ", '" + user + "', now(), '" + browser + "', 1, now(), 0, 0"
	)
	must(t, "INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev) VALUES ('"+user+"', 'Owner', 1, decode(repeat('01', 32), 'hex'), now(), 1)")
	must(t, "INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev) VALUES ('"+browserDev+"', '"+user+"', 'Browser', 6, 1, false, now(), now(), 1)")
	must(t, "INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev) VALUES ('"+nodeDev+"', '"+user+"', 'buildbox', 3, 1, false, now(), now(), 1)")
	must(t, "INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, client_installation_id, installed_at, last_active_at, rev) VALUES ('"+web+"', '"+browserDev+"', '"+user+"', 'arcforges-web', 'web', 'web', gen_random_uuid(), now(), now(), 1)")
	must(t, "INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, public_key, key_version, installed_at, last_active_at, rev) VALUES ('"+nodeInst+"', '"+nodeDev+"', '"+user+"', 'arcforges-node', '0.1.0-dev', 'linux', "+key+", 1, now(), now(), 1)")
	must(t, "INSERT INTO identity.session (session_id, user_id, device_id, installation_id, credential_kind, scope, product_id, purpose, auth_method, authenticated_at, issued_at, expires_at, idle_expires_at, last_activity_at, browser_handle_hash, browser_origin, auth_epoch, recovery_generation, session_policy_version, rev) VALUES ('"+browser+"', '"+user+"', '"+browserDev+"', '"+web+"', 2, 1, 'arcforges-web', 1, 1, now(), now(), now() + interval '12 hours', now() + interval '30 minutes', now(), decode(repeat('ad', 32), 'hex'), 'https://center.example', 0, 0, 'v1', 1)")
	must(t, "INSERT INTO identity.session (session_id, user_id, device_id, installation_id, family_id, credential_kind, scope, product_id, purpose, auth_method, authenticated_at, issued_at, expires_at, last_activity_at, access_token_hash, access_expires_at, refresh_token_hash, refresh_generation, refresh_expires_at, auth_epoch, recovery_generation, session_policy_version, rev) VALUES ('"+nodeSession+"', '"+user+"', '"+nodeDev+"', '"+nodeInst+"', '"+nodeSession+"', 1, 3, 'arcforges-node', 1, 1, now(), now(), now() + interval '365 days', now(), decode(repeat('a1', 32), 'hex'), now() + interval '1 hour', decode(repeat('a2', 32), 'hex'), 1, now() + interval '90 days', 0, 0, 'v1', 1)")
	must(t, "INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev) VALUES ('"+secondDev+"', '"+user+"', 'clone', 3, 1, false, now(), now(), 1)")
	must(t, "INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, installed_at, last_active_at, rev) VALUES ('"+secondInst+"', '"+secondDev+"', '"+user+"', 'arcforges-node', '1.0.0', 'linux', now(), now(), 1)")
	nodeRow := func(id, version, os string) string {
		return "INSERT INTO fleet.node (enrollment_id, node_id, user_id, device_id, installation_id, display_name, os, arch, version, enrolled_at, last_seen_at, rev) VALUES (" + id + ", '" + nodeID + "', '" + user + "', '" + nodeDev + "', '" + nodeInst + "', 'buildbox', " + os + ", 1, '" + version + "', now(), now(), 1)"
	}
	must(t, nodeRow("'"+enrollment+"'", "0.1.0-dev", "2"))
	signIn := func(id, state, extraCols, extraVals string) string {
		return "INSERT INTO fleet.node_sign_in (flow_id, state, node_id, node_name, os, arch, version, node_public_key, code_challenge, redirect_uri, client_state, created_at, expires_at, rev" + extraCols + ") VALUES (" + id + ", " + state + ", '" + nodeID + "', 'buildbox', 2, 1, '1.2.3', " + key + ", " + challenge + ", " + redirect + ", " + clientState + ", now(), now() + interval '10 minutes', 1" + extraVals + ")"
	}
	authorization := func(id, state, extraCols, extraVals string) string {
		return "INSERT INTO fleet.device_authorization (authorization_id, device_code_hash, user_code_hash, state, node_id, node_name, os, arch, version, node_public_key, interval_ms, lookups, created_at, expires_at, rev" + extraCols + ") VALUES (" + id + ", decode(md5(random()::text) || md5(random()::text), 'hex'), decode(md5(random()::text) || md5(random()::text), 'hex'), " + state + ", '" + nodeID + "', 'buildbox', 2, 1, '1.2.3', " + key + ", 5000, 0, now(), now() + interval '10 minutes', 1" + extraVals + ")"
	}
	// Admitted shapes: a pending flow with a country and an ASN, the largest ASN, an approved flow with its approver and code.
	must(t, signIn("gen_random_uuid()", "1", ", begin_country, begin_asn", ", 'DE', 4294967295"))
	must(t, signIn("gen_random_uuid()", "2", approverCols+", code_hash, code_expires_at", approverVals+", decode(repeat('c0', 32), 'hex'), now() + interval '2 minutes'"))
	must(t, signIn("'"+denied+"'", "4", ", user_id, decided_at", ", '"+user+"', now()"))
	must(t, signIn("'"+completed+"'", "3", approverCols+", code_hash, code_expires_at, code_redeemed_at, completed_at, session_id, enrollment_id",
		approverVals+", decode(repeat('c1', 32), 'hex'), now() + interval '2 minutes', now(), now(), '"+nodeSession+"', '"+enrollment+"'"))
	must(t, authorization("gen_random_uuid()", "1", "", ""))
	must(t, authorization("'"+delivered+"'", "6", approverCols+", completed_at, session_id, enrollment_id", approverVals+", now(), '"+nodeSession+"', '"+enrollment+"'"))
	// A node version keeps a prerelease; an authorization inserted without its lookups starts at 0.
	must(t, "UPDATE fleet.node SET version = '1.0.0-rc.1', rev = rev + 1 WHERE enrollment_id = '"+enrollment+"'")
	must(t, strings.Replace(strings.Replace(authorization("'00000000-0000-4000-8000-000000000094'", "1", "", ""), "interval_ms, lookups,", "interval_ms,", 1),
		"5000, 0,", "5000,", 1))
	var lookups int
	if err := conn.QueryRow(ctx, "SELECT lookups FROM fleet.device_authorization WHERE authorization_id = '00000000-0000-4000-8000-000000000094'").
		Scan(&lookups); err != nil || lookups != 0 {
		t.Fatalf("an authorization without its lookups: %d %v", lookups, err)
	}

	type refusal struct{ statement, constraint string }
	refused := map[string]refusal{
		"a version with build metadata":       {nodeRow("gen_random_uuid()", "0.1.0-dev+15d6717", "2"), "node_version"},
		"a version with a leading zero":       {nodeRow("gen_random_uuid()", "01.0.0", "2"), "node_version"},
		"a version that is not SemVer":        {nodeRow("gen_random_uuid()", "v1.0", "2"), "node_version"},
		"a device platform number for a node": {nodeRow("gen_random_uuid()", "1.0.0", "3"), "node_os"},
		"a second live row of one node ID": {strings.NewReplacer("'"+nodeDev+"'", "'"+secondDev+"'", "'"+nodeInst+"'", "'"+secondInst+"'").Replace(nodeRow("gen_random_uuid()", "1.0.0", "2")),
			"node_live_node_id"},
		"a revoked node without its reason":       {"UPDATE fleet.node SET revoked_at = now() WHERE enrollment_id = '" + enrollment + "'", "node_revoke_reason"},
		"a revoke reason other than the device's": {"UPDATE fleet.node SET revoked_at = now(), revoke_reason = 2 WHERE enrollment_id = '" + enrollment + "'", "node_revoke_reason"},
		// 0006 (AF-CTR-04 part M) adds reason 9, a reused mobile authorization code; nothing beyond it is admitted.
		"a revoke reason beyond 9":                 {"UPDATE identity.session SET revoked_at = now(), revoke_reason = 10 WHERE session_id = '" + nodeSession + "'", "session_revoke_reason"},
		"a key another installation holds":         {"INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, public_key, key_version, installed_at, last_active_at, rev) VALUES (gen_random_uuid(), '" + browserDev + "', '" + user + "', 'arcforges-node', '1', 'linux', " + key + ", 1, now(), now(), 1)", "installation_public_key"},
		"a flow key of 90 bytes":                   {strings.Replace(signIn("gen_random_uuid()", "1", "", ""), key, "decode(repeat('04', 90), 'hex')", 1), "node_sign_in_public_key"},
		"a challenge of 42 characters":             {strings.Replace(signIn("gen_random_uuid()", "1", "", ""), challenge, "repeat('A', 42)", 1), "node_sign_in_code_challenge"},
		"a redirect to localhost":                  {strings.Replace(signIn("gen_random_uuid()", "1", "", ""), redirect, "'http://localhost:49152/callback'", 1), "node_sign_in_redirect_uri"},
		"a client state of 15 characters":          {strings.Replace(signIn("gen_random_uuid()", "1", "", ""), clientState, "repeat('s', 15)", 1), "node_sign_in_client_state"},
		"a lower-case country":                     {signIn("gen_random_uuid()", "1", ", begin_country", ", 'de'"), "node_sign_in_begin_country"},
		"an ASN beyond 32 bits":                    {signIn("gen_random_uuid()", "1", ", begin_asn", ", 4294967296"), "node_sign_in_begin_asn"},
		"an approval without its approver session": {signIn("gen_random_uuid()", "2", ", user_id, decided_at, code_hash, code_expires_at", ", '"+user+"', now(), decode(repeat('c2', 32), 'hex'), now()"), "node_sign_in_approved"},
		"an approver record without its epochs":    {signIn("gen_random_uuid()", "2", ", user_id, decided_at, approver_session_id, approver_auth_method, approver_authenticated_at, code_hash, code_expires_at", ", '"+user+"', now(), '"+browser+"', 1, now(), decode(repeat('c3', 32), 'hex'), now()"), "node_sign_in_approver"},
		"a redeemed code on an approved flow":      {signIn("gen_random_uuid()", "2", approverCols+", code_hash, code_expires_at, code_redeemed_at", approverVals+", decode(repeat('c4', 32), 'hex'), now(), now()"), "node_sign_in_redeemed"},
		"a completed flow without its result":      {signIn("gen_random_uuid()", "3", approverCols+", code_hash, code_expires_at, code_redeemed_at", approverVals+", decode(repeat('c5', 32), 'hex'), now(), now()"), "node_sign_in_result"},
		"a SLOW_DOWN authorization":                {authorization("gen_random_uuid()", "2", "", ""), "device_authorization_state"},
		"a sixth lookup":                           {strings.Replace(authorization("gen_random_uuid()", "1", "", ""), "5000, 0,", "5000, 6,", 1), "device_authorization_lookups"},
		"an interval below one second":             {strings.Replace(authorization("gen_random_uuid()", "1", "", ""), "5000", "999", 1), "device_authorization_interval"},
		"an interval above a minute":               {strings.Replace(authorization("gen_random_uuid()", "1", "", ""), "5000", "60001", 1), "device_authorization_interval"},
		"a reuse mark on a pending authorization":  {authorization("gen_random_uuid()", "1", ", reused_at", ", now()"), "device_authorization_result"},
		"a completed authorization without result": {authorization("gen_random_uuid()", "6", approverCols+", completed_at", approverVals+", now()"), "device_authorization_result"},
	}
	for label, item := range refused {
		t.Run(label, func(t *testing.T) {
			tx, err := conn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			_, err = tx.Exec(ctx, item.statement)
			var pgError *pgconn.PgError
			if !errors.As(err, &pgError) || !strings.HasPrefix(pgError.Code, "23") || pgError.ConstraintName != item.constraint {
				t.Fatalf("not refused by %s (%v): %s", item.constraint, err, item.statement)
			}
		})
	}
	// A key of a revoked installation is still held: the index covers revoked rows.
	must(t, "UPDATE device.installation SET revoked_at = now(), rev = rev + 1 WHERE installation_id = '"+nodeInst+"'")
	if err := exec("INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, public_key, key_version, installed_at, last_active_at, rev) VALUES (gen_random_uuid(), '" + browserDev + "', '" + user + "', 'arcforges-node', '1', 'linux', " + key + ", 1, now(), now(), 1)"); !pgtest.IsCode(err, "23505") {
		t.Fatalf("a retired key was registered again: %v", err)
	}
	must(t, "INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, public_key, key_version, installed_at, last_active_at, rev) VALUES (gen_random_uuid(), '"+browserDev+"', '"+user+"', 'arcforges-node', '1', 'linux', "+otherKey+", 1, now(), now(), 1)")
	// The revoke reasons 7 (superseded) and 8 (enrollment code reused) are admitted.
	must(t, "UPDATE identity.session SET revoked_at = now(), revoke_reason = 7, rev = rev + 1 WHERE session_id = '"+nodeSession+"'")
	must(t, "UPDATE identity.session SET revoke_reason = 8, rev = rev + 1 WHERE session_id = '"+nodeSession+"'")

	// Final states: a denied flow never changes; a completed flow becomes REVOKED once and then never changes; a delivered
	// authorization records its reuse once and then never changes.
	triggerRefused := func(t *testing.T, statement string) {
		t.Helper()
		if err := exec(statement); !pgtest.IsCode(err, "23514") {
			t.Fatalf("a final row changed (%v): %s", err, statement)
		}
	}
	triggerRefused(t, "UPDATE fleet.node_sign_in SET viewed_by = '"+user+"', viewed_at = now() WHERE flow_id = '"+denied+"'")
	triggerRefused(t, "UPDATE fleet.node_sign_in SET state = 2, rev = rev + 1 WHERE flow_id = '"+denied+"'")
	triggerRefused(t, "UPDATE fleet.node_sign_in SET state = 6, completed_at = now() WHERE flow_id = '"+completed+"'")
	triggerRefused(t, "UPDATE fleet.node_sign_in SET state = 6 WHERE flow_id = '"+completed+"'")
	must(t, "UPDATE fleet.node_sign_in SET state = 6, rev = rev + 1 WHERE flow_id = '"+completed+"'")
	triggerRefused(t, "UPDATE fleet.node_sign_in SET rev = rev + 1 WHERE flow_id = '"+completed+"'")
	triggerRefused(t, "UPDATE fleet.device_authorization SET lookups = 1, rev = rev + 1 WHERE authorization_id = '"+delivered+"'")
	must(t, "UPDATE fleet.device_authorization SET reused_at = now(), rev = rev + 1 WHERE authorization_id = '"+delivered+"'")
	triggerRefused(t, "UPDATE fleet.device_authorization SET reused_at = now(), rev = rev + 1 WHERE authorization_id = '"+delivered+"'")
}

// migration0005SHA256 pins the applied form of 0005_device_user_code_index.sql (immutable once applied, as 0004).
const migration0005SHA256 = "f87e49f4d00167ceb7110cc571e36653bbae7a9866b9031446d6b27ed0253438"

// TestMigration0005IndexesEveryUserCode rehearses 0005 over version 4 with the center's own runner and a migration role that is not
// a superuser: it adds exactly the index device_authorization_user_code on user_code_hash, changes no grant, and a lookup of a user
// code in a state other than PENDING (which 0004's partial unique index cannot serve) reads it through that index.
func TestMigration0005IndexesEveryUserCode(t *testing.T) {
	build := centerBuild(t)
	if len(build) < 5 || build[4].Name != "0005_device_user_code_index.sql" {
		t.Fatalf("the build has no 0005 as its fifth migration: %d migrations", len(build))
	}
	if build[4].SHA256 != migration0005SHA256 {
		t.Fatalf("0005_device_user_code_index.sql has the checksum %s, pinned %s", build[4].SHA256, migration0005SHA256)
	}
	ctx := context.Background()
	url, name := pgtest.Database(t)
	conn := pgtest.Connect(t, url)
	// The grants of the build at 0005 (0006's table is not there yet; they equal version 4's).
	schemas5, grants5 := schemasAndGrantsAt(5)
	options := Options{Runner: "test", RuntimeRole: name + "_runtime", Schemas: schemas5, Grants: grants5}
	if fourth, err := apply(t, url, build[:4], options); err != nil || fourth.Version != 4 {
		t.Fatalf("version 4: %+v %v", fourth, err)
	}
	result, err := apply(t, url, build[:5], options)
	if err != nil || result.Version != 5 || len(result.Ran) != 1 || result.Ran[0].SHA256 != migration0005SHA256 || result.Grants != "reconciled" {
		t.Fatalf("0005 over version 4: %+v %v", result, err)
	}
	var definition string
	if err = conn.QueryRow(ctx, "SELECT indexdef FROM pg_indexes WHERE schemaname = 'fleet' AND indexname = 'device_authorization_user_code'").Scan(&definition); err != nil ||
		definition != "CREATE INDEX device_authorization_user_code ON fleet.device_authorization USING btree (user_code_hash)" {
		t.Fatalf("the index: %q %v", definition, err)
	}
	var plan string
	if _, err = conn.Exec(ctx, "SET enable_seqscan = off"); err == nil {
		err = conn.QueryRow(ctx, `EXPLAIN (FORMAT TEXT) SELECT authorization_id FROM fleet.device_authorization WHERE user_code_hash = '\x00'::bytea AND state <> 1`).Scan(&plan)
	}
	if err != nil || !strings.Contains(plan, "device_authorization_user_code") {
		t.Fatalf("a lookup of a non-live user code does not use the index: %q %v", plan, err)
	}
}
