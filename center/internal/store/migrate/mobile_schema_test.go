// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
)

// migration0006SHA256 pins the applied form of 0006_mobile_authorization.sql (immutable once applied).
const migration0006SHA256 = "ab174f5da3db70380e4cb2533d88e6447213feaced3c0c166fa819543736be05"

// TestMigration0006LandsOverVersion5 rehearses 0006 (AF-CTR-04 part M) as production receives it: a database at version 5, owned by a
// migration role that is not a superuser, receives 0006 from the center's own runner; its checksum is the pinned one, the runtime role
// holds exactly select, insert and update on identity.mobile_authorization (no delete), and every foreign key of the table leads an index.
func TestMigration0006LandsOverVersion5(t *testing.T) {
	build := centerBuild(t)
	if len(build) < 6 || build[5].Name != "0006_mobile_authorization.sql" {
		t.Fatalf("the build has no 0006 as its sixth migration: %d migrations", len(build))
	}
	if build[5].SHA256 != migration0006SHA256 {
		t.Fatalf("0006_mobile_authorization.sql has the checksum %s, pinned %s", build[5].SHA256, migration0006SHA256)
	}
	ctx := context.Background()
	url, name := pgtest.Database(t)
	conn := pgtest.Connect(t, url)
	schemas5, grants5 := schemasAndGrantsAt(5)
	if fifth, err := apply(t, url, build[:5], Options{Runner: "test", RuntimeRole: name + "_runtime", Schemas: schemas5, Grants: grants5}); err != nil || fifth.Version != 5 {
		t.Fatalf("version 5: %+v %v", fifth, err)
	}
	result, err := apply(t, url, build[:6], Options{Runner: "test", RuntimeRole: name + "_runtime"})
	if err != nil || result.Version != 6 || len(result.Ran) != 1 || result.Ran[0].SHA256 != migration0006SHA256 || result.Grants != "reconciled" {
		t.Fatalf("0006 over version 5: %+v %v", result, err)
	}
	for kind, want := range map[string]bool{"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": false, "TRUNCATE": false} {
		var has bool
		if err = conn.QueryRow(ctx, "SELECT has_table_privilege($1, 'identity.mobile_authorization', $2)", name+"_runtime", kind).Scan(&has); err != nil || has != want {
			t.Errorf("the runtime role's %s: %v %v", kind, has, err)
		}
	}
	var missing []string
	rows, err := conn.Query(ctx, `SELECT c.conname, EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.conrelid AND i.indkey[0] = c.conkey[1])
FROM pg_constraint c WHERE c.contype = 'f' AND c.conrelid = 'identity.mobile_authorization'::regclass ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
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
	if err = rows.Err(); err != nil || count != 4 || len(missing) > 0 {
		t.Fatalf("%d foreign keys, without an index: %v %v", count, missing, err)
	}
}

// TestTheMobileStoreConstraints holds 0006 to its invariants with the migration role, independently of the code that writes the rows:
// the client and its redirect form (the release App Link, the debug private-use scheme, never crossed, never a loopback redirect), the
// PKCE challenge, the state, the claim (nonzero installation, an Android platform, the claim text without '+'), a code never past the
// flow, the approver's complete record, a redeemed code only on a completed or revoked flow, the new revoke reason 9 (and nothing
// beyond), and the final-state trigger (only COMPLETED to REVOKED, once, changing nothing else).
func TestTheMobileStoreConstraints(t *testing.T) {
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
		user        = "00000000-0000-4000-8000-000000000001"
		browserDev  = "00000000-0000-4000-8000-000000000011"
		web         = "00000000-0000-4000-8000-000000000021"
		browser     = "00000000-0000-4000-8000-000000000051"
		completed   = "00000000-0000-4000-8000-000000000092"
		denied      = "00000000-0000-4000-8000-000000000091"
		approverCol = ", user_id, decided_at, approver_session_id, approver_auth_method, approver_authenticated_at, approver_auth_epoch, approver_recovery_generation"
		approverVal = ", '" + user + "', now(), '" + browser + "', 1, now(), 0, 0"
	)
	must(t, "INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev) VALUES ('"+user+"', 'Owner', 1, decode(repeat('01', 32), 'hex'), now(), 1)")
	must(t, "INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev) VALUES ('"+browserDev+"', '"+user+"', 'Browser', 6, 1, false, now(), now(), 1)")
	must(t, "INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, client_installation_id, installed_at, last_active_at, rev) VALUES ('"+web+"', '"+browserDev+"', '"+user+"', 'arcforges-web', 'web', 'web', gen_random_uuid(), now(), now(), 1)")
	must(t, "INSERT INTO identity.session (session_id, user_id, device_id, installation_id, credential_kind, scope, product_id, purpose, auth_method, authenticated_at, issued_at, expires_at, idle_expires_at, last_activity_at, browser_handle_hash, browser_origin, auth_epoch, recovery_generation, session_policy_version, rev) VALUES ('"+browser+"', '"+user+"', '"+browserDev+"', '"+web+"', 2, 1, 'arcforges-web', 1, 1, now(), now(), now() + interval '12 hours', now() + interval '30 minutes', now(), decode(repeat('ad', 32), 'hex'), 'https://center.example', 0, 0, 'v1', 1)")
	flow := func(id, state, client, redirect, platform, extraCols, extraVals string) string {
		return "INSERT INTO identity.mobile_authorization (flow_id, state, client_id, redirect_uri, code_challenge, client_state, installation_id, platform, app_version, " +
			"created_at, expires_at, rev" + extraCols + ") VALUES (" + id + ", " + state + ", '" + client + "', '" + redirect + "', repeat('A', 43), repeat('s', 16), " +
			"gen_random_uuid(), '" + platform + "', '1.2.3', now(), now() + interval '10 minutes', 1" + extraVals + ")"
	}
	release, debug := "https://arcforges.com/app/callback", "com.arcforges.android.debug:/callback"
	must(t, flow("gen_random_uuid()", "1", "arcforges.android", release, "android-15", ", begin_country, begin_asn", ", 'DE', 4294967295"))
	must(t, flow("gen_random_uuid()", "1", "arcforges.android.local", debug, "Android-14", "", ""))
	must(t, flow("gen_random_uuid()", "2", "arcforges.android", "https://proof.arcforges.com:8443/app/callback", "android", approverCol+", code_hash, code_expires_at",
		approverVal+", decode(repeat('c0', 32), 'hex'), now() + interval '2 minutes'"))
	must(t, flow("'"+denied+"'", "4", "arcforges.android", release, "android-15", ", user_id, decided_at", ", '"+user+"', now()"))
	must(t, flow("'"+completed+"'", "3", "arcforges.android", release, "android-15", approverCol+", code_hash, code_expires_at, code_redeemed_at, completed_at, session_id",
		approverVal+", decode(repeat('c1', 32), 'hex'), now() + interval '2 minutes', now(), now(), '"+browser+"'"))
	refused := map[string]struct{ statement, constraint string }{
		"another client":                {flow("gen_random_uuid()", "1", "companion.android", release, "android-15", "", ""), "mobile_authorization_client_id"},
		"a release client's scheme":     {flow("gen_random_uuid()", "1", "arcforges.android", debug, "android-15", "", ""), "mobile_authorization_redirect_uri"},
		"a debug client's App Link":     {flow("gen_random_uuid()", "1", "arcforges.android.local", release, "android-15", "", ""), "mobile_authorization_redirect_uri"},
		"a loopback redirect":           {flow("gen_random_uuid()", "1", "arcforges.android", "https://127.0.0.1/app/callback", "android-15", "", ""), "mobile_authorization_redirect_uri"},
		"another path":                  {flow("gen_random_uuid()", "1", "arcforges.android", "https://arcforges.com/app/node", "android-15", "", ""), "mobile_authorization_redirect_uri"},
		"an http App Link":              {flow("gen_random_uuid()", "1", "arcforges.android", "http://arcforges.com/app/callback", "android-15", "", ""), "mobile_authorization_redirect_uri"},
		"an iOS platform":               {flow("gen_random_uuid()", "1", "arcforges.android", release, "ios-18", "", ""), "mobile_authorization_platform"},
		"a platform with a plus":        {flow("gen_random_uuid()", "1", "arcforges.android", release, "android+15", "", ""), "mobile_authorization_platform"},
		"a nil installation":            {strings.Replace(flow("gen_random_uuid()", "1", "arcforges.android", release, "android-15", "", ""), "gen_random_uuid(), 'android", "'00000000-0000-0000-0000-000000000000', 'android", 1), "mobile_authorization_installation"},
		"a version with a plus":         {strings.Replace(flow("gen_random_uuid()", "1", "arcforges.android", release, "android-15", "", ""), "'1.2.3'", "'1.2.3+4'", 1), "mobile_authorization_app_version"},
		"a short challenge":             {strings.Replace(flow("gen_random_uuid()", "1", "arcforges.android", release, "android-15", "", ""), "repeat('A', 43)", "repeat('A', 42)", 1), "mobile_authorization_code_challenge"},
		"a short state":                 {strings.Replace(flow("gen_random_uuid()", "1", "arcforges.android", release, "android-15", "", ""), "repeat('s', 16)", "repeat('s', 15)", 1), "mobile_authorization_client_state"},
		"a code past the flow":          {flow("gen_random_uuid()", "2", "arcforges.android", release, "android-15", approverCol+", code_hash, code_expires_at", approverVal+", decode(repeat('c2', 32), 'hex'), now() + interval '11 minutes'"), "mobile_authorization_code"},
		"an approval without approver":  {flow("gen_random_uuid()", "2", "arcforges.android", release, "android-15", ", user_id, decided_at, code_hash, code_expires_at", ", '"+user+"', now(), decode(repeat('c3', 32), 'hex'), now() + interval '2 minutes'"), "mobile_authorization_approved"},
		"a redeemed code while pending": {flow("gen_random_uuid()", "1", "arcforges.android", release, "android-15", ", code_redeemed_at", ", now()"), "mobile_authorization_redeemed"},
		"a revoke reason beyond 9":      {"UPDATE identity.session SET revoked_at = now(), revoke_reason = 10 WHERE session_id = '" + browser + "'", "session_revoke_reason"},
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
	triggerRefused := func(t *testing.T, statement string) {
		t.Helper()
		if err := exec(statement); !pgtest.IsCode(err, "23514") {
			t.Fatalf("a final row changed (%v): %s", err, statement)
		}
	}
	triggerRefused(t, "UPDATE identity.mobile_authorization SET viewed_by = '"+user+"', viewed_at = now() WHERE flow_id = '"+denied+"'")
	triggerRefused(t, "UPDATE identity.mobile_authorization SET state = 2, rev = rev + 1 WHERE flow_id = '"+denied+"'")
	triggerRefused(t, "UPDATE identity.mobile_authorization SET state = 6, completed_at = now() WHERE flow_id = '"+completed+"'")
	must(t, "UPDATE identity.mobile_authorization SET state = 6, rev = rev + 1 WHERE flow_id = '"+completed+"'")
	triggerRefused(t, "UPDATE identity.mobile_authorization SET rev = rev + 1 WHERE flow_id = '"+completed+"'")
	must(t, "UPDATE identity.session SET revoked_at = now(), revoke_reason = 9 WHERE session_id = '"+browser+"'")
}
