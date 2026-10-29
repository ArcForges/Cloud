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

// TestTheIdentityStoreConstraints holds migration 0002 to its invariants with the migration role, independently of the code that
// writes the rows: the shape of each credential, session, flow and step-up kind, the device and installation bindings, the single
// bootstrap and the finality of a consumed flow. Each refused case names the constraint that must refuse it, and the rows it builds on
// exist before it runs, so a foreign key never refuses a case in a check's stead.
func TestTheIdentityStoreConstraints(t *testing.T) {
	url, name := pgtest.Database(t)
	if _, err := apply(t, url, centerBuild(t), Options{Runner: "test", RuntimeRole: name + "_runtime"}); err != nil {
		t.Fatal(err)
	}
	conn := pgtest.Connect(t, url)
	ctx := context.Background()
	exec := func(t *testing.T, statement string) error {
		t.Helper()
		_, err := conn.Exec(ctx, statement)
		return err
	}
	must := func(t *testing.T, statement string) {
		t.Helper()
		if err := exec(t, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	const (
		user        = "00000000-0000-4000-8000-000000000001"
		other       = "00000000-0000-4000-8000-000000000002"
		device      = "00000000-0000-4000-8000-000000000011"
		otherDevice = "00000000-0000-4000-8000-000000000012"
		web         = "00000000-0000-4000-8000-000000000021"
		mobile      = "00000000-0000-4000-8000-000000000022"
		claim       = "00000000-0000-4000-8000-000000000031"
		browser     = "00000000-0000-4000-8000-000000000051"
		emailStepUp = "00000000-0000-4000-8000-000000000061"
	)
	must(t, "INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev) VALUES ('"+user+"', 'Owner', 1, decode(repeat('01', 32), 'hex'), now(), 1)")
	must(t, "INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev) VALUES ('"+other+"', 'Other', 1, decode(repeat('02', 32), 'hex'), now(), 1)")
	must(t, "INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev) VALUES ('"+device+"', '"+user+"', 'Browser', 6, 1, false, now(), now(), 1)")
	must(t, "INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev) VALUES ('"+otherDevice+"', '"+other+"', 'Phone', 4, 1, false, now(), now(), 1)")
	must(t, "INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, client_installation_id, installed_at, last_active_at, rev) VALUES ('"+web+"', '"+device+"', '"+user+"', 'arcforges-web', 'web', 'web', '"+claim+"', now(), now(), 1)")
	// A browser session of the right shape is admitted; the flows and step-up challenges below are bound to it.
	must(t, "INSERT INTO identity.session (session_id, user_id, device_id, installation_id, credential_kind, scope, product_id, purpose, auth_method, authenticated_at, issued_at, expires_at, idle_expires_at, last_activity_at, browser_handle_hash, browser_origin, auth_epoch, recovery_generation, session_policy_version, rev) VALUES ('"+browser+"', '"+user+"', '"+device+"', '"+web+"', 2, 1, 'arcforges-web', 1, 1, now(), now(), now() + interval '12 hours', now() + interval '30 minutes', now(), decode(repeat('ad', 32), 'hex'), 'https://center.example', 0, 0, 'v1', 1)")

	// A passkey identity of the given subject: every passkey column set, so only the subject decides.
	passkey := func(subject string) string {
		return "INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, public_key, user_handle, sign_count, backup_eligible, backup_state, transports, aaguid, attestation_format, created_at, rev) VALUES (gen_random_uuid(), '" + user + "', 1, 'passkey', " + subject + ", decode(repeat('0a', 77), 'hex'), decode(repeat('01', 32), 'hex'), 0, false, false, '{}', decode(repeat('00', 16), 'hex'), 'none', now(), 1)"
	}
	// The base64url subject of a 1023-byte credential ID (1364 characters) is admitted, as is the longest e-mail address.
	must(t, passkey("repeat('A', 1364)"))
	must(t, "INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, created_at, rev) VALUES (gen_random_uuid(), '"+user+"', 2, 'email', repeat('a', 308) || '@example.com', now(), 1)")
	// A step-up challenge of a session: a passkey challenge and an e-mail challenge with its verifier.
	stepUp := func(id, method, material string) string {
		return "INSERT INTO identity.step_up_challenge (challenge_id, user_id, session_id, operation_id, target_hash, method, challenge, code_hash, code_salt, state, attempt_count, created_at, expires_at, auth_epoch, recovery_generation, rev) VALUES (" + id + ", '" + user + "', '" + browser + "', 'identity.removeAuthIdentity', decode(repeat('ce', 32), 'hex'), " + method + ", " + material + ", 1, 0, now(), now() + interval '5 minutes', 0, 0, 1)"
	}
	must(t, stepUp("gen_random_uuid()", "1", "decode(repeat('c1', 32), 'hex'), NULL, NULL"))
	must(t, stepUp("'"+emailStepUp+"'", "2", "NULL, decode(repeat('c2', 32), 'hex'), decode(repeat('c3', 16), 'hex')"))
	// A passkey registration flow of the session, with the label its credential gets.
	flowOf := func(kind, extra, values string) string {
		return "INSERT INTO identity.auth_flow (flow_id, channel, kind, purpose, user_id, session_id, challenge, webauthn_user_handle, sends, attempts, max_attempts, created_at, expires_at" + extra + ") VALUES (gen_random_uuid(), 1, " + kind + ", 1, '" + user + "', '" + browser + "', decode(repeat('ee', 32), 'hex'), decode(repeat('01', 32), 'hex'), 0, 0, 1, now(), now() + interval '5 minutes'" + values + ")"
	}
	must(t, flowOf("2", ", label", ", 'Work laptop'"))

	type refusal struct{ statement, constraint string }
	refused := map[string]refusal{
		"a display name with a control character":     {"INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev) VALUES (gen_random_uuid(), e'a\\nb', 1, decode(repeat('03', 32), 'hex'), now(), 1)", "user_display_name"},
		"a second account with the same user handle":  {"INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev) VALUES (gen_random_uuid(), 'x', 1, decode(repeat('01', 32), 'hex'), now(), 1)", "user_passkey_user_handle"},
		"an unknown product":                          {"INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, installed_at, last_active_at, rev) VALUES (gen_random_uuid(), '" + device + "', '" + user + "', 'arcforges-desktop', '1', 'x', now(), now(), 1)", "installation_product_id"},
		"an installation of another account's device": {"INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, installed_at, last_active_at, rev) VALUES ('" + mobile + "', '" + otherDevice + "', '" + user + "', 'arcforges-mobile', '1', 'android', now(), now(), 1)", "installation_device"},
		"a web installation without a claim":          {"INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, installed_at, last_active_at, rev) VALUES (gen_random_uuid(), '" + otherDevice + "', '" + other + "', 'arcforges-web', '1', 'web', now(), now(), 1)", "installation_web_claim"},
		"a second live web installation of one claim": {"INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev) VALUES ('00000000-0000-4000-8000-000000000013', '" + user + "', 'B', 6, 1, false, now(), now(), 1); " +
			"INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, client_installation_id, installed_at, last_active_at, rev) VALUES (gen_random_uuid(), '00000000-0000-4000-8000-000000000013', '" + user + "', 'arcforges-web', 'web', 'web', '" + claim + "', now(), now(), 1)", "installation_live_web_claim"},
		"a revoked device that keeps its trust":              {"UPDATE device.device SET revoked_at = now(), revoke_reason = 1 WHERE device_id = '" + device + "'", "device_revoked_trust"},
		"remote control of an untrusted device":              {"UPDATE device.device SET remote_enabled = true WHERE device_id = '" + device + "'", "device_remote_enabled_requires_trusted"},
		"a browser session with bearer material":             {"INSERT INTO identity.session (session_id, user_id, device_id, installation_id, credential_kind, scope, product_id, purpose, auth_method, authenticated_at, issued_at, expires_at, idle_expires_at, last_activity_at, browser_handle_hash, browser_origin, access_token_hash, access_expires_at, auth_epoch, recovery_generation, session_policy_version, rev) VALUES (gen_random_uuid(), '" + user + "', '" + device + "', '" + web + "', 2, 1, 'arcforges-web', 1, 1, now(), now(), now() + interval '12 hours', now() + interval '30 minutes', now(), decode(repeat('aa', 32), 'hex'), 'https://center.example', decode(repeat('bb', 32), 'hex'), now(), 0, 0, 'v1', 1)", "session_browser_cookie_shape"},
		"a session bound to another account's device":        {"INSERT INTO identity.session (session_id, user_id, device_id, installation_id, credential_kind, scope, product_id, purpose, auth_method, authenticated_at, issued_at, expires_at, idle_expires_at, last_activity_at, browser_handle_hash, browser_origin, auth_epoch, recovery_generation, session_policy_version, rev) VALUES (gen_random_uuid(), '" + other + "', '" + device + "', '" + web + "', 2, 1, 'arcforges-web', 1, 1, now(), now(), now() + interval '12 hours', now() + interval '30 minutes', now(), decode(repeat('ab', 32), 'hex'), 'https://center.example', 0, 0, 'v1', 1)", "session_device"},
		"the agent scope":                                    {"INSERT INTO identity.session (session_id, user_id, device_id, installation_id, credential_kind, scope, product_id, purpose, auth_method, authenticated_at, issued_at, expires_at, idle_expires_at, last_activity_at, browser_handle_hash, browser_origin, auth_epoch, recovery_generation, session_policy_version, rev) VALUES (gen_random_uuid(), '" + user + "', '" + device + "', '" + web + "', 2, 6, 'arcforges-web', 1, 1, now(), now(), now() + interval '12 hours', now() + interval '30 minutes', now(), decode(repeat('ac', 32), 'hex'), 'https://center.example', 0, 0, 'v1', 1)", "session_scope"},
		"a passkey without its material":                     {"INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, created_at, rev) VALUES (gen_random_uuid(), '" + user + "', 1, 'passkey', 'cred', now(), 1)", "auth_identity_passkey_material_complete"},
		"a password credential":                              {"INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, created_at, rev) VALUES (gen_random_uuid(), '" + user + "', 3, 'password', 'x', now(), 1)", "auth_identity_method"},
		"an e-mail identity with passkey material":           {"INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, sign_count, created_at, rev) VALUES (gen_random_uuid(), '" + user + "', 2, 'email', 'a@example.com', 0, now(), 1)", "auth_identity_passkey_material_only_for_passkey"},
		"a passkey subject beyond a 1023-byte credential ID": {passkey("repeat('B', 1365)"), "auth_identity_subject"},
		"an e-mail subject beyond 320 characters":            {"INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, created_at, rev) VALUES (gen_random_uuid(), '" + user + "', 2, 'email', repeat('b', 309) || '@example.com', now(), 1)", "auth_identity_subject"},
		"a second bootstrap":                                 {"INSERT INTO identity.bootstrap (singleton, token_sha256, user_id, consumed_at) VALUES (true, decode(repeat('cc', 32), 'hex'), '" + other + "', now())", "bootstrap_pkey"},
		"a bootstrap row that is not the singleton":          {"INSERT INTO identity.bootstrap (singleton, token_sha256, user_id, consumed_at) VALUES (false, decode(repeat('cc', 32), 'hex'), '" + other + "', now())", "bootstrap_single_row"},
		// Step-up challenges: an e-mail challenge needs its whole verifier, and it can never lose it.
		"an e-mail step-up without its verifier":    {stepUp("gen_random_uuid()", "2", "NULL, NULL, NULL"), "step_up_challenge_material"},
		"an e-mail step-up without its salt":        {stepUp("gen_random_uuid()", "2", "NULL, decode(repeat('c4', 32), 'hex'), NULL"), "step_up_challenge_material"},
		"an e-mail step-up without its hash":        {stepUp("gen_random_uuid()", "2", "NULL, NULL, decode(repeat('c5', 16), 'hex')"), "step_up_challenge_material"},
		"an e-mail step-up that loses its verifier": {"UPDATE identity.step_up_challenge SET code_hash = NULL, code_salt = NULL WHERE challenge_id = '" + emailStepUp + "'", "step_up_challenge_material"},
		"a passkey step-up without its challenge":   {stepUp("gen_random_uuid()", "1", "NULL, NULL, NULL"), "step_up_challenge_material"},
		// Flows: only a passkey registration has a label, always one, bounded like a credential label; only an e-mail flow has e-mail
		// material; a replay of a consumed flow is never stored as an outcome.
		"a label on a passkey sign-in flow":             {"INSERT INTO identity.auth_flow (flow_id, channel, kind, purpose, challenge, label, sends, attempts, max_attempts, created_at, expires_at) VALUES (gen_random_uuid(), 1, 1, 1, decode(repeat('ee', 32), 'hex'), 'Laptop', 0, 0, 1, now(), now() + interval '5 minutes')", "auth_flow_label"},
		"a passkey registration flow without a label":   {flowOf("2", "", ""), "auth_flow_label"},
		"a registration label of 65 characters":         {flowOf("2", ", label", ", repeat('x', 65)"), "auth_flow_label"},
		"a registration label with a control character": {flowOf("2", ", label", ", e'Work\\tlaptop'"), "auth_flow_label"},
		"an empty registration label":                   {flowOf("2", ", label", ", ''"), "auth_flow_label"},
		"e-mail material on a passkey sign-in flow":     {"INSERT INTO identity.auth_flow (flow_id, channel, kind, purpose, challenge, email_hash, sends, attempts, max_attempts, created_at, expires_at) VALUES (gen_random_uuid(), 1, 1, 1, decode(repeat('ee', 32), 'hex'), decode(repeat('e1', 32), 'hex'), 0, 0, 1, now(), now() + interval '5 minutes')", "auth_flow_email"},
		"an e-mail flow without its address digest":     {"INSERT INTO identity.auth_flow (flow_id, channel, kind, purpose, code_hash, code_salt, sends, attempts, max_attempts, created_at, expires_at) VALUES (gen_random_uuid(), 1, 4, 1, decode(repeat('e2', 32), 'hex'), decode(repeat('e3', 16), 'hex'), 0, 0, 5, now(), now() + interval '10 minutes')", "auth_flow_email"},
	}
	must(t, "INSERT INTO identity.bootstrap (singleton, token_sha256, user_id, consumed_at) VALUES (true, decode(repeat('cc', 32), 'hex'), '"+user+"', now())")
	must(t, "INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, created_at, rev) VALUES (gen_random_uuid(), '"+user+"', 2, 'email', 'owner@example.com', now(), 1)")
	refused["a subject that moves to another user"] = refusal{"INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, created_at, rev) VALUES (gen_random_uuid(), '" + other + "', 2, 'email', 'owner@example.com', now(), 1)", "auth_identity_provider_subject"}
	const flow = "00000000-0000-4000-8000-000000000041"
	must(t, "INSERT INTO identity.auth_flow (flow_id, channel, kind, purpose, challenge, sends, attempts, max_attempts, created_at, expires_at) VALUES ('"+flow+"', 1, 1, 1, decode(repeat('ee', 32), 'hex'), 0, 0, 5, now(), now() + interval '5 minutes')")
	refused["a replay outcome on a flow"] = refusal{"UPDATE identity.auth_flow SET consumed_at = now(), outcome = 3 WHERE flow_id = '" + flow + "'", "auth_flow_outcome"}
	for label, item := range refused {
		t.Run(label, func(t *testing.T) {
			tx, err := conn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			// Each refusal is the named integrity constraint (SQLSTATE class 23), never a syntax or privilege error or another constraint.
			_, err = tx.Exec(ctx, item.statement)
			var pgError *pgconn.PgError
			if !errors.As(err, &pgError) || !strings.HasPrefix(pgError.Code, "23") || pgError.ConstraintName != item.constraint {
				t.Fatalf("not refused by %s (%v): %s", item.constraint, err, item.statement)
			}
		})
	}

	// A consumed flow can never change again.
	must(t, "UPDATE identity.auth_flow SET attempts = attempts + 1 WHERE flow_id = '"+flow+"'")
	must(t, "UPDATE identity.auth_flow SET consumed_at = now(), outcome = 1 WHERE flow_id = '"+flow+"'")
	if err := exec(t, "UPDATE identity.auth_flow SET attempts = attempts + 1 WHERE flow_id = '"+flow+"'"); !pgtest.IsCode(err, "23514") {
		t.Fatalf("a consumed flow changed: %v", err)
	}
	var count int
	if err := conn.QueryRow(ctx, "SELECT count(*) FROM identity.bootstrap").Scan(&count); err != nil || count != 1 {
		t.Fatalf("bootstrap rows %d %v", count, err)
	}
}

// TestEveryIdentityForeignKeyHasAnIndex holds migration 0002 to its index decision (E8): the first referencing column of every foreign
// key of the identity and device schemas leads an index, so the retention sweeps' deletes and an account purge check each reference
// through an index. The single-row bootstrap is the one exception.
func TestEveryIdentityForeignKeyHasAnIndex(t *testing.T) {
	url, name := pgtest.Database(t)
	if _, err := apply(t, url, centerBuild(t), Options{Runner: "test", RuntimeRole: name + "_runtime"}); err != nil {
		t.Fatal(err)
	}
	rows, err := pgtest.Connect(t, url).Query(context.Background(), `SELECT c.conname
FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
WHERE c.contype = 'f' AND n.nspname IN ('identity', 'device') AND c.conname <> 'bootstrap_user'
    AND NOT EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.conrelid AND i.indkey[0] = c.conkey[1])
ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	for rows.Next() {
		var constraint string
		if err = rows.Scan(&constraint); err != nil {
			t.Fatal(err)
		}
		missing = append(missing, constraint)
	}
	if err = rows.Err(); err != nil || len(missing) > 0 {
		t.Fatalf("foreign keys without a leading index: %v %v", missing, err)
	}
}

// TestMigration0002LandsWholeOverVersion1 rehearses the production migration step of 0002 (G1). The database is at version 1 (0001
// only), as production is, and its owner is a migration role that is not a superuser and has only CREATEROLE and CREATEDB, as
// Neon's owner role has. The center's own runner applies 0002 and reconciles the runtime role's grants. 0002 runs in one
// transaction: when it fails at its last statement, the database stays at version 1 with nothing of 0002, so a failed deployment
// leaves the running revision's store as it was.
func TestMigration0002LandsWholeOverVersion1(t *testing.T) {
	build := centerBuild(t)
	if len(build) < 2 || build[1].Name != "0002_identity_device.sql" {
		t.Fatalf("the build has no 0002: %d migrations", len(build))
	}
	build = build[:2]
	ctx := context.Background()
	for _, failing := range []bool{true, false} {
		url, name := pgtest.Database(t)
		conn := pgtest.Connect(t, url)
		var superuser, createRole, createDatabase, replication, bypassRLS bool
		if err := conn.QueryRow(ctx, "SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls FROM pg_roles WHERE rolname = current_user").
			Scan(&superuser, &createRole, &createDatabase, &replication, &bypassRLS); err != nil {
			t.Fatal(err)
		}
		if superuser || !createRole || !createDatabase || replication || bypassRLS {
			t.Fatalf("the migration role is not a Neon-like owner: superuser=%v createrole=%v createdb=%v", superuser, createRole, createDatabase)
		}
		// Version 1 as the previous release left it (this build's grants name 0002's schemas, so they are reconciled with 0002).
		if first, err := apply(t, url, build[:1], Options{Runner: "test"}); err != nil || first.Version != 1 {
			t.Fatalf("version 1: %+v %v", first, err)
		}
		options := Options{Runner: "test", RuntimeRole: name + "_runtime"}
		if failing {
			// The last object 0002 creates exists already: 0002 fails at its last statement.
			if _, err := conn.Exec(ctx, "CREATE TABLE platform.rate_limit (bucket_hash bytea)"); err != nil {
				t.Fatal(err)
			}
			_, err := apply(t, url, build, options)
			var failure *Failure
			if !errors.As(err, &failure) || failure.Name != "0002_identity_device.sql" || failure.SQLState != "42P07" {
				t.Fatalf("the failing 0002: %v", err)
			}
			status, err := Inspect(ctx, conn, build)
			var objects int
			if err == nil {
				err = conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM pg_namespace WHERE nspname IN ('identity', 'device')) +
    (SELECT count(*) FROM pg_proc WHERE proname = 'refuse_consumed_flow_change')`).Scan(&objects)
			}
			if err != nil || status.Version != 1 || status.State != StatePending || len(status.Pending) != 1 || objects != 0 {
				t.Fatalf("after the failed 0002: %+v objects=%d %v", status, objects, err)
			}
			continue
		}
		result, err := apply(t, url, build, options)
		if err != nil || result.Version != 2 || len(result.Ran) != 1 || result.Ran[0].Name != "0002_identity_device.sql" ||
			result.Ran[0].SHA256 != build[1].SHA256 || result.Grants != "reconciled" || result.State != StateCurrent {
			t.Fatalf("0002 over version 1: %+v %v", result, err)
		}
		t.Logf("0002 applied over version 1 by a non-superuser owner in %d ms, sha256 %s, grants %s", result.Ran[0].DurationMS, result.Ran[0].SHA256,
			result.Grants)
		var insert, remove bool
		if err = conn.QueryRow(ctx, "SELECT has_table_privilege($1, 'identity.auth_flow', 'INSERT'), has_table_privilege($1, 'identity.auth_flow', 'DELETE')",
			name+"_runtime").Scan(&insert, &remove); err != nil || !insert || remove {
			t.Fatalf("the runtime role's grants on 0002's tables: insert=%v delete=%v %v", insert, remove, err)
		}
	}
}
