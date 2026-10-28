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
// writes the rows: the shape of each credential and session kind, the device and installation bindings, the single bootstrap and the
// finality of a consumed flow.
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
	)
	must(t, "INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev) VALUES ('"+user+"', 'Owner', 1, decode(repeat('01', 32), 'hex'), now(), 1)")
	must(t, "INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev) VALUES ('"+other+"', 'Other', 1, decode(repeat('02', 32), 'hex'), now(), 1)")
	must(t, "INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev) VALUES ('"+device+"', '"+user+"', 'Browser', 6, 1, false, now(), now(), 1)")
	must(t, "INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev) VALUES ('"+otherDevice+"', '"+other+"', 'Phone', 4, 1, false, now(), now(), 1)")
	must(t, "INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, client_installation_id, installed_at, last_active_at, rev) VALUES ('"+web+"', '"+device+"', '"+user+"', 'arcforges-web', 'web', 'web', '"+claim+"', now(), now(), 1)")

	refused := map[string]string{
		"a display name with a control character":     "INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev) VALUES (gen_random_uuid(), e'a\\nb', 1, decode(repeat('03', 32), 'hex'), now(), 1)",
		"a second account with the same user handle":  "INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev) VALUES (gen_random_uuid(), 'x', 1, decode(repeat('01', 32), 'hex'), now(), 1)",
		"an unknown product":                          "INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, installed_at, last_active_at, rev) VALUES (gen_random_uuid(), '" + device + "', '" + user + "', 'arcforges-desktop', '1', 'x', now(), now(), 1)",
		"an installation of another account's device": "INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, installed_at, last_active_at, rev) VALUES ('" + mobile + "', '" + otherDevice + "', '" + user + "', 'arcforges-mobile', '1', 'android', now(), now(), 1)",
		"a web installation without a claim":          "INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, installed_at, last_active_at, rev) VALUES (gen_random_uuid(), '" + otherDevice + "', '" + other + "', 'arcforges-web', '1', 'web', now(), now(), 1)",
		"a second live web installation of one claim": "INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev) VALUES ('00000000-0000-4000-8000-000000000013', '" + user + "', 'B', 6, 1, false, now(), now(), 1); " +
			"INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, client_installation_id, installed_at, last_active_at, rev) VALUES (gen_random_uuid(), '00000000-0000-4000-8000-000000000013', '" + user + "', 'arcforges-web', 'web', 'web', '" + claim + "', now(), now(), 1)",
		"a revoked device that keeps its trust":       "UPDATE device.device SET revoked_at = now(), revoke_reason = 1 WHERE device_id = '" + device + "'",
		"remote control of an untrusted device":       "UPDATE device.device SET remote_enabled = true WHERE device_id = '" + device + "'",
		"a browser session with bearer material":      "INSERT INTO identity.session (session_id, user_id, device_id, installation_id, credential_kind, scope, product_id, purpose, auth_method, authenticated_at, issued_at, expires_at, idle_expires_at, last_activity_at, browser_handle_hash, browser_origin, access_token_hash, access_expires_at, auth_epoch, recovery_generation, session_policy_version, rev) VALUES (gen_random_uuid(), '" + user + "', '" + device + "', '" + web + "', 2, 1, 'arcforges-web', 1, 1, now(), now(), now() + interval '12 hours', now() + interval '30 minutes', now(), decode(repeat('aa', 32), 'hex'), 'https://center.example', decode(repeat('bb', 32), 'hex'), now(), 0, 0, 'v1', 1)",
		"a session bound to another account's device": "INSERT INTO identity.session (session_id, user_id, device_id, installation_id, credential_kind, scope, product_id, purpose, auth_method, authenticated_at, issued_at, expires_at, idle_expires_at, last_activity_at, browser_handle_hash, browser_origin, auth_epoch, recovery_generation, session_policy_version, rev) VALUES (gen_random_uuid(), '" + other + "', '" + device + "', '" + web + "', 2, 1, 'arcforges-web', 1, 1, now(), now(), now() + interval '12 hours', now() + interval '30 minutes', now(), decode(repeat('ab', 32), 'hex'), 'https://center.example', 0, 0, 'v1', 1)",
		"the agent scope":                             "INSERT INTO identity.session (session_id, user_id, device_id, installation_id, credential_kind, scope, product_id, purpose, auth_method, authenticated_at, issued_at, expires_at, idle_expires_at, last_activity_at, browser_handle_hash, browser_origin, auth_epoch, recovery_generation, session_policy_version, rev) VALUES (gen_random_uuid(), '" + user + "', '" + device + "', '" + web + "', 2, 6, 'arcforges-web', 1, 1, now(), now(), now() + interval '12 hours', now() + interval '30 minutes', now(), decode(repeat('ac', 32), 'hex'), 'https://center.example', 0, 0, 'v1', 1)",
		"a passkey without its material":              "INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, created_at, rev) VALUES (gen_random_uuid(), '" + user + "', 1, 'passkey', 'cred', now(), 1)",
		"a password credential":                       "INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, created_at, rev) VALUES (gen_random_uuid(), '" + user + "', 3, 'password', 'x', now(), 1)",
		"an e-mail identity with passkey material":    "INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, sign_count, created_at, rev) VALUES (gen_random_uuid(), '" + user + "', 2, 'email', 'a@example.com', 0, now(), 1)",
		"a second bootstrap":                          "INSERT INTO identity.bootstrap (singleton, token_sha256, user_id, consumed_at) VALUES (true, decode(repeat('cc', 32), 'hex'), '" + other + "', now())",
		"a bootstrap row that is not the singleton":   "INSERT INTO identity.bootstrap (singleton, token_sha256, user_id, consumed_at) VALUES (false, decode(repeat('cc', 32), 'hex'), '" + other + "', now())",
	}
	must(t, "INSERT INTO identity.bootstrap (singleton, token_sha256, user_id, consumed_at) VALUES (true, decode(repeat('cc', 32), 'hex'), '"+user+"', now())")
	must(t, "INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, created_at, rev) VALUES (gen_random_uuid(), '"+user+"', 2, 'email', 'owner@example.com', now(), 1)")
	refused["a subject that moves to another user"] = "INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, created_at, rev) VALUES (gen_random_uuid(), '" + other + "', 2, 'email', 'owner@example.com', now(), 1)"
	for label, statement := range refused {
		t.Run(label, func(t *testing.T) {
			tx, err := conn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			// Each refusal is an integrity constraint (SQLSTATE class 23), never a syntax or privilege error.
			_, err = tx.Exec(ctx, statement)
			var pgError *pgconn.PgError
			if !errors.As(err, &pgError) || !strings.HasPrefix(pgError.Code, "23") {
				t.Fatalf("not refused by a constraint (%v): %s", err, statement)
			}
		})
	}

	// A browser session of the right shape is admitted, and a consumed flow can never change again.
	must(t, "INSERT INTO identity.session (session_id, user_id, device_id, installation_id, credential_kind, scope, product_id, purpose, auth_method, authenticated_at, issued_at, expires_at, idle_expires_at, last_activity_at, browser_handle_hash, browser_origin, auth_epoch, recovery_generation, session_policy_version, rev) VALUES (gen_random_uuid(), '"+user+"', '"+device+"', '"+web+"', 2, 1, 'arcforges-web', 1, 1, now(), now(), now() + interval '12 hours', now() + interval '30 minutes', now(), decode(repeat('ad', 32), 'hex'), 'https://center.example', 0, 0, 'v1', 1)")
	const flow = "00000000-0000-4000-8000-000000000041"
	must(t, "INSERT INTO identity.auth_flow (flow_id, channel, kind, purpose, challenge, sends, attempts, max_attempts, created_at, expires_at) VALUES ('"+flow+"', 1, 1, 1, decode(repeat('ee', 32), 'hex'), 0, 0, 5, now(), now() + interval '5 minutes')")
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
