// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

func writeKey(t *testing.T, directory, name string, public any, asPEM bool) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	data := der
	if asPEM {
		data = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	}
	path := filepath.Join(directory, name)
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestTheFleetAdministrationCommands (E1-19, Q6, Q21; EVIDENCE: REAL PostgreSQL, the real executable's command handlers with the
// migration role): register-signing-key records a PEM or DER P-256 public key under the rotation rules and audits it, refusing
// another algorithm, a duplicate key ID and a successor that does not overlap; the published set includes a registered successor
// whose validity lies ahead while the valid set does not; the runtime role cannot register; retire-signing-key retires once and
// reports the valid keys left; revoke-device releases a node ID with the full cascade, audited with the operator as actor.
func TestTheFleetAdministrationCommands(t *testing.T) {
	url, name := pgtest.Database(t)
	directory := t.TempDir()
	values := map[string]string{
		"ARCFORGES_CENTER_MODE": "self-hosted", "ARCFORGES_CENTER_MIGRATION_DATABASE_URL": url, "ARCFORGES_CENTER_DATABASE_NAME": name + "_center",
		"ARCFORGES_CENTER_RUNTIME_ROLE": name + "_runtime", "ARCFORGES_CENTER_RUNTIME_SECRET_FILE": filepath.Join(directory, "runtime.json"),
		"ARCFORGES_CENTER_RUNTIME_POOLED_HOST": pgtest.Host(t),
	}
	t.Cleanup(func() { pgtest.Drop(t, name+"_center") })
	command := func(expected int, arguments ...string) map[string]any {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if code := run(arguments, environment(values), &stdout, &stderr); code != expected {
			t.Fatalf("%v: exit %d, expected %d: %s", arguments, code, expected, stderr.String())
		}
		var document map[string]any
		if stdout.Len() > 0 {
			if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
				t.Fatalf("%v: %v %s", arguments, err, stdout.String())
			}
		}
		return document
	}
	command(0, "admin", "ensure-database")
	command(0, "migrate")
	ctx := context.Background()
	center := pgtest.Connect(t, pgtest.WithDatabase(t, url, name+"_center"))
	now := time.Now().UTC().Truncate(time.Second)
	current, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	successor, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	currentFile := writeKey(t, directory, "current.pem", &current.PublicKey, true)
	successorFile := writeKey(t, directory, "successor.der", &successor.PublicKey, false)
	rsaFile := writeKey(t, directory, "rsa.pem", &rsaKey.PublicKey, true)
	register := func(expected int, kid, file string, notBefore, notAfter time.Time) map[string]any {
		return command(expected, "admin", "register-signing-key", "--purpose", "command", "--kid", kid, "--public-key-file", file,
			"--secret-binding", "TEST_ONLY_"+strings.ToUpper(kid), "--not-before="+notBefore.Format(time.RFC3339), "--not-after", notAfter.Format(time.RFC3339))
	}
	registered := register(0, "cmdcurrent01", currentFile, now, now.Add(30*24*time.Hour))
	if registered["kid"] != "cmdcurrent01" || registered["purpose"] != "command" || !strings.Contains(registered["fingerprint"].(string), "-") {
		t.Fatalf("register: %v", registered)
	}
	register(1, "cmdcurrent01", successorFile, now, now.Add(30*24*time.Hour))
	register(1, "cmdrsakey001", rsaFile, now, now.Add(30*24*time.Hour))
	register(1, "cmdlate00001", successorFile, now.Add(29*24*time.Hour), now.Add(60*24*time.Hour))
	register(0, "cmdsuccessor", successorFile, now.Add(20*24*time.Hour), now.Add(60*24*time.Hour))
	command(2, "admin", "register-signing-key", "--purpose", "relay", "--kid", "x1234567", "--public-key-file", currentFile, "--secret-binding", "X",
		"--not-before", now.Format(time.RFC3339), "--not-after", now.Add(time.Hour).Format(time.RFC3339))
	command(2, "admin", "register-signing-key", "--kid", "x1234567")
	published, err := platform.PublishedKeys(ctx, center, platform.CommandSigning, now.Add(time.Minute))
	valid, validErr := platform.ValidKeys(ctx, center, platform.CommandSigning, now.Add(time.Minute))
	if err != nil || validErr != nil || len(published) != 2 || published[1].KID != "cmdsuccessor" || len(valid) != 1 || valid[0].KID != "cmdcurrent01" {
		t.Fatalf("published %d, valid %d: %v %v", len(published), len(valid), err, validErr)
	}
	var audited int
	if err = center.QueryRow(ctx, "SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.signing_key.registered' AND actor_ref = 'operator:cli'").
		Scan(&audited); err != nil || audited != 2 {
		t.Fatalf("registered audits %d %v", audited, err)
	}
	var runtimeInsert bool
	if err = center.QueryRow(ctx, "SELECT has_table_privilege($1, 'fleet.signing_key', 'INSERT')", name+"_runtime").Scan(&runtimeInsert); err != nil || runtimeInsert {
		t.Fatalf("the runtime role may register a key: %v", err)
	}
	retired := command(0, "admin", "retire-signing-key", "--kid", "cmdcurrent01")
	if retired["validKeys"] != float64(0) || retired["purpose"] != "command" {
		t.Fatalf("retire: %v", retired)
	}
	command(1, "admin", "retire-signing-key", "--kid", "cmdcurrent01")
	command(1, "admin", "retire-signing-key", "--kid", "unknownkid01")
	command(1, "admin", "retire-signing-key", "--kid", "cmdsuccessor", "--at", now.Add(-time.Hour).Format(time.RFC3339))
	if published, err = platform.PublishedKeys(ctx, center, platform.CommandSigning, time.Now().Add(time.Second)); err != nil || len(published) != 1 {
		t.Fatalf("published after the retirement: %d %v", len(published), err)
	}
	// F5: a retirement scheduled ahead is published as the key's not_after, so a node stops trusting it then.
	retireAt := now.Add(40 * 24 * time.Hour)
	command(0, "admin", "retire-signing-key", "--kid", "cmdsuccessor", "--at", retireAt.Format(time.RFC3339))
	if published, err = platform.PublishedKeys(ctx, center, platform.CommandSigning, time.Now().Add(time.Second)); err != nil || len(published) != 1 ||
		!published[0].NotAfter.Equal(retireAt) {
		t.Fatalf("a scheduled retirement: %+v %v", published, err)
	}

	// revoke-device: a node enrolled by an account, released by the operator by its node ID.
	user, browser, nodeID := platform.NewID(), platform.NewID(), platform.NewID()
	webDevice, webInstallation := platform.NewID(), platform.NewID()
	for _, statement := range []struct {
		sql       string
		arguments []any
	}{
		{"INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev) VALUES ($1, 'Owner', 1, $2, now(), 1)", []any{user, append(append([]byte{}, user[:]...), user[:]...)}},
		{"INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev) VALUES ($1, $2, 'Browser', 6, 1, false, now(), now(), 1)", []any{webDevice, user}},
		{"INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, client_installation_id, installed_at, last_active_at, rev) VALUES ($1, $2, $3, 'arcforges-web', 'web', 'web', gen_random_uuid(), now(), now(), 1)", []any{webInstallation, webDevice, user}},
		{"INSERT INTO identity.session (session_id, user_id, device_id, installation_id, credential_kind, scope, product_id, purpose, auth_method, authenticated_at, issued_at, expires_at, idle_expires_at, last_activity_at, browser_handle_hash, browser_origin, auth_epoch, recovery_generation, session_policy_version, rev) VALUES ($1, $2, $3, $4, 2, 1, 'arcforges-web', 1, 1, now(), now(), now() + interval '12 hours', now() + interval '30 minutes', now(), decode(repeat('ad', 32), 'hex'), 'https://center.example', 0, 0, 'v1', 1)", []any{browser, user, webDevice, webInstallation}},
	} {
		if _, err = center.Exec(ctx, statement.sql, statement.arguments...); err != nil {
			t.Fatal(err)
		}
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	platformOf, _ := fleet.PlatformOf(2)
	var enrolled fleet.Enrolled
	if err = pgx.BeginFunc(ctx, center, func(tx pgx.Tx) error {
		var err error
		enrolled, err = fleet.Enroll(ctx, tx, config.DefaultIdentityPolicy(), fleet.EnrollRequest{UserID: user, Approver: fleet.Approver{SessionID: browser, AuthMethod: 1,
			AuthenticatedAt: now}, NodeID: nodeID, Node: fleet.NodeInfo{Name: "squatted", Platform: platformOf, Arch: 1, Version: "1.0.0"}, PublicKey: der,
			Flow: fleet.FlowDevice}, time.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	command(2, "admin", "revoke-device", "--node", nodeID.String(), "--device", enrolled.DeviceID.String())
	command(2, "admin", "revoke-device", "--node", strings.ToUpper(nodeID.String()))
	released := command(0, "admin", "revoke-device", "--node", nodeID.String())
	if released["device"] != enrolled.DeviceID.String() || released["participants"].(map[string]any)["fleet.node"] != float64(1) ||
		released["sessions"].(map[string]any)["node"] != float64(1) {
		t.Fatalf("revoke-device: %v", released)
	}
	var live, audits int
	if err = center.QueryRow(ctx, `SELECT (SELECT count(*) FROM fleet.node WHERE node_id = $1 AND revoked_at IS NULL) +
    (SELECT count(*) FROM identity.session WHERE session_id = $2 AND revoked_at IS NULL)`, nodeID, enrolled.Session.SessionID).Scan(&live); err != nil || live != 0 {
		t.Fatalf("live rows after the release: %d %v", live, err)
	}
	if err = center.QueryRow(ctx, "SELECT count(*) FROM audit.audit_event WHERE event_type = 'device.revoked' AND actor_ref = 'operator:cli' AND target_id = $1",
		enrolled.DeviceID.String()).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("device.revoked audits %d %v", audits, err)
	}
	command(1, "admin", "revoke-device", "--node", nodeID.String())
	command(1, "admin", "revoke-device", "--device", enrolled.DeviceID.String())
}
