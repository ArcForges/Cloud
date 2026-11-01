// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

func TestTheMigrationAndAdministrationCommands(t *testing.T) {
	url, name := pgtest.Database(t)
	directory := t.TempDir()
	secretFile := filepath.Join(directory, "runtime.json")
	password := strings.Split(strings.Split(url, ":")[2], "@")[0]
	values := map[string]string{
		"ARCFORGES_CENTER_MODE":                   "self-hosted",
		"ARCFORGES_CENTER_MIGRATION_DATABASE_URL": url,
		"ARCFORGES_CENTER_DATABASE_NAME":          name + "_center",
		"ARCFORGES_CENTER_RUNTIME_ROLE":           name + "_runtime",
		"ARCFORGES_CENTER_RUNTIME_SECRET_FILE":    secretFile,
		"ARCFORGES_CENTER_RUNTIME_POOLED_HOST":    pgtest.Host(t),
	}
	t.Cleanup(func() { pgtest.Drop(t, name+"_center") })
	command := func(expected int, arguments ...string) map[string]any {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if code := run(arguments, environment(values), &stdout, &stderr); code != expected {
			t.Fatalf("%v: exit %d, expected %d: %s", arguments, code, expected, stderr.String())
		}
		if strings.Contains(stdout.String()+stderr.String(), password) {
			t.Fatalf("%v printed a credential", arguments)
		}
		var document map[string]any
		if stdout.Len() > 0 {
			if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
				t.Fatalf("%v: %v %s", arguments, err, stdout.String())
			}
		}
		return document
	}
	if document := command(0, "admin", "ensure-database"); document["created"] != true {
		t.Fatalf("ensure-database: %v", document)
	}
	if document := command(0, "admin", "ensure-database"); document["created"] != false {
		t.Fatalf("ensure-database again: %v", document)
	}
	if document := command(0, "migrate", "status"); document["state"] != "uninitialized" {
		t.Fatalf("status before: %v", document)
	}
	if document := command(0, "migrate", "plan"); len(document["pending"].([]any)) == 0 {
		t.Fatalf("plan: %v", document)
	}
	if document := command(0, "migrate"); document["state"] != "current" || document["grants"] != "reconciled" || len(document["ran"].([]any)) == 0 ||
		number(document["serverVersionNum"]) < 160000 {
		t.Fatalf("apply: %v", document)
	}
	if document := command(0, "migrate", "apply"); document["state"] != "current" || document["ran"] != nil {
		t.Fatalf("apply again: %v", document)
	}
	rotation := command(0, "admin", "rotate-runtime-credential")
	if rotation["slot"] != "a" || rotation["loginRole"] != name+"_runtime_a" || rotation["passwordForm"] != "scram-sha-256-verifier" {
		t.Fatalf("rotation: %v", rotation)
	}
	info, err := os.Stat(secretFile)
	// Windows has no POSIX permission bits (Go reports 0666 for a writable file); the mode is checked where it exists.
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("secret file: %v %v", info, err)
	}
	content, _ := os.ReadFile(secretFile)
	var secrets map[string]string
	if err = json.Unmarshal(content, &secrets); err != nil || len(secrets) != 1 || !strings.Contains(secrets["ARCFORGES_CENTER_DATABASE_URL"], name+"_runtime_a:") {
		t.Fatal("the secret file does not hold exactly the runtime URL")
	}
	runtimePassword := strings.Split(strings.Split(secrets["ARCFORGES_CENTER_DATABASE_URL"], ":")[2], "@")[0]
	if len(runtimePassword) != 40 || strings.Contains(fmt.Sprint(rotation), runtimePassword) {
		t.Fatal("the rotation printed the runtime credential")
	}
	// The promotion of slot a is recorded once; slot b was never rotated.
	command(4, "admin", "confirm-runtime-credential", "--slot", "b")
	confirmed := command(0, "admin", "confirm-runtime-credential", "--slot", "a")
	if confirmed["slot"] != "a" || confirmed["loginRole"] != name+"_runtime_a" || confirmed["alreadyConfirmed"] != false || confirmed["promotedAt"] == "" {
		t.Fatalf("confirm: %v", confirmed)
	}
	if again := command(0, "admin", "confirm-runtime-credential", "--slot=a"); again["alreadyConfirmed"] != true || again["promotedAt"] != confirmed["promotedAt"] {
		t.Fatalf("confirm again: %v", again)
	}
	// The file is never overwritten.
	command(1, "admin", "rotate-runtime-credential")
	// admin revoke-sessions (PLT-10): every unrevoked session of the account, whatever its scope, audited; another account's stay.
	center := pgtest.Connect(t, pgtest.WithDatabase(t, url, name+"_center"))
	owner, other := seedSessions(t, center), seedSessions(t, center)
	command(2, "admin", "revoke-sessions")
	command(2, "admin", "revoke-sessions", "--account", "not-a-uuid")
	command(2, "admin", "revoke-sessions", "--account", strings.ToUpper(owner.String()))
	command(2, "admin", "revoke-sessions", "--all", "--account", owner.String())
	revoked := command(0, "admin", "revoke-sessions", "--account", owner.String())
	if counts, _ := revoked["revoked"].(map[string]any); revoked["target"] != "account" || revoked["account"] != owner.String() || len(counts) != 2 ||
		number(counts["account"]) != 1 || number(counts["node"]) != 1 {
		t.Fatalf("revoke-sessions: %v", revoked)
	}
	var live, audits int
	if err = center.QueryRow(t.Context(), "SELECT count(*) FILTER (WHERE revoked_at IS NULL) FROM identity.session WHERE user_id = $1", other).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if err = center.QueryRow(t.Context(), `SELECT count(*) FROM audit.audit_event WHERE event_type = 'identity.sessions.revoked_by_operator'
    AND actor_ref = 'operator:cli' AND target_id = $1`, owner.String()).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if live != 2 || audits != 1 {
		t.Fatalf("another account's live sessions %d, audits %d", live, audits)
	}
	if again := command(0, "admin", "revoke-sessions", "--account="+owner.String()); len(again["revoked"].(map[string]any)) != 0 {
		t.Fatalf("revoke-sessions again: %v", again)
	}
	if all := command(0, "admin", "revoke-sessions", "--all"); all["target"] != "center" || number(all["revoked"].(map[string]any)["account"]) != 1 {
		t.Fatalf("revoke-sessions --all: %v", all)
	}
	// admin grant-operator and revoke-operator (decision n2, PLT-10): a bounded role on an active account, audited in the same
	// transaction, with the reason kept in the row and only its digest in the audit.
	candidate := seedSessions(t, center)
	text := "operator for the Q4 launch support rota"
	for _, arguments := range [][]string{
		{"admin", "grant-operator"}, {"admin", "grant-operator", "--account", candidate.String()}, {"admin", "grant-operator", "--reason", text},
		{"admin", "grant-operator", "--account", "not-a-uuid", "--reason", text}, {"admin", "grant-operator", "--account", strings.ToUpper(candidate.String()), "--reason", text},
		{"admin", "grant-operator", "--account", candidate.String(), "--reason", "   "}, {"admin", "grant-operator", "--account", candidate.String(), "--reason", strings.Repeat("r", 513)},
		{"admin", "grant-operator", "--account", candidate.String(), "--reason", "line\nbreak"},
		{"admin", "grant-operator", "--account", candidate.String(), "--reason", text, "--days", "0"}, {"admin", "grant-operator", "--account", candidate.String(), "--reason", text, "--days", "91"},
		{"admin", "grant-operator", "--account", candidate.String(), "--reason", text, "--days=030"}, {"admin", "grant-operator", "--account", candidate.String(), "--reason", text, "--days", "1.5"},
		{"admin", "grant-operator", "--account", candidate.String(), "--account", candidate.String(), "--reason", text}, {"admin", "grant-operator", "--account", candidate.String(), "--reason", text, "--bogus", "1"}, {"admin", "grant-operator", "--account", strings.ReplaceAll(candidate.String(), "-", ""), "--reason", text},
		{"admin", "grant-operator", "--account", candidate.String(), "--reason"}, {"admin", "revoke-operator"}, {"admin", "revoke-operator", "--account", candidate.String(), "--reason", text},
		{"admin", "revoke-operator", "--account", candidate.String(), "--days", "3"}, {"admin", "revoke-operator", "--all"},
	} {
		command(2, arguments...)
	}
	rows := func(where string) int {
		var count int
		if err = center.QueryRow(t.Context(), "SELECT count(*) FROM identity.operator WHERE user_id = $1 "+where, candidate).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	roleAudits := func(eventType string) int {
		var count int
		if err = center.QueryRow(t.Context(), "SELECT count(*) FROM audit.audit_event WHERE event_type = $1 AND actor_ref = 'operator:cli' AND target_id = $2", eventType, candidate.String()).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	if rows("") != 0 || roleAudits("identity.operator.granted") != 0 {
		t.Fatal("a refused command wrote")
	}
	// An account that does not exist and an account that is not active are refused without effect.
	command(1, "admin", "grant-operator", "--account", platform.NewID().String(), "--reason", text)
	if _, err = center.Exec(t.Context(), "UPDATE identity.user SET state = 3, rev = rev + 1 WHERE user_id = $1", candidate); err != nil {
		t.Fatal(err)
	}
	command(1, "admin", "grant-operator", "--account", candidate.String(), "--reason", text)
	if _, err = center.Exec(t.Context(), "UPDATE identity.user SET state = 1, rev = rev + 1 WHERE user_id = $1", candidate); err != nil {
		t.Fatal(err)
	}
	if rows("") != 0 || roleAudits("identity.operator.granted") != 0 {
		t.Fatal("a refused grant wrote")
	}
	granted := command(0, "admin", "grant-operator", "--account", candidate.String(), "--reason", text)
	grantedAt, _ := time.Parse(time.RFC3339, fmt.Sprint(granted["grantedAt"]))
	expiresAt, _ := time.Parse(time.RFC3339, fmt.Sprint(granted["expiresAt"]))
	if granted["account"] != candidate.String() || granted["operatorId"] == nil || expiresAt.Sub(grantedAt) != 30*24*time.Hour || strings.Contains(fmt.Sprint(granted), "Q4") {
		t.Fatalf("grant-operator: %v", granted)
	}
	var storedReason, grantedBy string
	if err = center.QueryRow(t.Context(), "SELECT reason, granted_by FROM identity.operator WHERE user_id = $1", candidate).Scan(&storedReason, &grantedBy); err != nil || storedReason != text || grantedBy != "operator:cli" {
		t.Fatalf("the row: %q %q %v", storedReason, grantedBy, err)
	}
	var payload []byte
	if err = center.QueryRow(t.Context(), "SELECT payload FROM audit.audit_event WHERE event_type = 'identity.operator.granted' AND target_id = $1", candidate.String()).Scan(&payload); err != nil ||
		strings.Contains(string(payload), "Q4") || !strings.Contains(string(payload), "reasonSha256") || !strings.Contains(string(payload), granted["operatorId"].(string)) {
		t.Fatalf("the audit payload %s: %v", payload, err)
	}
	// A live role is not granted twice; the role ends by revoking it, and a role can be granted for 90 days at most.
	command(1, "admin", "grant-operator", "--account", candidate.String(), "--reason", text)
	if rows("") != 1 || roleAudits("identity.operator.granted") != 1 {
		t.Fatal("a second grant wrote")
	}
	if ended := command(0, "admin", "revoke-operator", "--account", candidate.String()); number(ended["rowsEnded"]) != 1 || ended["account"] != candidate.String() {
		t.Fatalf("revoke-operator: %v", ended)
	}
	if rows("AND revoked_at IS NOT NULL") != 1 || roleAudits("identity.operator.revoked") != 1 {
		t.Fatal("the revocation")
	}
	if again := command(0, "admin", "revoke-operator", "--account", candidate.String()); number(again["rowsEnded"]) != 0 || roleAudits("identity.operator.revoked") != 2 {
		t.Fatalf("revoke-operator again: %v", again)
	}
	longRole := command(0, "admin", "grant-operator", "--account", candidate.String(), "--reason", text, "--days=90")
	grantedAt, _ = time.Parse(time.RFC3339, fmt.Sprint(longRole["grantedAt"]))
	expiresAt, _ = time.Parse(time.RFC3339, fmt.Sprint(longRole["expiresAt"]))
	if expiresAt.Sub(grantedAt) != 90*24*time.Hour || rows("") != 2 {
		t.Fatalf("grant-operator for 90 days: %v", longRole)
	}
	// An edited applied migration refuses with status 3.
	if _, err = pgtest.Connect(t, pgtest.WithDatabase(t, url, name+"_center")).Exec(t.Context(), "UPDATE platform.schema_migration SET sha256 = repeat('0', 64) WHERE version = 1"); err != nil {
		t.Fatal(err)
	}
	if document := command(3, "migrate"); document["state"] != "refused" {
		t.Fatalf("refused: %v", document)
	}
	command(3, "migrate", "status")
}

// number reads a JSON number, or -1 when the value is not one.
func number(value any) float64 {
	if number, ok := value.(float64); ok {
		return number
	}
	return -1
}

// seedSessions creates an account with one device, an account session and a node session on it, and returns the account.
func seedSessions(t *testing.T, conn *pgx.Conn) platform.ID {
	t.Helper()
	ctx := t.Context()
	userID := platform.NewID()
	handle := make([]byte, 32)
	copy(handle, userID[:])
	now := time.Now().UTC()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, "INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev) VALUES ($1, 'Seeded', 1, $2, $3, 1)",
		userID, handle, now); err != nil {
		t.Fatal(err)
	}
	claim := device.Claim{InstallationID: platform.NewID(), Product: "arcforges-mobile", Platform: "android-15", AppVersion: "1.0.0"}
	deviceID, err := device.EnsureNative(ctx, tx, userID, claim, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []session.Scope{session.ScopeAccount, session.ScopeNode} {
		if _, err = session.IssueNative(ctx, tx, config.DefaultIdentityPolicy(), session.Grant{UserID: userID, DeviceID: deviceID, InstallationID: claim.InstallationID,
			Scope: scope, Product: claim.Product, Purpose: session.PurposeAuthenticate, AuthMethod: 1, AuthenticatedAt: now}, now); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return userID
}
