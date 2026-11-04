// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// native seeds a native device and installation of an account and issues a native session of a scope on them (EVIDENCE: REAL
// PostgreSQL, the runtime role's store).
func native(t *testing.T, db *dbtest.Database, user platform.ID, scope Scope, product string, now time.Time) (Native, platform.ID) {
	t.Helper()
	device, installation := platform.NewID(), platform.NewID()
	ctx := context.Background()
	if _, err := db.Migration.Exec(ctx, `INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev)
VALUES ($1, $2, 'native', 3, 1, false, now(), now(), 1)`, device, user); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Migration.Exec(ctx, `INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, installed_at, last_active_at, rev)
VALUES ($1, $2, $3, $4, '1.0.0', 'linux', now(), now(), 1)`, installation, device, user, product); err != nil {
		t.Fatal(err)
	}
	var issued Native
	err := db.Runtime.InTx(ctx, "issue", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		issued, err = IssueNative(ctx, tx, config.DefaultIdentityPolicy(), Grant{UserID: user, DeviceID: device, InstallationID: installation, Scope: scope,
			Product: product, Purpose: PurposeAuthenticate, AuthMethod: 1, AuthenticatedAt: now}, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return issued, installation
}

func refusalKey(err error) string {
	if refusal, ok := err.(*arc.Refusal); ok {
		return refusal.Key()
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestRefreshAdmitsOnlyItsScopesAndTheLifetimesFollowTheScope pins the generalized refresh (AF-CTR-04 CRD-04, cloud-7): a node session
// gets the node lifetimes (60-minute access, 90 days idle, 365 days absolute) at issue and at rotation; the node admission needs no
// installation; a live token of the other kind is permission_denied with nothing written, in both directions; revocation and expiry
// keep winning over the scope; a spent token of either kind takes the reuse path and its audit names the family's scope; Lookup tells
// a current, a spent and an unknown token apart without deciding anything.
func TestRefreshAdmitsOnlyItsScopesAndTheLifetimesFollowTheScope(t *testing.T) {
	db := dbtest.New(t)
	ctx := context.Background()
	policy := config.DefaultIdentityPolicy()
	now := time.Now().UTC().Truncate(time.Microsecond)
	user := db.Account(1)
	node, nodeInstallation := native(t, db, user, ScopeNode, "arcforges-node", now)
	if node.AccessExpiresAt.Sub(node.IssuedAt) != time.Hour || node.RefreshExpiresAt.Sub(node.IssuedAt) != 90*24*time.Hour ||
		node.ExpiresAt.Sub(node.IssuedAt) != 365*24*time.Hour {
		t.Fatalf("node lifetimes %+v", node)
	}
	account, accountInstallation := native(t, db, user, ScopeAccount, "arcforges-mobile", now)
	if account.AccessExpiresAt.Sub(account.IssuedAt) != 15*time.Minute || account.ExpiresAt.Sub(account.IssuedAt) != 90*24*time.Hour {
		t.Fatalf("account lifetimes %+v", account)
	}
	if presented, err := Lookup(ctx, db.Runtime.Pool(), node.RefreshToken); err != nil || presented.Current == nil || *presented.Current != node.SessionID || presented.Spent {
		t.Fatalf("lookup of a current token %+v %v", presented, err)
	}
	for _, token := range []string{"afr1.x", "not a token", RefreshPrefix + NewSecret().Text()} {
		if presented, err := Lookup(ctx, db.Runtime.Pool(), token); err != nil || presented.Known() {
			t.Fatalf("lookup of %q %+v %v", token, presented, err)
		}
	}
	writes := func() int {
		return db.Count("SELECT (SELECT count(*) FROM identity.spent_refresh) + (SELECT coalesce(sum(rev), 0) FROM identity.session)")
	}
	// Cross-kind live tokens: permission_denied naming the method's operation, nothing written.
	before := writes()
	if _, _, err := Refresh(ctx, db.Runtime, policy, account.RefreshToken, NodeRefresh(), now, nil, nil); refusalKey(err) != "AUTHORIZATION/permission_denied" ||
		err.(*arc.Refusal).Reason != "fleet.refreshNodeSession" {
		t.Fatalf("an account token as a node: %v", err)
	}
	if _, _, err := Refresh(ctx, db.Runtime, policy, node.RefreshToken, AccountRefresh(nodeInstallation), now, nil, nil); refusalKey(err) != "AUTHORIZATION/permission_denied" ||
		err.(*arc.Refusal).Reason != "identity.refreshSession" {
		t.Fatalf("a node token as an account: %v", err)
	}
	// A wrong installation on the account path stays unauthenticated.
	if _, _, err := Refresh(ctx, db.Runtime, policy, node.RefreshToken, AccountRefresh(accountInstallation), now, nil, nil); refusalKey(err) != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("another installation: %v", err)
	}
	if writes() != before {
		t.Fatal("a refused cross-kind refresh wrote")
	}
	// The node rotates without an installation, with the node lifetimes, and within runs in the rotation.
	later := now.Add(time.Minute)
	ran := false
	rotated, reuse, err := Refresh(ctx, db.Runtime, policy, node.RefreshToken, NodeRefresh(), later, nil, func(context.Context, pgx.Tx, Native) error {
		ran = true
		return nil
	})
	if err != nil || reuse != nil || !ran || rotated.IssuedAt != later || rotated.AccessExpiresAt.Sub(later) != time.Hour ||
		rotated.RefreshExpiresAt.Sub(later) != 90*24*time.Hour || !rotated.ExpiresAt.Equal(node.ExpiresAt) {
		t.Fatalf("node rotation %+v %v %v", rotated, reuse, err)
	}
	if presented, err := Lookup(ctx, db.Runtime.Pool(), node.RefreshToken); err != nil || !presented.Spent || presented.Current != nil {
		t.Fatalf("lookup of a spent token %+v %v", presented, err)
	}
	// A spent node token presented to the account method still takes the reuse path, and the audit names the node scope.
	if _, reuse, err = Refresh(ctx, db.Runtime, policy, node.RefreshToken, AccountRefresh(nodeInstallation), later, nil, nil); refusalKey(err) != "AUTHENTICATION/credential_revoked" ||
		reuse == nil || reuse.Scope != ScopeNode || reuse.Revoked != 1 {
		t.Fatalf("a spent node token %+v %v", reuse, err)
	}
	var payload []byte
	if err := db.Migration.QueryRow(ctx, "SELECT payload FROM audit.audit_event WHERE event_type = 'identity.session.refresh_reused'").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(payload, &fields); err != nil || fields["scope"] != "node" || fields["revokedSessions"] != float64(1) {
		t.Fatalf("reuse payload %s %v", payload, err)
	}
	// Revoked and expired win over the scope: a revoked account token and an expired account token presented as a node.
	if _, err := db.Migration.Exec(ctx, "UPDATE identity.session SET expires_at = $2, refresh_expires_at = $2 WHERE session_id = $1", account.SessionID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Refresh(ctx, db.Runtime, policy, account.RefreshToken, NodeRefresh(), later, nil, nil); refusalKey(err) != "AUTHENTICATION/token_expired" {
		t.Fatalf("an expired account token as a node: %v", err)
	}
	if _, err := db.Migration.Exec(ctx, "UPDATE identity.session SET revoked_at = now(), revoke_reason = 2 WHERE session_id = $1", account.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Refresh(ctx, db.Runtime, policy, account.RefreshToken, NodeRefresh(), later, nil, nil); refusalKey(err) != "AUTHENTICATION/credential_revoked" {
		t.Fatalf("a revoked account token as a node: %v", err)
	}
}
