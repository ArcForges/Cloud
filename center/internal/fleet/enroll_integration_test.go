// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// EVIDENCE: REAL PostgreSQL (the pinned image of the Linux leg), the runtime role's store, the real Enroll; the enrollment is SEEDED:
// the account, its approving browser session and the approval data are inserted by the test and Enroll is called in a test
// transaction (no served sign-in path exists in part E1a; E1b's PKCE completion and E2's device poll call the same function).

// rig is a test database with an account and its approving browser session.
type rig struct {
	t        *testing.T
	db       *dbtest.Database
	policy   config.IdentityPolicy
	user     platform.ID
	approver dbtest.Session
}

func newRig(t *testing.T) *rig {
	t.Helper()
	db := dbtest.New(t)
	user := db.Account(1)
	return &rig{t: t, db: db, policy: config.DefaultIdentityPolicy(), user: user, approver: db.Session(user, 1)}
}

// account adds another account with its approving session.
func (r *rig) account(state int16) (platform.ID, dbtest.Session) {
	user := r.db.Account(state)
	return user, r.db.Session(user, 1)
}

func nodeKey(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func linuxNode(name, version string) NodeInfo {
	platform, _ := PlatformOf(2)
	return NodeInfo{Name: name, Platform: platform, Arch: 1, Version: version}
}

// request is an approved enrollment of a node by the rig's account.
func (r *rig) request(nodeID platform.ID, key []byte) EnrollRequest {
	return EnrollRequest{UserID: r.user, Approver: Approver{SessionID: r.approver.ID, AuthMethod: 1, AuthenticatedAt: time.Now().Add(-time.Minute)},
		NodeID: nodeID, Node: linuxNode("buildbox", "0.1.0-dev"), PublicKey: key, Flow: FlowPKCE}
}

// enroll runs Enroll in a transaction of its own, without retries (a deadlock is an error, never hidden).
func (r *rig) enroll(request EnrollRequest) (Enrolled, error) {
	var enrolled Enrolled
	err := r.db.Runtime.InTx(context.Background(), "enroll a node", store.TxOptions{Attempts: 1}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		enrolled, err = Enroll(ctx, tx, r.policy, request, time.Now())
		return err
	})
	return enrolled, err
}

func (r *rig) mustEnroll(request EnrollRequest) Enrolled {
	r.t.Helper()
	enrolled, err := r.enroll(request)
	if err != nil {
		r.t.Fatal(err)
	}
	return enrolled
}

func key(err error) string {
	var refusal *arc.Refusal
	switch {
	case err == nil:
		return ""
	case errors.As(err, &refusal):
		key := refusal.Key()
		if refusal.State != "" {
			key += " " + refusal.State + "/" + refusal.Reason
		}
		return key
	case errors.Is(err, ErrApprovalLapsed):
		return "lapsed"
	case errors.Is(err, store.ErrContention):
		return "contention"
	}
	return err.Error()
}

func (r *rig) count(query string, arguments ...any) int { return r.db.Count(query, arguments...) }

// TestEnrollRules pins CTR4-DES-06 as amended (cloud-1, cloud-11, Q5, Q20, Q21, C0 E-1, CR-04): a first enrollment creates the
// device (linux, the node's name, untrusted, no remote control), the arcforges-node installation (canonical version, the key at
// version 1) and the node row, issues a node session with the node lifetimes, publishes the keys and audits fleet.node.enrolled
// without a secret; a re-enrollment in the same account supersedes the old session in place, keeps the key version for the same key
// and raises it for another, renames the device only while it bears the name the node reported before; a node ID live in another
// account is already_exists (node); a key held live is already_exists (node_key, already_registered) and a retired one
// credential_revoked; a revoked node's ID enrolls again with a new key; the cap counts live (also signed-out) nodes; another OS on
// the same node ID is refused.
func TestEnrollRules(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	nodeID, firstKey := platform.NewID(), nodeKey(t)
	first := r.mustEnroll(r.request(nodeID, firstKey))
	if first.Reenrolled || first.KeyVersion != 1 || first.Session.AccessExpiresAt.Sub(first.Session.IssuedAt) != time.Hour ||
		first.Session.ExpiresAt.Sub(first.Session.IssuedAt) != 365*24*time.Hour || len(first.CommandKeys) != 0 || len(first.EntitlementKeys) != 0 {
		t.Fatalf("first enrollment %+v", first)
	}
	var devicePlatform, trust int16
	var remote bool
	var name, product, appVersion, platformText string
	var storedKey []byte
	if err := r.db.Migration.QueryRow(ctx, `SELECT d.platform, d.trust_level, d.remote_enabled, d.display_name, i.product_id, i.app_version, i.platform, i.public_key
FROM device.device d JOIN device.installation i ON i.device_id = d.device_id WHERE d.device_id = $1`, first.DeviceID).
		Scan(&devicePlatform, &trust, &remote, &name, &product, &appVersion, &platformText, &storedKey); err != nil {
		t.Fatal(err)
	}
	if devicePlatform != int16(device.PlatformLinux) || trust != 1 || remote || name != "buildbox" || product != "arcforges-node" || appVersion != "0.1.0-dev" ||
		platformText != "linux" || string(storedKey) != string(firstKey) {
		t.Fatalf("device %d %d %v %q %q %q %q", devicePlatform, trust, remote, name, product, appVersion, platformText)
	}
	if r.count("SELECT count(*) FROM identity.session WHERE session_id = $1 AND scope = 3 AND product_id = 'arcforges-node' AND revoked_at IS NULL AND installation_id = $2",
		first.Session.SessionID, first.InstallationID) != 1 {
		t.Fatal("no live node session on the installation")
	}
	var payload []byte
	if err := r.db.Migration.QueryRow(ctx, "SELECT payload FROM audit.audit_event WHERE event_type = 'fleet.node.enrolled' AND target_id = $1", first.EnrollmentID.String()).
		Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(payload, &fields); err != nil || fields["os"] != "linux" || fields["arch"] != "x64" || fields["version"] != "0.1.0-dev" ||
		fields["keyFingerprint"] != Fingerprint(firstKey) || fields["flow"] != "pkce" || fields["enrollment"] != "first" || fields["keyVersion"] != float64(1) ||
		fields["nodeId"] != nodeID.String() || len(fields) != 8 {
		t.Fatalf("enrolled payload %s", payload)
	}

	// (b) Same account, same key: in place, the old session superseded (reason 7), the key version kept; the device keeps a name the
	// user chose, and follows the node's name while it bears the reported one.
	again := r.request(nodeID, firstKey)
	again.Node = linuxNode("buildbox-2", "0.2.0")
	second := r.mustEnroll(again)
	if !second.Reenrolled || second.EnrollmentID != first.EnrollmentID || second.DeviceID != first.DeviceID || second.KeyVersion != 1 ||
		r.count("SELECT count(*) FROM identity.session WHERE session_id = $1 AND revoke_reason = 7", first.Session.SessionID) != 1 ||
		r.count("SELECT count(*) FROM device.device WHERE device_id = $1 AND display_name = 'buildbox-2'", first.DeviceID) != 1 ||
		r.count("SELECT count(*) FROM fleet.node WHERE enrollment_id = $1 AND display_name = 'buildbox-2' AND version = '0.2.0'", first.EnrollmentID) != 1 {
		t.Fatalf("re-enrollment %+v", second)
	}
	r.db.Exec("UPDATE device.device SET display_name = 'Work server' WHERE device_id = '" + first.DeviceID.String() + "'")
	// (b) with another key: the next key version, the old key no longer guarded (N-6).
	rotatedKey := nodeKey(t)
	third := r.request(nodeID, rotatedKey)
	third.Node = linuxNode("buildbox-3", "0.3.0")
	rotated := r.mustEnroll(third)
	if rotated.KeyVersion != 2 || r.count("SELECT count(*) FROM device.device WHERE device_id = $1 AND display_name = 'Work server'", first.DeviceID) != 1 ||
		r.count("SELECT count(*) FROM device.installation WHERE installation_id = $1 AND key_version = 2 AND public_key = $2", first.InstallationID, rotatedKey) != 1 {
		t.Fatalf("rotation %+v", rotated)
	}
	// Another OS on the same node ID.
	windows := r.request(nodeID, rotatedKey)
	windows.Node.Platform, _ = PlatformOf(1)
	if _, err := r.enroll(windows); key(err) != "VALIDATION/invalid_argument node.os/node.os: mismatch" {
		t.Fatalf("another OS: %v", key(err))
	}

	// (c) The node ID live in another account; (e) the key live elsewhere.
	other, otherApprover := r.account(1)
	foreign := r.request(nodeID, nodeKey(t))
	foreign.UserID, foreign.Approver.SessionID = other, otherApprover.ID
	if _, err := r.enroll(foreign); key(err) != "CONFLICT/already_exists node/already_exists" {
		t.Fatalf("a node ID of another account: %v", key(err))
	}
	held := r.request(platform.NewID(), rotatedKey)
	held.UserID, held.Approver.SessionID = other, otherApprover.ID
	if _, err := r.enroll(held); key(err) != "CONFLICT/already_exists node_key/already_registered" {
		t.Fatalf("a key held live: %v", key(err))
	}
	if _, err := r.enroll(r.request(platform.NewID(), rotatedKey)); key(err) != "CONFLICT/already_exists node_key/already_registered" {
		t.Fatalf("a key held live by another node of the account: %v", key(err))
	}
	// (b) rotating to a key another live installation holds.
	otherKey := nodeKey(t)
	r.mustEnroll(r.request(platform.NewID(), otherKey))
	if _, err := r.enroll(r.request(nodeID, otherKey)); key(err) != "CONFLICT/already_exists node_key/already_registered" {
		t.Fatalf("a rotation to a held key: %v", key(err))
	}

	// (d) The device revoked: the node row revoked with it; the node ID enrolls again only with a new key (the retired key is
	// credential_revoked).
	if err := r.db.Runtime.InTx(ctx, "revoke", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		cascade, err := device.Revoke(ctx, tx, r.user, first.DeviceID, device.RevokedByOwner, []device.Participant{NodeParticipant{}}, time.Now())
		if err == nil && cascade.Participants["fleet.node"] != 1 {
			t.Errorf("participant count %+v", cascade)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if r.count("SELECT count(*) FROM fleet.node WHERE enrollment_id = $1 AND revoke_reason = 1", first.EnrollmentID) != 1 {
		t.Fatal("the cascade left the node live")
	}
	if _, err := r.enroll(r.request(nodeID, rotatedKey)); key(err) != "AUTHENTICATION/credential_revoked" {
		t.Fatalf("a retired key: %v", key(err))
	}
	fresh := r.mustEnroll(r.request(nodeID, nodeKey(t)))
	if fresh.Reenrolled || fresh.EnrollmentID == first.EnrollmentID || fresh.DeviceID == first.DeviceID {
		t.Fatalf("enrollment after revocation %+v", fresh)
	}

	// (f) The cap: live nodes of the account, signed-out ones included.
	capped := newRig(t)
	capped.policy.MaxNodesPerAccount = 2
	signedOutID, signedOutKey := platform.NewID(), nodeKey(t)
	signedOut := capped.mustEnroll(capped.request(signedOutID, signedOutKey))
	capped.db.Exec("UPDATE identity.session SET revoked_at = now(), revoke_reason = 1 WHERE session_id = '" + signedOut.Session.SessionID.String() + "'")
	capped.mustEnroll(capped.request(platform.NewID(), nodeKey(t)))
	_, err := capped.enroll(capped.request(platform.NewID(), nodeKey(t)))
	var refusal *arc.Refusal
	if !errors.As(err, &refusal) || refusal.Key() != "RESOURCE/quota_exceeded" || refusal.Limit.Name != MaxNodesLimit || refusal.Limit.Maximum != 2 {
		t.Fatalf("the cap: %v", err)
	}
	// The cap refuses only a new node: the signed-out node signs in again in place.
	if back, err := capped.enroll(capped.request(signedOutID, signedOutKey)); err != nil || !back.Reenrolled {
		t.Fatalf("a re-enrollment at the cap: %+v %v", back, key(err))
	}
	if _, err = capped.enroll(capped.request(platform.NewID(), nil)); key(err) != "VALIDATION/invalid_argument node_public_key/node_public_key: not_p256" {
		t.Fatalf("no key: %v", key(err))
	}
}

// TestApprovalLapses pins the Enroll half of protocol-6 (rule 0 and the approving session): an approval lapses when the account is
// no longer Active (restricted, suspended), when the approving session was revoked by the account (2), by revoking all sessions (3),
// with its device (5) or by an operator (6), or when its authentication or recovery epoch moved; it stands when the approver signed
// out (1) or the session expired. A lapse writes nothing.
func TestApprovalLapses(t *testing.T) {
	r := newRig(t)
	writes := func() int {
		return r.count("SELECT (SELECT count(*) FROM fleet.node) + (SELECT count(*) FROM device.installation) + (SELECT count(*) FROM audit.audit_event)")
	}
	cases := map[string]struct {
		statement string
		lapses    bool
	}{
		"signed out":              {"UPDATE identity.session SET revoked_at = now(), revoke_reason = 1 WHERE session_id = $1", false},
		"expired":                 {"UPDATE identity.session SET expires_at = now() - interval '1 minute', idle_expires_at = now() - interval '1 minute', issued_at = now() - interval '2 hours', authenticated_at = now() - interval '2 hours' WHERE session_id = $1", false},
		"revoked by the account":  {"UPDATE identity.session SET revoked_at = now(), revoke_reason = 2 WHERE session_id = $1", true},
		"all sessions revoked":    {"UPDATE identity.session SET revoked_at = now(), revoke_reason = 3 WHERE session_id = $1", true},
		"device revoked":          {"UPDATE identity.session SET revoked_at = now(), revoke_reason = 5 WHERE session_id = $1", true},
		"operator":                {"UPDATE identity.session SET revoked_at = now(), revoke_reason = 6 WHERE session_id = $1", true},
		"an authentication epoch": {"UPDATE identity.session SET auth_epoch = auth_epoch + 1 WHERE session_id = $1", true},
		"a recovery generation":   {"UPDATE identity.session SET recovery_generation = recovery_generation + 1 WHERE session_id = $1", true},
		"a restricted account":    {"UPDATE identity.user SET state = 2 FROM identity.session s WHERE s.session_id = $1 AND identity.user.user_id = s.user_id", true},
		"a suspended account":     {"UPDATE identity.user SET state = 3 FROM identity.session s WHERE s.session_id = $1 AND identity.user.user_id = s.user_id", true},
	}
	for name, item := range cases {
		t.Run(name, func(t *testing.T) {
			user, approver := r.account(1)
			if _, err := r.db.Migration.Exec(context.Background(), item.statement, approver.ID); err != nil {
				t.Fatal(err)
			}
			request := r.request(platform.NewID(), nodeKey(t))
			request.UserID, request.Approver.SessionID = user, approver.ID
			before := writes()
			_, err := r.enroll(request)
			if item.lapses != (key(err) == "lapsed") || !item.lapses && err != nil {
				t.Fatalf("%v", key(err))
			}
			if item.lapses && writes() != before {
				t.Fatal("a lapsed enrollment wrote")
			}
		})
	}
	// A re-enrollment lapses too, and leaves the live credential as it was.
	nodeID, nodeKeyBytes := platform.NewID(), nodeKey(t)
	enrolled := r.mustEnroll(r.request(nodeID, nodeKeyBytes))
	r.db.Exec("UPDATE identity.session SET auth_epoch = auth_epoch + 1 WHERE session_id = '" + r.approver.ID.String() + "'")
	if _, err := r.enroll(r.request(nodeID, nodeKeyBytes)); key(err) != "lapsed" ||
		r.count("SELECT count(*) FROM identity.session WHERE session_id = $1 AND revoked_at IS NULL", enrolled.Session.SessionID) != 1 {
		t.Fatalf("a lapsed re-enrollment: %v", key(err))
	}
}
