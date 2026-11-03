// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The flows an enrollment comes from (the audit payload names it).
const (
	FlowPKCE   = "pkce"
	FlowDevice = "device"
)

// MaxNodesLimit is the limit name of the node cap's refusal (RESOURCE/quota_exceeded, Q5).
const MaxNodesLimit = "max_nodes_per_account"

// ErrApprovalLapsed is an enrollment whose approval no longer stands (protocol-6): the approving account is not Active, or the
// approving session was revoked by the account, by the revocation of all its sessions, of its device or by an operator, or an
// authentication or recovery epoch moved since the approval. Nothing was written; the caller ends the flow (EXPIRED) in a
// transaction of its own and answers STATE/expired.
var ErrApprovalLapsed = errors.New("the approval of the enrollment lapsed")

// Approver is the approving account's session as the approval recorded it.
type Approver struct {
	SessionID          platform.ID
	AuthMethod         int16
	AuthenticatedAt    time.Time
	AuthEpoch          int64
	RecoveryGeneration int64
}

// EnrollRequest is an approved sign-in that delivers a node credential: the approving account and session, the node as it described
// itself at the start of the flow, its public key and the flow kind.
type EnrollRequest struct {
	UserID        platform.ID
	Approver      Approver
	NodeID        platform.ID
	Node          NodeInfo
	PublicKey     []byte
	Flow          string
	CorrelationID *platform.ID
}

// Enrolled is the result: the node's enrollment, device and installation, its new node session (the tokens shown to the node once),
// the key version, whether it re-enrolled, and the center's published keys.
type Enrolled struct {
	EnrollmentID    platform.ID
	DeviceID        platform.ID
	InstallationID  platform.ID
	Session         session.Native
	KeyVersion      int64
	Reenrolled      bool
	CommandKeys     []platform.SigningKey
	EntitlementKeys []platform.SigningKey
}

// The approving session's revoke reasons that end its approvals: revoked by the account, all sessions revoked, device revoked,
// operator. A sign-out (1) and an expiry do not.
var lapsingReasons = map[int16]bool{session.RevokedByAccount: true, session.RevokedAll: true, session.RevokedDevice: true, session.RevokedOperator: true}

// Enroll is the one function that creates or re-uses a node's device, installation and fleet.node row, registers its key, supersedes
// its older credentials and issues its node session (CTR4-DES-06), in the caller's transaction (the flow's success transaction, which
// holds the flow row). Its rules, in this order:
//
//	(0) the approving account is Active (locked FOR UPDATE first);
//	(c) a node ID live in another account is CONFLICT/already_exists (state node, no resource);
//	(b) a node ID live in this account is re-enrolled in place: its device and installation are locked, the approving session is
//	    checked, the installation's live sessions are revoked as superseded, its name, version and architecture are updated, a key
//	    that differs replaces the stored one at the next key version, and the device is renamed only while it still bears the name
//	    the node reported before (Q20);
//	(a)/(d) a node ID with no live row gets a new device, installation and node row, after the node cap (live nodes of the account,
//	    signed-out ones included) admits one more;
//	(e) a key an installation holds (other than the one re-used by (b)) is refused: held by a live installation, CONFLICT/already_exists
//	    (state node_key, reason already_registered); held by a revoked one (the key was retired), AUTHENTICATION/credential_revoked.
//
// A device revoked between the unlocked read and its lock is resolved again as (d), so its revoked installation's key answers (e).
// The approving session is locked FOR SHARE in the session slot of the global order; a lapse returns ErrApprovalLapsed. The event
// fleet.node.enrolled is the last statement. A concurrent enrollment of the same node ID or key is store contention (the identical
// retry answers the rule that then applies).
func Enroll(ctx context.Context, tx pgx.Tx, policy config.IdentityPolicy, request EnrollRequest, now time.Time) (Enrolled, error) {
	now = now.UTC().Truncate(time.Microsecond)
	if !ValidNodeKey(request.PublicKey) {
		return Enrolled{}, arc.InvalidArgument("node_public_key", "not_p256")
	}
	if request.Flow != FlowPKCE && request.Flow != FlowDevice {
		return Enrolled{}, errors.New("fleet: an enrollment names its flow")
	}
	// (0) The account, first in the order.
	var state int16
	err := tx.QueryRow(ctx, "SELECT state FROM identity.user WHERE user_id = $1 FOR UPDATE", request.UserID).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && state != 1 {
		return Enrolled{}, ErrApprovalLapsed
	}
	if err != nil {
		return Enrolled{}, store.Sanitize("lock the approving account", err)
	}
	var live struct {
		enrollmentID, userID, deviceID, installationID platform.ID
	}
	err = tx.QueryRow(ctx, "SELECT enrollment_id, user_id, device_id, installation_id FROM fleet.node WHERE node_id = $1 AND revoked_at IS NULL",
		request.NodeID).Scan(&live.enrollmentID, &live.userID, &live.deviceID, &live.installationID)
	found := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Enrolled{}, store.Sanitize("find the node", err)
	}
	if found && live.userID != request.UserID {
		return Enrolled{}, arc.AlreadyExists("node", nil)
	}
	if found {
		var locked bool
		if err = tx.QueryRow(ctx, "SELECT true FROM device.device WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL FOR UPDATE",
			live.deviceID, request.UserID).Scan(&locked); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return Enrolled{}, store.Sanitize("lock the node's device", err)
		}
		if locked {
			return reenroll(ctx, tx, policy, request, live.enrollmentID, live.deviceID, live.installationID, now)
		}
		// The device was revoked after the read: its cascade revoked the node row, so the node ID has no live row now.
	}
	return enrollNew(ctx, tx, policy, request, now)
}

// keyHolder answers rule (e) for a key: nil when no installation other than except holds it.
func keyHolder(ctx context.Context, tx pgx.Tx, key []byte, except *platform.ID) error {
	var holder platform.ID
	var revoked bool
	err := tx.QueryRow(ctx, "SELECT installation_id, revoked_at IS NOT NULL FROM device.installation WHERE public_key = $1", key).Scan(&holder, &revoked)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil
	case err != nil:
		return store.Sanitize("find the key's holder", err)
	case except != nil && holder == *except:
		return nil
	case revoked:
		return arc.CredentialRevoked()
	}
	return arc.KeyAlreadyRegistered()
}

// approvalStands locks the approving session FOR SHARE (the session slot of the global order) and reports whether the approval still
// stands: not revoked by a lapsing reason, at the epochs of the approval.
func approvalStands(ctx context.Context, tx pgx.Tx, request EnrollRequest) error {
	var reason *int16
	var epoch, recovery int64
	err := tx.QueryRow(ctx, `SELECT revoke_reason, auth_epoch, recovery_generation FROM identity.session WHERE session_id = $1 AND user_id = $2
FOR SHARE`, request.Approver.SessionID, request.UserID).Scan(&reason, &epoch, &recovery)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrApprovalLapsed
	}
	if err != nil {
		return store.Sanitize("lock the approving session", err)
	}
	if reason != nil && lapsingReasons[*reason] || epoch != request.Approver.AuthEpoch || recovery != request.Approver.RecoveryGeneration {
		return ErrApprovalLapsed
	}
	return nil
}

func reenroll(ctx context.Context, tx pgx.Tx, policy config.IdentityPolicy, request EnrollRequest, enrollmentID, deviceID, installationID platform.ID,
	now time.Time) (Enrolled, error) {
	var storedKey []byte
	var keyVersion int64
	err := tx.QueryRow(ctx, "SELECT public_key, key_version FROM device.installation WHERE installation_id = $1 AND revoked_at IS NULL FOR UPDATE",
		installationID).Scan(&storedKey, &keyVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return Enrolled{}, &store.Error{Operation: "lock the node's installation", Kind: store.ErrContention}
	}
	if err != nil {
		return Enrolled{}, store.Sanitize("lock the node's installation", err)
	}
	if string(storedKey) != string(request.PublicKey) {
		if err = keyHolder(ctx, tx, request.PublicKey, &installationID); err != nil {
			return Enrolled{}, err
		}
		keyVersion++
	}
	if err = approvalStands(ctx, tx, request); err != nil {
		return Enrolled{}, err
	}
	if _, err = tx.Exec(ctx, "UPDATE identity.session SET revoked_at = $2, revoke_reason = $3, rev = rev + 1 WHERE installation_id = $1 AND revoked_at IS NULL",
		installationID, now, session.RevokedSuperseded); err != nil {
		return Enrolled{}, store.Sanitize("supersede the node's sessions", err)
	}
	var owner, onDevice platform.ID
	var reportedName string
	var os int16
	var stillLive bool
	err = tx.QueryRow(ctx, "SELECT user_id, device_id, display_name, os, revoked_at IS NULL FROM fleet.node WHERE enrollment_id = $1 FOR UPDATE", enrollmentID).
		Scan(&owner, &onDevice, &reportedName, &os, &stillLive)
	if err != nil || !stillLive || owner != request.UserID || onDevice != deviceID {
		return Enrolled{}, &store.Error{Operation: "lock the node", Kind: store.ErrContention}
	}
	// A node ID on another operating system is another machine: it signs in under a node ID of its own.
	if os != request.Node.Platform.OS {
		return Enrolled{}, arc.InvalidArgument("node.os", "mismatch")
	}
	if _, err = tx.Exec(ctx, `UPDATE device.installation SET public_key = $2, key_version = $3, app_version = $4, last_active_at = greatest(last_active_at, $5),
    rev = rev + 1 WHERE installation_id = $1`, installationID, request.PublicKey, keyVersion, request.Node.Version, now); err != nil {
		return Enrolled{}, keyContention("re-key the node's installation", err)
	}
	if _, err = tx.Exec(ctx, `UPDATE device.device SET display_name = $3, rev = rev + 1 WHERE device_id = $1 AND display_name = $2 AND display_name <> $3`,
		deviceID, reportedName, request.Node.Name); err != nil {
		return Enrolled{}, store.Sanitize("rename the node's device", err)
	}
	if _, err = tx.Exec(ctx, "UPDATE device.device SET last_seen_at = greatest(last_seen_at, $2), rev = rev + 1 WHERE device_id = $1", deviceID, now); err != nil {
		return Enrolled{}, store.Sanitize("touch the node's device", err)
	}
	if _, err = tx.Exec(ctx, `UPDATE fleet.node SET display_name = $2, arch = $3, version = $4, last_seen_at = greatest(last_seen_at, $5), rev = rev + 1
WHERE enrollment_id = $1`, enrollmentID, request.Node.Name, request.Node.Arch, request.Node.Version, now); err != nil {
		return Enrolled{}, store.Sanitize("update the node", err)
	}
	return issue(ctx, tx, policy, request, Enrolled{EnrollmentID: enrollmentID, DeviceID: deviceID, InstallationID: installationID, KeyVersion: keyVersion,
		Reenrolled: true}, now)
}

func enrollNew(ctx context.Context, tx pgx.Tx, policy config.IdentityPolicy, request EnrollRequest, now time.Time) (Enrolled, error) {
	if err := keyHolder(ctx, tx, request.PublicKey, nil); err != nil {
		return Enrolled{}, err
	}
	var nodes int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM fleet.node WHERE user_id = $1 AND revoked_at IS NULL", request.UserID).Scan(&nodes); err != nil {
		return Enrolled{}, store.Sanitize("count the account's nodes", err)
	}
	if nodes >= policy.MaxNodesPerAccount {
		return Enrolled{}, arc.QuotaExceeded(MaxNodesLimit, int64(policy.MaxNodesPerAccount))
	}
	deviceID, installationID, err := device.CreateNode(ctx, tx, device.Node{UserID: request.UserID, Name: request.Node.Name, Platform: request.Node.Platform.Device,
		PlatformText: request.Node.Platform.Text, AppVersion: request.Node.Version, PublicKey: request.PublicKey}, now)
	if err != nil {
		return Enrolled{}, err
	}
	if err = approvalStands(ctx, tx, request); err != nil {
		return Enrolled{}, err
	}
	enrollmentID := platform.NewID()
	if _, err = tx.Exec(ctx, `INSERT INTO fleet.node (enrollment_id, node_id, user_id, device_id, installation_id, display_name, os, arch, version, enrolled_at,
    last_seen_at, rev) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, 1)`, enrollmentID, request.NodeID, request.UserID, deviceID, installationID,
		request.Node.Name, request.Node.Platform.OS, request.Node.Arch, request.Node.Version, now); err != nil {
		return Enrolled{}, keyContention("create the node", err)
	}
	return issue(ctx, tx, policy, request, Enrolled{EnrollmentID: enrollmentID, DeviceID: deviceID, InstallationID: installationID, KeyVersion: 1}, now)
}

// keyContention answers a unique-index refusal of a concurrent enrollment (the live node ID, the key) as store contention.
func keyContention(operation string, err error) error {
	if errors.Is(store.Sanitize(operation, err), store.ErrConflict) {
		return &store.Error{Operation: operation, SQLState: "23505", Kind: store.ErrContention}
	}
	return store.Sanitize(operation, err)
}

// issue issues the node session, reads the published keys and appends fleet.node.enrolled, the last statement.
func issue(ctx context.Context, tx pgx.Tx, policy config.IdentityPolicy, request EnrollRequest, enrolled Enrolled, now time.Time) (Enrolled, error) {
	var err error
	if enrolled.Session, err = session.IssueNative(ctx, tx, policy, session.Grant{UserID: request.UserID, DeviceID: enrolled.DeviceID,
		InstallationID: enrolled.InstallationID, Scope: session.ScopeNode, Product: "arcforges-node", Purpose: session.PurposeAuthenticate,
		AuthMethod: request.Approver.AuthMethod, AuthenticatedAt: request.Approver.AuthenticatedAt}, now); err != nil {
		return Enrolled{}, err
	}
	if enrolled.CommandKeys, err = platform.PublishedKeys(ctx, tx, platform.CommandSigning, now); err != nil {
		return Enrolled{}, err
	}
	if enrolled.EntitlementKeys, err = platform.PublishedKeys(ctx, tx, platform.EntitlementToken, now); err != nil {
		return Enrolled{}, err
	}
	kind := "first"
	if enrolled.Reenrolled {
		kind = "reenrolled"
	}
	payload, err := json.Marshal(map[string]any{"nodeId": request.NodeID.String(), "os": OSName(request.Node.Platform.OS), "arch": ArchName(request.Node.Arch),
		"version": request.Node.Version, "keyFingerprint": Fingerprint(request.PublicKey), "flow": request.Flow, "enrollment": kind, "keyVersion": enrolled.KeyVersion})
	if err != nil {
		return Enrolled{}, err
	}
	if _, err = platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: now, ActorRef: "account:" + request.UserID.String(),
		EventType: "fleet.node.enrolled", Reason: kind, CorrelationID: request.CorrelationID, TargetKind: "node", TargetID: enrolled.EnrollmentID.String(),
		Payload: payload}); err != nil {
		return Enrolled{}, err
	}
	return enrolled, nil
}
