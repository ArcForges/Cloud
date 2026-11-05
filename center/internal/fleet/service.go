// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/ratelimit"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// Events counts the fleet surface's outcomes (observe.Metrics.ObserveFleet: closed labels).
type Events interface {
	ObserveFleet(event, outcome string)
}

type noEvents struct{}

func (noEvents) ObserveFleet(string, string) {}

// Service is the node side of the fleet surface: a node's refresh, report and sign-out. Every refusal it returns is an *arc.Refusal;
// any other error is a store failure.
//
// Transactions per request (docs/postgres-store.md): RefreshNodeSession reads what its token names (one point read, no transaction
// held), counts one bucket in its own short transaction (the per-session bucket for a current token, the prefix failure bucket for a
// token that names nothing; a spent token counts in neither, so its reuse always runs), then rotates in one transaction that also
// marks the node seen and reads the published keys. ReportNodeInfo counts its installation's bucket, then runs under its command
// receipt. SignOutNode runs under its command receipt. The device-code sign-in's transactions: StartDeviceAuthorization counts its
// buckets (own short transactions) and inserts (with the supersession) in one transaction; LookupDeviceCode reserves its entry (two
// short transactions) and reviews in one auxiliary transaction that gives the entry back; ApproveDeviceCode counts its decision,
// reserves its entry and decides in its receipt's transaction (a refusal of a reviewed code gives the entry back in a transaction of
// its own); PollDeviceAuthorization reads the authorization (no transaction held), counts a bucket, then records the poll (auxiliary)
// or delivers or records the reuse (an effect) in one transaction.
type Service struct {
	// attempts bounds the refresh rotation's retries (Options.RefreshAttempts), signInAttempts the sign-in transactions'.
	attempts       int
	signInAttempts int
	db             *store.DB
	policy         config.IdentityPolicy
	limits         *ratelimit.Limiter
	clock          func() time.Time
	events         Events
	logger         *slog.Logger
	// publicBaseURL is the center's public base URL: the base of the URLs it derives for a node and the audience of a node key proof.
	publicBaseURL string
	// userCodes draws a device authorization's user code (NewUserCode; the package's collision test replaces it).
	userCodes func() string
}

// Options configure a Service.
type Options struct {
	DB     *store.DB
	Policy config.IdentityPolicy
	Clock  func() time.Time
	Events Events
	Logger *slog.Logger
	// RefreshAttempts bounds the refresh rotation's retries of a deadlock or serialization failure; 0 is the store's default. The
	// race tests set 1, so a deadlock fails them.
	RefreshAttempts int
	// PublicBaseURL is the center's canonical public base URL (config.Config.PublicBaseURL): the sign-in builds the consent URL from
	// it and verifies a node key proof with its SHA-256 as the audience, never with a request's Host or Origin.
	PublicBaseURL string
	// SignInAttempts bounds the retries of the sign-in transactions (the supersession and insert of a Begin, a decision, a
	// completion) on a deadlock or serialization failure; 0 is the store's default. The race tests set 1.
	SignInAttempts int
}

// New is the fleet service of a store.
func New(options Options) *Service {
	service := &Service{attempts: options.RefreshAttempts, db: options.DB, policy: options.Policy, limits: ratelimit.New(options.DB), clock: options.Clock, events: options.Events,
		logger: options.Logger, publicBaseURL: options.PublicBaseURL, signInAttempts: options.SignInAttempts}
	service.userCodes = NewUserCode
	if service.clock == nil {
		service.clock = time.Now
	}
	if service.events == nil {
		service.events = noEvents{}
	}
	if service.logger == nil {
		service.logger = slog.New(slog.DiscardHandler)
	}
	return service
}

// Policy is the service's identity policy (the node keys are part of it).
func (s *Service) Policy() config.IdentityPolicy { return s.policy }

func (s *Service) now() time.Time { return s.clock().UTC().Truncate(time.Microsecond) }

// Request is what the transport knows of a call: the client address and the correlation id.
type Request struct {
	ClientIP      netip.Addr
	CorrelationID *platform.ID
	// Origin is where the request came from as the hosted edge saw it (Begin and Start record it for the review pages); the zero
	// value is "unknown", which is every self-hosted center's.
	Origin Origin
}

// Origin is the coarse origin of a node's Begin or Start (protocol-17): the two-letter country code and the autonomous system number
// Cloudflare reports for the request, forwarded by the hosted Worker only (a self-hosted center never reads them). Either may be
// unknown; the review pages say "Origin unknown" when the country is.
type Origin struct {
	Country *string
	ASN     *int64
}

// Anonymous is the actor of a call without an account (a refresh).
const Anonymous = "anonymous"

// NodeActor is the actor and receipt principal of a node credential: its installation.
func NodeActor(installationID platform.ID) string { return "node:" + installationID.String() }

func (s *Service) bucket(kind ratelimit.Kind, key string) ratelimit.Bucket {
	return ratelimit.Bucket{Kind: kind, Key: key, Window: ratelimit.Window(s.policy, kind)}
}

// limited answers a refused bucket: RESOURCE/rate_limited, the first refusal of a window audited identity.rate_limited.
func (s *Service) limited(ctx context.Context, request Request, bucket ratelimit.Bucket, decision ratelimit.Decision, event, actor string) error {
	s.events.ObserveFleet(event, "rate_limited")
	if decision.First {
		if err := s.auditAlone(ctx, request, actor, "identity.rate_limited", string(bucket.Kind), map[string]any{"bucket": string(bucket.Kind)}); err != nil {
			return err
		}
	}
	return decision.Refusal(bucket)
}

func (s *Service) auditAlone(ctx context.Context, request Request, actor, eventType, reason string, payload map[string]any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return s.db.InTx(ctx, "audit a fleet refusal", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: s.now(), ActorRef: actor, EventType: eventType,
			Reason: reason, CorrelationID: request.CorrelationID, Payload: data})
		return err
	})
}

// Refreshed is a rotated node session with the center's published keys.
type Refreshed struct {
	Session         session.Native
	CommandKeys     []platform.SigningKey
	EntitlementKeys []platform.SigningKey
}

// MaxTokenLength bounds a presented refresh token before anything reads it.
const MaxTokenLength = 8192

// Refresh rotates a node session (RefreshNodeSession; CRD-04, protocol-8). The token is looked up first: a token that names nothing
// (malformed or unknown) is answered RESOURCE/rate_limited when its client prefix's failure bucket holds its limit, and otherwise
// counted in that bucket and answered AUTHENTICATION/unauthenticated, while a token that names a session never waits on that bucket (a neighbour's
// junk cannot lock a network's nodes out). A session's current token is counted in its own bucket; a spent token is never limited, so
// its reuse always revokes the family. The rotation is strict (session.Refresh with the node admission): no grace window, a spent
// token revokes the family (credential_revoked), a live account token is AUTHORIZATION/permission_denied. In the rotating transaction
// the node row is marked seen; a session whose installation has no live node row is credential_revoked and the rotation rolls back.
func (s *Service) Refresh(ctx context.Context, request Request, token string) (Refreshed, error) {
	if token == "" || len(token) > MaxTokenLength {
		return Refreshed{}, arc.InvalidArgument("refresh_token", "length")
	}
	presented, err := session.Lookup(ctx, s.db.Pool(), token)
	if err != nil {
		return Refreshed{}, err
	}
	switch {
	case !presented.Known():
		// N-2: the prefix's failure bucket is checked (refused once it holds its limit, with nothing written), and only an admitted
		// call counts its failure; the failure that fills the window is audited identity.rate_limited, once per window.
		bucket := s.bucket(ratelimit.NodeRefreshPrefix, ratelimit.Prefix(request.ClientIP))
		decision, err := s.limits.Check(ctx, bucket, s.now())
		if err != nil {
			return Refreshed{}, err
		}
		if !decision.Allowed {
			s.events.ObserveFleet("refresh", "rate_limited")
			return Refreshed{}, decision.Refusal(bucket)
		}
		if decision, err = s.limits.Fail(ctx, bucket, s.now()); err != nil {
			return Refreshed{}, err
		}
		if decision.Count == bucket.Window.Limit {
			if err = s.auditAlone(ctx, request, Anonymous, "identity.rate_limited", string(bucket.Kind), map[string]any{"bucket": string(bucket.Kind)}); err != nil {
				return Refreshed{}, err
			}
		}
		s.events.ObserveFleet("refresh", "refused")
		return Refreshed{}, arc.Unauthenticated()
	case presented.Current != nil:
		bucket := s.bucket(ratelimit.NodeRefreshSession, presented.Current.String())
		decision, err := s.limits.Take(ctx, bucket, s.now())
		if err != nil {
			return Refreshed{}, err
		}
		if !decision.Allowed {
			return Refreshed{}, s.limited(ctx, request, bucket, decision, "refresh", Anonymous)
		}
	}
	var refreshed Refreshed
	now := s.now()
	admission := session.NodeRefresh()
	admission.Attempts = s.attempts
	issued, reuse, err := session.Refresh(ctx, s.db, s.policy, token, admission, now, request.CorrelationID,
		func(ctx context.Context, tx pgx.Tx, issued session.Native) error {
			tag, err := tx.Exec(ctx, `UPDATE fleet.node SET last_seen_at = greatest(last_seen_at, $2), rev = rev + 1
WHERE installation_id = (SELECT installation_id FROM identity.session WHERE session_id = $1) AND revoked_at IS NULL`, issued.SessionID, now)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return arc.CredentialRevoked()
			}
			if refreshed.CommandKeys, err = platform.PublishedKeys(ctx, tx, platform.CommandSigning, now); err != nil {
				return err
			}
			refreshed.EntitlementKeys, err = platform.PublishedKeys(ctx, tx, platform.EntitlementToken, now)
			return err
		})
	switch {
	case reuse != nil:
		s.events.ObserveFleet("refresh", "reused")
	case err != nil:
		var refusal *arc.Refusal
		if errors.As(err, &refusal) {
			s.events.ObserveFleet("refresh", "refused")
		}
	default:
		s.events.ObserveFleet("refresh", "rotated")
	}
	if err != nil {
		return Refreshed{}, err
	}
	refreshed.Session = issued
	return refreshed, nil
}

// Node is the caller of a node-credential method: its account, session and installation.
type Node struct {
	UserID         platform.ID
	SessionID      platform.ID
	InstallationID platform.ID
}

// TakeReport counts a node installation's reports (node_report_installation) before the receipt; over the limit it is
// RESOURCE/rate_limited.
func (s *Service) TakeReport(ctx context.Context, request Request, node Node) error {
	bucket := s.bucket(ratelimit.NodeReportInstallation, node.InstallationID.String())
	decision, err := s.limits.Take(ctx, bucket, s.now())
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return s.limited(ctx, request, bucket, decision, "report", NodeActor(node.InstallationID))
	}
	return nil
}

// liveNode reads the live node row of an installation without a lock; none is AUTHENTICATION/unauthenticated (C0 E-14).
func liveNode(ctx context.Context, tx pgx.Tx, installationID platform.ID) (row struct {
	enrollmentID, nodeID, deviceID platform.ID
	name, version                  string
	os, arch                       int16
}, err error) {
	err = tx.QueryRow(ctx, `SELECT enrollment_id, node_id, device_id, display_name, version, os, arch FROM fleet.node
WHERE installation_id = $1 AND revoked_at IS NULL`, installationID).Scan(&row.enrollmentID, &row.nodeID, &row.deviceID, &row.name, &row.version, &row.os, &row.arch)
	if errors.Is(err, pgx.ErrNoRows) {
		return row, arc.Unauthenticated()
	}
	return row, store.Sanitize("find the caller's node", err)
}

// Report records what a node reports about itself (ReportNodeInfo; CRD-05) in the caller's receipt transaction: the node ID must be
// the credential's (else node.node_id: mismatch), its OS cannot change (node.os: mismatch: another OS is another machine), and a
// changed name, architecture or canonical version updates the node row and the installation's version; the device takes the new name
// only while it still bears the name the node reported before (a name the account gave it wins; Q20). The node is always marked
// seen; fleet.node.info_reported is audited only when something changed. Locks: the device only when renaming, then the
// installation, then the node row (the global order).
func (s *Service) Report(ctx context.Context, tx pgx.Tx, request Request, node Node, nodeID platform.ID, info NodeInfo, now time.Time) (bool, error) {
	row, err := liveNode(ctx, tx, node.InstallationID)
	if err != nil {
		return false, err
	}
	switch {
	case row.nodeID != nodeID:
		return false, arc.InvalidArgument("node.node_id", "mismatch")
	case row.os != info.Platform.OS:
		return false, arc.InvalidArgument("node.os", "mismatch")
	}
	renaming := row.name != info.Name
	if renaming {
		if _, err = tx.Exec(ctx, "SELECT 1 FROM device.device WHERE device_id = $1 FOR UPDATE", row.deviceID); err != nil {
			return false, store.Sanitize("lock the node's device", err)
		}
	}
	if _, err = tx.Exec(ctx, "SELECT 1 FROM device.installation WHERE installation_id = $1 FOR UPDATE", node.InstallationID); err != nil {
		return false, store.Sanitize("lock the node's installation", err)
	}
	var current struct {
		name, version string
		arch          int16
		live          bool
	}
	if err = tx.QueryRow(ctx, "SELECT display_name, version, arch, revoked_at IS NULL FROM fleet.node WHERE enrollment_id = $1 FOR UPDATE", row.enrollmentID).
		Scan(&current.name, &current.version, &current.arch, &current.live); err != nil {
		return false, store.Sanitize("lock the node", err)
	}
	if !current.live || current.name != row.name {
		// A concurrent report or revocation changed the row after the read: the identical retry decides again.
		return false, &store.Error{Operation: "lock the node", Kind: store.ErrContention}
	}
	var changed []string
	if current.name != info.Name {
		changed = append(changed, "name")
	}
	if current.arch != info.Arch {
		changed = append(changed, "arch")
	}
	if current.version != info.Version {
		changed = append(changed, "version")
		if _, err = tx.Exec(ctx, "UPDATE device.installation SET app_version = $2, last_active_at = greatest(last_active_at, $3), rev = rev + 1 WHERE installation_id = $1",
			node.InstallationID, info.Version, now); err != nil {
			return false, store.Sanitize("update the node's version", err)
		}
	}
	if renaming {
		if _, err = tx.Exec(ctx, "UPDATE device.device SET display_name = $3, rev = rev + 1 WHERE device_id = $1 AND display_name = $2", row.deviceID, row.name,
			info.Name); err != nil {
			return false, store.Sanitize("rename the node's device", err)
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE fleet.node SET display_name = $2, arch = $3, version = $4, last_seen_at = greatest(last_seen_at, $5), rev = rev + 1
WHERE enrollment_id = $1`, row.enrollmentID, info.Name, info.Arch, info.Version, now); err != nil {
		return false, store.Sanitize("update the node", err)
	}
	if len(changed) == 0 {
		s.events.ObserveFleet("report", "unchanged")
		return false, nil
	}
	if err = s.audit(ctx, tx, request, NodeActor(node.InstallationID), "fleet.node.info_reported", "reported", row.enrollmentID,
		map[string]any{"changed": changed, "version": info.Version}, now); err != nil {
		return false, err
	}
	s.events.ObserveFleet("report", "changed")
	return true, nil
}

// SignOut signs a node out (SignOutNode; CRD-06) in the caller's receipt transaction: the calling node credential is revoked (signed
// out), while its device, installation and node row stay, so the node may sign in again in place. A credential whose installation
// has no live node row is AUTHENTICATION/unauthenticated (C0 E-14). A retry after the revocation is refused by the ingress
// (credential_revoked) before any receipt is read.
func (s *Service) SignOut(ctx context.Context, tx pgx.Tx, request Request, node Node, now time.Time) error {
	row, err := liveNode(ctx, tx, node.InstallationID)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, "UPDATE identity.session SET revoked_at = $2, revoke_reason = $3, rev = rev + 1 WHERE session_id = $1 AND revoked_at IS NULL",
		node.SessionID, now, session.RevokedSignedOut)
	if err != nil {
		return store.Sanitize("sign the node out", err)
	}
	if tag.RowsAffected() != 1 {
		return arc.CredentialRevoked()
	}
	// The node's channel closes once this transaction commits (AF-CTR-05 E1a, CTR5-HUB-08).
	session.Announce(ctx, session.Revocation{Sessions: []platform.ID{node.SessionID}})
	if err = s.audit(ctx, tx, request, NodeActor(node.InstallationID), "fleet.node.signed_out", "signed_out", row.enrollmentID,
		map[string]any{"nodeId": row.nodeID.String()}, now); err != nil {
		return err
	}
	s.events.ObserveFleet("sign_out", "signed_out")
	return nil
}

// audit appends a fleet event in the caller's transaction, its last statement.
func (s *Service) audit(ctx context.Context, tx pgx.Tx, request Request, actor, eventType, reason string, enrollmentID platform.ID, payload map[string]any,
	now time.Time) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: now, ActorRef: actor, EventType: eventType, Reason: reason,
		CorrelationID: request.CorrelationID, TargetKind: "node", TargetID: enrollmentID.String(), Payload: data})
	return err
}

// NodeCredentialExpiries are, for the account's live node devices, when the live node credential of each ends at the latest (its
// identity.session expires_at, the absolute lifetime): the devices page shows it (Q4's device-list expiry, AF-CTR-04 E3). A device
// without a live node session has no entry. It is one read, without a lock.
func NodeCredentialExpiries(ctx context.Context, db *store.DB, userID platform.ID) (map[platform.ID]time.Time, error) {
	rows, err := db.Pool().Query(ctx, `SELECT n.device_id, max(s.expires_at) FROM fleet.node n JOIN identity.session s ON s.installation_id = n.installation_id
WHERE n.user_id = $1 AND n.revoked_at IS NULL AND s.user_id = $1 AND s.scope = 3 AND s.revoked_at IS NULL GROUP BY n.device_id`, userID)
	if err != nil {
		return nil, store.Sanitize("read the node credentials' expiry", err)
	}
	result := map[platform.ID]time.Time{}
	for rows.Next() {
		var device platform.ID
		var expires time.Time
		if err = rows.Scan(&device, &expires); err != nil {
			rows.Close()
			return nil, store.Sanitize("read the node credentials' expiry", err)
		}
		result[device] = expires
	}
	if err = rows.Err(); err != nil {
		return nil, store.Sanitize("read the node credentials' expiry", err)
	}
	return result, nil
}
