// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/oneuse"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/ratelimit"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The device-code sign-in (AF-CTR-04 part E2, CTR4-DEV-01..09 as amended by Q8, protocol-8, protocol-9, protocol-19, contracts-9,
// cloud-5, cloud-10 and the C0 comments of fleet.proto). A headless node starts an authorization anonymously and shows its user code;
// an account looks the code up (LookupDeviceCode, the review; the /activate page calls these functions in process) and
// approves it (ApproveDeviceCode, with step-up evidence bound to the normalized user code) or denies it; the node polls with its device
// code and a proof by its node key and receives its node credentials from fleet.Enroll. A caller that holds the device code but not
// the node key learns nothing of the authorization's state and writes nothing to it: every poll whose proof fails is
// AUTHENTICATION/unauthenticated (it tells only that the code is stored) and counts only in its own network's failure bucket.

// The contract values of the device-code sign-in (C0: DeviceAuthorization.interval_ms "5,000; grows by 5,000 on SLOW_DOWN",
// expires_at "600 s"; LookupDeviceCode "5 lookups per live code"). They are no policy keys: a key would make the contract's comments
// false. MaxDeviceInterval is the center's cap of the growth (0004's interval_ms CHECK 1000..60000).
const (
	DeviceInterval              = 5000 * time.Millisecond
	DeviceIntervalStep          = 5000 * time.Millisecond
	MaxDeviceInterval           = 60000 * time.Millisecond
	DeviceAuthorizationLifetime = 600 * time.Second
	MaxLookups                  = 5
)

// EarlyPollTolerance is how much earlier than its interval a poll may come before it is answered SLOW_DOWN (CTR4-DEV-03).
const EarlyPollTolerance = 500 * time.Millisecond

// userCodeDraws bounds the user codes a Start draws before it gives up on a live-code collision (RESOURCE/overloaded).
const userCodeDraws = 5

// ClassApproveDeviceCode is the step-up class of an approval (C0 Q1): the operation ID of ApproveDeviceCode, bound to the normalized
// user code (identity.TextTargetHash).
const ClassApproveDeviceCode = "fleet.approveDeviceCode"

// AuthorizationKind is the object kind of a device authorization (state.state of its refusals, the audit target kind).
const AuthorizationKind = "device_authorization"

// LookupsLimit is the limit name of a live code's sixth lookup (C0: "limit.limit_name device_code_lookups, limit.available 0").
const LookupsLimit = "device_code_lookups"

// The states of a device authorization (arcforges.fleet.v1.DeviceAuthorizationState; fleet.device_authorization.state). SLOW_DOWN is
// a poll response only, never stored.
const (
	AuthorizationPending   int16 = 1
	AuthorizationSlowDown  int16 = 2
	AuthorizationApproved  int16 = 3
	AuthorizationDenied    int16 = 4
	AuthorizationExpired   int16 = 5
	AuthorizationCompleted int16 = 6
)

// authorizationStateName is the lower-case name of an authorization state (STATE/invalid_state reason).
func authorizationStateName(state int16) string {
	switch state {
	case AuthorizationPending:
		return "pending"
	case AuthorizationApproved:
		return "approved"
	case AuthorizationDenied:
		return "denied"
	case AuthorizationExpired:
		return "expired"
	case AuthorizationCompleted:
		return "completed"
	}
	return "unspecified"
}

// StartRequest is a validated StartDeviceAuthorization.
type StartRequest struct {
	NodeID    platform.ID
	Node      NodeInfo
	PublicKey []byte
}

// ParseStart validates a StartDeviceAuthorization field by field, in this order, before anything is counted or read
// (VALIDATION/invalid_argument names the first field that fails): node (required), node.node_id (16 bytes, not all zero), the node's
// description (ParseNodeInfo) and node_public_key (the 91-byte PKIX DER of a P-256 key).
func ParseStart(message *fleetv1.NodeEnrollmentServiceStartDeviceAuthorizationRequest) (StartRequest, error) {
	if message.GetNode() == nil {
		return StartRequest{}, arc.InvalidArgument("node", "required")
	}
	nodeID, ok := parseNodeID(message.GetNode().GetNodeId().GetValue())
	if !ok {
		return StartRequest{}, arc.InvalidArgument("node.node_id", "required")
	}
	info, err := ParseNodeInfo(message.GetNode())
	if err != nil {
		return StartRequest{}, err
	}
	switch {
	case len(message.GetNodePublicKey()) == 0:
		return StartRequest{}, arc.InvalidArgument("node_public_key", "required")
	case !ValidNodeKey(message.GetNodePublicKey()):
		return StartRequest{}, arc.InvalidArgument("node_public_key", "not_p256")
	}
	return StartRequest{NodeID: nodeID, Node: info, PublicKey: append([]byte(nil), message.GetNodePublicKey()...)}, nil
}

// Started is a started authorization: the device code and the user code (each shown once), the URIs the node shows, the poll
// interval and the expiry.
type Started struct {
	AuthorizationID         platform.ID
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	Interval                time.Duration
	ExpiresAt               time.Time
}

// VerificationURI is the activation page: <public base URL>/activate (C0; the node derives the same string and requires a match).
func VerificationURI(publicBaseURL string) string { return publicBaseURL + "/activate" }

// VerificationURIComplete is the activation page with the code in its fragment: <public base URL>/activate#code=XXXX-XXXX.
func VerificationURIComplete(publicBaseURL, userCode string) string {
	return publicBaseURL + "/activate#code=" + DisplayUserCode(userCode)
}

// Start starts a device-code sign-in (StartDeviceAuthorization): the client prefix's and the node ID's buckets, which Begin counts
// too (and the opt-in anonymous-flow ceiling), are counted; a key that an installation holds or held is refused before approval
// (CONFLICT/already_exists, node_key / already_registered); the node ID's PENDING authorizations that present the same key expire
// (locked in authorization ID order); the new authorization is PENDING for 600 seconds with a 5-second interval. Its user code is
// held by no other PENDING or APPROVED authorization (a collision draws again, five times at most, then RESOURCE/overloaded).
// meta.command_id is correlation only: every call starts a new authorization.
func (s *Service) Start(ctx context.Context, request Request, in StartRequest) (Started, error) {
	buckets := []ratelimit.Bucket{s.bucket(ratelimit.NodeFlowPrefix, ratelimit.Prefix(request.ClientIP)), s.bucket(ratelimit.NodeFlowNode, in.NodeID.String())}
	if s.policy.AnonymousFlows.Limit > 0 {
		buckets = append(buckets, s.bucket(ratelimit.AnonymousFlows, "all"))
	}
	for _, bucket := range buckets {
		decision, err := s.limits.Take(ctx, bucket, s.now())
		if err != nil {
			return Started{}, err
		}
		if !decision.Allowed {
			return Started{}, s.limited(ctx, request, bucket, decision, "start", Anonymous)
		}
	}
	var held bool
	if err := s.db.Pool().QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM device.installation WHERE public_key = $1)", in.PublicKey).Scan(&held); err != nil {
		return Started{}, store.Sanitize("find the key's holder", err)
	}
	if held {
		s.events.ObserveFleet("start", "refused")
		return Started{}, arc.KeyAlreadyRegistered()
	}
	var started Started
	err := s.db.InTx(ctx, "start a device authorization", store.TxOptions{Attempts: s.signInAttempts}, func(ctx context.Context, tx pgx.Tx) error {
		now := s.now()
		started = Started{AuthorizationID: platform.NewID(), Interval: DeviceInterval, ExpiresAt: now.Add(DeviceAuthorizationLifetime)}
		// Q21: only the node ID's pending authorizations that present this key are superseded, locked in authorization ID order (the
		// one order of every writer that locks several authorization rows).
		if _, err := tx.Exec(ctx, `UPDATE fleet.device_authorization SET state = 5, rev = rev + 1 WHERE state = 1 AND authorization_id IN (
    SELECT authorization_id FROM fleet.device_authorization WHERE node_id = $1 AND state = 1 AND node_public_key = $2 ORDER BY authorization_id FOR UPDATE)`,
			in.NodeID, in.PublicKey); err != nil {
			return err
		}
		deviceCode, deviceDigest := oneuse.NewCode()
		for draw := 0; ; draw++ {
			if draw == userCodeDraws {
				return arc.Unavailable()
			}
			code := s.userCodes()
			inserted, err := s.insertAuthorization(ctx, tx, started, in, request.Origin, deviceDigest[:], code, now)
			if err != nil {
				return err
			}
			if inserted {
				started.DeviceCode, started.UserCode = deviceCode, code
				return nil
			}
		}
	})
	if err != nil {
		var refusal *arc.Refusal
		if errors.As(err, &refusal) {
			s.events.ObserveFleet("start", "refused")
		}
		return Started{}, err
	}
	started.VerificationURI = VerificationURI(s.publicBaseURL)
	started.VerificationURIComplete = VerificationURIComplete(s.publicBaseURL, started.UserCode)
	s.events.ObserveFleet("start", "started")
	return started, nil
}

// insertAuthorization inserts a PENDING authorization with a drawn user code in a savepoint, and reports false (nothing inserted)
// when a PENDING or APPROVED authorization holds the code (a row reaches APPROVED only from PENDING, so this check and the live
// codes' unique index together decide every race).
func (s *Service) insertAuthorization(ctx context.Context, tx pgx.Tx, started Started, in StartRequest, origin Origin, deviceDigest []byte, code string,
	now time.Time) (bool, error) {
	digest := userCodeDigest(code)
	var holder bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM fleet.device_authorization WHERE user_code_hash = $1 AND state IN (1, 3))", digest).Scan(&holder); err != nil {
		return false, err
	}
	if holder {
		return false, nil
	}
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		return false, err
	}
	_, err = savepoint.Exec(ctx, `INSERT INTO fleet.device_authorization (authorization_id, device_code_hash, user_code_hash, state, node_id, node_name, os, arch,
    version, node_public_key, interval_ms, created_at, expires_at, begin_country, begin_asn, rev) VALUES ($1, $2, $3, 1, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
    $14, 1)`, started.AuthorizationID, deviceDigest, digest, in.NodeID, in.Node.Name, in.Node.Platform.OS, in.Node.Arch, in.Node.Version, in.PublicKey,
		DeviceInterval.Milliseconds(), now, started.ExpiresAt, origin.Country, origin.ASN)
	var failure *pgconn.PgError
	if errors.As(err, &failure) && failure.Code == "23505" && failure.ConstraintName == "device_authorization_live_user_code" {
		if rollbackErr := savepoint.Rollback(ctx); rollbackErr != nil {
			return false, rollbackErr
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, savepoint.Commit(ctx)
}

// authorizationRow is an authorization row as the device-code methods read it.
type authorizationRow struct {
	DeviceView
	interval           time.Duration
	lastPollAt         *time.Time
	lookups            int16
	userID, viewedBy   *platform.ID
	viewedAt, reusedAt *time.Time
	approver           Approver
	sessionID          *platform.ID
}

// DeviceView is an authorization as an account reviews it: the node as it described itself at Start, its key (the /activate page shows
// its fingerprint), the state and the times.
type DeviceView struct {
	AuthorizationID platform.ID
	NodeID          platform.ID
	Name            string
	OS              int16
	Arch            int16
	Version         string
	PublicKey       []byte
	State           int16
	CreatedAt       time.Time
	ExpiresAt       time.Time
	// Origin is the request's origin as Start recorded it (unknown on a self-hosted center).
	Origin Origin
}

const authorizationColumns = `authorization_id, node_id, node_name, os, arch, version, node_public_key, state, created_at, expires_at, interval_ms,
last_poll_at, lookups, user_id, viewed_by, viewed_at, approver_session_id, approver_auth_method, approver_authenticated_at, approver_auth_epoch,
approver_recovery_generation, session_id, reused_at, begin_country, begin_asn`

func scanAuthorization(row pgx.Row) (authorizationRow, error) {
	var a authorizationRow
	var interval int32
	var approverSession *platform.ID
	var method *int16
	var authenticatedAt *time.Time
	var epoch, recovery *int64
	err := row.Scan(&a.AuthorizationID, &a.NodeID, &a.Name, &a.OS, &a.Arch, &a.Version, &a.PublicKey, &a.State, &a.CreatedAt, &a.ExpiresAt, &interval,
		&a.lastPollAt, &a.lookups, &a.userID, &a.viewedBy, &a.viewedAt, &approverSession, &method, &authenticatedAt, &epoch, &recovery, &a.sessionID,
		&a.reusedAt, &a.Origin.Country, &a.Origin.ASN)
	if err != nil {
		return authorizationRow{}, err
	}
	a.interval = time.Duration(interval) * time.Millisecond
	if approverSession != nil && method != nil && authenticatedAt != nil && epoch != nil && recovery != nil {
		a.approver = Approver{SessionID: *approverSession, AuthMethod: *method, AuthenticatedAt: *authenticatedAt, AuthEpoch: *epoch, RecoveryGeneration: *recovery}
	}
	return a, nil
}

// foreign reports an authorization another account decided (approved, denied, or completed through its approval): it is answered as
// an unknown code, before any expiry is told (E1b N-1, extended to the device flow).
func (a authorizationRow) foreign(userID platform.ID) bool {
	return a.userID != nil && *a.userID != userID
}

// lapsedAt reports an authorization no caller can use at now: EXPIRED, or PENDING or APPROVED past its expiry.
func (a authorizationRow) lapsedAt(now time.Time) bool {
	return a.State == AuthorizationExpired || (a.State == AuthorizationPending || a.State == AuthorizationApproved) && !now.Before(a.ExpiresAt)
}

// reviewedBy reports a review by the account within the review window (C0: "Only a code this account looked up within the last 10
// minutes can be decided"; with the 600-second lifetime every review of a live code is younger, so this is the contract's guard).
func (a authorizationRow) reviewedBy(userID platform.ID, now time.Time) bool {
	return a.viewedBy != nil && *a.viewedBy == userID && a.viewedAt != nil && now.Sub(*a.viewedAt) <= ReviewWindow
}

// byUserCode locks the authorization a user code names: the PENDING or APPROVED one (at most one holds a code), else the newest.
const byUserCode = `SELECT ` + authorizationColumns + ` FROM fleet.device_authorization WHERE user_code_hash = $1
ORDER BY state IN (1, 3) DESC, created_at DESC, authorization_id DESC LIMIT 1 FOR UPDATE`

// Entry is one user-code entry's reservation of the account's and the client network's entry budgets (CTR4-DEV-05, Q8): taken before
// the code is read, given back when the entry names a live code the caller may act on, kept by every other entry. The deciding
// transaction records what it found; Settle gives back or keeps after the transaction.
type Entry struct {
	actor            string
	account, network ratelimit.Bucket
	accountHeld      ratelimit.Decision
	networkHeld      ratelimit.Decision
	// released: the deciding transaction gave both reservations back (it committed only if Settle sees no error); right: the entry
	// named a live code the caller reviewed, so a refusal after that point (step_up_required, quota_exceeded) gives them back too;
	// kind: the wrong-entry kind of a refusal that keeps them.
	released bool
	right    bool
	kind     string
	outcome  string
}

func (e *Entry) reset() { e.released, e.right, e.kind, e.outcome = false, false, "", "" }

// ReserveEntry reserves one unit of the account's entry budget and then one of the client network's (C0: "Every other entry first
// reserves one unit of the account budget and one of the network budget"). Once either is spent, the entry is RESOURCE/rate_limited
// with retry_at the window's end, a right one too, and nothing is read; a refused network reservation gives the account's unit back in
// its own transaction (a shared network does not burn a legitimate account's budget).
func (s *Service) ReserveEntry(ctx context.Context, request Request, account Account, event string) (*Entry, error) {
	entry := &Entry{actor: identity.Actor(account.Caller.UserID), account: s.bucket(ratelimit.DeviceEntryAccount, "account:"+account.Caller.UserID.String()),
		network: s.bucket(ratelimit.DeviceEntryPrefix, ratelimit.Prefix(request.ClientIP))}
	decision, err := s.limits.Reserve(ctx, entry.account, s.now())
	if err != nil {
		return nil, err
	}
	if !decision.Allowed {
		s.events.ObserveFleet(event, "rate_limited")
		return nil, decision.Refusal(entry.account)
	}
	entry.accountHeld = decision
	if decision, err = s.limits.Reserve(ctx, entry.network, s.now()); err != nil || !decision.Allowed {
		if giveBackErr := s.giveBack(ctx, entry.account, entry.accountHeld); err == nil && giveBackErr != nil {
			err = giveBackErr
		}
		if err != nil {
			return nil, err
		}
		s.events.ObserveFleet(event, "rate_limited")
		return nil, decision.Refusal(entry.network)
	}
	entry.networkHeld = decision
	return entry, nil
}

// release gives the entry's two reservations back in the deciding transaction (the account's first, then the network's: the one
// order of the rate-limit rows in a transaction), after every row of the global order and before the audit chain head.
func (e *Entry) release(ctx context.Context, tx pgx.Tx) error {
	if err := ratelimit.Release(ctx, tx, e.account, e.accountHeld); err != nil {
		return err
	}
	if err := ratelimit.Release(ctx, tx, e.network, e.networkHeld); err != nil {
		return err
	}
	e.released = true
	return nil
}

// giveBack gives one reservation back in its own short transaction.
func (s *Service) giveBack(ctx context.Context, bucket ratelimit.Bucket, held ratelimit.Decision) error {
	return s.db.InTx(ctx, "give an entry reservation back", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		return ratelimit.Release(ctx, tx, bucket, held)
	})
}

// GiveBack gives both reservations of an entry back in their own transaction (a replayed decision is no new entry).
func (s *Service) GiveBack(ctx context.Context, entry *Entry) error {
	return s.db.InTx(ctx, "give an entry reservation back", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		return entry.release(ctx, tx)
	})
}

// commitUnknown reports a failure after which the deciding transaction may have committed: a lost commit of an effect
// (store.ErrCommitUnknown) or an unanswered commit of an auxiliary transaction. Nothing is given back after it.
func commitUnknown(err error) bool {
	var storeErr *store.Error
	return errors.Is(err, store.ErrCommitUnknown) || errors.As(err, &storeErr) && storeErr.Unanswered
}

// Settle ends an entry after its deciding transaction, whose error (if any) is err: a decision that committed its give-back is done;
// after an unknown commit nothing is given back; a store failure, and a refusal of a code the caller reviewed (step_up_required,
// quota_exceeded), give both units back in their own transaction (best effort: a lost give-back keeps them); a wrong entry keeps them,
// counted by its kind, and the kept unit that fills a budget is audited identity.rate_limited.
func (s *Service) Settle(ctx context.Context, request Request, entry *Entry, err error, event string) {
	var refusal *arc.Refusal
	isRefusal := errors.As(err, &refusal)
	switch {
	case err == nil && entry.released:
		s.events.ObserveFleet(event, entry.outcome)
		return
	case commitUnknown(err):
		return
	case !isRefusal && err != nil, entry.right:
		_ = s.GiveBack(ctx, entry)
	case entry.kind != "":
		s.events.ObserveFleet("entry", entry.kind)
		for _, kept := range []struct {
			bucket ratelimit.Bucket
			held   ratelimit.Decision
		}{{entry.account, entry.accountHeld}, {entry.network, entry.networkHeld}} {
			if kept.held.Count == kept.bucket.Window.Limit {
				_ = s.auditAlone(ctx, request, entry.actor, "identity.rate_limited", string(kept.bucket.Kind), map[string]any{"bucket": string(kept.bucket.Kind)})
			}
		}
	default:
		_ = s.GiveBack(ctx, entry)
	}
	if isRefusal {
		s.events.ObserveFleet(event, "refused")
	}
}

// wrongCode is the refusal of a code that names no authorization the caller may use (unknown, or decided by another account):
// VALIDATION/code_invalid with the account's entries left after this one.
func (e *Entry) wrongCode() error {
	e.kind = "unknown"
	left := max(int64(e.account.Window.Limit-e.accountHeld.Count), 0)
	return arc.CodeInvalid(string(ratelimit.DeviceEntryAccount), int64(e.account.Window.Limit), left)
}

// Lookup shows the node behind a user code to an account (LookupDeviceCode), within the entry it reserved: for a PENDING, unexpired
// code with fewer than 5 lookups it counts one lookup, records the reviewing account and time (the latest review wins), gives the
// reservations back and returns the authorization; the fifth lookup is audited fleet.device_authorization.lookups_exhausted. Every other
// entry keeps the reservations and writes nothing to the authorization: an unknown code or one another account decided is
// VALIDATION/code_invalid (device_entry_account, the entries left), an expired one STATE/expired, one in another state
// STATE/invalid_state, and the sixth and later lookups of a live code VALIDATION/code_invalid (device_code_lookups, available 0),
// the authorization staying PENDING. Locks: the authorization row (the global order's flow slot), the review's foreign key on the
// account (FOR KEY SHARE), then the rate-limit rows.
func (s *Service) Lookup(ctx context.Context, request Request, account Account, entry *Entry, userCode string) (DeviceView, error) {
	var view DeviceView
	var outcome error
	err := s.db.InTx(ctx, "look up a device code", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		entry.reset()
		view, outcome = DeviceView{}, nil
		now := s.now()
		row, err := scanAuthorization(tx.QueryRow(ctx, byUserCode, userCodeDigest(userCode)))
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			outcome = entry.wrongCode()
			return nil
		case err != nil:
			return err
		case row.foreign(account.Caller.UserID):
			outcome = entry.wrongCode()
			return nil
		case row.lapsedAt(now):
			entry.kind, outcome = "expired", arc.Expired()
			return nil
		case row.State != AuthorizationPending:
			entry.kind, outcome = "state", arc.InvalidState(AuthorizationKind, authorizationStateName(row.State))
			return nil
		case row.lookups >= MaxLookups:
			entry.kind, outcome = "lookups", arc.CodeInvalid(LookupsLimit, MaxLookups, 0)
			return nil
		}
		if _, err = tx.Exec(ctx, "UPDATE fleet.device_authorization SET lookups = lookups + 1, viewed_by = $2, viewed_at = $3, rev = rev + 1 WHERE authorization_id = $1",
			row.AuthorizationID, account.Caller.UserID, now); err != nil {
			return err
		}
		if err = entry.release(ctx, tx); err != nil {
			return err
		}
		entry.outcome = "shown"
		view = row.DeviceView
		if row.lookups+1 == MaxLookups {
			return s.auditAuthorization(ctx, tx, request, entry.actor, "fleet.device_authorization.lookups_exhausted", "lookups_exhausted", row.AuthorizationID,
				map[string]any{}, now)
		}
		return nil
	})
	if err == nil {
		err = outcome
	}
	s.Settle(ctx, request, entry, err, "lookup")
	if err != nil {
		return DeviceView{}, err
	}
	return view, nil
}

// ReviewedDevice reads the authorization a user code names for the account that reviewed it within the review window, without a
// lock, a write or a lookup counted: the /activate decision page shows the review again with it after a decision answered
// AUTHENTICATION/step_up_required or a fingerprint tail mismatch, both of which come only after the decision's own review check passed
// (so the read tells the account nothing a free not_reviewed would). Anything else is refused without a count: a lapsed code
// STATE/expired, another state STATE/invalid_state, and an unknown code, one another account decided or one this account did not review
// in time alike as STATE/invalid_state not_reviewed (the page then asks for a fresh review, which counts as every review does).
func (s *Service) ReviewedDevice(ctx context.Context, account Account, userCode string) (DeviceView, error) {
	now := s.now()
	row, err := scanAuthorization(s.db.Pool().QueryRow(ctx, `SELECT `+authorizationColumns+` FROM fleet.device_authorization WHERE user_code_hash = $1
ORDER BY state IN (1, 3) DESC, created_at DESC, authorization_id DESC LIMIT 1`, userCodeDigest(userCode)))
	caller := account.Caller.UserID
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return DeviceView{}, arc.InvalidState(AuthorizationKind, "not_reviewed")
	case err != nil:
		return DeviceView{}, store.Sanitize("read a reviewed device code", err)
	case row.foreign(caller), !row.reviewedBy(caller, now):
		// The review check comes first: the read tells an account that did not review the code within the window nothing of its
		// state, whichever path reaches it (sec NB-2).
		return DeviceView{}, arc.InvalidState(AuthorizationKind, "not_reviewed")
	case row.lapsedAt(now):
		return DeviceView{}, arc.Expired()
	case row.State != AuthorizationPending:
		return DeviceView{}, arc.InvalidState(AuthorizationKind, authorizationStateName(row.State))
	}
	return row.DeviceView, nil
}

// TailLength is the length of a fingerprint's last group: 4 upper-case hexadecimal characters.
const TailLength = 4

// FingerprintTail is the last group of a node key's fingerprint: the part the /activate page withholds and asks the person to type.
func FingerprintTail(der []byte) string {
	fingerprint := Fingerprint(der)
	return fingerprint[len(fingerprint)-TailLength:]
}

// TailMatches reports whether a typed tail is the last group of the key's fingerprint (case-insensitive, constant time over the 4
// characters; a value of another shape never matches).
func TailMatches(der []byte, typed string) bool {
	if len(typed) != TailLength {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.ToUpper(typed)), []byte(FingerprintTail(der))) == 1
}

// TakeDecision counts an account's decision in node_approve_account (both sign-in flows' decisions share it) before its entry is
// reserved; over the limit it is RESOURCE/rate_limited.
func (s *Service) TakeDecision(ctx context.Context, request Request, account Account) error {
	bucket := s.bucket(ratelimit.NodeApproveAccount, "account:"+account.Caller.UserID.String())
	decision, err := s.limits.Take(ctx, bucket, s.now())
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return s.limited(ctx, request, bucket, decision, "device_decide", identity.Actor(account.Caller.UserID))
	}
	return nil
}

// DecideDevice approves or denies a device code (ApproveDeviceCode) in the caller's receipt transaction, within the entry it reserved.
// Only a code this account looked up within the last 10 minutes can be decided (else STATE/invalid_state not_reviewed, for a code
// nobody reviewed and for one another account reviewed later alike: a free not_reviewed would let a denial, which needs no step-up,
// probe the live codes under review). An approval of a PENDING code needs the proved step-up of class fleet.approveDeviceCode bound
// to the normalized user code (evidence: the operation row decides it, and it applies to an approval only; a denial consumes none),
// checks the node cap early (Enroll enforces it) and stores the approving session and its epochs (protocol-6). The approving account
// may deny an APPROVED authorization, whose credentials are not yet delivered; approving it again is invalid_state approved. A code
// another account decided is answered as an unknown code (VALIDATION/code_invalid), an expired one STATE/expired, one in another state
// STATE/invalid_state. A decision gives the entry's reservations back in this transaction and appends its audit event last. Locks:
// the authorization row, then (approving) the account through the evidence, the approval's foreign keys (FOR KEY SHARE on the account
// and the approving session), then the rate-limit rows.
func (s *Service) DecideDevice(ctx context.Context, tx pgx.Tx, request Request, account Account, entry *Entry, userCode string, approve, evidence bool,
	tail *string, now time.Time) error {
	entry.reset()
	caller := account.Caller.UserID
	row, err := scanAuthorization(tx.QueryRow(ctx, byUserCode, userCodeDigest(userCode)))
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return entry.wrongCode()
	case err != nil:
		return err
	case row.foreign(caller):
		return entry.wrongCode()
	case row.lapsedAt(now):
		entry.kind = "expired"
		return arc.Expired()
	case row.State != AuthorizationPending && row.State != AuthorizationApproved, row.State == AuthorizationApproved && approve:
		entry.kind = "state"
		return arc.InvalidState(AuthorizationKind, authorizationStateName(row.State))
	case !row.reviewedBy(caller, now):
		entry.kind = "unreviewed"
		return arc.InvalidState(AuthorizationKind, "not_reviewed")
	case approve && tail != nil && !TailMatches(row.PublicKey, *tail):
		// The /activate page's check (protocol-17): the person approving types the last group of the fingerprint the node prints, and
		// the page does not show it. A mismatch is a wrong entry (the reservation is kept) and is refused before any evidence is
		// consumed; nothing is written. The Connect method passes no tail.
		entry.kind = "tail"
		return arc.InvalidArgument("fingerprint_tail", "mismatch")
	}
	entry.right = true
	from := authorizationStateName(row.State)
	if !approve {
		if _, err = tx.Exec(ctx, "UPDATE fleet.device_authorization SET state = 4, user_id = $2, decided_at = $3, rev = rev + 1 WHERE authorization_id = $1",
			row.AuthorizationID, caller, now); err != nil {
			return err
		}
		if err = entry.release(ctx, tx); err != nil {
			return err
		}
		entry.outcome = "denied"
		return s.auditAuthorization(ctx, tx, request, entry.actor, "fleet.device_authorization.denied", "denied", row.AuthorizationID, map[string]any{"from": from}, now)
	}
	if evidence {
		target, err := hex.DecodeString(identity.TextTargetHash(ClassApproveDeviceCode, caller, userCode))
		if err != nil {
			return err
		}
		if err = identity.ConsumeEvidenceFor(ctx, tx, account.Caller, ClassApproveDeviceCode, target, now); err != nil {
			return err
		}
	}
	// The cap's early refusal: a node ID that is not live in this account would add a node.
	var live bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM fleet.node WHERE node_id = $1 AND user_id = $2 AND revoked_at IS NULL)", row.NodeID, caller).Scan(&live); err != nil {
		return err
	}
	if !live {
		var nodes int
		if err = tx.QueryRow(ctx, "SELECT count(*) FROM fleet.node WHERE user_id = $1 AND revoked_at IS NULL", caller).Scan(&nodes); err != nil {
			return err
		}
		if nodes >= s.policy.MaxNodesPerAccount {
			return arc.QuotaExceeded(MaxNodesLimit, int64(s.policy.MaxNodesPerAccount))
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE fleet.device_authorization SET state = 3, user_id = $2, decided_at = $3, approver_session_id = $4, approver_auth_method = $5,
    approver_authenticated_at = $6, approver_auth_epoch = $7, approver_recovery_generation = $8, rev = rev + 1 WHERE authorization_id = $1`, row.AuthorizationID,
		caller, now, account.Caller.SessionID, account.AuthMethod, account.AuthenticatedAt, account.Caller.AuthEpoch, account.Caller.RecoveryGeneration); err != nil {
		return err
	}
	if err = entry.release(ctx, tx); err != nil {
		return err
	}
	entry.outcome = "approved"
	return s.auditAuthorization(ctx, tx, request, entry.actor, "fleet.device_authorization.approved", "approved", row.AuthorizationID,
		map[string]any{"nodeId": row.NodeID.String(), "keyFingerprint": Fingerprint(row.PublicKey)}, now)
}

// auditAuthorization appends a device authorization's event in the caller's transaction, its last statement.
func (s *Service) auditAuthorization(ctx context.Context, tx pgx.Tx, request Request, actor, eventType, reason string, authorizationID platform.ID,
	payload map[string]any, now time.Time) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: now, ActorRef: actor, EventType: eventType, Reason: reason,
		CorrelationID: request.CorrelationID, TargetKind: AuthorizationKind, TargetID: authorizationID.String(), Payload: data})
	return err
}

// PollRequest is a PollDeviceAuthorization whose shape was checked: the device code as presented and the node key proof.
type PollRequest struct {
	DeviceCode string
	Proof      []byte
}

// ParsePoll checks a PollDeviceAuthorization's shape before anything is read or counted: device_code (required) and node_key_proof
// (required, 64 bytes) are VALIDATION/invalid_argument; a device code that is not 43 canonical characters names nothing (an unknown
// code); csr is ignored (C0: "reserved for roadmap RM-01").
func ParsePoll(message *fleetv1.NodeEnrollmentServicePollDeviceAuthorizationRequest) (PollRequest, error) {
	switch {
	case message.GetDeviceCode() == "":
		return PollRequest{}, arc.InvalidArgument("device_code", "required")
	case len(message.GetNodeKeyProof()) == 0:
		return PollRequest{}, arc.InvalidArgument("node_key_proof", "required")
	case len(message.GetNodeKeyProof()) != ProofLength:
		return PollRequest{}, arc.InvalidArgument("node_key_proof", "length")
	}
	return PollRequest{DeviceCode: message.GetDeviceCode(), Proof: append([]byte(nil), message.GetNodeKeyProof()...)}, nil
}

// Polled is a poll's answer: the state value (SLOW_DOWN included), the current interval, and, when the state is APPROVED, the
// delivered sign-in (the node's tokens, shown once).
type Polled struct {
	State     int16
	Interval  time.Duration
	Completed *Completed
}

// errReclassify asks Poll to run its decision again in an effect transaction: the locked row needs a delivery or a reuse revocation,
// which the auxiliary transaction chosen from the unlocked read must not carry (an unanswered commit of either is unknown).
var errReclassify = errors.New("the poll needs an effect transaction")

// Poll answers a node's poll (PollDeviceAuthorization), in this order:
//
//  1. the device code is looked up by its digest (one point read; the code is the lookup key, so a miss reads no row and there is no
//     stored value to compare in constant time): a code that names nothing is counted in the client prefix's failure bucket and is
//     STATE/not_found, refused RESOURCE/rate_limited with nothing counted once that bucket holds its limit;
//  2. the node key proof (purpose 0x02, binding the device code as presented, audience the SHA-256 of the center's own public base URL,
//     low-S) is verified outside any transaction: a failure is AUTHENTICATION/unauthenticated in every state, counted like an unknown
//     code, with nothing written (an APPROVED authorization stays APPROVED);
//  3. a proved poll counts in its authorization's bucket (6 per 10 seconds): over it, RESOURCE/rate_limited, nothing written;
//  4. one transaction locks the authorization and decides under the lock: PENDING or APPROVED past its expiry becomes EXPIRED; a final
//     state is answered as it is and written never, except the first poll of a COMPLETED authorization, which records the reuse,
//     revokes the delivered credential family (session revoke reason 8) and is audited fleet.device_authorization.code_reused; a
//     PENDING or APPROVED authorization polled before its interval less 500 ms has passed since its last poll (the first poll is never
//     early) is SLOW_DOWN with the interval grown by 5 seconds up to 60 seconds and nothing else; PENDING records the poll; APPROVED runs
//     fleet.Enroll in this transaction, becomes COMPLETED and answers APPROVED with the credentials. An approval that lapsed ends it
//     EXPIRED in the same transaction (answered EXPIRED); any other refusal of Enroll rolls everything back and leaves it APPROVED.
//
// A store failure of the delivery leaves the authorization APPROVED (the identical retry succeeds); an unanswered commit of it is
// store.ErrCommitUnknown and the node signs in again. A node never sends a poll before the reply of the previous one: the loser of two
// concurrent polls of an APPROVED authorization finds it COMPLETED and takes the reuse path, which revokes the winner's credentials.
func (s *Service) Poll(ctx context.Context, request Request, in PollRequest) (Polled, error) {
	secret, parsed := oneuse.ParseCode(in.DeviceCode)
	if !parsed {
		return Polled{}, s.failedPoll(ctx, request, arc.NotFound(AuthorizationKind, nil), "not_found")
	}
	digest := secret.Digest()
	row, err := scanAuthorization(s.db.Pool().QueryRow(ctx, "SELECT "+authorizationColumns+" FROM fleet.device_authorization WHERE device_code_hash = $1", digest[:]))
	if errors.Is(err, pgx.ErrNoRows) {
		return Polled{}, s.failedPoll(ctx, request, arc.NotFound(AuthorizationKind, nil), "not_found")
	}
	if err != nil {
		return Polled{}, store.Sanitize("find the authorization", err)
	}
	if !VerifyNodeKeyProof(row.PublicKey, ProofMessage(ProofPoll, s.publicBaseURL, row.NodeID, PollBinding(in.DeviceCode)), in.Proof) {
		return Polled{}, s.failedPoll(ctx, request, arc.Unauthenticated(), "proof_failed")
	}
	bucket := ratelimit.Bucket{Kind: ratelimit.NodePollAuthorization, Key: row.AuthorizationID.String(), Window: ratelimit.PollAuthorizationWindow}
	decision, err := s.limits.Take(ctx, bucket, s.now())
	if err != nil {
		return Polled{}, err
	}
	if !decision.Allowed {
		return Polled{}, s.limited(ctx, request, bucket, decision, "poll", Anonymous)
	}
	effect := row.State == AuthorizationApproved || row.State == AuthorizationCompleted && row.reusedAt == nil
	var polled Polled
	metric := ""
	decide := func(ctx context.Context, tx pgx.Tx) error {
		polled, metric = Polled{}, ""
		now := s.now()
		locked, err := scanAuthorization(tx.QueryRow(ctx, "SELECT "+authorizationColumns+" FROM fleet.device_authorization WHERE authorization_id = $1 FOR UPDATE",
			row.AuthorizationID))
		if err != nil {
			return err
		}
		polled = Polled{State: locked.State, Interval: locked.interval}
		switch {
		case (locked.State == AuthorizationPending || locked.State == AuthorizationApproved) && !now.Before(locked.ExpiresAt):
			polled.State, metric = AuthorizationExpired, "expired"
			_, err = tx.Exec(ctx, "UPDATE fleet.device_authorization SET state = 5, rev = rev + 1 WHERE authorization_id = $1", locked.AuthorizationID)
			return err
		case locked.State == AuthorizationDenied:
			metric = "denied"
			return nil
		case locked.State == AuthorizationExpired:
			metric = "expired"
			return nil
		case locked.State == AuthorizationCompleted && locked.reusedAt != nil:
			metric = "reused"
			return nil
		case locked.State == AuthorizationCompleted:
			if !effect {
				return errReclassify
			}
			metric = "reused"
			return s.revokeReusedAuthorization(ctx, tx, request, locked, now)
		case locked.lastPollAt != nil && now.Sub(*locked.lastPollAt) < locked.interval-EarlyPollTolerance:
			polled.State, polled.Interval, metric = AuthorizationSlowDown, min(locked.interval+DeviceIntervalStep, MaxDeviceInterval), "slow_down"
			_, err = tx.Exec(ctx, "UPDATE fleet.device_authorization SET interval_ms = $2, last_poll_at = $3, rev = rev + 1 WHERE authorization_id = $1",
				locked.AuthorizationID, polled.Interval.Milliseconds(), now)
			return err
		case locked.State == AuthorizationPending:
			metric = "pending"
			_, err = tx.Exec(ctx, "UPDATE fleet.device_authorization SET last_poll_at = $2, rev = rev + 1 WHERE authorization_id = $1", locked.AuthorizationID, now)
			return err
		}
		// APPROVED, unexpired, not early: deliver.
		if !effect {
			return errReclassify
		}
		info := NodeInfo{Name: locked.Name, Arch: locked.Arch, Version: locked.Version}
		var ok bool
		if info.Platform, ok = platformOfStored(locked.OS); !ok {
			return errors.New("fleet: a device authorization stores an unknown operating system")
		}
		enrolled, err := Enroll(ctx, tx, s.policy, EnrollRequest{UserID: *locked.userID, Approver: locked.approver, NodeID: locked.NodeID, Node: info,
			PublicKey: locked.PublicKey, Flow: FlowDevice, CorrelationID: request.CorrelationID,
			Record: func(ctx context.Context, tx pgx.Tx, enrolled Enrolled) error {
				_, err := tx.Exec(ctx, `UPDATE fleet.device_authorization SET state = 6, completed_at = $2, last_poll_at = $2, session_id = $3, enrollment_id = $4,
    rev = rev + 1 WHERE authorization_id = $1`, locked.AuthorizationID, now, enrolled.Session.SessionID, enrolled.EnrollmentID)
				return err
			}}, now)
		if errors.Is(err, ErrApprovalLapsed) {
			if _, err = tx.Exec(ctx, "UPDATE fleet.device_authorization SET state = 5, rev = rev + 1 WHERE authorization_id = $1", locked.AuthorizationID); err != nil {
				return err
			}
			polled.State, metric = AuthorizationExpired, "lapsed"
			return s.auditAuthorization(ctx, tx, request, Anonymous, "fleet.device_authorization.approval_lapsed", "approval_lapsed", locked.AuthorizationID,
				map[string]any{}, now)
		}
		if err != nil {
			return err
		}
		account, err := summary(ctx, tx, *locked.userID)
		if err != nil {
			return err
		}
		polled.State, polled.Completed, metric = AuthorizationApproved, &Completed{Enrolled: enrolled, Account: account}, "delivered"
		return nil
	}
	for {
		if effect {
			err = s.db.InTx(ctx, "deliver a device authorization", store.TxOptions{Attempts: s.signInAttempts}, decide)
		} else {
			err = s.db.InTx(ctx, "record a device authorization's poll", store.TxOptions{Attempts: s.signInAttempts, Auxiliary: true}, decide)
		}
		if errors.Is(err, errReclassify) && !effect {
			effect = true
			continue
		}
		break
	}
	var refusal *arc.Refusal
	switch {
	case err == nil:
		s.events.ObserveFleet("poll", metric)
		switch {
		case metric == "lapsed":
			s.events.ObserveFleet("enroll", "lapsed")
		case polled.Completed != nil && polled.Completed.Enrolled.Reenrolled:
			s.events.ObserveFleet("enroll", "reenrolled")
		case polled.Completed != nil:
			s.events.ObserveFleet("enroll", "first")
		}
		return polled, nil
	case errors.As(err, &refusal):
		if outcome := enrollOutcome(refusal); outcome != "" {
			s.events.ObserveFleet("enroll", outcome)
		}
		s.events.ObserveFleet("poll", "refused")
	}
	return Polled{}, err
}

// PollBinding is the binding of PollDeviceAuthorization's proof: the device code as presented (UTF-8, 43 characters).
func PollBinding(deviceCode string) []byte { return []byte(deviceCode) }

// failedPoll answers a poll whose device code names nothing or whose node key proof fails, counted in the client prefix's failure
// bucket: refused once the window is full (nothing counted), otherwise counted, the count that fills the window audited
// identity.rate_limited once. A proved poll never waits on this bucket.
func (s *Service) failedPoll(ctx context.Context, request Request, refusal *arc.Refusal, metric string) error {
	bucket := s.bucket(ratelimit.NodePollPrefix, ratelimit.Prefix(request.ClientIP))
	decision, err := s.limits.Check(ctx, bucket, s.now())
	if err != nil {
		return err
	}
	if !decision.Allowed {
		s.events.ObserveFleet("poll", "rate_limited")
		return decision.Refusal(bucket)
	}
	if decision, err = s.limits.Fail(ctx, bucket, s.now()); err != nil {
		return err
	}
	if decision.Count == bucket.Window.Limit {
		if err = s.auditAlone(ctx, request, Anonymous, "identity.rate_limited", string(bucket.Kind), map[string]any{"bucket": string(bucket.Kind)}); err != nil {
			return err
		}
	}
	s.events.ObserveFleet("poll", metric)
	return refusal
}

// revokeReusedAuthorization records the first poll of a COMPLETED authorization (CTR4-DEV-08: strict, a lost reply signs the node out):
// reused_at once (the one change the final-state trigger allows), the credential family it delivered revoked (session revoke reason
// 8), audited once.
func (s *Service) revokeReusedAuthorization(ctx context.Context, tx pgx.Tx, request Request, row authorizationRow, now time.Time) error {
	if _, err := tx.Exec(ctx, "UPDATE fleet.device_authorization SET reused_at = $2, rev = rev + 1 WHERE authorization_id = $1 AND reused_at IS NULL",
		row.AuthorizationID, now); err != nil {
		return err
	}
	var revoked int64
	if row.sessionID != nil {
		tag, err := tx.Exec(ctx, `UPDATE identity.session SET revoked_at = $2, revoke_reason = $3, rev = rev + 1
WHERE family_id = (SELECT family_id FROM identity.session WHERE session_id = $1) AND revoked_at IS NULL`, *row.sessionID, now, session.RevokedEnrollmentCodeReused)
		if err != nil {
			return err
		}
		revoked = tag.RowsAffected()
		session.Announce(ctx, session.Revocation{Sessions: []platform.ID{*row.sessionID}})
	}
	return s.auditAuthorization(ctx, tx, request, Anonymous, "fleet.device_authorization.code_reused", "code_reused", row.AuthorizationID,
		map[string]any{"sessions": revoked}, now)
}
