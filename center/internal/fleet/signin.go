// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/oneuse"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/ratelimit"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The browser node sign-in (PKCE loopback; AF-CTR-04 part E1b, CTR4-FLW-01..08 as amended by protocol-1, protocol-4, protocol-6,
// cloud-2 and the C0 comments). A node begins a flow anonymously; an account reviews it and approves it (with step-up evidence bound
// to the flow) or denies it; the node completes it with the one-use code, its PKCE verifier and a proof by its node key, and
// receives its node credentials from fleet.Enroll. A caller that does not hold the code can neither revoke a node nor end an
// approved flow: Complete compares the code first and answers every mismatch alike, with nothing written.

// FlowLifetime is the life of a sign-in flow (C0: BeginNodeSignInValue.expires_at "10 minutes"); a contract value, no policy key.
const FlowLifetime = 10 * time.Minute

// ReviewWindow bounds how old the deciding account's review may be (C0: "Only a flow this account reviewed within the last 10
// minutes can be decided"). With a flow lifetime of 10 minutes every review is younger than any live flow: the window is the
// contract's guard, which the flow lifetime already implies.
const ReviewWindow = 10 * time.Minute

// ClassApproveNodeSignIn is the step-up class of an approval (C0 Q1): the operation ID of ApproveNodeSignIn, bound to the flow ID.
const ClassApproveNodeSignIn = "fleet.approveNodeSignIn"

// The states of a sign-in flow (arcforges.fleet.v1.NodeSignInState; fleet.node_sign_in.state).
const (
	FlowPending   int16 = 1
	FlowApproved  int16 = 2
	FlowCompleted int16 = 3
	FlowDenied    int16 = 4
	FlowExpired   int16 = 5
	FlowRevoked   int16 = 6
)

// stateName is the lower-case name of a flow state (STATE/invalid_state reason).
func stateName(state int16) string {
	switch state {
	case FlowPending:
		return "pending"
	case FlowApproved:
		return "approved"
	case FlowCompleted:
		return "completed"
	case FlowDenied:
		return "denied"
	case FlowExpired:
		return "expired"
	case FlowRevoked:
		return "revoked"
	}
	return "unspecified"
}

// FlowKind is the resource kind a missing flow is named by (STATE/not_found).
const FlowKind = "node_sign_in"

// BeginRequest is a validated BeginNodeSignIn.
type BeginRequest struct {
	NodeID        platform.ID
	Node          NodeInfo
	PublicKey     []byte
	CodeChallenge string
	RedirectURI   string
	State         string
}

// ParseBegin validates a BeginNodeSignIn request field by field, in this order, before anything is counted or read
// (VALIDATION/invalid_argument names the first field that fails): code_challenge (43 characters of [A-Za-z0-9_-], S256 only),
// redirect_uri (the two loopback forms), node (required), node.node_id (16 bytes, not all zero), the node's description
// (ParseNodeInfo), state (16 to 128 characters of [A-Za-z0-9._~-]) and node_public_key (the 91-byte PKIX DER of a P-256 key).
func ParseBegin(message *fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest) (BeginRequest, error) {
	switch {
	case message.CodeChallenge == nil:
		return BeginRequest{}, arc.InvalidArgument("code_challenge", "required")
	case !oneuse.ValidChallenge(message.GetCodeChallenge()):
		return BeginRequest{}, arc.InvalidArgument("code_challenge", "pattern")
	case message.RedirectUri == nil:
		return BeginRequest{}, arc.InvalidArgument("redirect_uri", "required")
	case !ValidLoopbackRedirect(message.GetRedirectUri()):
		return BeginRequest{}, arc.InvalidArgument("redirect_uri", "not_admitted")
	case message.GetNode() == nil:
		return BeginRequest{}, arc.InvalidArgument("node", "required")
	}
	nodeID, ok := parseNodeID(message.GetNode().GetNodeId().GetValue())
	if !ok {
		return BeginRequest{}, arc.InvalidArgument("node.node_id", "required")
	}
	info, err := ParseNodeInfo(message.GetNode())
	if err != nil {
		return BeginRequest{}, err
	}
	switch {
	case message.State == nil:
		return BeginRequest{}, arc.InvalidArgument("state", "required")
	case !oneuse.ValidState(message.GetState()):
		return BeginRequest{}, arc.InvalidArgument("state", "pattern")
	case len(message.GetNodePublicKey()) == 0:
		return BeginRequest{}, arc.InvalidArgument("node_public_key", "required")
	case !ValidNodeKey(message.GetNodePublicKey()):
		return BeginRequest{}, arc.InvalidArgument("node_public_key", "not_p256")
	}
	return BeginRequest{NodeID: nodeID, Node: info, PublicKey: append([]byte(nil), message.GetNodePublicKey()...), CodeChallenge: message.GetCodeChallenge(),
		RedirectURI: message.GetRedirectUri(), State: message.GetState()}, nil
}

func parseNodeID(value []byte) (platform.ID, bool) {
	var id platform.ID
	if len(value) != len(id) {
		return platform.ID{}, false
	}
	copy(id[:], value)
	return id, id != platform.ID{}
}

// Begun is a started flow: its ID, the URL the node opens and when the flow expires.
type Begun struct {
	FlowID       platform.ID
	AuthorizeURL string
	ExpiresAt    time.Time
}

// AuthorizeURL is the consent page of a flow: <public base URL>/connect#flow=<flow ID> with the flow ID in its lower-case 8-4-4-4-12
// form of the 16 bytes in order (C0; the node derives the same string from its configured center and requires an exact match).
func AuthorizeURL(publicBaseURL string, flowID platform.ID) string {
	return publicBaseURL + "/connect#flow=" + flowID.String()
}

// MaxDerivedURLLength bounds every URL the center derives for a node (C0: "<= 512 chars"); the configuration refuses a fleet center
// whose public base URL would exceed it (config.MaxFleetPublicBaseURLLength).
const MaxDerivedURLLength = 512

// Begin starts a browser sign-in (BeginNodeSignIn): the client prefix's and the node ID's buckets (and the opt-in anonymous-flow
// ceiling) are counted, a key that an installation holds or held is refused before approval (CONFLICT/already_exists, node_key /
// already_registered: the node replaces its key once and starts again), the node ID's pending flows that present the same key expire
// (a party that knows only a node ID cannot end the owner's flow), and the new flow is PENDING for 10 minutes. meta.command_id is
// correlation only: every call starts a new flow.
func (s *Service) Begin(ctx context.Context, request Request, in BeginRequest) (Begun, error) {
	buckets := []ratelimit.Bucket{s.bucket(ratelimit.NodeFlowPrefix, ratelimit.Prefix(request.ClientIP)), s.bucket(ratelimit.NodeFlowNode, in.NodeID.String())}
	if s.policy.AnonymousFlows.Limit > 0 {
		buckets = append(buckets, s.bucket(ratelimit.AnonymousFlows, "all"))
	}
	for _, bucket := range buckets {
		decision, err := s.limits.Take(ctx, bucket, s.now())
		if err != nil {
			return Begun{}, err
		}
		if !decision.Allowed {
			return Begun{}, s.limited(ctx, request, bucket, decision, "begin", Anonymous)
		}
	}
	var held bool
	if err := s.db.Pool().QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM device.installation WHERE public_key = $1)", in.PublicKey).Scan(&held); err != nil {
		return Begun{}, store.Sanitize("find the key's holder", err)
	}
	if held {
		s.events.ObserveFleet("begin", "refused")
		return Begun{}, arc.KeyAlreadyRegistered()
	}
	var begun Begun
	err := s.db.InTx(ctx, "begin a node sign-in", store.TxOptions{Attempts: s.signInAttempts}, func(ctx context.Context, tx pgx.Tx) error {
		now := s.now()
		begun = Begun{FlowID: platform.NewID(), ExpiresAt: now.Add(FlowLifetime)}
		begun.AuthorizeURL = AuthorizeURL(s.publicBaseURL, begun.FlowID)
		// Q21: only the node ID's pending flows that present this key are superseded, locked in flow ID order (one order for every
		// writer that locks several flow rows).
		if _, err := tx.Exec(ctx, `UPDATE fleet.node_sign_in SET state = 5, rev = rev + 1 WHERE state = 1 AND flow_id IN (SELECT flow_id FROM fleet.node_sign_in
WHERE node_id = $1 AND state = 1 AND node_public_key = $2 ORDER BY flow_id FOR UPDATE)`, in.NodeID, in.PublicKey); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO fleet.node_sign_in (flow_id, state, node_id, node_name, os, arch, version, node_public_key, code_challenge, redirect_uri,
    client_state, created_at, expires_at, begin_country, begin_asn, rev) VALUES ($1, 1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 1)`, begun.FlowID,
			in.NodeID, in.Node.Name, in.Node.Platform.OS, in.Node.Arch, in.Node.Version, in.PublicKey, in.CodeChallenge, in.RedirectURI, in.State, now, begun.ExpiresAt,
			request.Origin.Country, request.Origin.ASN)
		return err
	})
	if err != nil {
		return Begun{}, err
	}
	s.events.ObserveFleet("begin", "started")
	return begun, nil
}

// Account is the account session that reviews or decides a flow: the identity caller (its account, session and epochs, for the
// step-up evidence) and how and when the session authenticated (recorded with an approval and copied to the node session).
type Account struct {
	Caller          identity.Caller
	AuthMethod      int16
	AuthenticatedAt time.Time
}

// FlowView is a flow as an account sees it: the node as it described itself at Begin, its key (the pages show its fingerprint), the
// state and the times.
type FlowView struct {
	FlowID    platform.ID
	NodeID    platform.ID
	Name      string
	OS        int16
	Arch      int16
	Version   string
	PublicKey []byte
	State     int16
	CreatedAt time.Time
	ExpiresAt time.Time
	// Origin is the request's origin as Begin recorded it (unknown on a self-hosted center).
	Origin Origin
}

// flowRow is a flow row as the sign-in methods read it.
type flowRow struct {
	FlowView
	codeChallenge, redirectURI, clientState string
	userID, viewedBy                        *platform.ID
	viewedAt, codeExpiresAt                 *time.Time
	codeHash                                []byte
	approver                                Approver
	sessionID                               *platform.ID
}

const flowColumns = `flow_id, node_id, node_name, os, arch, version, node_public_key, state, created_at, expires_at, code_challenge, redirect_uri,
client_state, user_id, viewed_by, viewed_at, code_hash, code_expires_at, approver_session_id, approver_auth_method, approver_authenticated_at,
approver_auth_epoch, approver_recovery_generation, session_id, begin_country, begin_asn`

func scanFlow(row pgx.Row) (flowRow, error) {
	var flow flowRow
	var approverSession *platform.ID
	var method *int16
	var authenticatedAt *time.Time
	var epoch, recovery *int64
	err := row.Scan(&flow.FlowID, &flow.NodeID, &flow.Name, &flow.OS, &flow.Arch, &flow.Version, &flow.PublicKey, &flow.State, &flow.CreatedAt,
		&flow.ExpiresAt, &flow.codeChallenge, &flow.redirectURI, &flow.clientState, &flow.userID, &flow.viewedBy, &flow.viewedAt, &flow.codeHash,
		&flow.codeExpiresAt, &approverSession, &method, &authenticatedAt, &epoch, &recovery, &flow.sessionID, &flow.Origin.Country, &flow.Origin.ASN)
	if err != nil {
		return flowRow{}, err
	}
	if approverSession != nil && method != nil && authenticatedAt != nil && epoch != nil && recovery != nil {
		flow.approver = Approver{SessionID: *approverSession, AuthMethod: *method, AuthenticatedAt: *authenticatedAt, AuthEpoch: *epoch, RecoveryGeneration: *recovery}
	}
	return flow, nil
}

// foreign reports a flow decided by another account (approved, denied or completed by it): it is answered as an unknown flow, so
// unknown and foreign flows look alike (SEC-07/08), before any expiry is told.
func (f flowRow) foreign(userID platform.ID) bool { return f.userID != nil && *f.userID != userID }

// lapsedAt reports a flow that a caller can no longer use at now: EXPIRED, or PENDING or APPROVED past its expiry.
func (f flowRow) lapsedAt(now time.Time) bool {
	return f.State == FlowExpired || (f.State == FlowPending || f.State == FlowApproved) && !now.Before(f.ExpiresAt)
}

// Review shows a flow to an account (GetNodeSignInFlow): reviewing a PENDING, unexpired flow records the reviewing account and time
// (the latest review wins: a displaced reviewer's decision is not_reviewed); any other flow is shown with its state and records
// nothing. An unknown flow and one another account decided are STATE/not_found; an expired one STATE/expired.
func (s *Service) Review(ctx context.Context, account Account, flowID platform.ID) (FlowView, error) {
	var view FlowView
	err := s.db.InTx(ctx, "review a node sign-in", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		now := s.now()
		flow, err := scanFlow(tx.QueryRow(ctx, `UPDATE fleet.node_sign_in SET viewed_by = $2, viewed_at = $3, rev = rev + 1
WHERE flow_id = $1 AND state = 1 AND expires_at > $3 RETURNING `+flowColumns, flowID, account.Caller.UserID, now))
		if err == nil {
			view = flow.FlowView
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		flow, err = scanFlow(tx.QueryRow(ctx, "SELECT "+flowColumns+" FROM fleet.node_sign_in WHERE flow_id = $1", flowID))
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return arc.NotFound(FlowKind, flowID[:])
		case err != nil:
			return err
		case flow.foreign(account.Caller.UserID):
			return arc.NotFound(FlowKind, flowID[:])
		case flow.lapsedAt(now):
			return arc.Expired()
		}
		view = flow.FlowView
		return nil
	})
	var refusal *arc.Refusal
	switch {
	case errors.As(err, &refusal):
		s.events.ObserveFleet("review", "refused")
	case err == nil && view.State == FlowPending:
		s.events.ObserveFleet("review", "reviewed")
	case err == nil:
		s.events.ObserveFleet("review", "shown")
	}
	return view, err
}

// Decision is a decided flow: the redirect the browser takes back to the node (with the one-use code on an approval) and the flow.
type Decision struct {
	RedirectURL string
	Flow        FlowView
}

// Decide approves or denies a flow (ApproveNodeSignIn). Only a flow this account reviewed within the last 10 minutes can be decided;
// an approval needs a proved step-up of class fleet.approveNodeSignIn bound to the flow ID (consumed in this transaction), a denial
// none. While the flow is APPROVED and its code unredeemed, the approving account may deny it, or approve it again, which replaces
// the code. An approval stores the approving session and its epochs (protocol-6), draws a fresh one-use code that lives
// nodeCodeLifetime and never past the flow, and checks the node cap early (Enroll enforces it). The account's decisions are counted
// first. evidence is whether this decision consumes step-up evidence: the operation row decides it
// (access.Operation.NeedsEvidenceToDecide: an approval of ApproveNodeSignIn's EvidenceOnApprove row, never a denial). Locks: the
// flow row, then (with evidence) the account through the evidence (the global order).
func (s *Service) Decide(ctx context.Context, request Request, account Account, flowID platform.ID, approve, evidence bool) (Decision, error) {
	actor := identity.Actor(account.Caller.UserID)
	bucket := s.bucket(ratelimit.NodeApproveAccount, "account:"+account.Caller.UserID.String())
	decision, err := s.limits.Take(ctx, bucket, s.now())
	if err != nil {
		return Decision{}, err
	}
	if !decision.Allowed {
		return Decision{}, s.limited(ctx, request, bucket, decision, "approve", actor)
	}
	var result Decision
	outcome := ""
	err = s.db.InTx(ctx, "decide a node sign-in", store.TxOptions{Attempts: s.signInAttempts}, func(ctx context.Context, tx pgx.Tx) error {
		now := s.now()
		flow, err := scanFlow(tx.QueryRow(ctx, "SELECT "+flowColumns+" FROM fleet.node_sign_in WHERE flow_id = $1 FOR UPDATE", flowID))
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return arc.NotFound(FlowKind, flowID[:])
		case err != nil:
			return err
		case flow.foreign(account.Caller.UserID):
			return arc.NotFound(FlowKind, flowID[:])
		case flow.lapsedAt(now):
			return arc.Expired()
		case flow.State != FlowPending && flow.State != FlowApproved:
			return arc.InvalidState(FlowKind, stateName(flow.State))
		case flow.viewedBy == nil || *flow.viewedBy != account.Caller.UserID || flow.viewedAt == nil || now.Sub(*flow.viewedAt) > ReviewWindow:
			return arc.InvalidState(FlowKind, "not_reviewed")
		}
		from := stateName(flow.State)
		if !approve {
			if _, err = tx.Exec(ctx, "UPDATE fleet.node_sign_in SET state = 4, user_id = $2, decided_at = $3, rev = rev + 1 WHERE flow_id = $1",
				flowID, account.Caller.UserID, now); err != nil {
				return err
			}
			flow.State = FlowDenied
			result = Decision{RedirectURL: DenyRedirect(flow.redirectURI, flow.clientState), Flow: flow.FlowView}
			outcome = "denied"
			return s.auditFlow(ctx, tx, request, actor, "fleet.node_sign_in.denied", "denied", flowID, map[string]any{"from": from}, now)
		}
		// evidence applies to an approval only; a denial (above) consumes none.
		if evidence {
			if err = identity.ConsumeEvidence(ctx, tx, account.Caller, ClassApproveNodeSignIn, flowID, now); err != nil {
				return err
			}
		}
		// The cap's early refusal: a node ID that is not live in this account would add a node.
		var live bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM fleet.node WHERE node_id = $1 AND user_id = $2 AND revoked_at IS NULL)", flow.NodeID,
			account.Caller.UserID).Scan(&live); err != nil {
			return err
		}
		if !live {
			var nodes int
			if err = tx.QueryRow(ctx, "SELECT count(*) FROM fleet.node WHERE user_id = $1 AND revoked_at IS NULL", account.Caller.UserID).Scan(&nodes); err != nil {
				return err
			}
			if nodes >= s.policy.MaxNodesPerAccount {
				return arc.QuotaExceeded(MaxNodesLimit, int64(s.policy.MaxNodesPerAccount))
			}
		}
		code, digest := oneuse.NewCode()
		codeExpires := now.Add(s.policy.NodeCodeLifetime)
		if codeExpires.After(flow.ExpiresAt) {
			codeExpires = flow.ExpiresAt
		}
		if _, err = tx.Exec(ctx, `UPDATE fleet.node_sign_in SET state = 2, user_id = $2, decided_at = $3, approver_session_id = $4, approver_auth_method = $5,
    approver_authenticated_at = $6, approver_auth_epoch = $7, approver_recovery_generation = $8, code_hash = $9, code_expires_at = $10, rev = rev + 1
WHERE flow_id = $1`, flowID, account.Caller.UserID, now, account.Caller.SessionID, account.AuthMethod, account.AuthenticatedAt, account.Caller.AuthEpoch,
			account.Caller.RecoveryGeneration, digest[:], codeExpires); err != nil {
			return err
		}
		eventType, reason := "fleet.node_sign_in.approved", "approved"
		outcome = "approved"
		if flow.State == FlowApproved {
			eventType, reason, outcome = "fleet.node_sign_in.code_reissued", "code_reissued", "reissued"
		}
		flow.State = FlowApproved
		result = Decision{RedirectURL: CodeRedirect(flow.redirectURI, code, flow.clientState), Flow: flow.FlowView}
		return s.auditFlow(ctx, tx, request, actor, eventType, reason, flowID, map[string]any{"nodeId": flow.NodeID.String(), "keyFingerprint": Fingerprint(flow.PublicKey)},
			now)
	})
	var refusal *arc.Refusal
	switch {
	case err == nil:
		s.events.ObserveFleet("approve", outcome)
	case errors.As(err, &refusal):
		s.events.ObserveFleet("approve", "refused")
	}
	if err != nil {
		return Decision{}, err
	}
	return result, nil
}

// auditFlow appends a sign-in flow's event in the caller's transaction, its last statement.
func (s *Service) auditFlow(ctx context.Context, tx pgx.Tx, request Request, actor, eventType, reason string, flowID platform.ID, payload map[string]any,
	now time.Time) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: now, ActorRef: actor, EventType: eventType, Reason: reason,
		CorrelationID: request.CorrelationID, TargetKind: FlowKind, TargetID: flowID.String(), Payload: data})
	return err
}

// CompleteRequest is a CompleteNodeSignIn whose shape was checked: the flow, the presented code (any text: a malformed code is a
// wrong code), the PKCE verifier and the node key proof.
type CompleteRequest struct {
	FlowID   platform.ID
	Code     string
	Verifier string
	Proof    []byte
}

// ParseComplete checks a CompleteNodeSignIn's shape before anything is read or counted: flow_id (16 bytes, not all zero),
// code_verifier (43 to 128 characters of [A-Za-z0-9._~-]) and node_key_proof (64 bytes) are VALIDATION/invalid_argument; the code is
// not checked here, because a malformed code is a failed proof like a wrong one (C0: "A failed proof (code, verifier or node key
// proof) is AUTHENTICATION/unauthenticated"); csr is ignored (C0: "ignored in release 1").
func ParseComplete(message *fleetv1.NodeEnrollmentServiceCompleteNodeSignInRequest) (CompleteRequest, error) {
	flowID, ok := parseNodeID(message.GetFlowId().GetValue())
	switch {
	case !ok:
		return CompleteRequest{}, arc.InvalidArgument("flow_id", "required")
	case message.CodeVerifier == nil:
		return CompleteRequest{}, arc.InvalidArgument("code_verifier", "required")
	case !oneuse.ValidVerifier(message.GetCodeVerifier()):
		return CompleteRequest{}, arc.InvalidArgument("code_verifier", "pattern")
	case len(message.GetNodeKeyProof()) == 0:
		return CompleteRequest{}, arc.InvalidArgument("node_key_proof", "required")
	case len(message.GetNodeKeyProof()) != ProofLength:
		return CompleteRequest{}, arc.InvalidArgument("node_key_proof", "length")
	}
	return CompleteRequest{FlowID: flowID, Code: message.GetCode(), Verifier: message.GetCodeVerifier(), Proof: append([]byte(nil), message.GetNodeKeyProof()...)}, nil
}

// AccountSummary is the account a node joined (NodeCredentials.account): its ID, display name and masked e-mail address.
type AccountSummary struct {
	ID          platform.ID
	DisplayName string
	EmailMasked string
}

// Completed is a completed sign-in: the enrollment (the node's tokens, shown once) and the account it joined.
type Completed struct {
	Enrolled Enrolled
	Account  AccountSummary
}

// completion is what a presentation of a matching code on an APPROVED flow leads to: an enrollment, or the failure marker of a failed
// verifier or proof.
type completion int

const (
	completionNone completion = iota
	completionEnroll
	completionMarker
)

// Complete exchanges the code, the verifier and the node key proof for the node's credentials (CompleteNodeSignIn), in this order:
//
//  1. an unknown flow is STATE/not_found; a PENDING or APPROVED flow past its expiry, or an APPROVED flow whose code expired, is
//     STATE/expired ("a correct code presented after its lifetime consumes nothing and leaves the flow APPROVED");
//  2. the presented code is compared with the flow's code digest in constant time, against a dummy digest when the flow has none:
//     any mismatch (or a malformed code), in every state, is AUTHENTICATION/unauthenticated and changes nothing, so the flow's state
//     is never visible to a caller who does not hold the code; only the unknown flows and the mismatches count in the client
//     prefix's failure bucket, and a matching code never waits on it;
//  3. a matching code on a DENIED flow is unauthenticated, on an EXPIRED flow STATE/expired, on a REVOKED flow CONFLICT/code_reused;
//  4. on an APPROVED flow the PKCE verifier and the node key proof (purpose 0x01, audience the SHA-256 of the center's own public base
//     URL, low-S) are verified outside any transaction;
//  5. one transaction locks the flow row and decides again under the lock: a matching code on a COMPLETED flow is a reuse (the flow
//     is REVOKED, the credential family it delivered is revoked, CONFLICT/code_reused); on an APPROVED flow a failed verifier or
//     proof revokes the flow (the code may have been intercepted) and answers unauthenticated; otherwise fleet.Enroll runs in this
//     transaction and the flow is COMPLETED. An approval that lapsed (fleet.ErrApprovalLapsed) ends the flow EXPIRED in the same
//     transaction (Enroll rolled its savepoint back) and answers STATE/expired; any other refusal of Enroll rolls everything back and
//     leaves the flow APPROVED with its code unredeemed.
//
// A store failure leaves the code unredeemed (the identical retry succeeds); an unanswered commit of the completion is
// store.ErrCommitUnknown (the node signs in again). The loser of two concurrent presentations of the correct code takes the reuse
// path, which also revokes the winner's credentials: a node never resends a Complete whose body was sent.
func (s *Service) Complete(ctx context.Context, request Request, in CompleteRequest) (Completed, error) {
	flow, err := scanFlow(s.db.Pool().QueryRow(ctx, "SELECT "+flowColumns+" FROM fleet.node_sign_in WHERE flow_id = $1", in.FlowID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Completed{}, s.failedPresentation(ctx, request, arc.NotFound(FlowKind, in.FlowID[:]))
	}
	if err != nil {
		return Completed{}, store.Sanitize("find the flow", err)
	}
	now := s.now()
	if expiredBeforeTheCompare(flow, now) {
		s.events.ObserveFleet("complete", "refused")
		return Completed{}, arc.Expired()
	}
	if !oneuse.Matches(in.Code, flow.codeHash) {
		return Completed{}, s.failedPresentation(ctx, request, arc.Unauthenticated())
	}
	kind := completionNone
	proofFailed := ""
	switch flow.State {
	case FlowDenied, FlowPending:
		s.events.ObserveFleet("complete", "refused")
		return Completed{}, arc.Unauthenticated()
	case FlowExpired:
		s.events.ObserveFleet("complete", "refused")
		return Completed{}, arc.Expired()
	case FlowRevoked:
		s.events.ObserveFleet("complete", "reused")
		return Completed{}, arc.CodeReused()
	case FlowApproved:
		kind = completionEnroll
		switch {
		case !oneuse.VerifyS256(in.Verifier, flow.codeChallenge):
			kind, proofFailed = completionMarker, "verifier"
		case !VerifyNodeKeyProof(flow.PublicKey, ProofMessage(ProofComplete, s.publicBaseURL, flow.NodeID, CompleteBinding(flow.FlowID, in.Code)), in.Proof):
			kind, proofFailed = completionMarker, "key_proof"
		}
	}
	// The transaction's kind follows what the pre-read found (the completion and the reuse are effects, the failure marker an
	// auxiliary end of the flow); the locked row decides the outcome, so a marker that finds the flow completed by a racing
	// presentation of the code takes the reuse path in its own (auxiliary) transaction (N-6). An unanswered commit of that
	// transaction is answered RESOURCE/overloaded although the family's revocation may have committed; the retry then finds the flow
	// REVOKED and answers code_reused.
	var completed Completed
	var outcome error
	metric := ""
	decide := func(ctx context.Context, tx pgx.Tx) error {
		completed, outcome, metric = Completed{}, nil, ""
		now := s.now()
		locked, err := scanFlow(tx.QueryRow(ctx, "SELECT "+flowColumns+" FROM fleet.node_sign_in WHERE flow_id = $1 FOR UPDATE", in.FlowID))
		if err != nil {
			return err
		}
		switch {
		case expiredBeforeTheCompare(locked, now):
			outcome, metric = arc.Expired(), "refused"
			return nil
		case !oneuse.Matches(in.Code, locked.codeHash), locked.State == FlowDenied, locked.State == FlowPending:
			outcome, metric = arc.Unauthenticated(), "refused"
			return nil
		case locked.State == FlowExpired:
			outcome, metric = arc.Expired(), "refused"
			return nil
		case locked.State == FlowRevoked:
			outcome, metric = arc.CodeReused(), "reused"
			return nil
		case locked.State == FlowCompleted:
			outcome, metric = arc.CodeReused(), "reused"
			return s.revokeReused(ctx, tx, request, locked, now)
		case kind == completionMarker:
			if _, err = tx.Exec(ctx, "UPDATE fleet.node_sign_in SET state = 6, code_redeemed_at = $2, rev = rev + 1 WHERE flow_id = $1", in.FlowID, now); err != nil {
				return err
			}
			outcome, metric = arc.Unauthenticated(), "proof_failed"
			return s.auditFlow(ctx, tx, request, Anonymous, "fleet.node_sign_in.verifier_failed", "verifier_failed", in.FlowID,
				map[string]any{"failed": proofFailed}, now)
		}
		if kind != completionEnroll {
			// Unreachable: a flow is APPROVED under the lock only when it was APPROVED at the pre-read (COMPLETED and REVOKED are final).
			outcome, metric = arc.Unauthenticated(), "refused"
			return nil
		}
		// APPROVED, the code matches and both proofs held: enroll.
		info := NodeInfo{Name: locked.Name, Arch: locked.Arch, Version: locked.Version}
		var ok bool
		if info.Platform, ok = platformOfStored(locked.OS); !ok {
			return errors.New("fleet: a sign-in flow stores an unknown operating system")
		}
		enrolled, err := Enroll(ctx, tx, s.policy, EnrollRequest{UserID: *locked.userID, Approver: locked.approver, NodeID: locked.NodeID, Node: info,
			PublicKey: locked.PublicKey, Flow: FlowPKCE, CorrelationID: request.CorrelationID,
			Record: func(ctx context.Context, tx pgx.Tx, enrolled Enrolled) error {
				_, err := tx.Exec(ctx, `UPDATE fleet.node_sign_in SET state = 3, code_redeemed_at = $2, completed_at = $2, session_id = $3, enrollment_id = $4,
    rev = rev + 1 WHERE flow_id = $1`, in.FlowID, now, enrolled.Session.SessionID, enrolled.EnrollmentID)
				return err
			}}, now)
		if errors.Is(err, ErrApprovalLapsed) {
			if _, err = tx.Exec(ctx, "UPDATE fleet.node_sign_in SET state = 5, rev = rev + 1 WHERE flow_id = $1", in.FlowID); err != nil {
				return err
			}
			outcome, metric = arc.Expired(), "lapsed"
			return s.auditFlow(ctx, tx, request, Anonymous, "fleet.node_sign_in.approval_lapsed", "approval_lapsed", in.FlowID, map[string]any{}, now)
		}
		if err != nil {
			return err
		}
		account, err := summary(ctx, tx, *locked.userID)
		if err != nil {
			return err
		}
		completed = Completed{Enrolled: enrolled, Account: account}
		metric = "completed"
		return nil
	}
	if kind == completionMarker {
		err = s.db.InTx(ctx, "end a node sign-in after a failed proof", store.TxOptions{Attempts: s.signInAttempts, Auxiliary: true}, decide)
	} else {
		err = s.db.InTx(ctx, "complete a node sign-in", store.TxOptions{Attempts: s.signInAttempts}, decide)
	}
	var refusal *arc.Refusal
	switch {
	case err == nil && outcome == nil:
		s.events.ObserveFleet("complete", metric)
		if completed.Enrolled.Reenrolled {
			s.events.ObserveFleet("enroll", "reenrolled")
		} else {
			s.events.ObserveFleet("enroll", "first")
		}
		return completed, nil
	case err == nil:
		if metric == "lapsed" {
			s.events.ObserveFleet("enroll", "lapsed")
		}
		s.events.ObserveFleet("complete", metric)
		return Completed{}, outcome
	case errors.As(err, &refusal):
		if outcome := enrollOutcome(refusal); outcome != "" {
			s.events.ObserveFleet("enroll", outcome)
		}
		s.events.ObserveFleet("complete", "refused")
	}
	return Completed{}, err
}

// expiredBeforeTheCompare reports the expiries a Complete answers before the code compare (protocol-1): a PENDING or APPROVED flow
// past its expiry, or an APPROVED flow whose code expired. An EXPIRED flow inside its expiry (superseded, or an approval that lapsed)
// is told only to the holder of its code.
func expiredBeforeTheCompare(flow flowRow, now time.Time) bool {
	switch flow.State {
	case FlowPending:
		return !now.Before(flow.ExpiresAt)
	case FlowApproved:
		return !now.Before(flow.ExpiresAt) || flow.codeExpiresAt != nil && !now.Before(*flow.codeExpiresAt)
	}
	return false
}

// failedPresentation answers a Complete that names no flow or presents no matching code, counted in the client prefix's failure
// bucket: refused once the window is full (nothing counted), otherwise counted, the count that fills the window audited
// identity.rate_limited once.
func (s *Service) failedPresentation(ctx context.Context, request Request, refusal *arc.Refusal) error {
	bucket := s.bucket(ratelimit.NodeCompletePrefix, ratelimit.Prefix(request.ClientIP))
	decision, err := s.limits.Check(ctx, bucket, s.now())
	if err != nil {
		return err
	}
	if !decision.Allowed {
		s.events.ObserveFleet("complete", "rate_limited")
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
	s.events.ObserveFleet("complete", "refused")
	return refusal
}

// revokeReused ends a completed flow whose correct code was presented again (FLW-08): REVOKED (the one change the final-state trigger
// allows), the credential family it delivered revoked (session revoke reason 8), audited once.
func (s *Service) revokeReused(ctx context.Context, tx pgx.Tx, request Request, flow flowRow, now time.Time) error {
	if _, err := tx.Exec(ctx, "UPDATE fleet.node_sign_in SET state = 6, rev = rev + 1 WHERE flow_id = $1 AND state = 3", flow.FlowID); err != nil {
		return err
	}
	var revoked int64
	if flow.sessionID != nil {
		tag, err := tx.Exec(ctx, `UPDATE identity.session SET revoked_at = $2, revoke_reason = $3, rev = rev + 1
WHERE family_id = (SELECT family_id FROM identity.session WHERE session_id = $1) AND revoked_at IS NULL`, *flow.sessionID, now, session.RevokedEnrollmentCodeReused)
		if err != nil {
			return err
		}
		revoked = tag.RowsAffected()
	}
	return s.auditFlow(ctx, tx, request, Anonymous, "fleet.node_sign_in.code_reused", "code_reused", flow.FlowID, map[string]any{"sessions": revoked}, now)
}

// platformOfStored is the platform of a stored OsFamily number.
func platformOfStored(os int16) (Platform, bool) { return PlatformOf(nodev1.OsFamily(os)) }

// enrollOutcome is the enroll metric of a refusal of Enroll, or empty for a refusal the closed list does not count (an OS mismatch).
func enrollOutcome(refusal *arc.Refusal) string {
	switch {
	case refusal.Code == "already_exists" && refusal.State == "node_key":
		return "key_registered"
	case refusal.Code == "already_exists":
		return "node_conflict"
	case refusal.Code == "credential_revoked":
		return "key_retired"
	case refusal.Code == "quota_exceeded":
		return "quota"
	}
	return ""
}

// summary is the account a node joined: its display name and its oldest live e-mail address, masked.
// rowQuerier is what a single-row read needs: a transaction or the pool.
type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Summary is the account a node will join as the consent pages show it (the same AccountSummary a node receives): its display name
// and its masked e-mail address (none for an account that has no e-mail identity).
func (s *Service) Summary(ctx context.Context, userID platform.ID) (AccountSummary, error) {
	result, err := summary(ctx, s.db.Pool(), userID)
	if err != nil {
		return AccountSummary{}, store.Sanitize("read the account summary", err)
	}
	return result, nil
}

func summary(ctx context.Context, tx rowQuerier, userID platform.ID) (AccountSummary, error) {
	result := AccountSummary{ID: userID}
	var email *string
	if err := tx.QueryRow(ctx, `SELECT u.display_name, (SELECT a.subject FROM identity.auth_identity a WHERE a.user_id = u.user_id AND a.method = 2 AND
    a.revoked_at IS NULL ORDER BY a.created_at, a.auth_identity_id LIMIT 1) FROM identity.user u WHERE u.user_id = $1`, userID).Scan(&result.DisplayName, &email); err != nil {
		return AccountSummary{}, err
	}
	if email != nil {
		result.EmailMasked = identity.MaskEmail(*email)
	}
	return result, nil
}
