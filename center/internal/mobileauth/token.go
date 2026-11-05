// SPDX-License-Identifier: AGPL-3.0-only

package mobileauth

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/oneuse"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/ratelimit"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// TokenRequest is a MobileTokenRequest whose JSON shape was read (pages): the flow, the presented code, the PKCE verifier and the
// binding (the client, its redirect and the installation the begin request named).
type TokenRequest struct {
	FlowID         platform.ID
	Code           string
	Verifier       string
	ClientID       string
	RedirectURI    string
	InstallationID platform.ID
}

// Issued is a completed flow: the account session of the claimed installation (its tokens, shown to the app once) and the phone's
// device as the center keeps it.
type Issued struct {
	Session session.Native
	Device  device.View
	UserID  platform.ID
}

// ErrApprovalLapsed is a redemption whose approval no longer stands (protocol-6): the approving account may no longer sign in, or
// the approving session was revoked by the account, by the revocation of all its sessions, of its device or by an operator, or an
// authentication or recovery epoch moved since the approval. The flow ends EXPIRED and the app is answered STATE/expired.
var ErrApprovalLapsed = errors.New("the approval of the mobile authorization lapsed")

// redemption is what a presentation of a matching code on an APPROVED flow leads to: a session, or the failure marker of a wrong
// verifier or a binding mismatch.
type redemption int

const (
	redemptionNone redemption = iota
	redemptionIssue
	redemptionMarker
)

// Token redeems the code (mobile.token), mirroring fleet's Complete (MB-4, protocol-1), in this order:
//
//  1. an unknown flow is STATE/not_found, counted in the client prefix's failure bucket (mobile_token_prefix);
//  2. a PENDING or APPROVED flow past its expiry, or an APPROVED flow whose code expired, is STATE/expired (before the compare: a
//     correct code presented after its lifetime consumes nothing and leaves the flow APPROVED);
//  3. the presented code is compared with the flow's code digest first, in constant time, against a dummy digest when the flow has
//     none: every mismatch, in every state, is AUTHENTICATION/unauthenticated, counted in the failure bucket, and changes nothing, so
//     a caller who does not hold the code can neither learn a flow's state nor end it; a matching code never waits on the bucket;
//  4. a matching code on a DENIED or PENDING flow is unauthenticated, on an EXPIRED flow STATE/expired, on a REVOKED flow
//     CONFLICT/code_reused;
//  5. on an APPROVED flow, outside any transaction, the PKCE verifier (S256) and the binding (clientId, redirectUri and installationId
//     exactly the begin request's) are checked;
//  6. one transaction locks the flow row and decides again under the lock: a matching code on a COMPLETED flow is a reuse (the flow
//     becomes REVOKED, the session family it delivered is revoked with reason 9, audited once, CONFLICT/code_reused); on an APPROVED
//     flow a wrong verifier or binding ends the flow REVOKED (the code may have been intercepted; audited verifier_failed) and answers
//     unauthenticated; otherwise, in the global lock order, the account is locked FOR SHARE (it may sign in: Active or Restricted),
//     device.EnsureNative finds or creates the claimed installation and its device (another account's or product's is
//     AUTHORIZATION/permission_denied, a revoked one AUTHENTICATION/credential_revoked), the approving session is checked again
//     (session.ApprovalStands), the account session (scope account, product arcforges-mobile, purpose authenticate) is issued and the
//     flow is COMPLETED. A lapsed approval rolls the issue back (a savepoint) and ends the flow EXPIRED in the same transaction
//     (STATE/expired, audited approval_lapsed); any other refusal rolls everything back and leaves the flow APPROVED with its code
//     unredeemed.
//
// A store failure leaves the code unredeemed; an unanswered commit of the completion is store.ErrCommitUnknown (the app begins again:
// it never resends a token request whose body was sent). The loser of two concurrent presentations of the correct code takes the
// reuse path, which also revokes the winner's session family. Older sessions of the same installation are not ended (Q-10).
func (s *Service) Token(ctx context.Context, request Request, in TokenRequest) (Issued, error) {
	flow, err := scanFlow(s.db.Pool().QueryRow(ctx, "SELECT "+flowColumns+" FROM identity.mobile_authorization WHERE flow_id = $1", in.FlowID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Issued{}, s.failedPresentation(ctx, request, arc.NotFound(FlowKind, in.FlowID[:]))
	}
	if err != nil {
		return Issued{}, store.Sanitize("find the flow", err)
	}
	now := s.now()
	if expiredBeforeTheCompare(flow, now) {
		s.events.ObserveMobile("token", "refused")
		return Issued{}, arc.Expired()
	}
	if !oneuse.Matches(in.Code, flow.codeHash) {
		return Issued{}, s.failedPresentation(ctx, request, arc.Unauthenticated())
	}
	kind := redemptionNone
	failed := ""
	switch flow.State {
	case FlowDenied, FlowPending:
		s.events.ObserveMobile("token", "refused")
		return Issued{}, arc.Unauthenticated()
	case FlowExpired:
		s.events.ObserveMobile("token", "refused")
		return Issued{}, arc.Expired()
	case FlowRevoked:
		s.events.ObserveMobile("token", "reused")
		return Issued{}, arc.CodeReused()
	case FlowApproved:
		kind = redemptionIssue
		switch {
		case !oneuse.VerifyS256(in.Verifier, flow.codeChallenge):
			kind, failed = redemptionMarker, "verifier"
		case in.ClientID != flow.ClientID, in.RedirectURI != flow.redirectURI, in.InstallationID != flow.InstallationID:
			kind, failed = redemptionMarker, "binding"
		}
	}
	// The transaction's kind follows what the pre-read found (the issue and the reuse are effects, the failure marker an auxiliary end
	// of the flow); the locked row decides the outcome.
	var issued Issued
	var outcome error
	metric := ""
	decide := func(ctx context.Context, tx pgx.Tx) error {
		issued, outcome, metric = Issued{}, nil, ""
		now := s.now()
		locked, err := scanFlow(tx.QueryRow(ctx, "SELECT "+flowColumns+" FROM identity.mobile_authorization WHERE flow_id = $1 FOR UPDATE", in.FlowID))
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
		case kind == redemptionMarker:
			if _, err = tx.Exec(ctx, "UPDATE identity.mobile_authorization SET state = 6, code_redeemed_at = $2, rev = rev + 1 WHERE flow_id = $1", in.FlowID,
				now); err != nil {
				return err
			}
			outcome, metric = arc.Unauthenticated(), "verifier_failed"
			return s.auditFlow(ctx, tx, request, Anonymous, "identity.mobile_authorization.verifier_failed", "verifier_failed", in.FlowID,
				map[string]any{"failed": failed}, now)
		case kind != redemptionIssue || locked.userID == nil || !locked.approved:
			// Unreachable: a flow is APPROVED under the lock only when it was APPROVED at the pre-read (COMPLETED and REVOKED are final).
			outcome, metric = arc.Unauthenticated(), "refused"
			return nil
		}
		result, err := s.issue(ctx, tx, request, locked, now)
		if errors.Is(err, ErrApprovalLapsed) {
			if _, err = tx.Exec(ctx, "UPDATE identity.mobile_authorization SET state = 5, rev = rev + 1 WHERE flow_id = $1", in.FlowID); err != nil {
				return err
			}
			outcome, metric = arc.Expired(), "lapsed"
			return s.auditFlow(ctx, tx, request, Anonymous, "identity.mobile_authorization.approval_lapsed", "approval_lapsed", in.FlowID, map[string]any{}, now)
		}
		if err != nil {
			return err
		}
		issued, metric = result, "completed"
		return nil
	}
	if kind == redemptionMarker {
		err = s.db.InTx(ctx, "end a mobile authorization after a failed verifier", store.TxOptions{Attempts: s.attempts, Auxiliary: true}, decide)
	} else {
		err = s.db.InTx(ctx, "complete a mobile authorization", store.TxOptions{Attempts: s.attempts}, decide)
	}
	var refusal *arc.Refusal
	switch {
	case err == nil && outcome == nil:
		s.events.ObserveMobile("token", metric)
		return issued, nil
	case err == nil:
		s.events.ObserveMobile("token", metric)
		return Issued{}, outcome
	case errors.As(err, &refusal):
		s.events.ObserveMobile("token", "refused")
	}
	return Issued{}, err
}

// issue is the success of a redemption, in the caller's transaction, which holds the flow row: in a savepoint, the account (FOR
// SHARE, MaySignIn), the claimed installation and its device (device.EnsureNative), the approving session (session.ApprovalStands),
// the account session, the COMPLETED flow and identity.mobile_authorization.completed (the last statement). Every error rolls the
// savepoint back, so a caller that commits after a lapse (to end its flow) keeps nothing of the issue: no device, installation or
// session.
func (s *Service) issue(ctx context.Context, tx pgx.Tx, request Request, flow flowRow, now time.Time) (Issued, error) {
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		return Issued{}, store.Sanitize("open the issue's savepoint", err)
	}
	issued, err := s.issueIn(ctx, savepoint, request, flow, now)
	if err != nil {
		if rollbackErr := savepoint.Rollback(ctx); rollbackErr != nil {
			return Issued{}, store.Sanitize("roll the issue back", rollbackErr)
		}
		return Issued{}, err
	}
	if err = savepoint.Commit(ctx); err != nil {
		return Issued{}, store.Sanitize("release the issue's savepoint", err)
	}
	return issued, nil
}

func (s *Service) issueIn(ctx context.Context, tx pgx.Tx, request Request, flow flowRow, now time.Time) (Issued, error) {
	userID := *flow.userID
	var state int16
	err := tx.QueryRow(ctx, "SELECT state FROM identity.user WHERE user_id = $1 FOR SHARE", userID).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !identity.UserState(state).MaySignIn() {
		return Issued{}, ErrApprovalLapsed
	}
	if err != nil {
		return Issued{}, store.Sanitize("lock the approving account", err)
	}
	claim := device.Claim{InstallationID: flow.InstallationID, Product: Product, Platform: flow.Platform, AppVersion: flow.AppVersion}
	deviceID, err := device.EnsureNative(ctx, tx, userID, claim, now)
	if err != nil {
		return Issued{}, err
	}
	stands, err := session.ApprovalStands(ctx, tx, flow.approver, userID)
	if err != nil {
		return Issued{}, err
	}
	if !stands {
		return Issued{}, ErrApprovalLapsed
	}
	native, err := session.IssueNative(ctx, tx, s.policy, session.Grant{UserID: userID, DeviceID: deviceID, InstallationID: flow.InstallationID,
		Scope: session.ScopeAccount, Product: Product, Purpose: session.PurposeAuthenticate, AuthMethod: flow.approver.AuthMethod,
		AuthenticatedAt: flow.approver.AuthenticatedAt}, now)
	if err != nil {
		return Issued{}, err
	}
	view, err := device.Get(ctx, tx, userID, deviceID)
	if err != nil {
		return Issued{}, err
	}
	if view == nil {
		return Issued{}, errors.New("mobileauth: the phone's device is not readable")
	}
	if _, err = tx.Exec(ctx, `UPDATE identity.mobile_authorization SET state = 3, code_redeemed_at = $2, completed_at = $2, session_id = $3, rev = rev + 1
WHERE flow_id = $1`, flow.FlowID, now, native.SessionID); err != nil {
		return Issued{}, err
	}
	if err = s.auditFlow(ctx, tx, request, identity.Actor(userID), "identity.mobile_authorization.completed", "completed", flow.FlowID,
		map[string]any{"sessionId": native.SessionID.String(), "deviceId": deviceID.String(), "clientId": flow.ClientID}, now); err != nil {
		return Issued{}, err
	}
	return Issued{Session: native, Device: *view, UserID: userID}, nil
}

// expiredBeforeTheCompare reports the expiries a token request answers before the code compare (protocol-1): a PENDING or APPROVED
// flow past its expiry, or an APPROVED flow whose code expired. An EXPIRED flow inside its expiry (an approval that lapsed) is told
// only to the holder of its code.
func expiredBeforeTheCompare(flow flowRow, now time.Time) bool {
	switch flow.State {
	case FlowPending:
		return !now.Before(flow.ExpiresAt)
	case FlowApproved:
		return !now.Before(flow.ExpiresAt) || flow.codeExpiresAt != nil && !now.Before(*flow.codeExpiresAt)
	}
	return false
}

// failedPresentation answers a token request that names no flow or presents no matching code, counted in the client prefix's
// failure bucket: refused once the window is full (nothing counted), otherwise counted, the count that fills the window audited
// identity.rate_limited once.
func (s *Service) failedPresentation(ctx context.Context, request Request, refusal *arc.Refusal) error {
	bucket := s.bucket(ratelimit.MobileTokenPrefix, ratelimit.Prefix(request.ClientIP))
	decision, err := s.limits.Check(ctx, bucket, s.now())
	if err != nil {
		return err
	}
	if !decision.Allowed {
		s.events.ObserveMobile("token", "rate_limited")
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
	s.events.ObserveMobile("token", "refused")
	return refusal
}

// revokeReused ends a completed flow whose correct code was presented again: REVOKED (the one change the final-state trigger allows),
// the session family it delivered revoked (revoke reason 9, Q-9), audited once.
func (s *Service) revokeReused(ctx context.Context, tx pgx.Tx, request Request, flow flowRow, now time.Time) error {
	if _, err := tx.Exec(ctx, "UPDATE identity.mobile_authorization SET state = 6, rev = rev + 1 WHERE flow_id = $1 AND state = 3", flow.FlowID); err != nil {
		return err
	}
	var revoked int64
	if flow.sessionID != nil {
		tag, err := tx.Exec(ctx, `UPDATE identity.session SET revoked_at = $2, revoke_reason = $3, rev = rev + 1
WHERE family_id = (SELECT family_id FROM identity.session WHERE session_id = $1) AND revoked_at IS NULL`, *flow.sessionID, now, session.RevokedMobileCodeReused)
		if err != nil {
			return err
		}
		revoked = tag.RowsAffected()
	}
	return s.auditFlow(ctx, tx, request, Anonymous, "identity.mobile_authorization.code_reused", "code_reused", flow.FlowID, map[string]any{"sessions": revoked}, now)
}
