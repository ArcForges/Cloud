// SPDX-License-Identifier: AGPL-3.0-only

package mobileauth

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/oneuse"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/ratelimit"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// Class is the step-up class of an approval (M-17): the center-defined operation identity.authorizeMobile, bound to the flow ID.
const Class = access.MobileAuthorizationClass

// Account is the account session that reviews or decides a flow: the identity caller (its account, session and epochs, for the
// step-up evidence) and how and when the session authenticated (recorded with an approval and copied to the mobile session).
type Account struct {
	Caller          identity.Caller
	AuthMethod      int16
	AuthenticatedAt time.Time
}

// Standing is what the claimed installation is to the reviewing account (Q-7): not known yet, this account's live mobile
// installation, another account's (or another product's), or revoked.
type Standing int

// The standings.
const (
	StandingNew Standing = iota + 1
	StandingOwn
	StandingForeign
	StandingRevoked
)

// FlowView is a flow as an account sees it: the client and the claim as the app reports it, the state, the times and the begin
// request's origin, and what the claimed installation is to this account.
type FlowView struct {
	FlowID         platform.ID
	ClientID       string
	InstallationID platform.ID
	Platform       string
	AppVersion     string
	State          int16
	CreatedAt      time.Time
	ExpiresAt      time.Time
	Origin         Origin
	Standing       Standing
}

// flowRow is a flow row as the methods read it.
type flowRow struct {
	FlowView
	redirectURI, codeChallenge, clientState string
	userID, viewedBy                        *platform.ID
	viewedAt, codeExpiresAt                 *time.Time
	codeHash                                []byte
	approver                                session.Approver
	approved                                bool
	sessionID                               *platform.ID
}

const flowColumns = `flow_id, state, client_id, redirect_uri, code_challenge, client_state, installation_id, platform, app_version, begin_country,
begin_asn, created_at, expires_at, viewed_by, viewed_at, user_id, code_hash, code_expires_at, approver_session_id, approver_auth_method,
approver_authenticated_at, approver_auth_epoch, approver_recovery_generation, session_id`

func scanFlow(row pgx.Row) (flowRow, error) {
	var flow flowRow
	var approverSession *platform.ID
	var method *int16
	var authenticatedAt *time.Time
	var epoch, recovery *int64
	err := row.Scan(&flow.FlowID, &flow.State, &flow.ClientID, &flow.redirectURI, &flow.codeChallenge, &flow.clientState, &flow.InstallationID,
		&flow.Platform, &flow.AppVersion, &flow.Origin.Country, &flow.Origin.ASN, &flow.CreatedAt, &flow.ExpiresAt, &flow.viewedBy, &flow.viewedAt,
		&flow.userID, &flow.codeHash, &flow.codeExpiresAt, &approverSession, &method, &authenticatedAt, &epoch, &recovery, &flow.sessionID)
	if err != nil {
		return flowRow{}, err
	}
	if approverSession != nil && method != nil && authenticatedAt != nil && epoch != nil && recovery != nil {
		flow.approver = session.Approver{SessionID: *approverSession, AuthMethod: *method, AuthenticatedAt: *authenticatedAt, AuthEpoch: *epoch,
			RecoveryGeneration: *recovery}
		flow.approved = true
	}
	return flow, nil
}

// foreign reports a flow decided by another account: it is answered as an unknown flow, so unknown and foreign flows look alike,
// before any expiry is told.
func (f flowRow) foreign(userID platform.ID) bool { return f.userID != nil && *f.userID != userID }

// lapsedAt reports a flow that a caller can no longer use at now: EXPIRED, or PENDING or APPROVED past its expiry.
func (f flowRow) lapsedAt(now time.Time) bool {
	return f.State == FlowExpired || (f.State == FlowPending || f.State == FlowApproved) && !now.Before(f.ExpiresAt)
}

// rowQuerier is what a single-row read needs: a transaction or the pool.
type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// standingOf reads what a claimed installation is to an account, without a lock (the token re-decides it under its locks through
// device.EnsureNative).
func standingOf(ctx context.Context, q rowQuerier, installationID, userID platform.ID) (Standing, error) {
	var owner platform.ID
	var product string
	var revoked bool
	err := q.QueryRow(ctx, `SELECT i.user_id, i.product_id, i.revoked_at IS NOT NULL OR d.revoked_at IS NOT NULL FROM device.installation i
JOIN device.device d ON d.device_id = i.device_id WHERE i.installation_id = $1`, installationID).Scan(&owner, &product, &revoked)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return StandingNew, nil
	case err != nil:
		return 0, err
	case owner != userID || product != Product:
		return StandingForeign, nil
	case revoked:
		return StandingRevoked, nil
	}
	return StandingOwn, nil
}

// standingRefusal is the refusal of an approval for an installation that cannot be this account's (Q-7): another account's or
// product's is AUTHORIZATION/permission_denied (reason installation), a revoked one AUTHENTICATION/credential_revoked; nil otherwise.
func standingRefusal(standing Standing) *arc.Refusal {
	switch standing {
	case StandingForeign:
		return arc.PermissionDenied("installation")
	case StandingRevoked:
		return arc.CredentialRevoked()
	}
	return nil
}

// Review shows a flow to an account: reviewing a PENDING, unexpired flow records the reviewing account and time (the latest review
// wins: a displaced reviewer's decision is not_reviewed); any other flow is shown with its state and records nothing. An unknown flow
// and one another account decided are STATE/not_found; an expired one STATE/expired. The view says what the claimed installation is
// to the account, so the page can tell the person before any step-up (Q-7).
func (s *Service) Review(ctx context.Context, account Account, flowID platform.ID) (FlowView, error) {
	var view FlowView
	err := s.db.InTx(ctx, "review a mobile authorization", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		now := s.now()
		flow, err := scanFlow(tx.QueryRow(ctx, `UPDATE identity.mobile_authorization SET viewed_by = $2, viewed_at = $3, rev = rev + 1
WHERE flow_id = $1 AND state = 1 AND expires_at > $3 RETURNING `+flowColumns, flowID, account.Caller.UserID, now))
		if errors.Is(err, pgx.ErrNoRows) {
			flow, err = scanFlow(tx.QueryRow(ctx, "SELECT "+flowColumns+" FROM identity.mobile_authorization WHERE flow_id = $1", flowID))
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
		} else if err != nil {
			return err
		}
		view = flow.FlowView
		view.Standing, err = standingOf(ctx, tx, flow.InstallationID, account.Caller.UserID)
		return err
	})
	var refusal *arc.Refusal
	switch {
	case errors.As(err, &refusal):
		s.events.ObserveMobile("review", "refused")
	case err == nil && view.State == FlowPending:
		s.events.ObserveMobile("review", "reviewed")
	case err == nil:
		s.events.ObserveMobile("review", "shown")
	}
	return view, err
}

// Decision is a decided flow: the redirect the browser hands to the app (the callback with the one-use code and the issuer on an
// approval, the denial with the issuer on a denial) and the flow.
type Decision struct {
	RedirectURL string
	Flow        FlowView
}

// Decide approves or denies a flow (the center-defined operation identity.authorizeMobile), mirroring fleet's Decide (MB-4):
//
//  1. the account's decisions are counted first (mobile_approve_account);
//  2. the flow row is locked FOR UPDATE;
//  3. a flow another account decided or an unknown one is STATE/not_found, a lapsed one STATE/expired, a final one STATE/invalid_state
//     (its state's name), and one this account did not review within the last 10 minutes STATE/invalid_state not_reviewed;
//  4. a denial needs no evidence and makes the flow DENIED; an approval first refuses an installation that cannot be this account's
//     (Q-7: another account's or product's is permission_denied, a revoked one credential_revoked), then consumes the step-up
//     evidence of class identity.authorizeMobile bound to the flow ID in this transaction (evidence: the operation's
//     EvidenceOnApprove rule, never on a denial);
//  5. an approval stores the approving session, its auth method, its authentication time and its epochs (protocol-6);
//  6. and draws a fresh one-use code that lives the policy's mobileCodeLifetime (at most 2 minutes) and never past the flow; while
//     the flow is APPROVED and its code unredeemed, the account may approve again, which replaces the code, or deny it.
//
// Locks: the flow row, then (approving, with evidence) the account through the evidence (the global order).
func (s *Service) Decide(ctx context.Context, request Request, account Account, flowID platform.ID, approve, evidence bool) (Decision, error) {
	actor := identity.Actor(account.Caller.UserID)
	bucket := s.bucket(ratelimit.MobileApproveAccount, "account:"+account.Caller.UserID.String())
	decision, err := s.limits.Take(ctx, bucket, s.now())
	if err != nil {
		return Decision{}, err
	}
	if !decision.Allowed {
		return Decision{}, s.limited(ctx, request, bucket, decision, "approve", actor)
	}
	var result Decision
	outcome := ""
	err = s.db.InTx(ctx, "decide a mobile authorization", store.TxOptions{Attempts: s.attempts}, func(ctx context.Context, tx pgx.Tx) error {
		result, outcome = Decision{}, ""
		now := s.now()
		flow, err := scanFlow(tx.QueryRow(ctx, "SELECT "+flowColumns+" FROM identity.mobile_authorization WHERE flow_id = $1 FOR UPDATE", flowID))
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
			return arc.InvalidState(FlowKind, StateName(flow.State))
		case flow.viewedBy == nil || *flow.viewedBy != account.Caller.UserID || flow.viewedAt == nil || now.Sub(*flow.viewedAt) > ReviewWindow:
			return arc.InvalidState(FlowKind, "not_reviewed")
		}
		from := StateName(flow.State)
		if !approve {
			if _, err = tx.Exec(ctx, "UPDATE identity.mobile_authorization SET state = 4, user_id = $2, decided_at = $3, rev = rev + 1 WHERE flow_id = $1",
				flowID, account.Caller.UserID, now); err != nil {
				return err
			}
			flow.State = FlowDenied
			result = Decision{RedirectURL: DenyRedirect(flow.redirectURI, flow.clientState, s.publicBaseURL), Flow: flow.FlowView}
			outcome = "denied"
			return s.auditFlow(ctx, tx, request, actor, "identity.mobile_authorization.denied", "denied", flowID, map[string]any{"from": from}, now)
		}
		standing, err := standingOf(ctx, tx, flow.InstallationID, account.Caller.UserID)
		if err != nil {
			return err
		}
		if refusal := standingRefusal(standing); refusal != nil {
			return refusal
		}
		flow.Standing = standing
		// evidence applies to an approval only; a denial (above) consumes none.
		if evidence {
			if err = identity.ConsumeEvidence(ctx, tx, account.Caller, Class, flowID, now); err != nil {
				return err
			}
		}
		code, digest := oneuse.NewCode()
		lifetime := min(s.policy.MobileCodeLifetime, MaxCodeLifetime)
		codeExpires := now.Add(lifetime)
		if codeExpires.After(flow.ExpiresAt) {
			codeExpires = flow.ExpiresAt
		}
		if _, err = tx.Exec(ctx, `UPDATE identity.mobile_authorization SET state = 2, user_id = $2, decided_at = $3, approver_session_id = $4,
    approver_auth_method = $5, approver_authenticated_at = $6, approver_auth_epoch = $7, approver_recovery_generation = $8, code_hash = $9,
    code_expires_at = $10, rev = rev + 1 WHERE flow_id = $1`, flowID, account.Caller.UserID, now, account.Caller.SessionID, account.AuthMethod,
			account.AuthenticatedAt, account.Caller.AuthEpoch, account.Caller.RecoveryGeneration, digest[:], codeExpires); err != nil {
			return err
		}
		eventType, reason := "identity.mobile_authorization.approved", "approved"
		outcome = "approved"
		if flow.State == FlowApproved {
			eventType, reason, outcome = "identity.mobile_authorization.code_reissued", "code_reissued", "reissued"
		}
		flow.State = FlowApproved
		result = Decision{RedirectURL: SuccessRedirect(flow.redirectURI, code, flow.clientState, s.publicBaseURL), Flow: flow.FlowView}
		return s.auditFlow(ctx, tx, request, actor, eventType, reason, flowID, map[string]any{"clientId": flow.ClientID,
			"installationId": flow.InstallationID.String(), "platform": flow.Platform, "appVersion": flow.AppVersion}, now)
	})
	var refusal *arc.Refusal
	switch {
	case err == nil:
		s.events.ObserveMobile("approve", outcome)
	case errors.As(err, &refusal):
		s.events.ObserveMobile("approve", "refused")
	}
	if err != nil {
		return Decision{}, err
	}
	return result, nil
}

// MaxCodeLifetime is the contract's bound of a code's life (MobileAuthorizeCallbackSuccess.code: 2 minutes); the policy key
// mobileCodeLifetime is bounded by it as well (config.MaxMobileCodeLifetime), so neither can make the closed statement false.
const MaxCodeLifetime = 2 * time.Minute
