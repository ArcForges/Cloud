// SPDX-License-Identifier: AGPL-3.0-only

// Package mobileauth is the mobile app's native authorization (AF-CTR-04 part M; Contracts public/http/v1/mobile-native.schema.json,
// MobileNativeAuth v1; ArcForges-Design android.md; RFC 7636, RFC 8252 sections 7.1, 7.2 and 8, RFC 9207, RFC 9700 section 4.4). The
// app begins a flow anonymously (begin.go), an account reviews it on the center's own authorization page in a Custom Tab and
// approves it with a step-up of class identity.authorizeMobile bound to the flow, or denies it (decide.go), and the app redeems the
// one-use code with its PKCE verifier, bound to the flow, for an account session of its arcforges-mobile installation (token.go).
//
// It mirrors the built browser node sign-in (package fleet, signin.go) with three differences (MB-4): no node key proof, the
// installation claim in place of the node, and a binding compare (clientId, redirectUri and installationId of the token request
// equal the begin request's). It reuses the pure functions of package oneuse (the code, PKCE S256, the character classes) and the
// shared approval check session.ApprovalStands; its redirect rules (the release App Link and the debug private-use scheme, the
// fragment delivery with the issuer) are its own (redirect.go), and its flows are their own table, identity.mobile_authorization
// (migration 0006).
//
// The pages (package pages) call these functions in process: the native JSON routes /session/v1/mobile/begin and /token, the
// /mobile/authorize pages and the two apex routes. Every refusal returned is an *arc.Refusal; any other error is a store failure.
//
// Lock order (cloud-1, as package fleet documents it): the flow row first, then identity.user (the decision's step-up evidence locks
// it FOR UPDATE; the token's success transaction FOR SHARE, with MaySignIn), then the installation and its device (device.EnsureNative,
// one statement, the documented exception of the order), then the approving session (FOR SHARE, session.ApprovalStands), then the
// new session's insert. The account participant (approvals.go) locks the account's flows in flow ID order before the remediation
// locks the account. In every transaction the audit chain head is the last row written.
package mobileauth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/ratelimit"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// FlowLifetime is the life of a mobile authorization flow (MobileBeginResponse.expiresAt: "10 minutes after begin"); a contract
// value, no policy key.
const FlowLifetime = 10 * time.Minute

// ReviewWindow bounds how old the deciding account's review may be: 10 minutes, as for the node sign-in (the flow lifetime already
// implies it).
const ReviewWindow = 10 * time.Minute

// FlowKind is the resource kind a missing flow is named by (STATE/not_found) and the audit target kind.
const FlowKind = "mobile_authorization"

// The clients of the contract (MobileBeginRequest.clientId).
const (
	// ClientRelease is the release app: its redirect is the verified App Link <origin of the public base URL>/app/callback.
	ClientRelease = "arcforges.android"
	// ClientDebug is the debug app: its redirect is <ARCFORGES_CENTER_MOBILE_DEBUG_REDIRECT>:/callback, on a self-hosted center only.
	ClientDebug = "arcforges.android.local"
)

// Product is the installation product of a mobile session (the contract admits arcforges-mobile only).
const Product = "arcforges-mobile"

// The states of a flow (identity.mobile_authorization.state; the fleet.node_sign_in numbering).
const (
	FlowPending   int16 = 1
	FlowApproved  int16 = 2
	FlowCompleted int16 = 3
	FlowDenied    int16 = 4
	FlowExpired   int16 = 5
	FlowRevoked   int16 = 6
)

// StateName is the lower-case name of a flow state (the STATE/invalid_state reason).
func StateName(state int16) string {
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

// Events counts the mobile surface's outcomes (observe.Metrics.ObserveMobile: closed labels).
type Events interface {
	ObserveMobile(event, outcome string)
}

type noEvents struct{}

func (noEvents) ObserveMobile(string, string) {}

// Anonymous is the actor of the app's calls (begin, token): the app holds no credential.
const Anonymous = "anonymous"

// Service is the mobile native authorization of a store.
type Service struct {
	db       *store.DB
	policy   config.IdentityPolicy
	limits   *ratelimit.Limiter
	clock    func() time.Time
	events   Events
	logger   *slog.Logger
	attempts int
	// publicBaseURL is the center's canonical public base URL: the issuer (iss) of every callback and the base of the authorization
	// page's URL, never a request's Host or Origin.
	publicBaseURL string
	// release and debug are the one redirect each client may register here ("" when that client is not admitted).
	release, debug string
	// assetLinks is the asset links statement list, rendered once from the configuration.
	assetLinks []byte
}

// Options configure a Service.
type Options struct {
	DB     *store.DB
	Policy config.IdentityPolicy
	// Mobile is the mobile surface's configuration (the Android app identity, the debug scheme).
	Mobile config.Mobile
	// PublicBaseURL is the center's canonical public base URL (config.Config.PublicBaseURL).
	PublicBaseURL string
	Clock         func() time.Time
	Events        Events
	Logger        *slog.Logger
	// Attempts bounds the retries of the flow transactions on a deadlock or serialization failure; 0 is the store's default. The race
	// tests set 1.
	Attempts int
}

// New is the mobile service of a store.
func New(options Options) *Service {
	service := &Service{db: options.DB, policy: options.Policy, limits: ratelimit.New(options.DB), clock: options.Clock, events: options.Events,
		logger: options.Logger, attempts: options.Attempts, publicBaseURL: options.PublicBaseURL, release: ReleaseRedirect(options.PublicBaseURL),
		debug: options.Mobile.DebugRedirect(), assetLinks: AssetLinks(options.Mobile.AndroidApps)}
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

// Policy is the service's identity policy.
func (s *Service) Policy() config.IdentityPolicy { return s.policy }

// Issuer is the issuer every callback names (RFC 9207): the center's own public base URL.
func (s *Service) Issuer() string { return s.publicBaseURL }

// AssetLinksStatement is the exact body of /.well-known/assetlinks.json.
func (s *Service) AssetLinksStatement() []byte { return append([]byte(nil), s.assetLinks...) }

// AccountSummary is the account the app signs in to as the review page shows it: its display name and its masked e-mail address
// (none for an account without an e-mail identity).
type AccountSummary struct {
	DisplayName string
	EmailMasked string
}

// Account reads the summary of an account (one read, no lock).
func (s *Service) Account(ctx context.Context, userID platform.ID) (AccountSummary, error) {
	var result AccountSummary
	var email *string
	if err := s.db.Pool().QueryRow(ctx, `SELECT u.display_name, (SELECT a.subject FROM identity.auth_identity a WHERE a.user_id = u.user_id AND a.method = 2 AND
    a.revoked_at IS NULL ORDER BY a.created_at, a.auth_identity_id LIMIT 1) FROM identity.user u WHERE u.user_id = $1`, userID).Scan(&result.DisplayName,
		&email); err != nil {
		return AccountSummary{}, store.Sanitize("read the account summary", err)
	}
	if email != nil {
		result.EmailMasked = identity.MaskEmail(*email)
	}
	return result, nil
}

func (s *Service) now() time.Time { return s.clock().UTC().Truncate(time.Microsecond) }

// Request is what the transport knows of a call: the client address, the correlation id and the coarse origin the hosted edge saw.
type Request struct {
	ClientIP      netip.Addr
	CorrelationID *platform.ID
	Origin        Origin
}

// Origin is the coarse origin of a begin request (protocol-17): the country and network Cloudflare reports, forwarded by the hosted
// Worker only; the zero value is unknown (every self-hosted center's).
type Origin struct {
	Country *string
	ASN     *int64
}

func (s *Service) bucket(kind ratelimit.Kind, key string) ratelimit.Bucket {
	return ratelimit.Bucket{Kind: kind, Key: key, Window: ratelimit.Window(s.policy, kind)}
}

// limited answers a refused request bucket: RESOURCE/rate_limited, the first refusal of a window audited identity.rate_limited.
func (s *Service) limited(ctx context.Context, request Request, bucket ratelimit.Bucket, decision ratelimit.Decision, event, actor string) error {
	s.events.ObserveMobile(event, "rate_limited")
	if decision.First {
		if err := s.auditAlone(ctx, request, actor, "identity.rate_limited", string(bucket.Kind), map[string]any{"bucket": string(bucket.Kind)}); err != nil {
			return err
		}
	}
	return decision.Refusal(bucket)
}

// auditAlone appends an event in a short auxiliary transaction of its own.
func (s *Service) auditAlone(ctx context.Context, request Request, actor, eventType, reason string, payload map[string]any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return s.db.InTx(ctx, "audit a mobile refusal", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: s.now(), ActorRef: actor, EventType: eventType,
			Reason: reason, CorrelationID: request.CorrelationID, Payload: data})
		return err
	})
}

// auditFlow appends a flow's event in the caller's transaction, its last statement. No code, verifier, state or token is ever part
// of a payload (SEC-14).
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
