// SPDX-License-Identifier: AGPL-3.0-only

package mobileauth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/oneuse"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/ratelimit"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// BeginRequest is a MobileBeginRequest whose JSON shape was read (pages: one object, no unknown or repeated member, the document's
// types, lengths and patterns, codeChallengeMethod S256).
type BeginRequest struct {
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	State         string
	Claim         device.Claim
}

// Begun is a begun flow: its ID, the authorization page's URL and when the flow expires.
type Begun struct {
	FlowID       platform.ID
	AuthorizeURL string
	ExpiresAt    time.Time
}

// ValidateClaim checks the installation claim's shape at begin (M-12): a nonzero installation ID, the product arcforges-mobile, the
// contract's text rules (at most 128 characters of [A-Za-z0-9._:/-]; a '+' is refused, so the app sends its version without build
// metadata) and an Android platform (device.MobilePlatform, whose family is read case-insensitively; iOS is refused, the contract names
// the Android app only). It reads no installation: there is no anonymous ownership oracle.
func ValidateClaim(claim device.Claim) *arc.Refusal {
	switch {
	case claim.InstallationID == platform.ID{}:
		return arc.InvalidArgument("installation.installationId", "required")
	case claim.Product != Product:
		return arc.InvalidArgument("installation.product", "not_admitted")
	case !device.ValidClaimText(claim.Platform):
		return arc.InvalidArgument("installation.platform", "pattern")
	case !device.ValidClaimText(claim.AppVersion):
		return arc.InvalidArgument("installation.appVersion", "pattern")
	}
	if family, ok := device.MobilePlatform(claim.Platform); !ok || family != device.PlatformAndroid {
		return arc.InvalidArgument("installation.platform", "not_admitted")
	}
	return nil
}

// Begin begins a flow (mobile.begin), in this order: the PKCE challenge, the state, the client and its redirect (exactly the one
// redirect this center admits for the client, else redirectUri: not_admitted) and the claim are checked before anything is counted
// or read (malformed input costs nothing); then the client prefix's bucket (and the opt-in anonymous-flow ceiling) is taken; then
// the flow is inserted PENDING for 10 minutes. Nothing else is read: no installation (ownership is checked at the decision and at
// token), no other flow (there is no supersession by installation, Q21: the holder of an installation ID cannot end another party's
// flow; the app keeps one pending attempt itself).
func (s *Service) Begin(ctx context.Context, request Request, in BeginRequest) (Begun, error) {
	refuse := func(refusal *arc.Refusal) (Begun, error) {
		s.events.ObserveMobile("begin", "refused")
		return Begun{}, refusal
	}
	switch {
	case !oneuse.ValidChallenge(in.CodeChallenge):
		return refuse(arc.InvalidArgument("codeChallenge", "pattern"))
	case !oneuse.ValidState(in.State):
		return refuse(arc.InvalidArgument("state", "pattern"))
	case !s.AdmitRedirect(in.ClientID, in.RedirectURI):
		return refuse(arc.InvalidArgument("redirectUri", "not_admitted"))
	}
	if refusal := ValidateClaim(in.Claim); refusal != nil {
		return refuse(refusal)
	}
	buckets := []ratelimit.Bucket{s.bucket(ratelimit.MobileBeginPrefix, ratelimit.Prefix(request.ClientIP))}
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
	var begun Begun
	err := s.db.InTx(ctx, "begin a mobile authorization", store.TxOptions{Attempts: s.attempts}, func(ctx context.Context, tx pgx.Tx) error {
		now := s.now()
		begun = Begun{FlowID: platform.NewID(), ExpiresAt: now.Add(FlowLifetime)}
		begun.AuthorizeURL = AuthorizeURL(s.publicBaseURL, begun.FlowID)
		_, err := tx.Exec(ctx, `INSERT INTO identity.mobile_authorization (flow_id, state, client_id, redirect_uri, code_challenge, client_state, installation_id,
    platform, app_version, begin_country, begin_asn, created_at, expires_at, rev) VALUES ($1, 1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 1)`,
			begun.FlowID, in.ClientID, in.RedirectURI, in.CodeChallenge, in.State, in.Claim.InstallationID, in.Claim.Platform, in.Claim.AppVersion,
			request.Origin.Country, request.Origin.ASN, now, begun.ExpiresAt)
		return err
	})
	if err != nil {
		return Begun{}, err
	}
	s.events.ObserveMobile("begin", "started")
	return begun, nil
}
