// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/page"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/ratelimit"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// Provider is an offered sign-in provider (the contract's AuthProviderView).
type Provider struct {
	ID     string
	Method int32
	Name   string
	// Enrollment reports whether the provider creates accounts; none does (accounts come from the owner bootstrap and, later, from
	// AF-ID-02's invitations), and the answer never says whether a bootstrap is pending.
	Enrollment bool
}

// Providers are the offered providers: passkeys always, e-mail codes only while mail is enabled.
func (s *Service) Providers() []Provider {
	providers := []Provider{{ID: "passkey", Method: MethodValuePasskey, Name: "Passkey"}}
	if s.mailer.Enabled() {
		providers = append(providers, Provider{ID: "email", Method: MethodValueEmail, Name: "E-mail code"})
	}
	return providers
}

// Profile is an account's profile (the contract's AccountProfile).
type Profile struct {
	DisplayName  string
	PrimaryEmail *string
	Locale       string
	Timezone     string
	Revision     int64
}

// GetProfile reads the caller's account; its primary e-mail is the oldest live e-mail identity.
func (s *Service) GetProfile(ctx context.Context, userID platform.ID) (Profile, error) {
	var profile Profile
	err := s.db.InTx(ctx, "read a profile", store.TxOptions{ReadOnly: true}, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT u.display_name, u.locale, u.timezone, u.rev,
    (SELECT a.subject FROM identity.auth_identity a WHERE a.user_id = u.user_id AND a.provider_id = 'email' AND a.revoked_at IS NULL
     ORDER BY a.created_at, a.auth_identity_id LIMIT 1)
FROM identity.user u WHERE u.user_id = $1`, userID).Scan(&profile.DisplayName, &profile.Locale, &profile.Timezone, &profile.Revision, &profile.PrimaryEmail)
		if errors.Is(err, pgx.ErrNoRows) {
			return arc.NotFound()
		}
		return err
	})
	return profile, err
}

// Credential is a listed credential (the contract's CredentialSummary).
type Credential struct {
	ID          platform.ID
	Kind        string
	DisplayName string
	CreatedAt   time.Time
	LastUsedAt  *time.Time
}

// ListCredentials is one page of the caller's live credentials, oldest first. A passkey shows its label or "Passkey"; an e-mail
// identity shows its address (the account's own).
func (s *Service) ListCredentials(ctx context.Context, userID platform.ID, request page.Request) ([]Credential, string, error) {
	var items []Credential
	next := ""
	err := s.db.InTx(ctx, "list credentials", store.TxOptions{ReadOnly: true}, func(ctx context.Context, tx pgx.Tx) error {
		items, next = nil, ""
		after, afterID := time.Unix(0, 0).UTC().Add(-100*365*24*time.Hour), platform.ID{}
		if request.After != nil {
			after, afterID = request.After.At, request.After.ID
		}
		rows, err := tx.Query(ctx, `SELECT auth_identity_id, method, coalesce(label, CASE WHEN method = 1 THEN 'Passkey' ELSE subject END), created_at,
    last_used_at
FROM identity.auth_identity
WHERE user_id = $1 AND revoked_at IS NULL AND (created_at, auth_identity_id) > ($2, $3)
ORDER BY created_at, auth_identity_id
LIMIT $4`, userID, after, afterID, request.Limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item Credential
			var method int16
			if err = rows.Scan(&item.ID, &method, &item.DisplayName, &item.CreatedAt, &item.LastUsedAt); err != nil {
				return err
			}
			item.Kind = Method(method).Kind()
			items = append(items, item)
		}
		if err = rows.Err(); err != nil {
			return err
		}
		if len(items) > request.Limit {
			items = items[:request.Limit]
			last := items[len(items)-1]
			next = page.Encode(page.Credentials, page.Cursor{At: last.CreatedAt, ID: last.ID})
		}
		return nil
	})
	return items, next, err
}

// Refresh rotates a native session (RefreshSession) after the refresh bucket of the client's prefix, and reads the session's
// device for the reply. A reuse revokes the family (session.Refresh) and is counted.
func (s *Service) Refresh(ctx context.Context, request Request, token string, installationID platform.ID) (SignedIn, error) {
	if token == "" || len(token) > 8192 {
		return SignedIn{}, arc.InvalidArgument("refresh_token", "length")
	}
	if err := s.take(ctx, request, s.bucket(ratelimit.RefreshPrefix, ratelimit.Prefix(request.ClientIP)), Anonymous); err != nil {
		return SignedIn{}, err
	}
	issued, reuse, err := session.Refresh(ctx, s.db, s.policy, token, installationID, s.now(), request.CorrelationID)
	if reuse != nil {
		s.events.ObserveIdentity("refresh", "reused")
	}
	if err != nil {
		if refusalOf(err) != nil && reuse == nil {
			s.events.ObserveIdentity("refresh", "refused")
		}
		return SignedIn{}, err
	}
	var view *device.View
	err = s.db.InTx(ctx, "read a session's device", store.TxOptions{ReadOnly: true}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		view, err = device.Get(ctx, tx, issued.UserID, issued.DeviceID)
		return err
	})
	if err != nil {
		return SignedIn{}, err
	}
	if view == nil {
		return SignedIn{}, arc.CredentialRevoked()
	}
	s.events.ObserveIdentity("refresh", "rotated")
	return SignedIn{Session: issued, Device: *view}, nil
}
