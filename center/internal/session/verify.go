// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// Verifier checks native bearer credentials and browser cookies against the store on every call (ingress.BearerVerifier and
// ingress.BrowserSessionVerifier). It never renews a session: a browser session's idle expiry moves only when an account page
// loads (AF-CTR-03's browser part), never on an RPC.
type Verifier struct {
	db     *store.DB
	origin string
	clock  func() time.Time
}

// NewVerifier is the verifier of a store; origin is the one exact Origin a browser session is bound to.
func NewVerifier(db *store.DB, origin string, clock func() time.Time) *Verifier {
	if clock == nil {
		clock = time.Now
	}
	return &Verifier{db: db, origin: origin, clock: clock}
}

// verifyTimeout bounds a credential check.
const verifyTimeout = 5 * time.Second

type verified struct {
	sessionID, userID, deviceID, installationID platform.ID
	kind, scope, method, state                  int16
	product                                     string
	authenticatedAt, expiresAt                  time.Time
	accessExpiresAt, idleExpiresAt              *time.Time
	origin                                      *string
	authEpoch, recoveryGeneration               int64
	revoked                                     bool
	purpose                                     int16
}

const verifyColumns = `SELECT s.session_id, s.user_id, s.device_id, s.installation_id, s.credential_kind, s.scope, s.auth_method, u.state,
    s.product_id, s.authenticated_at, s.expires_at, s.access_expires_at, s.idle_expires_at, s.browser_origin, s.auth_epoch,
    s.recovery_generation, s.revoked_at IS NOT NULL OR d.revoked_at IS NOT NULL OR i.revoked_at IS NOT NULL, s.purpose
FROM identity.session s
JOIN identity.user u ON u.user_id = s.user_id
JOIN device.device d ON d.device_id = s.device_id
JOIN device.installation i ON i.installation_id = s.installation_id
`

func (v *Verifier) lookup(ctx context.Context, where string, digest [32]byte) (*verified, error) {
	var row verified
	found := true
	err := v.db.InTx(ctx, "verify a session", store.TxOptions{ReadOnly: true, Timeout: verifyTimeout}, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx, verifyColumns+where, digest[:]).Scan(&row.sessionID, &row.userID, &row.deviceID, &row.installationID, &row.kind,
			&row.scope, &row.method, &row.state, &row.product, &row.authenticatedAt, &row.expiresAt, &row.accessExpiresAt, &row.idleExpiresAt,
			&row.origin, &row.authEpoch, &row.recoveryGeneration, &row.revoked, &row.purpose)
		if errors.Is(err, pgx.ErrNoRows) {
			found = false
			return nil
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &row, nil
}

func (row *verified) caller(credential ingress.CredentialKind) *ingress.Caller {
	method := "passkey"
	if row.method == 2 {
		method = "email_code"
	}
	return &ingress.Caller{
		Credential: credential, SessionID: row.sessionID.String(), UserID: row.userID.String(), DeviceID: row.deviceID.String(),
		InstallationID: row.installationID.String(), Scope: Scope(row.scope).String(), Product: row.product, AuthMethod: method,
		AuthenticatedAt: row.authenticatedAt, AuthEpoch: row.authEpoch, AccountState: row.state, RecoveryGeneration: uint64(row.recoveryGeneration),
	}
}

// Verify checks a native access token: unknown is no caller; a revoked session, device or installation is
// ingress.ErrCredentialRevoked; an expired access token is ingress.ErrTokenExpired (the client refreshes); an account that may
// not sign in is no caller.
func (v *Verifier) Verify(ctx context.Context, token string) (*ingress.Caller, error) {
	secret, ok := ParseToken(AccessPrefix, token)
	if !ok {
		return nil, nil
	}
	row, err := v.lookup(ctx, "WHERE s.access_token_hash = $1 AND s.credential_kind = 1", secret.Digest())
	if err != nil || row == nil {
		return nil, err
	}
	now := v.clock()
	switch {
	case row.revoked:
		return nil, ingress.ErrCredentialRevoked
	case row.accessExpiresAt == nil || !now.Before(*row.accessExpiresAt) || !now.Before(row.expiresAt):
		return nil, ingress.ErrTokenExpired
	case row.state != 1 && row.state != 2:
		return nil, nil
	}
	return row.caller(ingress.CredentialNativeBearer), nil
}

// AllowedOrigin is the one exact Origin of browser sessions.
func (v *Verifier) AllowedOrigin() string { return v.origin }

// Resolve checks a browser cookie handle: a live session of this origin within its absolute and idle expiry, whose device and
// installation are live and whose account may sign in. The CSRF check accepts exactly the token derived from this handle. It is
// ResolveSession's answer without the page-only fields, so the API's cookie routes and the account pages never judge a cookie
// differently.
func (v *Verifier) Resolve(ctx context.Context, cookie string) (*ingress.BrowserCredential, error) {
	resolved, err := v.ResolveSession(ctx, cookie)
	if err != nil || resolved == nil {
		return nil, err
	}
	return resolved.Credential, nil
}
