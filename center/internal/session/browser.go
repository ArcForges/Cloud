// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// preSessionLabel is the message of the pre-session CSRF token.
const preSessionLabel = "af-csrf-pre-v1\n"

// PreSessionCSRF is the CSRF token of a request that has no session yet (the sign-in and enrollment routes; decision 4.2): the
// unpadded base64url of the SHA-256 of a fixed label and the public origin. It is a constant of the deployment and public by
// design: it keeps no secret and proves only that the caller read it from the origin's own bootstrap reply, a cross-site page
// cannot, while the exact Origin check of every POST is what refuses a cross-site form. A request that has a session uses the
// session's own token (CSRF) and is never helped by this one.
func PreSessionCSRF(origin string) string {
	digest := sha256.Sum256([]byte(preSessionLabel + origin))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// BrowserSession is a resolved browser cookie session as the account pages read it: the caller, the check of its CSRF token, the
// token itself (the bootstrap reply and the forms carry it) and the session's lifetimes.
type BrowserSession struct {
	Credential *ingress.BrowserCredential
	CSRF       string
	SessionID  platform.ID
	UserID     platform.ID
	DeviceID   platform.ID
	// Handle is the cookie value's secret; Renew needs it.
	Handle             Secret
	ExpiresAt          time.Time
	IdleExpiresAt      time.Time
	Purpose            Purpose
	RecoveryGeneration int64
}

// ResolveSession reads a browser cookie like Resolve (a live session of this origin within its absolute and idle expiry, whose
// device and installation are live and whose account may sign in) and returns what the account pages need of it; nil is no
// session. It changes nothing: a page load renews the session explicitly (Renew).
func (v *Verifier) ResolveSession(ctx context.Context, cookie string) (*BrowserSession, error) {
	handle, ok := ParseHandle(cookie)
	if !ok {
		return nil, nil
	}
	row, err := v.lookup(ctx, "WHERE s.browser_handle_hash = $1 AND s.credential_kind = 2", handle.Digest())
	if err != nil || row == nil {
		return nil, err
	}
	now := v.clock()
	if row.revoked || !now.Before(row.expiresAt) || row.idleExpiresAt == nil || !now.Before(*row.idleExpiresAt) || row.origin == nil ||
		*row.origin != v.origin || (row.state != 1 && row.state != 2) {
		return nil, nil
	}
	return &BrowserSession{
		Credential: &ingress.BrowserCredential{Caller: *row.caller(ingress.CredentialBrowserSession),
			VerifyCSRF: func(token string, present bool) bool { return present && CheckCSRF(handle, token) }},
		CSRF: CSRF(handle), SessionID: row.sessionID, UserID: row.userID, DeviceID: row.deviceID, Handle: handle, ExpiresAt: row.expiresAt,
		IdleExpiresAt: *row.idleExpiresAt, Purpose: Purpose(row.purpose), RecoveryGeneration: row.recoveryGeneration,
	}, nil
}

// Renew moves a live browser session's idle expiry to the policy's idle lifetime from now, never beyond its absolute expiry and
// never earlier than it is (SEC-12): a session is renewed only by an explicit page load or the bootstrap read, never by an RPC. It
// returns the new idle expiry; a session that is no longer live (revoked, expired, idle past its limit) is not renewed and returns
// false.
func Renew(ctx context.Context, db *store.DB, policy config.IdentityPolicy, handle Secret, now time.Time) (time.Time, bool, error) {
	now = now.UTC().Truncate(time.Microsecond)
	digest := handle.Digest()
	var idle time.Time
	err := db.InTx(ctx, "renew a browser session", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		idle = time.Time{}
		err := tx.QueryRow(ctx, `UPDATE identity.session SET idle_expires_at = greatest(idle_expires_at, least($2::timestamptz, expires_at)),
    last_activity_at = greatest(last_activity_at, $3), rev = rev + 1
WHERE browser_handle_hash = $1 AND credential_kind = 2 AND revoked_at IS NULL AND expires_at > $3 AND idle_expires_at > $3
RETURNING idle_expires_at`, digest[:], now.Add(policy.BrowserIdle), now).Scan(&idle)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	if err != nil {
		return time.Time{}, false, store.Sanitize("renew a browser session", err)
	}
	return idle.UTC(), !idle.IsZero(), nil
}
