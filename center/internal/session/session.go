// SPDX-License-Identifier: AGPL-3.0-only

// Package session is the center's account sessions (AF-CTR-03; ArcForges-Design AD-0011 section 5, AD-0021 sections 5 and 7):
// native bearer sessions with an access token and a rotating refresh token, and browser cookie sessions bound to one origin, each
// bound to a device and an installation of its account. It issues and rotates them, detects the reuse of a spent refresh token
// (which revokes the token's family), lists an account's sessions and verifies a credential on every call for the ingress
// pipeline. Only SHA-256 digests of credentials are stored; a browser session's CSRF token is derived from its cookie handle.
package session

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// Scope is a session's scope (AD-0011 section 5; identity.session_scope). Account sessions are account and mobile.limited; node,
// push and automation sessions are issued by later tasks (AF-CTR-04, AF-CLD-02, AF-CLD-06) and reach only their own operations.
// There is no agent scope: AF-CTR-07 keeps agent grants in its own table.
type Scope int16

// The scopes.
const (
	ScopeAccount       Scope = 1
	ScopeMobileLimited Scope = 2
	ScopeNode          Scope = 3
	ScopePush          Scope = 4
	ScopeAutomation    Scope = 5
)

// String is the scope's name as the operation table and the audit name it.
func (s Scope) String() string {
	switch s {
	case ScopeAccount:
		return "account"
	case ScopeMobileLimited:
		return "mobile.limited"
	case ScopeNode:
		return "node"
	case ScopePush:
		return "push"
	case ScopeAutomation:
		return "automation"
	}
	return "unknown"
}

// IsAccountSession reports the account-session scopes: the only ones the session methods admit, list and revoke (DC-03).
func (s Scope) IsAccountSession() bool { return s == ScopeAccount || s == ScopeMobileLimited }

// Purpose is a session's purpose (the contract's AuthPurpose): 1 authenticate, 2 enroll, 4 recover.
type Purpose int16

// The purposes a session can be issued for.
const (
	PurposeAuthenticate Purpose = 1
	PurposeEnroll       Purpose = 2
)

// Revoke reasons (identity.session_revoke_reason).
const (
	RevokedSignedOut     int16 = 1
	RevokedByAccount     int16 = 2
	RevokedAll           int16 = 3
	RevokedRefreshReused int16 = 4
	RevokedDevice        int16 = 5
	RevokedOperator      int16 = 6
)

// PolicyVersion is the stored session_policy_version of the sessions this build issues.
const PolicyVersion = "af-ctr-03.1"

// Grant is what a sign-in grants: the account, its device and installation, the scope and how the account authenticated.
type Grant struct {
	UserID         platform.ID
	DeviceID       platform.ID
	InstallationID platform.ID
	Scope          Scope
	Product        string
	Purpose        Purpose
	// AuthMethod is the stored identity.auth_method (1 passkey, 2 e-mail code).
	AuthMethod      int16
	AuthenticatedAt time.Time
}

// Native is an issued (or rotated) native session: its tokens, shown to the client once, and their expiries.
type Native struct {
	SessionID        platform.ID
	UserID           platform.ID
	DeviceID         platform.ID
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
	ExpiresAt        time.Time
	Purpose          Purpose
}

// Browser is an issued browser session: its cookie handle and CSRF token, shown to the browser once.
type Browser struct {
	SessionID     platform.ID
	Handle        string
	CSRF          string
	ExpiresAt     time.Time
	IdleExpiresAt time.Time
}

func earliest(first time.Time, others ...time.Time) time.Time {
	result := first
	for _, other := range others {
		if other.Before(result) {
			result = other
		}
	}
	return result
}

// IssueNative creates a native bearer session in the caller's transaction: a new family whose first refresh generation is 1.
func IssueNative(ctx context.Context, tx pgx.Tx, policy config.IdentityPolicy, grant Grant, now time.Time) (Native, error) {
	now = now.UTC().Truncate(time.Microsecond)
	access, refresh := NewSecret(), NewSecret()
	issued := Native{SessionID: platform.NewID(), UserID: grant.UserID, DeviceID: grant.DeviceID, AccessToken: access.Token(AccessPrefix),
		RefreshToken: refresh.Token(RefreshPrefix), ExpiresAt: now.Add(policy.RefreshAbsolute), Purpose: grant.Purpose}
	issued.RefreshExpiresAt = earliest(now.Add(policy.RefreshIdleLifetime), issued.ExpiresAt)
	issued.AccessExpiresAt = earliest(now.Add(policy.AccessTokenLifetime), issued.RefreshExpiresAt)
	accessDigest, refreshDigest := access.Digest(), refresh.Digest()
	_, err := tx.Exec(ctx, `INSERT INTO identity.session (session_id, user_id, device_id, installation_id, family_id, credential_kind, scope, product_id,
    purpose, auth_method, authenticated_at, issued_at, expires_at, last_activity_at, access_token_hash, access_expires_at, refresh_token_hash,
    refresh_generation, refresh_expires_at, auth_epoch, recovery_generation, session_policy_version, rev)
VALUES ($1, $2, $3, $4, $1, 1, $5, $6, $7, $8, $9, $10, $11, $10, $12, $13, $14, 1, $15, 0, 0, $16, 1)`,
		issued.SessionID, grant.UserID, grant.DeviceID, grant.InstallationID, int16(grant.Scope), grant.Product, int16(grant.Purpose), grant.AuthMethod,
		earliest(grant.AuthenticatedAt.UTC(), now), now, issued.ExpiresAt, accessDigest[:], issued.AccessExpiresAt, refreshDigest[:],
		issued.RefreshExpiresAt, PolicyVersion)
	if err != nil {
		return Native{}, store.Sanitize("issue a native session", err)
	}
	return issued, nil
}

// IssueBrowser creates a browser cookie session bound to an origin in the caller's transaction (the account pages of AF-CTR-03's
// browser part use it; its tests use it to authenticate by cookie).
func IssueBrowser(ctx context.Context, tx pgx.Tx, policy config.IdentityPolicy, grant Grant, origin string, now time.Time) (Browser, error) {
	now = now.UTC().Truncate(time.Microsecond)
	handle := NewSecret()
	issued := Browser{SessionID: platform.NewID(), Handle: handle.Text(), CSRF: CSRF(handle), ExpiresAt: now.Add(policy.BrowserAbsolute)}
	issued.IdleExpiresAt = earliest(now.Add(policy.BrowserIdle), issued.ExpiresAt)
	digest := handle.Digest()
	_, err := tx.Exec(ctx, `INSERT INTO identity.session (session_id, user_id, device_id, installation_id, credential_kind, scope, product_id, purpose,
    auth_method, authenticated_at, issued_at, expires_at, idle_expires_at, last_activity_at, browser_handle_hash, browser_origin, auth_epoch,
    recovery_generation, session_policy_version, rev)
VALUES ($1, $2, $3, $4, 2, $5, 'arcforges-web', $6, $7, $8, $9, $10, $11, $9, $12, $13, 0, 0, $14, 1)`,
		issued.SessionID, grant.UserID, grant.DeviceID, grant.InstallationID, int16(grant.Scope), int16(grant.Purpose), grant.AuthMethod,
		earliest(grant.AuthenticatedAt.UTC(), now), now, issued.ExpiresAt, issued.IdleExpiresAt, digest[:], origin, PolicyVersion)
	if err != nil {
		return Browser{}, store.Sanitize("issue a browser session", err)
	}
	return issued, nil
}

// Reuse is the outcome of a refresh that presented a spent refresh token: its family was revoked in a committed transaction.
type Reuse struct {
	UserID   platform.ID
	FamilyID platform.ID
	Revoked  int64
}

// Refresh rotates a native session's tokens (RefreshSession): in one transaction it locks the session by the presented token's
// digest, checks it and records the presented digest as spent before it issues the next generation. A digest that is already
// spent is a reuse: every live session of its family is revoked, the reuse is audited when it revoked one (a later presentation of
// the family's spent tokens is only counted by the caller's metric) and the call answers credential_revoked,
// also for a client that lost the response to its previous refresh (strict rotation, no grace window). Two concurrent refreshes
// with one token serialize on the row: the second finds the token spent and revokes the family. The checks run in this order:
// the digest, then revocation (session, device, installation) and expiry, then the installation, the scope and the account.
// within runs in the rotating transaction after the rotation and before the commit (the caller's reads for its reply), so a
// failure of it rolls the rotation back and the presented token stays valid; nil runs nothing.
func Refresh(ctx context.Context, db *store.DB, policy config.IdentityPolicy, token string, installationID platform.ID, now time.Time,
	correlationID *platform.ID, within func(ctx context.Context, tx pgx.Tx, issued Native) error) (Native, *Reuse, error) {
	now = now.UTC().Truncate(time.Microsecond)
	secret, ok := ParseToken(RefreshPrefix, token)
	if !ok {
		return Native{}, nil, arc.Unauthenticated()
	}
	digest := secret.Digest()
	var issued Native
	var reuse *Reuse
	err := db.InTx(ctx, "refresh a session", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		issued, reuse = Native{}, nil
		var row struct {
			sessionID, userID, deviceID, installationID, familyID platform.ID
			scope, purpose, state                                 int16
			generation                                            int64
			expiresAt, refreshExpiresAt                           time.Time
			revoked                                               bool
		}
		err := tx.QueryRow(ctx, `SELECT s.session_id, s.user_id, s.device_id, s.installation_id, s.family_id, s.scope, s.purpose, u.state,
    s.refresh_generation, s.expires_at, s.refresh_expires_at,
    s.revoked_at IS NOT NULL OR d.revoked_at IS NOT NULL OR i.revoked_at IS NOT NULL
FROM identity.session s
JOIN identity.user u ON u.user_id = s.user_id
JOIN device.device d ON d.device_id = s.device_id
JOIN device.installation i ON i.installation_id = s.installation_id
WHERE s.refresh_token_hash = $1 AND s.credential_kind = 1
FOR UPDATE OF s`, digest[:]).Scan(&row.sessionID, &row.userID, &row.deviceID, &row.installationID, &row.familyID, &row.scope, &row.purpose,
			&row.state, &row.generation, &row.expiresAt, &row.refreshExpiresAt, &row.revoked)
		if errors.Is(err, pgx.ErrNoRows) {
			found, err := revokeReusedFamily(ctx, tx, digest, now, correlationID)
			if err != nil {
				return err
			}
			if found == nil {
				return arc.Unauthenticated()
			}
			reuse = found
			return nil
		}
		if err != nil {
			return err
		}
		switch {
		case row.revoked:
			return arc.CredentialRevoked()
		case !now.Before(row.expiresAt) || !now.Before(row.refreshExpiresAt):
			return arc.TokenExpired()
		case row.installationID != installationID:
			return arc.Unauthenticated()
		case !Scope(row.scope).IsAccountSession():
			return arc.PermissionDenied("identity.refreshSession")
		case row.state != 1 && row.state != 2:
			return arc.Unauthenticated()
		}
		if _, err = tx.Exec(ctx, `INSERT INTO identity.spent_refresh (token_hash, session_id, family_id, generation, consumed_at, family_expires_at)
VALUES ($1, $2, $3, $4, $5, $6)`, digest[:], row.sessionID, row.familyID, row.generation, now, row.expiresAt); err != nil {
			return err
		}
		access, refresh := NewSecret(), NewSecret()
		issued = Native{SessionID: row.sessionID, UserID: row.userID, DeviceID: row.deviceID, AccessToken: access.Token(AccessPrefix),
			RefreshToken: refresh.Token(RefreshPrefix), ExpiresAt: row.expiresAt, Purpose: Purpose(row.purpose)}
		issued.RefreshExpiresAt = earliest(now.Add(policy.RefreshIdleLifetime), row.expiresAt)
		issued.AccessExpiresAt = earliest(now.Add(policy.AccessTokenLifetime), issued.RefreshExpiresAt)
		accessDigest, refreshDigest := access.Digest(), refresh.Digest()
		_, err = tx.Exec(ctx, `UPDATE identity.session SET access_token_hash = $2, access_expires_at = $3, refresh_token_hash = $4,
    refresh_generation = refresh_generation + 1, refresh_expires_at = $5, last_activity_at = $6, rev = rev + 1
WHERE session_id = $1`, row.sessionID, accessDigest[:], issued.AccessExpiresAt, refreshDigest[:], issued.RefreshExpiresAt, now)
		if err != nil || within == nil {
			return err
		}
		return within(ctx, tx, issued)
	})
	if err != nil {
		var refusal *arc.Refusal
		if errors.As(err, &refusal) {
			return Native{}, nil, refusal
		}
		return Native{}, nil, store.Sanitize("refresh a session", err)
	}
	if reuse != nil {
		return Native{}, reuse, arc.CredentialRevoked()
	}
	return issued, nil, nil
}

// revokeReusedFamily revokes the live sessions of the family of a spent refresh digest and audits the reuse when it revoked a session;
// nil when the digest was never issued. A family that is already revoked (by an earlier, audited reuse or by its own revocation)
// appends nothing, so replaying a spent token cannot grow the audit chain (E5).
func revokeReusedFamily(ctx context.Context, tx pgx.Tx, digest [32]byte, now time.Time, correlationID *platform.ID) (*Reuse, error) {
	var reuse Reuse
	var generation int64
	err := tx.QueryRow(ctx, `SELECT s.user_id, r.family_id, r.generation FROM identity.spent_refresh r
JOIN identity.session s ON s.session_id = r.session_id WHERE r.token_hash = $1`, digest[:]).Scan(&reuse.UserID, &reuse.FamilyID, &generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	tag, err := tx.Exec(ctx, `UPDATE identity.session SET revoked_at = $2, revoke_reason = $3, rev = rev + 1
WHERE family_id = $1 AND revoked_at IS NULL`, reuse.FamilyID, now, RevokedRefreshReused)
	if err != nil {
		return nil, err
	}
	reuse.Revoked = tag.RowsAffected()
	if reuse.Revoked == 0 {
		return &reuse, nil
	}
	payload, err := json.Marshal(map[string]any{"generation": generation, "revokedSessions": reuse.Revoked})
	if err != nil {
		return nil, err
	}
	if _, err = platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: now, ActorRef: "account:" + reuse.UserID.String(),
		EventType: "identity.session.refresh_reused", Reason: "refresh_token_reused", CorrelationID: correlationID, TargetKind: "session_family",
		TargetID: reuse.FamilyID.String(), Payload: payload}); err != nil {
		return nil, err
	}
	return &reuse, nil
}
