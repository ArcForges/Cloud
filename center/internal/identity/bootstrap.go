// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/ratelimit"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// MaxCredentialIDBytes bounds a passkey's credential ID as the contract and WebAuthn do; its unpadded base64url form, at most 1364
// characters, is the credential's subject (migration 0002, auth_identity_subject).
const MaxCredentialIDBytes = 1023

// Enrollment is a CompleteEnrollment request of the owner bootstrap.
type Enrollment struct {
	FlowID platform.ID
	// LocalCode is the bootstrap token (EnrollmentProof.local_code).
	LocalCode   string
	Creation    passkey.Creation
	DisplayName string
	Locale      *string
	Timezone    *string
}

// The reasons of a refused bootstrap; only the audit event carries them, every refusal looks the same.
const (
	bootstrapDisabled      = "disabled"
	bootstrapExpired       = "expired"
	bootstrapTokenInvalid  = "token_invalid"
	bootstrapAccountExists = "account_exists"
	bootstrapPasskey       = "passkey_invalid"
)

// validCreation checks the contract's bounds of a WebAuthnCreation.
func validCreation(creation passkey.Creation) *arc.Refusal {
	switch {
	case len(creation.CredentialID) < 1 || len(creation.CredentialID) > MaxCredentialIDBytes:
		return arc.InvalidArgument("credential.passkey.credential_id", "length")
	case len(creation.ClientDataJSON) < 1 || len(creation.ClientDataJSON) > 16384:
		return arc.InvalidArgument("credential.passkey.client_data_json", "length")
	case len(creation.AttestationObject) < 1 || len(creation.AttestationObject) > 16384:
		return arc.InvalidArgument("credential.passkey.attestation_object", "length")
	case len(creation.Transports) > 8:
		return arc.InvalidArgument("credential.passkey.transports", "max_items")
	}
	for _, transport := range creation.Transports {
		if len(transport) < 1 || len(transport) > 128 {
			return arc.InvalidArgument("credential.passkey.transports", "pattern")
		}
	}
	return nil
}

// Bootstrap is the owner bootstrap (AD-0021 section 6) through CompleteEnrollment: the configured one-time token creates the
// first account and its first passkey while no account exists. The token is compared first, in constant time and before any
// WebAuthn verification or write; a wrong token counts in its client prefix's bucket (there is no global bucket, so nobody can
// lock the owner out), and a disabled, expired, used or wrong bootstrap all give the same AUTHENTICATION/unauthenticated, the reason
// only in the audit. The creating transaction first takes the bootstrap's transaction-scoped advisory lock, so concurrent attempts
// run one after the other and each sees the accounts its predecessors committed, and it inserts the singleton bootstrap row, whose
// key refuses a second bootstrap whatever happens: concurrent attempts create one account.
func (s *Service) Bootstrap(ctx context.Context, request Request, in Enrollment) (SignedIn, error) {
	if refusal := validCreation(in.Creation); refusal != nil {
		return SignedIn{}, refusal
	}
	switch {
	case !ValidDisplayName(in.DisplayName):
		return SignedIn{}, arc.InvalidArgument("profile.display_name", "required")
	case in.Locale != nil && !ValidLocale(*in.Locale):
		return SignedIn{}, arc.InvalidArgument("profile.locale", "pattern")
	case in.Timezone != nil && !ValidTimezone(*in.Timezone):
		return SignedIn{}, arc.InvalidArgument("profile.timezone", "pattern")
	case in.LocalCode == "" || len(in.LocalCode) > 128:
		return SignedIn{}, arc.InvalidArgument("proof.local_code", "length")
	}
	failures := s.bucket(ratelimit.BootstrapPrefix, ratelimit.Prefix(request.ClientIP))
	refuse := func(reason string) (SignedIn, error) {
		s.events.ObserveIdentity("bootstrap", reason)
		decision, err := s.limits.Fail(ctx, failures, s.now())
		if err != nil {
			return SignedIn{}, err
		}
		if decision.First {
			if err = s.auditAlone(ctx, request, Anonymous, "identity.bootstrap.refused", reason, "", "", map[string]any{"reason": reason}); err != nil {
				return SignedIn{}, err
			}
		}
		if !decision.Allowed && decision.Count > failures.Window.Limit {
			return SignedIn{}, decision.Refusal(failures)
		}
		return SignedIn{}, arc.Unauthenticated()
	}
	now := s.now()
	_, ok := session.ParseToken(session.BootstrapPrefix, in.LocalCode)
	digest := session.BootstrapDigest(in.LocalCode)
	switch {
	case s.bootstrap == nil:
		return refuse(bootstrapDisabled)
	case !ok || subtle.ConstantTimeCompare(digest[:], s.bootstrap.TokenSHA256[:]) != 1:
		return refuse(bootstrapTokenInvalid)
	case !now.Before(s.bootstrap.ExpiresAt):
		return refuse(bootstrapExpired)
	}
	exists, err := s.accountExists(ctx)
	if err != nil {
		return SignedIn{}, err
	}
	if exists {
		return refuse(bootstrapAccountExists)
	}
	row, err := s.takeAttempt(ctx, in.FlowID, ChannelNative, []FlowKind{FlowEnrollment}, PurposeEnroll)
	if err != nil {
		return SignedIn{}, err
	}
	credential, err := s.rp.VerifyCreation(row.Challenge, row.UserHandle, in.Creation, row.ExpiresAt)
	if err != nil {
		if err = s.exhaust(ctx, row.ID); err != nil {
			return SignedIn{}, err
		}
		return refuse(bootstrapPasskey)
	}
	if row.Claim == nil {
		return SignedIn{}, arc.Internal()
	}
	locale, timezone := "en-US", "UTC"
	if in.Locale != nil {
		locale = *in.Locale
	}
	if in.Timezone != nil {
		timezone = *in.Timezone
	}
	var result SignedIn
	err = s.db.InTx(ctx, "bootstrap the owner", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		result = SignedIn{}
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", bootstrapLock); err != nil {
			return err
		}
		now := s.now()
		var users, used bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM identity.user), EXISTS (SELECT 1 FROM identity.bootstrap)").Scan(&users, &used); err != nil {
			return err
		}
		if users || used {
			return errAccountExists
		}
		if err := consume(ctx, tx, row.ID, now); err != nil {
			return err
		}
		userID := platform.NewID()
		if _, err := tx.Exec(ctx, `INSERT INTO identity.user (user_id, display_name, state, locale, timezone, passkey_user_handle, created_at, rev)
VALUES ($1, $2, 1, $3, $4, $5, $6, 1)`, userID, in.DisplayName, locale, timezone, row.UserHandle, now); err != nil {
			return err
		}
		identityID := platform.NewID()
		if _, err := tx.Exec(ctx, `INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, public_key, user_handle,
    sign_count, backup_eligible, backup_state, transports, aaguid, attestation_format, created_at, rev)
VALUES ($1, $2, 1, 'passkey', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 1)`, identityID, userID,
			base64.RawURLEncoding.EncodeToString(credential.ID), credential.PublicKey, row.UserHandle, int64(credential.SignCount),
			credential.BackupEligible, credential.BackupState, credential.Transports, credential.AAGUID, credential.AttestationFormat, now); err != nil {
			return err
		}
		deviceID, err := device.EnsureNative(ctx, tx, userID, *row.Claim, now)
		if err != nil {
			return err
		}
		issued, err := session.IssueNative(ctx, tx, s.policy, session.Grant{UserID: userID, DeviceID: deviceID, InstallationID: row.Claim.InstallationID,
			Scope: session.ScopeAccount, Product: row.Claim.Product, Purpose: session.PurposeEnroll, AuthMethod: int16(MethodPasskey), AuthenticatedAt: now}, now)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO identity.bootstrap (singleton, token_sha256, user_id, consumed_at) VALUES (true, $1, $2, $3)",
			s.bootstrap.TokenSHA256[:], userID, now); err != nil {
			return err
		}
		view, err := device.Get(ctx, tx, userID, deviceID)
		if err != nil || view == nil {
			return errors.Join(err, errors.New("the new device is not readable"))
		}
		result = SignedIn{Session: issued, Device: *view}
		return s.audit(ctx, tx, request, Actor(userID), "identity.bootstrap.completed", "", "account", userID.String(),
			map[string]any{"method": "passkey", "channel": "native", "credential": identityID.String()})
	})
	switch {
	case errors.Is(err, errAccountExists) || errors.Is(err, store.ErrConflict):
		if exhaustErr := s.exhaust(ctx, row.ID); exhaustErr != nil {
			return SignedIn{}, exhaustErr
		}
		return refuse(bootstrapAccountExists)
	case err != nil:
		if refusalOf(err) == nil {
			// The token and the creation verified and the store failed: the attempt is given back for the advised retry.
			s.release(ctx, row.ID)
		} else if exhaustErr := s.exhaust(ctx, row.ID); exhaustErr != nil {
			return SignedIn{}, exhaustErr
		}
		return SignedIn{}, err
	}
	s.events.ObserveIdentity("bootstrap", "completed")
	return result, nil
}

var errAccountExists = errors.New("an account exists")

// bootstrapLock is the advisory lock key of the owner bootstrap (an arbitrary constant: "afboot01" as a big-endian integer).
const bootstrapLock int64 = 0x6166626f6f743031

func (s *Service) accountExists(ctx context.Context) (bool, error) {
	var exists bool
	err := s.db.InTx(ctx, "check for an account", store.TxOptions{ReadOnly: true, Timeout: 5 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM identity.user) OR EXISTS (SELECT 1 FROM identity.bootstrap)").Scan(&exists)
	})
	return exists, err
}
