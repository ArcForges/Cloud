// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

// The contract's AuthMethod values the API names.
const (
	MethodValuePasskey = 1
	MethodValueEmail   = 2
)

// Begin is a BeginAuthentication request.
type Begin struct {
	Method     int32
	Purpose    int32
	LoginHint  *string
	ProviderID *string
	Claim      device.Claim
	HasClaim   bool
}

// Challenge is a started ceremony (the contract's AuthChallenge).
type Challenge struct {
	FlowID     platform.ID
	Method     int32
	Purpose    Purpose
	Challenge  []byte
	ExpiresAt  time.Time
	ProviderID string
	// Options are the WebAuthn options of a passkey ceremony, nil for an e-mail flow.
	Options *passkey.Options
}

// SignedIn is a completed sign-in: the native session and its device.
type SignedIn struct {
	Session session.Native
	Device  device.View
}

func randomBytes(size int) []byte {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}
	return data
}

// emailChallenge is the challenge an e-mail flow reports: it is proved by its code, so the challenge is only a stable value
// derived from the flow ID (the contract requires one).
func emailChallenge(id platform.ID) []byte {
	digest := sha256.Sum256(append([]byte("arcforges.email-flow.v1\x00"), id[:]...))
	return digest[:]
}

// EmailHash is the stored digest of a normalised address.
func EmailHash(normalized string) []byte {
	digest := sha256.Sum256([]byte(normalized))
	return digest[:]
}

// BeginAuthentication starts a native ceremony (DC-08): a discoverable passkey sign-in, the owner's enrollment (always answered
// with creation options, whatever the bootstrap's state, and rate limited), or an e-mail flow for an address, which sends nothing
// until RequestEmailCode. E-mail enrollment is not offered (accounts are never created from an e-mail address), and the e-mail
// method is not offered at all while mail is disabled.
func (s *Service) BeginAuthentication(ctx context.Context, request Request, in Begin) (Challenge, error) {
	if refusal := device.ValidateNativeClaim(in.Claim, in.HasClaim); refusal != nil {
		return Challenge{}, refusal
	}
	var normalized string
	switch {
	case in.Purpose != int32(PurposeAuthenticate) && in.Purpose != int32(PurposeEnroll):
		return Challenge{}, arc.InvalidArgument("purpose", "not_offered")
	case in.Method == MethodValuePasskey:
		if in.ProviderID != nil && *in.ProviderID != "passkey" {
			return Challenge{}, arc.InvalidArgument("provider_id", "unknown")
		}
	case in.Method == MethodValueEmail:
		if !s.mailer.Enabled() {
			return Challenge{}, arc.InvalidArgument("method", "not_offered")
		}
		if in.Purpose != int32(PurposeAuthenticate) {
			return Challenge{}, arc.InvalidArgument("purpose", "not_offered")
		}
		if in.ProviderID != nil && *in.ProviderID != "email" {
			return Challenge{}, arc.InvalidArgument("provider_id", "unknown")
		}
		if in.LoginHint == nil {
			return Challenge{}, arc.InvalidArgument("login_hint", "required")
		}
		var ok bool
		if normalized, ok = NormalizeEmail(*in.LoginHint); !ok {
			return Challenge{}, arc.InvalidArgument("login_hint", "pattern")
		}
	default:
		return Challenge{}, arc.InvalidArgument("method", "not_offered")
	}
	if err := s.take(ctx, request, s.bucket(ratelimit.SignInPrefix, ratelimit.Prefix(request.ClientIP)), Anonymous); err != nil {
		return Challenge{}, err
	}
	// The opt-in global ceiling on the flows anonymous calls create (C1; set only in the acceptance environment).
	if s.policy.AnonymousFlows.Limit > 0 {
		if err := s.take(ctx, request, s.bucket(ratelimit.AnonymousFlows, "all"), Anonymous); err != nil {
			return Challenge{}, err
		}
	}
	now := s.now()
	claim := in.Claim
	row := flow{ID: platform.NewID(), Channel: ChannelNative, Purpose: Purpose(in.Purpose), Claim: &claim, CreatedAt: now}
	result := Challenge{FlowID: row.ID, Method: in.Method, Purpose: row.Purpose}
	switch {
	case in.Method == MethodValueEmail:
		row.Kind, row.EmailHash, row.CodeHash, row.CodeSalt = FlowEmailCode, EmailHash(normalized), randomBytes(32), randomBytes(16)
		row.MaxAttempts, row.ExpiresAt = int16(s.policy.EmailCodeAttempts), now.Add(s.policy.EmailCodeLifetime)
		result.Challenge, result.ProviderID = emailChallenge(row.ID), "email"
	case in.Purpose == int32(PurposeEnroll):
		row.Kind, row.Challenge, row.UserHandle = FlowEnrollment, randomBytes(passkey.ChallengeBytes), randomBytes(32)
		row.MaxAttempts, row.ExpiresAt = passkeyAttempts, now.Add(s.policy.PasskeyFlowLifetime)
		options := s.rp.CreationOptions(row.UserHandle, nil)
		result.Challenge, result.Options, result.ProviderID = row.Challenge, &options, "passkey"
	default:
		row.Kind, row.Challenge = FlowPasskeySignIn, randomBytes(passkey.ChallengeBytes)
		row.MaxAttempts, row.ExpiresAt = passkeyAttempts, now.Add(s.policy.PasskeyFlowLifetime)
		options := s.rp.LoginOptions()
		result.Challenge, result.Options, result.ProviderID = row.Challenge, &options, "passkey"
	}
	result.ExpiresAt = row.ExpiresAt
	err := s.db.InTx(ctx, "begin a sign-in", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error { return s.insertFlow(ctx, tx, row) })
	if err != nil {
		return Challenge{}, err
	}
	s.events.ObserveIdentity("sign_in_begin", methodLabel(in.Method))
	return result, nil
}

func methodLabel(method int32) string {
	if method == MethodValueEmail {
		return "email_code"
	}
	return "passkey"
}

// storedPasskey is a live passkey and its owner.
type storedPasskey struct {
	identityID platform.ID
	userID     platform.ID
	state      UserState
	stored     passkey.Stored
}

func (s *Service) findPasskey(ctx context.Context, credentialID []byte) (*storedPasskey, error) {
	var found *storedPasskey
	err := s.db.InTx(ctx, "find a passkey", store.TxOptions{ReadOnly: true, Timeout: 5 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
		found = nil
		var item storedPasskey
		var state int16
		var signCount int64
		err := tx.QueryRow(ctx, `SELECT a.auth_identity_id, a.user_id, u.state, u.passkey_user_handle, a.public_key, a.sign_count, a.backup_eligible,
    a.backup_state, a.aaguid, a.attestation_format
FROM identity.auth_identity a JOIN identity.user u ON u.user_id = a.user_id
WHERE a.provider_id = 'passkey' AND a.subject = $1 AND a.revoked_at IS NULL`, base64.RawURLEncoding.EncodeToString(credentialID)).Scan(
			&item.identityID, &item.userID, &state, &item.stored.UserHandle, &item.stored.Credential.PublicKey, &signCount,
			&item.stored.Credential.BackupEligible, &item.stored.Credential.BackupState, &item.stored.Credential.AAGUID,
			&item.stored.Credential.AttestationFormat)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		item.state = UserState(state)
		item.stored.Credential.ID = credentialID
		item.stored.Credential.SignCount = uint32(signCount)
		found = &item
		return nil
	})
	return found, err
}

// validAssertion checks the contract's bounds of a WebAuthnAssertion; a discoverable sign-in needs the user handle.
func validAssertion(assertion passkey.Assertion) *arc.Refusal {
	switch {
	case len(assertion.CredentialID) < 1 || len(assertion.CredentialID) > MaxCredentialIDBytes:
		return arc.InvalidArgument("proof.passkey.credential_id", "length")
	case len(assertion.ClientDataJSON) < 1 || len(assertion.ClientDataJSON) > 16384:
		return arc.InvalidArgument("proof.passkey.client_data_json", "length")
	case len(assertion.AuthenticatorData) < 1 || len(assertion.AuthenticatorData) > 16384:
		return arc.InvalidArgument("proof.passkey.authenticator_data", "length")
	case len(assertion.Signature) < 1 || len(assertion.Signature) > 256:
		return arc.InvalidArgument("proof.passkey.signature", "length")
	case len(assertion.UserHandle) < 1 || len(assertion.UserHandle) > 64:
		return arc.InvalidArgument("proof.passkey.user_handle", "required")
	}
	return nil
}

// CompletePasskey completes a discoverable passkey sign-in (CompleteAuthentication with a passkey proof): the sign-in bucket of
// the client's prefix, the failure bucket of the account the credential names (or of the unknown credential), the flow's one
// attempt, then the WebAuthn verification outside any transaction, and one success transaction that consumes the flow, advances
// the credential's counter, finds or creates the device and installation of the flow's claim and issues an account session.
// Every failure of the proof (unknown credential, an account that may not sign in, a ceremony that does not verify) gives the
// same AUTHENTICATION/unauthenticated.
func (s *Service) CompletePasskey(ctx context.Context, request Request, flowID platform.ID, assertion passkey.Assertion) (SignedIn, error) {
	if refusal := validAssertion(assertion); refusal != nil {
		return SignedIn{}, refusal
	}
	if err := s.take(ctx, request, s.bucket(ratelimit.SignInPrefix, ratelimit.Prefix(request.ClientIP)), Anonymous); err != nil {
		return SignedIn{}, err
	}
	found, err := s.findPasskey(ctx, assertion.CredentialID)
	if err != nil {
		return SignedIn{}, err
	}
	accountKey := "credential:" + hex.EncodeToString(sha256Of(assertion.CredentialID))
	actor := Anonymous
	if found != nil {
		accountKey, actor = "account:"+found.userID.String(), Actor(found.userID)
	}
	failures := s.bucket(ratelimit.SignInFailuresAccount, accountKey)
	if err = s.check(ctx, request, failures, actor); err != nil {
		return SignedIn{}, err
	}
	row, err := s.takeAttempt(ctx, flowID, ChannelNative, []FlowKind{FlowPasskeySignIn}, PurposeAuthenticate)
	if err != nil {
		return SignedIn{}, err
	}
	refuse := func(reason string) (SignedIn, error) {
		s.events.ObserveIdentity("sign_in_complete", "refused")
		if err := s.exhaust(ctx, row.ID); err != nil {
			return SignedIn{}, err
		}
		if err := s.fail(ctx, request, failures, actor, "identity.sign_in.failed", reason, map[string]any{"method": "passkey", "channel": "native"}); err != nil {
			return SignedIn{}, err
		}
		return SignedIn{}, arc.Unauthenticated()
	}
	if found == nil {
		return refuse("unknown_credential")
	}
	if !found.state.MaySignIn() {
		return refuse("account_state")
	}
	verified, err := s.rp.VerifyAssertion(row.Challenge, assertion, found.stored, row.ExpiresAt)
	if err != nil {
		return refuse("passkey_invalid")
	}
	result, err := s.signIn(ctx, request, row, found.userID, int16(MethodPasskey), func(ctx context.Context, tx pgx.Tx, now time.Time) error {
		// A concurrent sign-in that advanced the counter past this one refuses it as a possible clone.
		return advanceCounter(ctx, tx, found.identityID, verified, now)
	})
	if refusal := refusalOf(err); refusal != nil && refusal.Code == "unauthenticated" {
		return refuse("sign_in_refused")
	}
	return result, err
}

func sha256Of(data []byte) []byte {
	digest := sha256.Sum256(data)
	return digest[:]
}

// signIn is the success transaction of a native sign-in: it consumes the flow, runs the method's own changes, re-reads the
// account's state, finds or creates the device and installation of the flow's claim, issues an account session and audits it.
// A refusal inside it rolls it back and ends the flow.
func (s *Service) signIn(ctx context.Context, request Request, row flow, userID platform.ID, method int16,
	changes func(ctx context.Context, tx pgx.Tx, now time.Time) error) (SignedIn, error) {
	if row.Claim == nil {
		return SignedIn{}, arc.Internal()
	}
	var result SignedIn
	err := s.db.InTx(ctx, "complete a sign-in", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		result = SignedIn{}
		now := s.now()
		if err := consume(ctx, tx, row.ID, now); err != nil {
			return err
		}
		if err := changes(ctx, tx, now); err != nil {
			return err
		}
		var state int16
		if err := tx.QueryRow(ctx, "SELECT state FROM identity.user WHERE user_id = $1 FOR SHARE", userID).Scan(&state); err != nil {
			return err
		}
		if !UserState(state).MaySignIn() {
			return arc.Unauthenticated()
		}
		deviceID, err := device.EnsureNative(ctx, tx, userID, *row.Claim, now)
		if err != nil {
			return err
		}
		issued, err := session.IssueNative(ctx, tx, s.policy, session.Grant{UserID: userID, DeviceID: deviceID, InstallationID: row.Claim.InstallationID,
			Scope: session.ScopeAccount, Product: row.Claim.Product, Purpose: session.PurposeAuthenticate, AuthMethod: method, AuthenticatedAt: now}, now)
		if err != nil {
			return err
		}
		view, err := device.Get(ctx, tx, userID, deviceID)
		if err != nil || view == nil {
			return errors.Join(err, errors.New("the new device is not readable"))
		}
		result = SignedIn{Session: issued, Device: *view}
		return s.audit(ctx, tx, request, Actor(userID), "identity.sign_in.succeeded", "", "session", issued.SessionID.String(),
			map[string]any{"method": methodName(method), "channel": "native", "scope": "account"})
	})
	if err != nil {
		if refusalOf(err) == nil {
			// The proof verified and the store failed (a lost race for a new installation included, D4): the attempt is given back
			// for the advised retry.
			s.release(ctx, row.ID)
		} else if exhaustErr := s.exhaust(ctx, row.ID); exhaustErr != nil {
			return SignedIn{}, exhaustErr
		}
		return SignedIn{}, err
	}
	s.events.ObserveIdentity("sign_in_complete", "succeeded")
	return result, nil
}

func methodName(method int16) string {
	if Method(method) == MethodEmailCode {
		return "email_code"
	}
	return "passkey"
}
