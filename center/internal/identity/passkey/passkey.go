// SPDX-License-Identifier: AGPL-3.0-only

// Package passkey is the center's WebAuthn relying party (AF-CTR-03; ArcForges-Design AD-0011 section 4, AD-0021 section 5) over
// github.com/go-webauthn/webauthn. The policy is fixed and narrow: the RP ID is the host of the public base URL and the only
// origin is its origin (no cross-origin use, no top origins, no Android origins until the Android task); user verification is
// required on every ceremony; the only algorithm is ES256 (-7); a registration is admitted only with attestation "none"; a
// discoverable sign-in must name the credential owner's user handle; a signature counter that does not advance (a possible
// clone) is refused. The center generates and stores every challenge itself and rebuilds the library's session data from its
// flow rows. Every library error becomes the one ErrRefused, so no refusal says which check failed.
package passkey

import (
	"bytes"
	"encoding/base64"
	"errors"
	"slices"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
)

// The fixed policy values, as the contract's WebAuthnOptions carry them.
const (
	UserVerification = "required"
	// AlgorithmES256 is the one admitted COSE algorithm.
	AlgorithmES256 = int32(webauthncose.AlgES256)
	// ChallengeBytes is the length of every challenge the center issues.
	ChallengeBytes = 32
	// AttestationNone is the one admitted attestation format.
	AttestationNone = "none"
)

// ErrRefused is the one error of a ceremony that does not verify.
var ErrRefused = errors.New("the passkey ceremony did not verify")

// RelyingParty verifies the ceremonies of one public origin.
type RelyingParty struct {
	library   *webauthn.WebAuthn
	rpID      string
	origin    string
	requireUV bool
}

// New is the relying party of an RP ID (the public base URL's host) and its one origin.
func New(rpID, origin string) (*RelyingParty, error) {
	library, err := webauthn.New(&webauthn.Config{
		RPID: rpID, RPDisplayName: "ArcForges", RPOrigins: []string{origin}, AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired},
	})
	if err != nil {
		return nil, err
	}
	return &RelyingParty{library: library, rpID: rpID, origin: origin, requireUV: true}, nil
}

// RPID is the relying party ID.
func (rp *RelyingParty) RPID() string { return rp.rpID }

// Origin is the one admitted origin.
func (rp *RelyingParty) Origin() string { return rp.origin }

// Options are the ceremony options the client passes to the authenticator (the contract's WebAuthnOptions).
type Options struct {
	RPID             string
	UserHandle       []byte
	Allowed          [][]byte
	Excluded         [][]byte
	UserVerification string
	Algorithms       []int32
}

// LoginOptions are the options of a discoverable sign-in: no allowed credentials, user verification required.
func (rp *RelyingParty) LoginOptions() Options {
	return Options{RPID: rp.rpID, UserVerification: UserVerification, Algorithms: []int32{AlgorithmES256}}
}

// StepUpOptions are the options of a step-up of a known account: its passkeys are named as the allowed credentials, user
// verification is required, and the assertion is verified like a discoverable sign-in (it must name the owner's user handle).
func (rp *RelyingParty) StepUpOptions(allowed [][]byte) Options {
	return Options{RPID: rp.rpID, Allowed: allowed, UserVerification: UserVerification, Algorithms: []int32{AlgorithmES256}}
}

// CreationOptions are the options of a registration for a user handle, excluding the user's existing credentials.
func (rp *RelyingParty) CreationOptions(userHandle []byte, excluded [][]byte) Options {
	return Options{RPID: rp.rpID, UserHandle: slices.Clone(userHandle), Excluded: excluded, UserVerification: UserVerification,
		Algorithms: []int32{AlgorithmES256}}
}

// Creation is the client's registration result (the contract's WebAuthnCreation).
type Creation struct {
	CredentialID      []byte
	ClientDataJSON    []byte
	AttestationObject []byte
	Transports        []string
}

// Credential is a verified passkey as the store keeps it.
type Credential struct {
	ID                []byte
	PublicKey         []byte
	SignCount         uint32
	BackupEligible    bool
	BackupState       bool
	Transports        []string
	AAGUID            []byte
	AttestationFormat string
}

type user struct {
	handle      []byte
	credentials []webauthn.Credential
}

func (u *user) WebAuthnID() []byte                         { return u.handle }
func (u *user) WebAuthnName() string                       { return "account" }
func (u *user) WebAuthnDisplayName() string                { return "account" }
func (u *user) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func (rp *RelyingParty) session(challenge, userHandle []byte, expires time.Time, credParams bool) webauthn.SessionData {
	session := webauthn.SessionData{
		Challenge: base64.RawURLEncoding.EncodeToString(challenge), RelyingPartyID: rp.rpID, UserID: slices.Clone(userHandle), Expires: expires,
		UserVerification: protocol.VerificationPreferred,
	}
	if rp.requireUV {
		session.UserVerification = protocol.VerificationRequired
	}
	if credParams {
		session.CredParams = []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}}
	}
	return session
}

// VerifyCreation verifies a registration against the challenge and user handle of its flow: the client data (type, challenge,
// origin), the RP ID hash, user presence and verification, the algorithm, the attestation format "none" and the flags.
func (rp *RelyingParty) VerifyCreation(challenge, userHandle []byte, creation Creation, expires time.Time) (Credential, error) {
	if len(challenge) != ChallengeBytes || len(userHandle) == 0 || len(creation.CredentialID) == 0 {
		return Credential{}, ErrRefused
	}
	response := protocol.CredentialCreationResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{ID: base64.RawURLEncoding.EncodeToString(creation.CredentialID), Type: string(protocol.PublicKeyCredentialType)},
			RawID:      creation.CredentialID,
		},
		AttestationResponse: protocol.AuthenticatorAttestationResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: creation.ClientDataJSON},
			Transports:            creation.Transports, AttestationObject: creation.AttestationObject,
		},
	}
	parsed, err := response.Parse()
	if err != nil {
		return Credential{}, ErrRefused
	}
	created, err := rp.library.CreateCredential(&user{handle: userHandle}, rp.session(challenge, userHandle, expires, true), parsed)
	if err != nil || created.AttestationFormat != AttestationNone || !bytes.Equal(created.ID, creation.CredentialID) {
		return Credential{}, ErrRefused
	}
	if rp.requireUV && !created.Flags.UserVerified {
		return Credential{}, ErrRefused
	}
	key, err := webauthncose.ParsePublicKey(created.PublicKey)
	if err != nil {
		return Credential{}, ErrRefused
	}
	ec2, ok := key.(webauthncose.EC2PublicKeyData)
	if !ok || ec2.Algorithm != int64(webauthncose.AlgES256) || ec2.Curve != 1 {
		return Credential{}, ErrRefused
	}
	credential := Credential{
		ID: created.ID, PublicKey: created.PublicKey, SignCount: created.Authenticator.SignCount, BackupEligible: created.Flags.BackupEligible,
		BackupState: created.Flags.BackupState, AAGUID: created.Authenticator.AAGUID, AttestationFormat: AttestationNone, Transports: []string{},
	}
	for _, transport := range created.Transport {
		credential.Transports = append(credential.Transports, string(transport))
	}
	if len(credential.AAGUID) != 16 {
		credential.AAGUID = make([]byte, 16)
	}
	return credential, nil
}

// Assertion is the client's sign-in result (the contract's WebAuthnAssertion).
type Assertion struct {
	CredentialID      []byte
	ClientDataJSON    []byte
	AuthenticatorData []byte
	Signature         []byte
	UserHandle        []byte
}

// Stored is the stored credential an assertion names and its owner's user handle.
type Stored struct {
	UserHandle []byte
	Credential Credential
}

// Verified is what a verified assertion changes on the stored credential.
type Verified struct {
	SignCount   uint32
	BackupState bool
}

// VerifyAssertion verifies a discoverable sign-in against the challenge of its flow and the stored credential it names: the
// user handle must be the owner's, the signature must verify with the stored key, user presence and verification must be set,
// the backup eligibility must be unchanged and the counter must advance (or stay zero on both sides).
func (rp *RelyingParty) VerifyAssertion(challenge []byte, assertion Assertion, stored Stored, expires time.Time) (Verified, error) {
	if len(challenge) != ChallengeBytes || len(assertion.UserHandle) == 0 || !bytes.Equal(assertion.CredentialID, stored.Credential.ID) ||
		!bytes.Equal(assertion.UserHandle, stored.UserHandle) {
		return Verified{}, ErrRefused
	}
	response := protocol.CredentialAssertionResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{ID: base64.RawURLEncoding.EncodeToString(assertion.CredentialID), Type: string(protocol.PublicKeyCredentialType)},
			RawID:      assertion.CredentialID,
		},
		AssertionResponse: protocol.AuthenticatorAssertionResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: assertion.ClientDataJSON},
			AuthenticatorData:     assertion.AuthenticatorData, Signature: assertion.Signature, UserHandle: assertion.UserHandle,
		},
	}
	parsed, err := response.Parse()
	if err != nil {
		return Verified{}, ErrRefused
	}
	owner := &user{handle: stored.UserHandle, credentials: []webauthn.Credential{{
		ID: stored.Credential.ID, PublicKey: stored.Credential.PublicKey, AttestationFormat: stored.Credential.AttestationFormat,
		Flags:         webauthn.CredentialFlags{UserPresent: true, UserVerified: true, BackupEligible: stored.Credential.BackupEligible, BackupState: stored.Credential.BackupState},
		Authenticator: webauthn.Authenticator{AAGUID: stored.Credential.AAGUID, SignCount: stored.Credential.SignCount},
	}}}
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		if !bytes.Equal(rawID, stored.Credential.ID) || !bytes.Equal(userHandle, stored.UserHandle) {
			return nil, ErrRefused
		}
		return owner, nil
	}
	_, credential, err := rp.library.ValidatePasskeyLogin(handler, rp.session(challenge, nil, expires, false), parsed)
	if err != nil || credential.Authenticator.CloneWarning {
		return Verified{}, ErrRefused
	}
	flags := parsed.Response.AuthenticatorData.Flags
	if !flags.HasUserPresent() || (rp.requireUV && !flags.HasUserVerified()) {
		return Verified{}, ErrRefused
	}
	return Verified{SignCount: credential.Authenticator.SignCount, BackupState: flags.HasBackupState()}, nil
}
