// SPDX-License-Identifier: AGPL-3.0-only

// Package virtual is a software WebAuthn authenticator for tests (never linked into the center): it creates ES256 credentials
// with attestation "none", answers discoverable sign-ins with the stored user handle and counts signatures. Every key is
// generated at run time. Its knobs produce the ceremonies the relying party must refuse: no user verification, a wrong origin, a
// wrong RP ID, another attestation format, an RS256 key and a counter that does not advance.
package virtual

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"

	"github.com/ArcForges/Cloud/center/internal/identity/passkey"
)

// The authenticator data flags.
const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
	flagAT = 0x40
)

// Authenticator is one virtual authenticator of an RP ID, used from one origin.
type Authenticator struct {
	RPID   string
	Origin string
	// SkipUV leaves the user-verification flag unset; NoPresence leaves the user-presence flag unset.
	SkipUV     bool
	NoPresence bool
	// BackupEligible and BackedUp set the BE and BS flags.
	BackupEligible bool
	BackedUp       bool
	// Format is the attestation format ("none" when empty); a non-empty other format adds a dummy statement.
	Format string
	// RS256 creates RSA keys (algorithm -257) instead of ES256.
	RS256 bool
	// ClientRPID overrides the RP ID hashed into the authenticator data; ClientType overrides the client data type.
	ClientRPID string
	ClientType string
}

// Key is one created credential.
type Key struct {
	ID         []byte
	UserHandle []byte
	Counter    uint32
	ec         *ecdsa.PrivateKey
	rsa        *rsa.PrivateKey
}

// New is an authenticator for an RP ID and origin.
func New(rpID, origin string) *Authenticator { return &Authenticator{RPID: rpID, Origin: origin} }

func (a *Authenticator) flags(attested bool) byte {
	flags := byte(0)
	if !a.NoPresence {
		flags |= flagUP
	}
	if !a.SkipUV {
		flags |= flagUV
	}
	if a.BackupEligible {
		flags |= flagBE
	}
	if a.BackedUp {
		flags |= flagBS
	}
	if attested {
		flags |= flagAT
	}
	return flags
}

func (a *Authenticator) clientData(kind string, challenge []byte) []byte {
	if a.ClientType != "" {
		kind = a.ClientType
	}
	data, err := json.Marshal(map[string]any{"type": kind, "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": a.Origin,
		"crossOrigin": false})
	if err != nil {
		panic(err)
	}
	return data
}

func (a *Authenticator) rpIDHash() []byte {
	rpID := a.RPID
	if a.ClientRPID != "" {
		rpID = a.ClientRPID
	}
	hash := sha256.Sum256([]byte(rpID))
	return hash[:]
}

func random(size int) []byte {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}
	return data
}

// Create makes a new credential for a registration challenge and user handle.
func (a *Authenticator) Create(challenge, userHandle []byte) (passkey.Creation, *Key) {
	key := &Key{ID: random(32), UserHandle: append([]byte(nil), userHandle...)}
	var cose []byte
	var err error
	if a.RS256 {
		if key.rsa, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		exponent := make([]byte, 4)
		binary.BigEndian.PutUint32(exponent, uint32(key.rsa.E))
		cose, err = webauthncbor.Marshal(map[int]any{1: 3, 3: -257, -1: key.rsa.N.Bytes(), -2: exponent[1:]})
	} else {
		if key.ec, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			panic(err)
		}
		point, pointErr := key.ec.PublicKey.Bytes()
		if pointErr != nil {
			panic(pointErr)
		}
		cose, err = webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: point[1:33], -3: point[33:65]})
	}
	if err != nil {
		panic(err)
	}
	authData := append([]byte{}, a.rpIDHash()...)
	authData = append(authData, a.flags(true), 0, 0, 0, 0)
	authData = append(authData, make([]byte, 16)...) // AAGUID: zero, as a "none" attestation reports
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(key.ID)))
	authData = append(authData, key.ID...)
	authData = append(authData, cose...)
	format := a.Format
	statement := map[string]any{}
	if format == "" {
		format = passkey.AttestationNone
	} else if format != passkey.AttestationNone {
		statement = map[string]any{"alg": -7, "sig": []byte{0}}
	}
	clientData := a.clientData("webauthn.create", challenge)
	if format == "packed" {
		// Self attestation: the credential key signs the authenticator data and the client data hash.
		hash := sha256.Sum256(clientData)
		statement = map[string]any{"alg": -7, "sig": key.sign(append(append([]byte{}, authData...), hash[:]...))}
	}
	object, err := webauthncbor.Marshal(map[string]any{"fmt": format, "attStmt": statement, "authData": authData})
	if err != nil {
		panic(err)
	}
	return passkey.Creation{CredentialID: key.ID, ClientDataJSON: clientData, AttestationObject: object, Transports: []string{"internal"}}, key
}

func (k *Key) sign(message []byte) []byte {
	digest := sha256.Sum256(message)
	if k.rsa != nil {
		signature, err := rsa.SignPKCS1v15(rand.Reader, k.rsa, crypto.SHA256, digest[:])
		if err != nil {
			panic(err)
		}
		return signature
	}
	signature, err := ecdsa.SignASN1(rand.Reader, k.ec, digest[:])
	if err != nil {
		panic(err)
	}
	return signature
}

// Assert answers a sign-in challenge with a key: the counter advances by one unless counter is given.
func (a *Authenticator) Assert(key *Key, challenge []byte, counter ...uint32) passkey.Assertion {
	if len(counter) > 0 {
		key.Counter = counter[0]
	} else {
		key.Counter++
	}
	authData := append([]byte{}, a.rpIDHash()...)
	authData = append(authData, a.flags(false))
	authData = binary.BigEndian.AppendUint32(authData, key.Counter)
	clientData := a.clientData("webauthn.get", challenge)
	hash := sha256.Sum256(clientData)
	return passkey.Assertion{
		CredentialID: key.ID, ClientDataJSON: clientData, AuthenticatorData: authData,
		Signature: key.sign(append(append([]byte{}, authData...), hash[:]...)), UserHandle: key.UserHandle,
	}
}
