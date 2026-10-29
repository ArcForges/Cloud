// SPDX-License-Identifier: AGPL-3.0-only

package passkey_test

import (
	"bytes"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"

	"github.com/ArcForges/Cloud/center/internal/identity/passkey"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey/virtual"
)

// probeFormat is an attestation format the library dispatches to the probe below; no authenticator sends it.
const probeFormat = "x-arcforges-g3-probe"

var probeCalls atomic.Int64

func init() {
	protocol.RegisterAttestationFormat(probeFormat, func(protocol.AttestationObject, []byte, metadata.Provider, protocol.AttestationPolicy,
		protocol.SignaturePolicy) (string, []any, error) {
		probeCalls.Add(1)
		return "", nil, errors.New("the G3 probe statement parser was reached")
	})
}

// TestNoStatementParserRunsForAnotherFormat (G3): a registration that passes every other check (challenge, origin, RP ID hash,
// flags, ES256 key) but names another format is refused before the library dispatches its statement to a format parser.
func TestNoStatementParserRunsForAnotherFormat(t *testing.T) {
	authenticator := virtual.New(rpID, origin)
	authenticator.Format = probeFormat
	handle, challenge := randomBytes(t, 32), randomBytes(t, 32)
	creation, _ := authenticator.Create(challenge, handle)
	before := probeCalls.Load()
	_, err := relyingParty(t, rpID, origin).VerifyCreation(challenge, handle, creation, time.Now().Add(time.Minute))
	if !errors.Is(err, passkey.ErrRefused) {
		t.Fatal("a registration in another format was admitted")
	}
	if calls := probeCalls.Load() - before; calls != 0 {
		t.Fatalf("the library parsed the statement of a registration in another format (%d calls)", calls)
	}
}

// TestOnlyTheExactEmptyStatementIsNone (G3): a "none" registration whose statement is not exactly the empty map 0xa0 is refused,
// although the library alone would admit each of these (it decodes non-shortest lengths and skips a null or absent statement).
func TestOnlyTheExactEmptyStatementIsNone(t *testing.T) {
	key := append([]byte{0x67}, "attStmt"...)
	for name, statement := range map[string][]byte{
		"a two-byte length":   {0xb8, 0x00},
		"a three-byte length": {0xb9, 0x00, 0x00},
		"a null":              {0xf6},
	} {
		authenticator := virtual.New(rpID, origin)
		handle, challenge := randomBytes(t, 32), randomBytes(t, 32)
		creation, _ := authenticator.Create(challenge, handle)
		at := bytes.Index(creation.AttestationObject, append(append([]byte{}, key...), 0xa0))
		if at < 0 {
			t.Fatal("the virtual authenticator's none statement is not the empty map")
		}
		changed := append(append(append([]byte{}, creation.AttestationObject[:at+len(key)]...), statement...),
			creation.AttestationObject[at+len(key)+1:]...)
		original := creation.AttestationObject
		creation.AttestationObject = changed
		if _, err := relyingParty(t, rpID, origin).VerifyCreation(challenge, handle, creation, time.Now().Add(time.Minute)); !errors.Is(err, passkey.ErrRefused) {
			t.Errorf("a none registration with %s statement was admitted", name)
		}
		creation.AttestationObject = original
		if _, err := relyingParty(t, rpID, origin).VerifyCreation(challenge, handle, creation, time.Now().Add(time.Minute)); err != nil {
			t.Fatalf("the unchanged registration was refused: %v", err)
		}
	}
}
