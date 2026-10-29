// SPDX-License-Identifier: AGPL-3.0-only

package passkey_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/identity/passkey"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey/virtual"
)

const (
	rpID   = "center.example.test"
	origin = "https://center.example.test"
)

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return data
}

func relyingParty(t *testing.T, id, at string) *passkey.RelyingParty {
	t.Helper()
	rp, err := passkey.New(id, at)
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

type vector struct {
	creation  passkey.Creation
	challenge []byte
}

// vectors reads the W3C WebAuthn Level 3 section 16 registration test vectors (https://www.w3.org/TR/webauthn-3/#sctn-test-vectors:
// RP ID example.org, origin https://example.org) from the admitted go-webauthn module itself, whose spec test transcribes them
// (protocol/attestation_spec_test.go of the version go.sum pins), so no copy of them is kept here.
func vectors(t *testing.T) map[string]vector {
	t.Helper()
	output, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/go-webauthn/webauthn").Output()
	if err != nil {
		t.Fatalf("locate the go-webauthn module: %v", err)
	}
	source, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(output)), "protocol", "attestation_spec_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]vector{}
	for name, function := range map[string]string{"none-es256": "TestSpecVectors_NoneES256", "packed-self-es256": "TestSpecVectors_PackedSelfES256"} {
		text := string(source)
		start := strings.Index(text, "func "+function+"(")
		if start < 0 {
			t.Fatalf("the module has no %s", function)
		}
		text = text[start:]
		field := func(pattern string) []byte {
			match := regexp.MustCompile(pattern).FindStringSubmatch(text)
			if match == nil {
				t.Fatalf("%s: no %s", function, pattern)
			}
			value, err := hex.DecodeString(match[1])
			if err != nil {
				t.Fatal(err)
			}
			return value
		}
		clientData := field(`clientDataJSONHex := "([0-9a-f]+)"`)
		var collected struct {
			Challenge string `json:"challenge"`
			Origin    string `json:"origin"`
		}
		if err = json.Unmarshal(clientData, &collected); err != nil || collected.Origin != "https://example.org" {
			t.Fatalf("%s: client data %v", function, err)
		}
		challenge, err := base64.RawURLEncoding.DecodeString(collected.Challenge)
		if err != nil {
			t.Fatal(err)
		}
		result[name] = vector{challenge: challenge, creation: passkey.Creation{
			CredentialID: field(`credID := specTestDecodeHex\(t, "([0-9a-f]+)"\)`), ClientDataJSON: clientData,
			AttestationObject: field(`attObjHex := "([0-9a-f]+)"`),
		}}
	}
	return result
}

// TestTheW3CVectorsMeetThePolicy runs the specification's registration vectors (sections 16.2 and 16.3) through the relying party: the "none" ES256 vector
// verifies except for user verification, which the vector does not set and the center requires, and the packed self-attested
// vector is refused for its attestation format. A wrong origin, RP ID or challenge refuses either.
func TestTheW3CVectorsMeetThePolicy(t *testing.T) {
	all := vectors(t)
	none, packed := all["none-es256"], all["packed-self-es256"]
	if len(none.challenge) != passkey.ChallengeBytes || len(packed.challenge) != passkey.ChallengeBytes {
		t.Fatal("the vectors' challenges are not 32 bytes")
	}
	handle := randomBytes(t, 32)
	expires := time.Now().Add(time.Minute)
	strict := relyingParty(t, "example.org", "https://example.org")
	if _, err := strict.VerifyCreation(none.challenge, handle, none.creation, expires); !errors.Is(err, passkey.ErrRefused) {
		t.Fatal("a registration without user verification was admitted")
	}
	lenient := passkey.WithoutUserVerification(strict)
	credential, err := lenient.VerifyCreation(none.challenge, handle, none.creation, expires)
	if err != nil {
		t.Fatalf("the none ES256 vector: %v", err)
	}
	if !bytes.Equal(credential.ID, none.creation.CredentialID) || credential.AttestationFormat != "none" || !credential.BackupEligible ||
		!credential.BackupState || credential.SignCount != 0 || len(credential.AAGUID) != 16 {
		t.Fatalf("credential %+v", credential)
	}
	if _, err = lenient.VerifyCreation(packed.challenge, handle, packed.creation, expires); !errors.Is(err, passkey.ErrRefused) {
		t.Fatal("a packed attestation was admitted")
	}
	wrong := map[string]*passkey.RelyingParty{
		"another origin": passkey.WithoutUserVerification(relyingParty(t, "example.org", "https://other.example.org")),
		"another RP ID":  passkey.WithoutUserVerification(relyingParty(t, "example.com", "https://example.org")),
	}
	for name, rp := range wrong {
		if _, err = rp.VerifyCreation(none.challenge, handle, none.creation, expires); !errors.Is(err, passkey.ErrRefused) {
			t.Fatalf("%s was admitted", name)
		}
	}
	if _, err = lenient.VerifyCreation(randomBytes(t, 32), handle, none.creation, expires); !errors.Is(err, passkey.ErrRefused) {
		t.Fatal("another challenge was admitted")
	}
	if _, err = lenient.VerifyCreation(none.challenge, handle, none.creation, time.Now().Add(-time.Second)); !errors.Is(err, passkey.ErrRefused) {
		t.Fatal("an expired ceremony was admitted")
	}
}

func TestAVirtualPasskeyRegistersAndSignsIn(t *testing.T) {
	rp := relyingParty(t, rpID, origin)
	authenticator := virtual.New(rpID, origin)
	authenticator.BackupEligible = true
	handle, challenge, expires := randomBytes(t, 32), randomBytes(t, 32), time.Now().Add(time.Minute)
	creation, key := authenticator.Create(challenge, handle)
	credential, err := rp.VerifyCreation(challenge, handle, creation, expires)
	if err != nil {
		t.Fatal(err)
	}
	if !credential.BackupEligible || credential.BackupState || len(credential.Transports) != 1 || credential.Transports[0] != "internal" {
		t.Fatalf("credential %+v", credential)
	}
	stored := passkey.Stored{UserHandle: handle, Credential: credential}
	for range 3 {
		login := randomBytes(t, 32)
		verified, err := rp.VerifyAssertion(login, authenticator.Assert(key, login), stored, expires)
		if err != nil {
			t.Fatal(err)
		}
		if verified.SignCount != key.Counter {
			t.Fatalf("counter %d, want %d", verified.SignCount, key.Counter)
		}
		stored.Credential.SignCount = verified.SignCount
	}
	options := rp.LoginOptions()
	if options.RPID != rpID || options.UserVerification != "required" || len(options.Algorithms) != 1 || options.Algorithms[0] != -7 ||
		len(options.UserHandle) != 0 {
		t.Fatalf("login options %+v", options)
	}
	creationOptions := rp.CreationOptions(handle, [][]byte{key.ID})
	if !bytes.Equal(creationOptions.UserHandle, handle) || len(creationOptions.Excluded) != 1 {
		t.Fatalf("creation options %+v", creationOptions)
	}
}

func TestRegistrationsOutsideThePolicyAreRefused(t *testing.T) {
	rp := relyingParty(t, rpID, origin)
	cases := map[string]func(*virtual.Authenticator){
		"no user verification":    func(a *virtual.Authenticator) { a.SkipUV = true },
		"no user presence":        func(a *virtual.Authenticator) { a.NoPresence = true },
		"another origin":          func(a *virtual.Authenticator) { a.Origin = "https://evil.example.test" },
		"another RP ID":           func(a *virtual.Authenticator) { a.ClientRPID = "example.test" },
		"a sign-in's client data": func(a *virtual.Authenticator) { a.ClientType = "webauthn.get" },
		"an RS256 key":            func(a *virtual.Authenticator) { a.RS256 = true },
		"a packed attestation":    func(a *virtual.Authenticator) { a.Format = "packed" },
		"backed up, not eligible": func(a *virtual.Authenticator) { a.BackedUp = true },
	}
	for name, change := range cases {
		authenticator := virtual.New(rpID, origin)
		change(authenticator)
		handle, challenge := randomBytes(t, 32), randomBytes(t, 32)
		creation, _ := authenticator.Create(challenge, handle)
		if _, err := rp.VerifyCreation(challenge, handle, creation, time.Now().Add(time.Minute)); !errors.Is(err, passkey.ErrRefused) {
			t.Errorf("%s was admitted", name)
		}
	}
	authenticator := virtual.New(rpID, origin)
	handle, challenge := randomBytes(t, 32), randomBytes(t, 32)
	creation, _ := authenticator.Create(challenge, handle)
	if _, err := rp.VerifyCreation(challenge, randomBytes(t, 32), creation, time.Now().Add(time.Minute)); err != nil {
		// The user handle is the flow's: the authenticator stores whatever it was given, so another handle still verifies; the
		// flow binds the handle, not the attestation.
		t.Fatalf("the flow's handle: %v", err)
	}
	if _, err := rp.VerifyCreation(challenge[:16], handle, creation, time.Now().Add(time.Minute)); !errors.Is(err, passkey.ErrRefused) {
		t.Fatal("a short challenge was admitted")
	}
}

func TestSignInsOutsideThePolicyAreRefused(t *testing.T) {
	rp := relyingParty(t, rpID, origin)
	setup := func(change func(*virtual.Authenticator)) (*virtual.Authenticator, *virtual.Key, passkey.Stored) {
		authenticator := virtual.New(rpID, origin)
		handle, challenge := randomBytes(t, 32), randomBytes(t, 32)
		creation, key := authenticator.Create(challenge, handle)
		credential, err := rp.VerifyCreation(challenge, handle, creation, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		change(authenticator)
		return authenticator, key, passkey.Stored{UserHandle: handle, Credential: credential}
	}
	expires := time.Now().Add(time.Minute)
	cases := map[string]func(*testing.T) (passkey.Assertion, []byte, passkey.Stored, time.Time){
		"no user verification": func(t *testing.T) (passkey.Assertion, []byte, passkey.Stored, time.Time) {
			a, key, stored := setup(func(a *virtual.Authenticator) { a.SkipUV = true })
			challenge := randomBytes(t, 32)
			return a.Assert(key, challenge), challenge, stored, expires
		},
		"another origin": func(t *testing.T) (passkey.Assertion, []byte, passkey.Stored, time.Time) {
			a, key, stored := setup(func(a *virtual.Authenticator) { a.Origin = "https://evil.example.test" })
			challenge := randomBytes(t, 32)
			return a.Assert(key, challenge), challenge, stored, expires
		},
		"another challenge": func(t *testing.T) (passkey.Assertion, []byte, passkey.Stored, time.Time) {
			a, key, stored := setup(func(*virtual.Authenticator) {})
			return a.Assert(key, randomBytes(t, 32)), randomBytes(t, 32), stored, expires
		},
		"a counter that does not advance": func(t *testing.T) (passkey.Assertion, []byte, passkey.Stored, time.Time) {
			a, key, stored := setup(func(*virtual.Authenticator) {})
			stored.Credential.SignCount = 7
			challenge := randomBytes(t, 32)
			return a.Assert(key, challenge, 7), challenge, stored, expires
		},
		"another user handle": func(t *testing.T) (passkey.Assertion, []byte, passkey.Stored, time.Time) {
			a, key, stored := setup(func(*virtual.Authenticator) {})
			stored.UserHandle = randomBytes(t, 32)
			challenge := randomBytes(t, 32)
			return a.Assert(key, challenge), challenge, stored, expires
		},
		"no user handle": func(t *testing.T) (passkey.Assertion, []byte, passkey.Stored, time.Time) {
			a, key, stored := setup(func(*virtual.Authenticator) {})
			challenge := randomBytes(t, 32)
			assertion := a.Assert(key, challenge)
			assertion.UserHandle = nil
			return assertion, challenge, stored, expires
		},
		"another credential's key": func(t *testing.T) (passkey.Assertion, []byte, passkey.Stored, time.Time) {
			a, key, stored := setup(func(*virtual.Authenticator) {})
			_, other, _ := setup(func(*virtual.Authenticator) {})
			other.ID, other.UserHandle = key.ID, key.UserHandle
			challenge := randomBytes(t, 32)
			return a.Assert(other, challenge), challenge, stored, expires
		},
		"backup eligibility changed": func(t *testing.T) (passkey.Assertion, []byte, passkey.Stored, time.Time) {
			a, key, stored := setup(func(a *virtual.Authenticator) { a.BackupEligible = true })
			challenge := randomBytes(t, 32)
			return a.Assert(key, challenge), challenge, stored, expires
		},
		"a registration's client data": func(t *testing.T) (passkey.Assertion, []byte, passkey.Stored, time.Time) {
			a, key, stored := setup(func(a *virtual.Authenticator) { a.ClientType = "webauthn.create" })
			challenge := randomBytes(t, 32)
			return a.Assert(key, challenge), challenge, stored, expires
		},
		"an expired ceremony": func(t *testing.T) (passkey.Assertion, []byte, passkey.Stored, time.Time) {
			a, key, stored := setup(func(*virtual.Authenticator) {})
			challenge := randomBytes(t, 32)
			return a.Assert(key, challenge), challenge, stored, time.Now().Add(-time.Second)
		},
	}
	for name, build := range cases {
		assertion, challenge, stored, until := build(t)
		if _, err := rp.VerifyAssertion(challenge, assertion, stored, until); !errors.Is(err, passkey.ErrRefused) {
			t.Errorf("%s was admitted", name)
		}
	}
}
