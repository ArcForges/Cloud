// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// EVIDENCE: REAL (the center's own configuration loader, URL derivation, loopback redirect rule, node key proof message and
// verifier, node key check and fingerprint) over FIXED inputs. The signatures are made by FIXED TEST-ONLY P-256 keys (vectorKey),
// deterministically (RFC 6979), and normalized to the lower half as a node normalizes them. Nothing here reaches a database.
//
// The two files are the center's side of the vector lists the node is to share with it (protocol-4 item 3, node-13): they are made
// for the ArcForges node (part N1) to vendor byte for byte with their source commit, instead of a hand-made mirror of the center's
// rules, and to check its own URL canonicalization and derivation, proof message, verifier and fingerprint against; nothing in this
// repository checks a node against them. They are generated from the production functions; a file that differs from a fresh
// generation fails here.

// The vector files and the variable that rewrites them.
const (
	urlVectorsFile   = "testdata/url-vectors.json"
	proofVectorsFile = "testdata/node-key-proof-vectors.json"
	updateVectorsEnv = "ARCFORGES_UPDATE_VECTORS"
	vectorsSchema    = 1
)

// checkVectorFile compares a fresh generation with the committed file as JSON values (Prettier formats the committed file); with
// ARCFORGES_UPDATE_VECTORS=1 it writes the file instead.
func checkVectorFile(t *testing.T, path string, generated any) {
	t.Helper()
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(generated); err != nil {
		t.Fatal(err)
	}
	if os.Getenv(updateVectorsEnv) == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buffer.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v (run %s=1 go test -run TestFleetVectorFiles ./internal/fleet, then npx prettier --write it)", path, err, updateVectorsEnv)
	}
	var want, got any
	if err = json.Unmarshal(committed, &want); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if err = json.Unmarshal(buffer.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("%s differs from a fresh generation: run %s=1 go test -run TestFleetVectorFiles ./internal/fleet, then npx prettier --write it",
			path, updateVectorsEnv)
	}
}

// TestFleetVectorFiles (protocol-4 item 3, node-13, N1 decisions R-2 and G-4): the URL and the node key proof vector files equal a
// fresh generation from the production functions, and the generations hold the cases the node relies on.
func TestFleetVectorFiles(t *testing.T) {
	checkVectorFile(t, urlVectorsFile, urlVectors(t))
	checkVectorFile(t, proofVectorsFile, proofVectors(t))
}

// ---------------------------------------------------------------------------------------------------------------------------------
// URL derivation (protocol-4 item 3)

// urlVerdict is the center's answer to a value: accepted, or refused with the loader's reason (the reason text is informative).
type urlVerdict struct {
	Accepted bool   `json:"accepted"`
	Refusal  string `json:"refusal,omitempty"`
}

func verdictOf(err error) urlVerdict {
	if err != nil {
		return urlVerdict{Refusal: err.Error()}
	}
	return urlVerdict{Accepted: true}
}

// modeVerdicts are a mode's two answers: config.ParsePublicBaseURL alone, and the whole configuration loader of a center that serves
// the fleet surface (with identity and pages, which it needs): the public base URL bound of 462 characters and the passkey rule
// (a domain name, not an IP address) apply there.
type modeVerdicts struct {
	PublicBaseURL urlVerdict `json:"publicBaseUrl"`
	FleetCenter   urlVerdict `json:"fleetCenter"`
}

// derivedURLs are what a fleet center with this public base URL derives for a node, and the proof audience digest.
type derivedURLs struct {
	ProofAudienceSHA256     string `json:"proofAudienceSha256"`
	AuthorizeURL            string `json:"authorizeUrl"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	LongestLength           int    `json:"longestLength"`
}

type baseURLVector struct {
	Name           string       `json:"name"`
	Input          string       `json:"input"`
	Length         int          `json:"byteLength"`
	SelfHosted     modeVerdicts `json:"selfHosted"`
	OfficialHosted modeVerdicts `json:"officialHosted"`
	Derived        *derivedURLs `json:"derived,omitempty"`
}

type redirectVector struct {
	Name         string `json:"name"`
	Input        string `json:"input"`
	Accepted     bool   `json:"accepted"`
	CodeRedirect string `json:"codeRedirect,omitempty"`
	DenyRedirect string `json:"denyRedirect,omitempty"`
}

type urlVectorFile struct {
	SchemaVersion               int              `json:"schemaVersion"`
	Source                      string           `json:"source"`
	Rules                       []string         `json:"rules"`
	FlowID                      string           `json:"flowId"`
	FlowIDText                  string           `json:"flowIdText"`
	UserCode                    string           `json:"userCode"`
	DisplayUserCode             string           `json:"displayUserCode"`
	LoopbackCode                string           `json:"loopbackCode"`
	LoopbackState               string           `json:"loopbackState"`
	MaxDerivedURLLength         int              `json:"maxDerivedUrlLength"`
	MaxFleetPublicBaseURLLength int              `json:"maxFleetPublicBaseUrlLength"`
	MaxPublicBaseURLLength      int              `json:"maxPublicBaseUrlLength"`
	BaseURLs                    []baseURLVector  `json:"baseUrls"`
	Redirects                   []redirectVector `json:"redirects"`
}

// The fixed inputs of the derivation: a flow ID whose bytes are not symmetric (a byte-order swap shows), a user code of the alphabet,
// a loopback code and state as the center would send them back.
var (
	vectorFlowID   = platform.ID{0xf1, 0x0e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0x0f}
	vectorUserCode = "BCDFGHJK"
	vectorCode     = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xc5}, 32))
	vectorState    = "node-state-0123456789abcdefghij"
)

// loadFleetCenter runs the center's configuration loader for a center of the mode that serves the fleet surface at value. The database
// URL is parsed, never connected to.
func loadFleetCenter(value string, mode config.Mode) error {
	values := map[string]string{
		config.EnvMode: string(mode), config.EnvPublicBaseURL: value, config.EnvSurfaces: "identity,pages,fleet",
		config.EnvDatabaseURL: "postgres://center@127.0.0.1:5432/center?sslmode=disable",
	}
	if mode == config.OfficialHosted {
		values[config.EnvClientIPHeader] = config.ClientIPHeader
		values[config.EnvDatabaseURL] = "postgres://center@db.example.test:5432/center?sslmode=verify-full&channel_binding=require"
	}
	_, err := config.Load(func(key string) (string, bool) { value, ok := values[key]; return value, ok })
	return err
}

// pathOfLength is https://center.example.test/ followed by a path of letters, length characters in all.
func pathOfLength(length int) string {
	prefix := "https://center.example.test/"
	return prefix + strings.Repeat("a", length-len(prefix))
}

func urlVectors(t *testing.T) urlVectorFile {
	t.Helper()
	inputs := []struct{ name, value string }{
		{"the official center: a host and the path prefix /api", "https://arcforges.com/api"},
		{"a host without a path", "https://center.example.test"},
		{"a port and a path prefix", "https://center.example.test:8443/api"},
		{"the local official-hosted rehearsal (localhost, a port, /api)", "https://localhost:28443/api"},
		{"a deeper path of every admitted character class", "https://center.example.test/a-b/c_d/e.f/g~h/IJ09"},
		{"an internationalized host in its punycode form", "https://xn--bcher-kva.example/api"},
		{"http for localhost (self-hosted only)", "http://localhost:8080/api"},
		{"http for the IPv4 loopback (self-hosted only; an IP address is no passkey relying party)", "http://127.0.0.1:8080"},
		{"http for the IPv6 loopback (self-hosted only; an IP address is no passkey relying party)", "http://[::1]:8080"},
		{"https for an IP address (no passkey relying party)", "https://192.0.2.10/api"},
		{"the longest fleet public base URL: 462 characters", pathOfLength(config.MaxFleetPublicBaseURLLength)},
		{"one character over the fleet bound: 463 characters", pathOfLength(config.MaxFleetPublicBaseURLLength + 1)},
		{"the node's own bound: 512 characters", pathOfLength(MaxDerivedURLLength)},
		{"the configuration bound: 2048 characters", pathOfLength(config.MaxPublicBaseURLLength)},
		{"over the configuration bound: 2049 characters", pathOfLength(config.MaxPublicBaseURLLength + 1)},
		{"the internationalized host as Unicode", "https://bücher.example/api"},
		{"an upper-case host", "https://Center.example.test/api"},
		{"an upper-case scheme", "HTTPS://center.example.test/api"},
		{"a trailing slash", "https://center.example.test/api/"},
		{"a lone slash as the path", "https://center.example.test/"},
		{"the default https port", "https://center.example.test:443/api"},
		{"the default http port of localhost", "http://localhost:80/api"},
		{"an empty port", "https://center.example.test:/api"},
		{"port 0", "https://center.example.test:0/api"},
		{"port 65536", "https://center.example.test:65536/api"},
		{"a port with a leading zero", "https://center.example.test:08443/api"},
		{"a host with a trailing dot", "https://center.example.test./api"},
		{"http for a host that is not a loopback", "http://center.example.test/api"},
		{"another scheme", "ftp://center.example.test/api"},
		{"a query", "https://center.example.test/api?x=1"},
		{"an empty query", "https://center.example.test/api?"},
		{"a fragment", "https://center.example.test/api#top"},
		{"user information", "https://user@center.example.test/api"},
		{"percent-encoding", "https://center.example.test/%61pi"},
		{"a dot segment", "https://center.example.test/a/../api"},
		{"an empty path segment", "https://center.example.test//api"},
		{"a character outside the path classes", "https://center.example.test/a+b"},
		{"a space", "https://center.example.test/a b"},
		{"a backslash", "https://center.example.test\\api"},
		{"no scheme", "center.example.test/api"},
		{"empty", ""},
	}
	file := urlVectorFile{
		SchemaVersion: vectorsSchema, Source: "TestFleetVectorFiles (center/internal/fleet/vectors_test.go)",
		Rules: []string{
			"publicBaseUrl is config.ParsePublicBaseURL in the mode; the canonical form it returns is the input itself (the generator fails otherwise), so an accepted value is never rewritten",
			"fleetCenter is config.Load of a center of the mode that serves identity, pages and fleet: the public base URL is at most maxFleetPublicBaseUrlLength characters and its host is a domain name (passkeys), not an IP address",
			"derived is present when a fleet center of either mode accepts the input: authorizeUrl = input + /connect#flow= + flowIdText, verificationUri = input + /activate, verificationUriComplete = input + /activate#code= + displayUserCode, each at most maxDerivedUrlLength characters; proofAudienceSha256 is the SHA-256 of the input's bytes, the audience of a node key proof",
			"a refusal text is informative; the verdict is the accepted flag",
			"redirects: the loopback redirect URI a node sends (fleet.ValidLoopbackRedirect) and, when accepted, the redirect of an approval (fleet.CodeRedirect) and of a denial (fleet.DenyRedirect) with loopbackCode and loopbackState",
		},
		FlowID: hex.EncodeToString(vectorFlowID[:]), FlowIDText: vectorFlowID.String(), UserCode: vectorUserCode,
		DisplayUserCode: DisplayUserCode(vectorUserCode), LoopbackCode: vectorCode, LoopbackState: vectorState,
		MaxDerivedURLLength: MaxDerivedURLLength, MaxFleetPublicBaseURLLength: config.MaxFleetPublicBaseURLLength,
		MaxPublicBaseURLLength: config.MaxPublicBaseURLLength,
	}
	for _, input := range inputs {
		vector := baseURLVector{Name: input.name, Input: input.value, Length: len(input.value)}
		canonical := ""
		for _, mode := range []config.Mode{config.SelfHosted, config.OfficialHosted} {
			value, parsed := config.ParsePublicBaseURL(input.value, mode)
			if parsed == nil {
				if value != input.value {
					t.Fatalf("%q: ParsePublicBaseURL rewrites it to %q; the vectors assume an accepted value is its own canonical form", input.value, value)
				}
				canonical = value
			}
			verdicts := modeVerdicts{PublicBaseURL: verdictOf(parsed), FleetCenter: verdictOf(loadFleetCenter(input.value, mode))}
			if verdicts.FleetCenter.Accepted && !verdicts.PublicBaseURL.Accepted {
				t.Fatalf("%q: a fleet center accepts what ParsePublicBaseURL refuses", input.value)
			}
			if mode == config.SelfHosted {
				vector.SelfHosted = verdicts
			} else {
				vector.OfficialHosted = verdicts
			}
		}
		if vector.SelfHosted.FleetCenter.Accepted || vector.OfficialHosted.FleetCenter.Accepted {
			// Derived from the canonical value the center keeps (equal to the input, checked above), as the center derives them.
			audience := sha256.Sum256([]byte(canonical))
			derived := &derivedURLs{ProofAudienceSHA256: hex.EncodeToString(audience[:]), AuthorizeURL: AuthorizeURL(canonical, vectorFlowID),
				VerificationURI: VerificationURI(canonical), VerificationURIComplete: VerificationURIComplete(canonical, vectorUserCode)}
			for _, derivedURL := range []string{derived.AuthorizeURL, derived.VerificationURI, derived.VerificationURIComplete} {
				derived.LongestLength = max(derived.LongestLength, len(derivedURL))
			}
			if derived.LongestLength > MaxDerivedURLLength {
				t.Fatalf("%q derives a URL of %d characters", input.value, derived.LongestLength)
			}
			vector.Derived = derived
		}
		file.BaseURLs = append(file.BaseURLs, vector)
	}
	redirects := []struct{ name, value string }{
		{"IPv4 loopback", "http://127.0.0.1:53682/callback"},
		{"IPv6 loopback", "http://[::1]:53682/callback"},
		{"the lowest port", "http://127.0.0.1:1024/callback"},
		{"the highest port", "http://[::1]:65535/callback"},
		{"a port under 1024", "http://127.0.0.1:1023/callback"},
		{"a port over 65535", "http://127.0.0.1:65536/callback"},
		{"a port with a leading zero", "http://127.0.0.1:01024/callback"},
		{"localhost", "http://localhost:53682/callback"},
		{"https", "https://127.0.0.1:53682/callback"},
		{"another path", "http://127.0.0.1:53682/cb"},
		{"a trailing slash", "http://127.0.0.1:53682/callback/"},
		{"a query", "http://127.0.0.1:53682/callback?x=1"},
		{"no port", "http://127.0.0.1/callback"},
		{"a short IPv4 form", "http://127.1:53682/callback"},
		{"an IPv6 zone", "http://[::1%25lo]:53682/callback"},
	}
	for _, redirect := range redirects {
		vector := redirectVector{Name: redirect.name, Input: redirect.value, Accepted: ValidLoopbackRedirect(redirect.value)}
		if vector.Accepted {
			vector.CodeRedirect = CodeRedirect(redirect.value, vectorCode, vectorState)
			vector.DenyRedirect = DenyRedirect(redirect.value, vectorState)
		}
		file.Redirects = append(file.Redirects, vector)
	}
	// The cases the node relies on hold: the official center and a path prefix, both fleet bounds, a loopback http center.
	expect := map[string][2]bool{ // input: {self-hosted fleet center, official-hosted fleet center}
		"https://arcforges.com/api":                          {true, true},
		"http://localhost:8080/api":                          {true, false},
		"http://127.0.0.1:8080":                              {false, false},
		pathOfLength(config.MaxFleetPublicBaseURLLength):     {true, true},
		pathOfLength(config.MaxFleetPublicBaseURLLength + 1): {false, false},
		"https://center.example.test:443/api":                {false, false},
	}
	for _, vector := range file.BaseURLs {
		if want, ok := expect[vector.Input]; ok && (vector.SelfHosted.FleetCenter.Accepted != want[0] || vector.OfficialHosted.FleetCenter.Accepted != want[1]) {
			t.Errorf("%s: fleet center verdicts %v, %v; want %v", vector.Name, vector.SelfHosted.FleetCenter, vector.OfficialHosted.FleetCenter, want)
		}
	}
	return file
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Node key proof and fingerprint (G-4, node-13)

// vectorKeyLabel is hashed (SHA-256) to the private scalar of a TEST-ONLY P-256 key. The label is public on purpose: these keys sign
// test vectors only and are never a node's key; the vector file holds their public keys alone.
const vectorKeyLabel = "ArcForges node-key-proof test vectors v1: TEST-ONLY key %d, never a node key"

func vectorKey(t *testing.T, number int) *ecdsa.PrivateKey {
	t.Helper()
	scalar := sha256.Sum256(fmt.Appendf(nil, vectorKeyLabel, number))
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar[:])
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func spki(t *testing.T, key *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// signature is a deterministic ES256 signature (RFC 6979) of message in IEEE P1363 form, s normalized to the lower half as a node
// normalizes it; high reports whether the raw signature's s was in the upper half.
func signature(t *testing.T, key *ecdsa.PrivateKey, message []byte) (proof []byte, high bool) {
	t.Helper()
	digest := sha256.Sum256(message)
	der, err := key.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	var rs struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &rs); err != nil || len(rest) != 0 {
		t.Fatalf("an ES256 signature that is no DER pair: %v", err)
	}
	order := elliptic.P256().Params().N
	if rs.S.Cmp(halfOrder) > 0 {
		rs.S, high = new(big.Int).Sub(order, rs.S), true
	}
	proof = make([]byte, ProofLength)
	rs.R.FillBytes(proof[:32])
	rs.S.FillBytes(proof[32:])
	return proof, high
}

type keyVector struct {
	Name            string `json:"name"`
	SPKI            string `json:"spki"`
	ValidNodeKey    bool   `json:"validNodeKey"`
	Fingerprint     string `json:"fingerprint,omitempty"`
	FingerprintTail string `json:"fingerprintTail,omitempty"`
}

type proofVector struct {
	Name                 string `json:"name"`
	Purpose              byte   `json:"purpose"`
	Audience             string `json:"audience"`
	AudienceSHA256       string `json:"audienceSha256"`
	NodeID               string `json:"nodeId"`
	FlowID               string `json:"flowId,omitempty"`
	Code                 string `json:"code,omitempty"`
	DeviceCode           string `json:"deviceCode,omitempty"`
	Binding              string `json:"binding"`
	MessageConstruction  string `json:"messageConstruction,omitempty"`
	Message              string `json:"message"`
	NodeKey              string `json:"nodeKey"`
	Proof                string `json:"proof"`
	LeadingZero          string `json:"leadingZero,omitempty"`
	RawSignatureWasHighS bool   `json:"rawSignatureWasHighS,omitempty"`
	Accepted             bool   `json:"accepted"`
	Why                  string `json:"why,omitempty"`
}

type proofVectorFile struct {
	SchemaVersion int           `json:"schemaVersion"`
	Source        string        `json:"source"`
	TestOnly      string        `json:"testOnly"`
	Rules         []string      `json:"rules"`
	Domain        string        `json:"domain"`
	DomainHex     string        `json:"domainHex"`
	Keys          []keyVector   `json:"keys"`
	Proofs        []proofVector `json:"proofs"`
}

// proofInputs are the inputs of one proof message.
type proofInputs struct {
	purpose        byte
	audience       string
	nodeID, flowID platform.ID
	code           string // the code (purpose 0x01) or the device code (purpose 0x02)
}

func (in proofInputs) binding() []byte {
	if in.purpose == ProofComplete {
		return CompleteBinding(in.flowID, in.code)
	}
	return PollBinding(in.code)
}

func (in proofInputs) message() []byte {
	return ProofMessage(in.purpose, in.audience, in.nodeID, in.binding())
}

// independentMessage is the message assembled from the contract's sentence (C0, fleet.proto "Node key proof"), not from ProofMessage:
// 28 ASCII bytes "ArcForges node-key-proof v1" and LF, the purpose byte, SHA-256 of the audience's UTF-8 bytes, the node ID's 16 bytes,
// then flow_id (16 bytes) and code as UTF-8 for purpose 0x01, or device_code as UTF-8 for purpose 0x02.
func (in proofInputs) independentMessage() []byte {
	var message []byte
	message = append(message, "ArcForges node-key-proof v1"...)
	message = append(message, 0x0a, in.purpose)
	digest := sha256.Sum256([]byte(in.audience))
	message = append(message, digest[:]...)
	message = append(message, in.nodeID[:]...)
	if in.purpose == 0x01 {
		message = append(message, in.flowID[:]...)
	}
	return append(message, in.code...)
}

func (in proofInputs) vector(name string) proofVector {
	digest := sha256.Sum256([]byte(in.audience))
	vector := proofVector{Name: name, Purpose: in.purpose, Audience: in.audience, AudienceSHA256: hex.EncodeToString(digest[:]),
		NodeID: hex.EncodeToString(in.nodeID[:]), Binding: hex.EncodeToString(in.binding()), Message: hex.EncodeToString(in.message())}
	if in.purpose == ProofComplete {
		vector.FlowID, vector.Code = hex.EncodeToString(in.flowID[:]), in.code
	} else {
		vector.DeviceCode = in.code
	}
	return vector
}

// vectorHandle is the n-th fixed 43-character code: the canonical base64url of SHA-256(label n).
func vectorHandle(label string, n int) string {
	digest := sha256.Sum256(fmt.Appendf(nil, "%s %d", label, n))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func proofVectors(t *testing.T) proofVectorFile {
	t.Helper()
	const audience = "https://center.example.test/api"
	keyOne, keyTwo := vectorKey(t, 1), vectorKey(t, 2)
	keys := map[string][]byte{"test-key-1": spki(t, &keyOne.PublicKey), "test-key-2": spki(t, &keyTwo.PublicKey)}
	signers := map[string]*ecdsa.PrivateKey{"test-key-1": keyOne}
	nodeID := platform.ID{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	otherNodeID := platform.ID{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01}
	otherFlowID := platform.ID{0x0f, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x0e, 0xf1}

	file := proofVectorFile{
		SchemaVersion: vectorsSchema, Source: "TestFleetVectorFiles (center/internal/fleet/vectors_test.go)",
		TestOnly: "Every key here is a fixed TEST-ONLY key, never a node's key, and the file holds public keys and signatures only. The private " +
			"scalars are public test values: test-key-1 and test-key-2 are the SHA-256 of a public label in the generator; capture-node-0x2a is " +
			"the exchange capture harness's fixed scalar, 32 bytes of 0x2a; the P-384 key (a refused key) is 48 bytes of 0x2b; the other " +
			"refused keys are forms of test-key-1.",
		Rules: []string{
			"message = domain (28 bytes) || purpose (1 byte) || SHA-256(audience as UTF-8) (32 bytes) || node ID (16 bytes) || binding; every field before the binding has a fixed length",
			"binding: purpose 0x01 (CompleteNodeSignIn) = flow ID (16 bytes) || code (UTF-8, 43 characters); purpose 0x02 (PollDeviceAuthorization) = device code (UTF-8, 43 characters)",
			"the audience is the full canonical center URL the node is configured with; the center uses its own public base URL",
			"proof = ES256 over SHA-256(message) as IEEE P1363 r || s, 32 bytes each, r and s in [1, n-1] and s <= n/2 (low-S); the node normalizes s, the center refuses a high-S proof",
			"nodeKey names the key (keys[].name) whose spki (PKIX DER, 91 bytes for P-256) verifies the proof; accepted is fleet.VerifyNodeKeyProof's verdict",
			"messageConstruction marks a message that is not ProofMessage of the vector's inputs (a negative case): such a vector is verified from its message alone, and its input fields name what the message was made from; otherwise message = ProofMessage(purpose, audience, nodeId, binding)",
			"leadingZero names r or s when its first byte is 0x00 (a fixed-width encoder must keep it); rawSignatureWasHighS marks a deterministic (RFC 6979) signature whose s was normalized to n - s",
			"fingerprint = the first 10 bytes of SHA-256(spki) in upper-case hexadecimal, five groups of four joined by '-'; fingerprintTail is the last group",
		},
		Domain: ProofDomain, DomainHex: hex.EncodeToString([]byte(ProofDomain)),
	}

	// Keys: the two test keys, the capture node 0x2a's key (its scalar is 32 bytes of 0x2a: the fleetapi exchange captures present it),
	// and malformed keys the center refuses.
	captureNode, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), bytes.Repeat([]byte{0x2a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), bytes.Repeat([]byte{0x2b}, 48))
	if err != nil {
		t.Fatal(err)
	}
	keyOneDER := keys["test-key-1"]
	uncompressed, err := keyOne.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	keyRows := []struct {
		name string
		der  []byte
	}{
		{"test-key-1", keyOneDER},
		{"test-key-2", keys["test-key-2"]},
		{"capture-node-0x2a", spki(t, &captureNode.PublicKey)},
		{"truncated: test-key-1 without its last byte", keyOneDER[:len(keyOneDER)-1]},
		{"the raw uncompressed point of test-key-1, not PKIX DER", uncompressed},
		{"a P-384 key", spki(t, &p384.PublicKey)},
	}
	for _, row := range keyRows {
		vector := keyVector{Name: row.name, SPKI: hex.EncodeToString(row.der), ValidNodeKey: ValidNodeKey(row.der)}
		if vector.ValidNodeKey {
			vector.Fingerprint, vector.FingerprintTail = Fingerprint(row.der), FingerprintTail(row.der)
		}
		keys[row.name] = row.der
		file.Keys = append(file.Keys, vector)
	}

	add := func(vector proofVector, in proofInputs, message, proof []byte, key string) {
		t.Helper()
		vector.NodeKey, vector.Proof, vector.Message = key, hex.EncodeToString(proof), hex.EncodeToString(message)
		vector.Accepted = VerifyNodeKeyProof(keys[key], message, proof)
		if vector.MessageConstruction == "" && !bytes.Equal(message, in.message()) {
			t.Fatalf("%s: the message is not ProofMessage of the inputs", vector.Name)
		}
		file.Proofs = append(file.Proofs, vector)
	}
	sign := func(name string, in proofInputs) ([]byte, proofVector) {
		t.Helper()
		message := in.message()
		if !bytes.Equal(message, in.independentMessage()) {
			t.Fatalf("%s: ProofMessage disagrees with the contract's layout", name)
		}
		proof, high := signature(t, signers["test-key-1"], message)
		vector := in.vector(name)
		vector.RawSignatureWasHighS = high
		switch {
		case proof[0] == 0:
			vector.LeadingZero = "r"
		case proof[32] == 0:
			vector.LeadingZero = "s"
		}
		add(vector, in, message, proof, "test-key-1")
		return proof, vector
	}
	// search signs the first of the codes label 0, 1, ... whose proof has a leading zero byte in the half named.
	search := func(name, label, half string, in proofInputs) {
		t.Helper()
		for n := range 4096 {
			in.code = vectorHandle(label, n)
			proof, _ := signature(t, signers["test-key-1"], in.message())
			if half == "r" && proof[0] == 0 || half == "s" && proof[32] == 0 && proof[0] != 0 {
				sign(name, in)
				return
			}
		}
		t.Fatalf("no proof with a leading zero in %s", half)
	}

	// Accepted proofs: both purposes, the official audience and a path prefix, a leading zero byte in r and in s.
	official := proofInputs{purpose: ProofComplete, audience: "https://arcforges.com/api", nodeID: nodeID, flowID: vectorFlowID, code: vectorHandle("code", 0)}
	sign("complete: the official center", official)
	complete := proofInputs{purpose: ProofComplete, audience: audience, nodeID: nodeID, flowID: vectorFlowID, code: vectorHandle("code", 1)}
	completeProof, _ := sign("complete: a center with a path prefix", complete)
	search("complete: r has a leading zero byte", "code r", "r", complete)
	poll := proofInputs{purpose: ProofPoll, audience: audience, nodeID: nodeID, code: vectorHandle("device code", 0)}
	pollProof, _ := sign("poll: a center with a path prefix", poll)
	search("poll: s has a leading zero byte", "device code s", "s", poll)
	sign("poll: the local rehearsal center", proofInputs{purpose: ProofPoll, audience: "https://localhost:28443/api", nodeID: nodeID,
		code: vectorHandle("device code", 1)})
	high := false
	for _, vector := range file.Proofs {
		high = high || vector.RawSignatureWasHighS
	}
	for n := 2; !high; n++ {
		if n > 64 {
			t.Fatal("no deterministic signature with a high s")
		}
		in := complete
		in.code = vectorHandle("code", n)
		if _, raw := signature(t, signers["test-key-1"], in.message()); raw {
			sign("complete: the raw signature had a high s, normalized", in)
			high = true
		}
	}

	// Refused: the proofs above with another message, other proof bytes or another key.
	refuse := func(name, why string, in proofInputs, construction string, message, proof []byte, key string) {
		t.Helper()
		vector := in.vector(name)
		vector.MessageConstruction, vector.Why = construction, why
		if message == nil {
			message = in.message()
		}
		add(vector, in, message, proof, key)
	}
	order := elliptic.P256().Params().N
	r, s := new(big.Int).SetBytes(completeProof[:32]), new(big.Int).SetBytes(completeProof[32:])
	highS := append([]byte(nil), completeProof...)
	new(big.Int).Sub(order, s).FillBytes(highS[32:])
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal(err)
	}
	zeroR, zeroS, bigR, bigS := append([]byte(nil), completeProof...), append([]byte(nil), completeProof...), append([]byte(nil), completeProof...),
		append([]byte(nil), completeProof...)
	clear(zeroR[:32])
	clear(zeroS[32:])
	order.FillBytes(bigR[:32])
	order.FillBytes(bigS[32:])
	flipped := append([]byte(nil), completeProof...)
	flipped[63] ^= 0x01
	with := func(change func(*proofInputs)) proofInputs {
		in := complete
		change(&in)
		return in
	}
	refuse("refused: the high-S twin of an accepted proof", "s > n/2", complete, "", nil, highS, "test-key-1")
	refuse("refused: an ASN.1 DER signature", "not 64 bytes r || s", complete, "", nil, der, "test-key-1")
	refuse("refused: 63 bytes", "not 64 bytes", complete, "", nil, completeProof[:63], "test-key-1")
	refuse("refused: 65 bytes", "not 64 bytes", complete, "", nil, append(append([]byte(nil), completeProof...), 0), "test-key-1")
	refuse("refused: r = 0", "r outside [1, n-1]", complete, "", nil, zeroR, "test-key-1")
	refuse("refused: s = 0", "s outside [1, n/2]", complete, "", nil, zeroS, "test-key-1")
	refuse("refused: r = n", "r outside [1, n-1]", complete, "", nil, bigR, "test-key-1")
	refuse("refused: s = n", "s outside [1, n/2]", complete, "", nil, bigS, "test-key-1")
	refuse("refused: the last proof byte flipped", "the signature does not verify", complete, "", nil, flipped, "test-key-1")
	refuse("refused: another key", "the signature is test-key-1's", complete, "", nil, completeProof, "test-key-2")
	refuse("refused: a truncated key", "the key is no 91-byte P-256 PKIX DER", complete, "", nil, completeProof, "truncated: test-key-1 without its last byte")
	refuse("refused: the raw point as the key", "the key is no PKIX DER", complete, "", nil, completeProof, "the raw uncompressed point of test-key-1, not PKIX DER")
	for _, variant := range []struct {
		name string
		in   proofInputs
	}{
		{"another path of the same host", with(func(in *proofInputs) { in.audience = "https://center.example.test/other" })},
		{"the origin without the path", with(func(in *proofInputs) { in.audience = "https://center.example.test" })},
		{"another host with the same path", with(func(in *proofInputs) { in.audience = "https://other.example.test/api" })},
		{"a trailing slash on the audience", with(func(in *proofInputs) { in.audience = audience + "/" })},
		{"another node ID", with(func(in *proofInputs) { in.nodeID = otherNodeID })},
		{"another flow ID", with(func(in *proofInputs) { in.flowID = otherFlowID })},
		{"another code", with(func(in *proofInputs) { in.code = vectorHandle("code", 0) })},
	} {
		refuse("refused: "+variant.name, "the proof signs another message", variant.in, "", nil, completeProof, "test-key-1")
	}
	// The same complete proof under purpose 0x02 with the same binding bytes (flow ID || code).
	refuse("refused: the complete proof presented with purpose 0x02", "another purpose", complete, "purpose 0x02 with the complete binding",
		ProofMessage(ProofPoll, audience, nodeID, CompleteBinding(vectorFlowID, complete.code)), completeProof, "test-key-1")
	file.Proofs[len(file.Proofs)-1].Purpose = ProofPoll // the purpose byte of its message; flowId and code are its binding
	refuse("refused: the poll proof presented for a complete message", "another purpose and binding", complete, "", nil, pollProof, "test-key-1")
	message := complete.message()
	refuse("refused: the message without its domain", "the domain is part of the message", complete, "the message without its 28-byte domain",
		message[len(ProofDomain):], completeProof, "test-key-1")
	refuse("refused: the domain without its line feed", "the domain is 28 bytes with the line feed", complete,
		"the domain without its final line feed, the rest unchanged", append([]byte("ArcForges node-key-proof v1"), message[len(ProofDomain):]...),
		completeProof, "test-key-1")
	swapped := append(append(append([]byte(nil), message[:len(ProofDomain)+1+32]...), vectorFlowID[:]...), nodeID[:]...)
	refuse("refused: node ID and flow ID swapped", "the field order is fixed", complete, "node ID and flow ID swapped", append(swapped, complete.code...),
		completeProof, "test-key-1")
	refuse("refused: the binding without the flow ID", "the binding of purpose 0x01 starts with the flow ID", complete, "the binding is the code alone",
		ProofMessage(ProofComplete, audience, nodeID, []byte(complete.code)), completeProof, "test-key-1")

	// Every accepted vector is one of the signed ones, every refusal is refused; r and s leading zeros and a normalized s are present.
	seen := map[string]bool{}
	for _, vector := range file.Proofs {
		refused := strings.HasPrefix(vector.Name, "refused: ")
		if vector.Accepted == refused {
			t.Errorf("%s: accepted %v", vector.Name, vector.Accepted)
		}
		seen["zero "+vector.LeadingZero] = seen["zero "+vector.LeadingZero] || !refused
		seen["high"] = seen["high"] || !refused && vector.RawSignatureWasHighS
		seen[fmt.Sprintf("purpose %d", vector.Purpose)] = seen[fmt.Sprintf("purpose %d", vector.Purpose)] || !refused
	}
	for _, want := range []string{"zero r", "zero s", "high", "purpose 1", "purpose 2"} {
		if !seen[want] {
			t.Errorf("no accepted vector with %s", want)
		}
	}
	return file
}
