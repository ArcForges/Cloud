// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// EVIDENCE: REAL PostgreSQL, the REAL center behind its ingress, binary gRPC-Web posted by this harness exactly as a node sends it
// (E1-25, delivery-5): the node-facing exchanges of the browser sign-in and the node credential, captured as the bytes on the wire
// and normalized. Parts N1 and N2 will copy the directory verbatim for the ArcForges FakeCenter's conformance test; nothing checks
// it against a node yet. MOCKED: the node's keys and PKCE values are fixed by the test, the account's passkey is virtual. Some
// states are SEEDED by SQL (an expired code, a revoked installation). Determinism comes from normalization, not from seams: no fixed
// clock and no injected randomness in the center. Only values the center or a random source produced are replaced (correlation IDs,
// the flow IDs, installation and account IDs, tokens, the one-use codes, node key proofs, instants), each distinct value by its own
// placeholder of the same shape (16-byte IDs, the token formats, 43-character canonical base64url codes, 64-byte proofs), the same
// placeholder wherever the value appears (request, reply, details, the authorization header); the test's own constants (a wrong
// code, an unknown flow ID, an unknown token, command IDs, node IDs and keys) stay as they are.

// exchangesDirectory holds one file per captured case.
const exchangesDirectory = "testdata/exchanges"

// exchangeSchemaVersion versions the capture format.
const exchangeSchemaVersion = 2

// normalizationRules describe the placeholders, recorded in every file.
var normalizationRules = []string{
	"a 16-byte ID the center drew: 15 bytes of its kind (0xa1 correlation, 0xa2 flow, 0xa3 installation, 0xa4 account) and n for the n-th distinct one of the kind",
	"a token the center issued: its prefix (afa1. or afr1.) and the canonical base64url of 32 bytes of n (the n-th distinct token of that format)",
	"a one-use code the center drew: the canonical base64url of 32 bytes of 0xc0+n",
	"a node key proof (ES256 draws a nonce): 64 bytes of 0xe0+n",
	"every Instant: unix_seconds is the offset from the harness clock at the call, rounded to 5 seconds; nanos 0",
	"the authorization header carries the placeholder of its token; the client address header is recorded as sent",
}

// exchange is one captured call.
type exchange struct {
	SchemaVersion   int               `json:"schemaVersion"`
	Source          string            `json:"source"`
	ContractsCohort string            `json:"contractsCohort"`
	CenterCommit    string            `json:"centerCommit"`
	Method          string            `json:"method"`
	Case            string            `json:"case"`
	Outcome         string            `json:"outcome"`
	Headers         map[string]string `json:"headers"`
	Request         wireCall          `json:"request"`
	Reply           wireCall          `json:"reply"`
	Normalized      []string          `json:"normalized"`
	SHA256          string            `json:"sha256"`
}

// wireCall is one direction of a call: the content type, the HTTP status of a reply, the data frames and the trailer frame in hex.
type wireCall struct {
	ContentType string   `json:"contentType"`
	HTTPStatus  int      `json:"httpStatus,omitempty"`
	Frames      []string `json:"frames"`
	Trailers    string   `json:"trailers,omitempty"`
}

func frame(flag byte, payload []byte) []byte {
	result := make([]byte, 5+len(payload))
	result[0] = flag
	binary.BigEndian.PutUint32(result[1:5], uint32(len(payload)))
	copy(result[5:], payload)
	return result
}

var (
	accessShape  = regexp.MustCompile(`^afa1\.[A-Za-z0-9_-]{43}$`)
	refreshShape = regexp.MustCompile(`^afr1\.[A-Za-z0-9_-]{43}$`)
)

// placeholders maps each volatile value to its placeholder, consistently over the whole capture.
type placeholders struct {
	t      *testing.T
	ids    map[string][]byte
	values map[string]string
	bytes  map[string][]byte
	counts map[string]int
	// volatile are the IDs the center drew that the test has seen (the flow IDs it returned).
	volatile map[string]bool
}

func newPlaceholders(t *testing.T) *placeholders {
	return &placeholders{t: t, ids: map[string][]byte{}, values: map[string]string{}, bytes: map[string][]byte{}, counts: map[string]int{}, volatile: map[string]bool{}}
}

func (p *placeholders) next(kind string) int {
	p.counts[kind]++
	return p.counts[kind]
}

// id is the placeholder of a 16-byte ID the center drew; kind is its kind byte.
func (p *placeholders) id(value []byte, kind byte) []byte {
	if len(value) != 16 {
		p.t.Fatalf("a volatile ID of %d bytes", len(value))
	}
	key := hex.EncodeToString(value)
	if placeholder, ok := p.ids[key]; ok {
		return placeholder
	}
	// One counter per kind: the n-th distinct ID of a kind is the same placeholder whatever order a message's fields are visited in.
	placeholder := bytes.Repeat([]byte{kind}, 16)
	placeholder[15] = byte(p.next(fmt.Sprintf("id-%x", kind)))
	p.ids[key] = placeholder
	return placeholder
}

// token is the placeholder of a token the center issued, after its shape is checked.
func (p *placeholders) token(value string) string {
	if placeholder, ok := p.values[value]; ok {
		return placeholder
	}
	prefix := session.AccessPrefix
	switch {
	case accessShape.MatchString(value):
	case refreshShape.MatchString(value):
		prefix = session.RefreshPrefix
	default:
		p.t.Fatalf("a token of an unknown shape: %d characters", len(value))
	}
	if _, ok := session.ParseToken(prefix, value); !ok {
		p.t.Fatal("a token that is not canonical")
	}
	// One counter per format, so the numbering does not depend on the order a message's fields are visited in.
	placeholder := prefix + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(p.next("token " + prefix))}, 32))
	if _, ok := session.ParseToken(prefix, placeholder); !ok {
		p.t.Fatal("a token placeholder of the wrong shape")
	}
	p.values[value] = placeholder
	return placeholder
}

// code is the placeholder of a one-use code the center drew (registered when the test receives it).
func (p *placeholders) code(value string) string {
	if _, ok := session.ParseHandle(value); !ok {
		p.t.Fatal("a one-use code that is not 43 canonical base64url characters")
	}
	if placeholder, ok := p.values[value]; ok {
		return placeholder
	}
	placeholder := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xc0 + byte(p.next("code"))}, 32))
	if _, ok := session.ParseHandle(placeholder); !ok {
		p.t.Fatal("a code placeholder of the wrong shape")
	}
	p.values[value] = placeholder
	return placeholder
}

// proof is the placeholder of a node key proof.
func (p *placeholders) proof(value []byte) []byte {
	if len(value) != 64 {
		p.t.Fatalf("a proof of %d bytes", len(value))
	}
	key := hex.EncodeToString(value)
	if placeholder, ok := p.bytes[key]; ok {
		return placeholder
	}
	placeholder := bytes.Repeat([]byte{0xe0 + byte(p.next("proof"))}, 64)
	p.bytes[key] = placeholder
	return placeholder
}

// normalize replaces the volatile values of a message in place.
func (p *placeholders) normalize(message protoreflect.Message, base time.Time) {
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		name := string(field.Name())
		switch {
		case field.Kind() == protoreflect.MessageKind && field.Message().FullName() == "arcforges.foundation.v1.Id" && !field.IsList():
			raw := value.Message().Interface().(*foundationv1.Id).GetValue()
			kinds := map[string]byte{"correlation_id": 0xa1, "installation_id": 0xa3, "account_id": 0xa4}
			if kind, ok := kinds[name]; ok {
				message.Set(field, protoreflect.ValueOfMessage((&foundationv1.Id{Value: p.id(raw, kind)}).ProtoReflect()))
			} else if p.volatile[hex.EncodeToString(raw)] {
				// A flow ID the center drew, wherever it appears (flow_id, a resource of a refusal).
				message.Set(field, protoreflect.ValueOfMessage((&foundationv1.Id{Value: p.id(raw, 0xa2)}).ProtoReflect()))
			}
		case field.Kind() == protoreflect.MessageKind && field.Message().FullName() == "arcforges.foundation.v1.Instant" && !field.IsList():
			instant := value.Message().Interface().(*foundationv1.Instant)
			at := time.Unix(instant.GetUnixSeconds(), int64(instant.GetNanos()))
			offset := int64(math.Round(at.Sub(base).Seconds()/5) * 5)
			message.Set(field, protoreflect.ValueOfMessage((&foundationv1.Instant{UnixSeconds: proto.Int64(offset), Nanos: proto.Uint32(0)}).ProtoReflect()))
		case field.Kind() == protoreflect.MessageKind && !field.IsList() && !field.IsMap():
			p.normalize(value.Message(), base)
		case field.Kind() == protoreflect.MessageKind && field.IsList():
			list := value.List()
			for i := 0; i < list.Len(); i++ {
				p.normalize(list.Get(i).Message(), base)
			}
		case name == "access_token" || name == "refresh_token":
			if text := value.String(); p.values[text] != "" || accessShape.MatchString(text) && issued[text] || refreshShape.MatchString(text) && issued[text] {
				message.Set(field, protoreflect.ValueOfString(p.token(text)))
			}
		case name == "code" && field.ContainingMessage().FullName() == "arcforges.fleet.v1.NodeEnrollmentServiceCompleteNodeSignInRequest":
			if placeholder, ok := p.values[value.String()]; ok {
				message.Set(field, protoreflect.ValueOfString(placeholder))
			}
		case name == "node_key_proof":
			message.Set(field, protoreflect.ValueOfBytes(p.proof(value.Bytes())))
		case name == "authorize_url":
			text := value.String()
			flow, found := strings.CutPrefix(text, publicBaseURL+"/connect#flow=")
			raw, err := hex.DecodeString(strings.ReplaceAll(flow, "-", ""))
			if !found || err != nil || len(raw) != 16 || text != nodetest.DerivedAuthorizeURL(publicBaseURL, raw) {
				p.t.Fatalf("authorize_url %q is not the derived form", text)
			}
			message.Set(field, protoreflect.ValueOfString(nodetest.DerivedAuthorizeURL(publicBaseURL, p.id(raw, 0xa2))))
		}
		return true
	})
}

// issued are the tokens the center issued during the capture (the test's own tokens, such as an unknown one, are not).
var issued = map[string]bool{}

// capturer posts calls and records them.
type capturer struct {
	t     *testing.T
	p     *placeholders
	cases map[string]exchange
}

// call is one captured call: the harness it goes to, the client address and the bearer.
type call struct {
	h      *harness
	ip     string
	bearer string
}

// outcomeOf is a reply's outcome key: ok, CATEGORY/code (with :state for a CONFLICT/already_exists), or transport:<message>.
func outcomeOf(response proto.Message, trailers string) string {
	if strings.Contains(trailers, "grpc-status: ") && !strings.Contains(trailers, "grpc-status: 0\r") {
		message := ""
		for _, line := range strings.Split(trailers, "\r\n") {
			if value, ok := strings.CutPrefix(line, "grpc-message: "); ok {
				message = value
			}
		}
		return "transport:" + message
	}
	field := response.ProtoReflect().Descriptor().Fields().ByName("error")
	if field == nil || !response.ProtoReflect().Has(field) {
		return "ok"
	}
	value := response.ProtoReflect().Get(field).Message().Interface().(*foundationv1.ArcError)
	key := failure(value)
	if key == "CONFLICT/already_exists" {
		key += ":" + value.GetDetails().GetState().GetState()
	}
	return key
}

// capture sends a request as a node does, returns the decoded reply and records the exchange under method-case.
func capture[Response proto.Message](c *capturer, to call, method, name string, request proto.Message, response Response) Response {
	c.t.Helper()
	base := time.Now()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		c.t.Fatal(err)
	}
	httpRequest, err := http.NewRequest(http.MethodPost, to.h.client.URL+"/arcforges.fleet.v1.NodeEnrollmentService/"+method, bytes.NewReader(frame(0, payload)))
	if err != nil {
		c.t.Fatal(err)
	}
	ip := to.ip
	if ip == "" {
		ip = "198.51.100.7"
	}
	httpRequest.Header.Set("Content-Type", "application/grpc-web+proto")
	httpRequest.Header.Set(config.ClientIPHeader, ip)
	headers := map[string]string{strings.ToLower(config.ClientIPHeader): ip}
	if to.bearer != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+to.bearer)
		headers["authorization"] = "Bearer " + c.p.token(to.bearer)
	}
	reply, err := http.DefaultClient.Do(httpRequest)
	if err != nil {
		c.t.Fatal(err)
	}
	body, err := io.ReadAll(reply.Body)
	_ = reply.Body.Close()
	if err != nil {
		c.t.Fatal(err)
	}
	result := exchange{SchemaVersion: exchangeSchemaVersion, Source: "TestFleetExchangeCapture", ContractsCohort: "1.0.0-ci.424.1", Method: method, Case: name,
		Headers: headers, Reply: wireCall{ContentType: reply.Header.Get("Content-Type"), HTTPStatus: reply.StatusCode, Frames: []string{}},
		Normalized: normalizationRules}
	var replyMessages []proto.Message
	for position := 0; position+5 <= len(body); {
		flag, length := body[position], int(binary.BigEndian.Uint32(body[position+1:position+5]))
		data := body[position+5 : position+5+length]
		position += 5 + length
		if flag&0x80 != 0 {
			result.Reply.Trailers = string(data)
			continue
		}
		if err = proto.Unmarshal(data, response); err != nil {
			c.t.Fatal(err)
		}
		replyMessages = append(replyMessages, proto.Clone(response))
	}
	// Register the volatile values of the reply before normalizing either direction (a flow ID or a token a reply returns).
	for _, message := range replyMessages {
		c.p.register(message.ProtoReflect())
	}
	result.Outcome = outcomeOf(response, result.Reply.Trailers)
	normalizedRequest := proto.Clone(request)
	c.p.normalize(normalizedRequest.ProtoReflect(), base)
	requestBytes, _ := proto.MarshalOptions{Deterministic: true}.Marshal(normalizedRequest)
	result.Request = wireCall{ContentType: "application/grpc-web+proto", Frames: []string{hex.EncodeToString(frame(0, requestBytes))}}
	for _, message := range replyMessages {
		c.p.normalize(message.ProtoReflect(), base)
		encoded, _ := proto.MarshalOptions{Deterministic: true}.Marshal(message)
		result.Reply.Frames = append(result.Reply.Frames, hex.EncodeToString(frame(0, encoded)))
	}
	content, _ := json.Marshal(struct {
		Method, Case, Outcome string
		Headers               map[string]string
		Request, Reply        wireCall
		Normalized            []string
	}{result.Method, result.Case, result.Outcome, result.Headers, result.Request, result.Reply, result.Normalized})
	digest := sha256.Sum256(content)
	result.SHA256 = hex.EncodeToString(digest[:])
	if _, twice := c.cases[method+"-"+name]; twice {
		c.t.Fatalf("two captures named %s-%s", method, name)
	}
	c.cases[method+"-"+name] = result
	return response
}

// register notes the volatile values a reply carries: the tokens it issued and the flow IDs it drew (a BeginNodeSignIn value).
func (p *placeholders) register(message protoreflect.Message) {
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case string(field.Name()) == "flow_id" && message.Descriptor().FullName() == "arcforges.fleet.v1.NodeEnrollmentServiceBeginNodeSignInValue":
			p.volatile[hex.EncodeToString(value.Message().Interface().(*foundationv1.Id).GetValue())] = true
		case field.Kind() == protoreflect.MessageKind && !field.IsList() && !field.IsMap():
			p.register(value.Message())
		case string(field.Name()) == "access_token" || string(field.Name()) == "refresh_token":
			issued[value.String()] = true
		}
		return true
	})
}

// fixedNode is a capture node: a fixed node ID and a fixed P-256 key, so its requests are the same on every run.
func fixedNode(t *testing.T, seed byte) *nodetest.Node {
	t.Helper()
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	id := platform.ID{0x6e, 0x6f, 0x64, 0x65, 0x2d, 0x69, 0x64, 0x2d, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, seed}
	return &nodetest.Node{ID: id, Key: key, PublicKey: der, Name: "buildbox", Version: "0.1.0-dev+15d6717144468ce0be615e8538f858d29b0fed7d",
		OS: nodev1.OsFamily_OS_FAMILY_LINUX, Arch: nodev1.CpuArchitecture_CPU_ARCHITECTURE_X64}
}

// fixedSignIn is a node's fixed PKCE pair, loopback and state.
func fixedSignIn(seed byte) nodetest.SignIn {
	verifier := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 32))
	challenge := sha256.Sum256([]byte(verifier))
	return nodetest.SignIn{Verifier: verifier, Challenge: base64.RawURLEncoding.EncodeToString(challenge[:]), RedirectURI: "http://127.0.0.1:53682/callback",
		State: fmt.Sprintf("node-state-%02x-0123456789abcdefghij", seed)}
}

// requiredOutcomes are the outcomes the capture must hold per node-facing method: every outcome of the checkpoint's c.2 table for
// BeginNodeSignIn and CompleteNodeSignIn that the center produces (kill_switch_active is not produced in AF-CTR-04; overloaded and
// internal are store failures), and the success and the refusals a node reacts to for the E1a methods.
var requiredOutcomes = map[string][]string{
	"BeginNodeSignIn": {"ok", "VALIDATION/invalid_argument", "RESOURCE/rate_limited", "CONFLICT/already_exists:node_key", "STATE/not_activated"},
	"CompleteNodeSignIn": {"ok", "STATE/not_found", "STATE/expired", "CONFLICT/code_reused", "AUTHENTICATION/unauthenticated", "VALIDATION/invalid_argument",
		"CONFLICT/already_exists:node", "CONFLICT/already_exists:node_key", "AUTHENTICATION/credential_revoked", "RESOURCE/quota_exceeded", "RESOURCE/rate_limited",
		"STATE/not_activated"},
	"RefreshNodeSession": {"ok", "AUTHENTICATION/unauthenticated", "AUTHENTICATION/credential_revoked", "AUTHORIZATION/permission_denied"},
	"ReportNodeInfo":     {"ok", "VALIDATION/invalid_argument", "CONFLICT/command_id_reused"},
	"SignOutNode":        {"ok", "transport:auth.credential_revoked"},
}

// TestFleetExchangeCapture (E1-25, delivery-5): captures the node-facing exchanges (Begin, Complete, Refresh, ReportNodeInfo,
// SignOutNode) with every outcome of requiredOutcomes and compares them with the committed directory; with
// ARCFORGES_UPDATE_EXCHANGES=1 it writes the directory instead (ARCFORGES_CENTER_COMMIT names the commit in the headers; npx prettier
// --write formats the files, and the comparison reads them as JSON).
func TestFleetExchangeCapture(t *testing.T) {
	clear(issued)
	h := newHarness(t, settings{policy: `{"maxNodesPerAccount": 2, "nodeCompletePrefixLimit": 3, "nodeFlowPrefixLimit": 20}`})
	off := newHarness(t, settings{surfaces: "identity,pages"})
	c := &capturer{t: t, p: newPlaceholders(t), cases: map[string]exchange{}}
	at := call{h: h}
	owner := h.person(1)
	other := h.person(1)
	// The account's own refresh token is the center's too (the permission_denied case presents it).
	issued[owner.refresh] = true

	// beginFlow begins a captured or uncaptured flow of a fixed node and approves it; the center's flow ID and code are volatile.
	begin := func(node *nodetest.Node, pkce nodetest.SignIn, name string) *signIn {
		t.Helper()
		var response *fleetv1.NodeEnrollmentServiceBeginNodeSignInResponse
		if name != "" {
			response = capture(c, at, "BeginNodeSignIn", name, node.BeginRequest(pkce), &fleetv1.NodeEnrollmentServiceBeginNodeSignInResponse{})
		} else {
			response = rpc(h, beginPath, node.BeginRequest(pkce), "", &fleetv1.NodeEnrollmentServiceBeginNodeSignInResponse{})
		}
		if response.GetError() != nil {
			t.Fatalf("begin %s: %s", name, failure(response.GetError()))
		}
		s := &signIn{node: node, pkce: pkce, flowID: flowIDOf(response.GetValue().GetFlowId()), value: response.GetValue()}
		// An uncaptured Begin's flow ID is the center's draw too (a captured one was registered from its reply).
		c.p.volatile[hex.EncodeToString(s.flowID[:])] = true
		return s
	}
	approve := func(s *signIn) {
		t.Helper()
		h.approve(owner, s, false)
		c.p.code(s.code)
	}
	complete := func(name string, s *signIn, code, verifier string, to call) *fleetv1.NodeEnrollmentServiceCompleteNodeSignInResponse {
		t.Helper()
		request := s.node.CompleteRequest(s.flowID, code, nodetest.SignIn{Verifier: verifier}, s.node.CompleteProof(publicBaseURL, s.flowID, code))
		return capture(c, to, "CompleteNodeSignIn", name, request, &fleetv1.NodeEnrollmentServiceCompleteNodeSignInResponse{})
	}

	node := fixedNode(t, 0x2a)
	pkce := fixedSignIn(0x2a)
	invalid := node.BeginRequest(pkce)
	invalid.RedirectUri = proto.String("http://localhost:53682/callback")
	capture(c, at, "BeginNodeSignIn", "invalid-redirect", invalid, &fleetv1.NodeEnrollmentServiceBeginNodeSignInResponse{})
	capture(c, call{h: off}, "BeginNodeSignIn", "surface-off", node.BeginRequest(pkce), &fleetv1.NodeEnrollmentServiceBeginNodeSignInResponse{})
	s := begin(node, pkce, "ok")
	approve(s)

	// A well-formed wrong code, an unknown flow, a malformed verifier, then the success and the code again.
	wrong := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x77}, 32))
	complete("unauthenticated", s, wrong, pkce.Verifier, at)
	unknown := &signIn{node: node, pkce: pkce, flowID: platform.ID{0xde, 0xad, 0xbe, 0xef}}
	complete("not-found", unknown, s.code, pkce.Verifier, at)
	complete("invalid-verifier", s, s.code, "short", at)
	completed := complete("ok", s, s.code, pkce.Verifier, at)
	credentials := completed.GetValue().GetCredentials()
	if completed.GetError() != nil || credentials == nil {
		t.Fatalf("complete: %s", failure(completed.GetError()))
	}
	h.secrets = append(h.secrets, credentials.GetAccessToken(), credentials.GetRefreshToken())
	capture(c, at, "BeginNodeSignIn", "key-registered", node.BeginRequest(pkce), &fleetv1.NodeEnrollmentServiceBeginNodeSignInResponse{})
	capture(c, call{h: off}, "CompleteNodeSignIn", "surface-off", node.CompleteRequest(s.flowID, s.code, pkce, node.CompleteProof(publicBaseURL, s.flowID, s.code)),
		&fleetv1.NodeEnrollmentServiceCompleteNodeSignInResponse{})

	// The code's lifetime passed (SEEDED: code_expires_at set in the past).
	expiring := begin(fixedNode(t, 0x31), fixedSignIn(0x31), "")
	approve(expiring)
	h.db.Exec("UPDATE fleet.node_sign_in SET code_expires_at = now() - interval '1 second', rev = rev + 1 WHERE flow_id = '" + expiring.flowID.String() + "'")
	complete("expired", expiring, expiring.code, expiring.pkce.Verifier, at)

	// The node ID is live in another account (a node of that account with the same node ID enrolled after the approval).
	squatted := begin(fixedNode(t, 0x32), fixedSignIn(0x32), "")
	approve(squatted)
	squatter, err := nodetest.New()
	if err != nil {
		t.Fatal(err)
	}
	squatter.ID = squatted.node.ID
	h.enrollNode(other.id, h.db.Session(other.id, 1), squatter)
	complete("node-id-of-another-account", squatted, squatted.code, squatted.pkce.Verifier, at)

	// The key is registered by a live installation of another account, then (another flow) by a revoked one.
	held := begin(fixedNode(t, 0x33), fixedSignIn(0x33), "")
	approve(held)
	holder, err := nodetest.New()
	if err != nil {
		t.Fatal(err)
	}
	holder.Key, holder.PublicKey = held.node.Key, held.node.PublicKey
	h.enrollNode(other.id, h.db.Session(other.id, 1), holder)
	complete("key-held", held, held.code, held.pkce.Verifier, at)
	retired := begin(fixedNode(t, 0x34), fixedSignIn(0x34), "")
	approve(retired)
	former, err := nodetest.New()
	if err != nil {
		t.Fatal(err)
	}
	former.Key, former.PublicKey = retired.node.Key, retired.node.PublicKey
	third := h.db.Account(1) // the node cap of the capture harness is 2: a third account holds the retired key
	formerEnrollment := h.enrollNode(third, h.db.Session(third, 1), former)
	h.db.Exec("UPDATE device.installation SET revoked_at = now(), rev = rev + 1 WHERE installation_id = '" + formerEnrollment.InstallationID.String() + "'")
	complete("key-retired", retired, retired.code, retired.pkce.Verifier, at)

	// The node cap (2) is reached between the approval and the completion.
	capped := begin(fixedNode(t, 0x35), fixedSignIn(0x35), "")
	approve(capped)
	filler, err := nodetest.New()
	if err != nil {
		t.Fatal(err)
	}
	h.enrollNode(owner.id, h.db.Session(owner.id, 1), filler)
	complete("quota", capped, capped.code, capped.pkce.Verifier, at)

	// A network's failure bucket (3) is full: three junk presentations from it, then the refused one.
	burst := call{h: h, ip: "192.0.2.10"}
	for range 3 {
		junk := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x78}, 32))
		rpcFrom(h, burst.ip, completePath, s.node.CompleteRequest(s.flowID, junk, pkce, s.node.CompleteProof(publicBaseURL, s.flowID, junk)))
	}
	complete("rate-limited", s, wrong, pkce.Verifier, burst)
	// A network's Begin bucket (20) is full.
	flood := call{h: h, ip: "192.0.2.20"}
	for range 20 {
		filler, err := nodetest.New()
		if err != nil {
			t.Fatal(err)
		}
		rpcFrom(h, flood.ip, beginPath, filler.BeginRequest(nodetest.NewSignIn()))
	}
	capture(c, flood, "BeginNodeSignIn", "rate-limited", fixedNode(t, 0x36).BeginRequest(fixedSignIn(0x36)), &fleetv1.NodeEnrollmentServiceBeginNodeSignInResponse{})

	// The node credential: its report, its refresh, its sign-out.
	report := &fleetv1.NodeEnrollmentServiceReportNodeInfoRequest{Meta: &foundationv1.RequestMeta{CommandId: &foundationv1.Id{Value: bytes.Repeat([]byte{0x01}, 16)}},
		Node: node.Info()}
	capture(c, call{h: h, bearer: credentials.GetAccessToken()}, "ReportNodeInfo", "ok", report, &fleetv1.NodeEnrollmentServiceReportNodeInfoResponse{})
	reused := proto.Clone(report).(*fleetv1.NodeEnrollmentServiceReportNodeInfoRequest)
	reused.Node.Name = proto.String("renamed")
	capture(c, call{h: h, bearer: credentials.GetAccessToken()}, "ReportNodeInfo", "command-id-reused", reused, &fleetv1.NodeEnrollmentServiceReportNodeInfoResponse{})
	mismatch := proto.Clone(report).(*fleetv1.NodeEnrollmentServiceReportNodeInfoRequest)
	mismatch.Meta.CommandId = &foundationv1.Id{Value: bytes.Repeat([]byte{0x02}, 16)}
	mismatch.Node.NodeId = &foundationv1.Id{Value: bytes.Repeat([]byte{0x03}, 16)}
	capture(c, call{h: h, bearer: credentials.GetAccessToken()}, "ReportNodeInfo", "node-id-mismatch", mismatch, &fleetv1.NodeEnrollmentServiceReportNodeInfoResponse{})

	refresh := func(token string) *fleetv1.NodeEnrollmentServiceRefreshNodeSessionRequest {
		return &fleetv1.NodeEnrollmentServiceRefreshNodeSessionRequest{Meta: &foundationv1.RequestMeta{}, RefreshToken: proto.String(token)}
	}
	capture(c, at, "RefreshNodeSession", "unknown-token", refresh(session.RefreshPrefix+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 32))),
		&fleetv1.NodeEnrollmentServiceRefreshNodeSessionResponse{})
	capture(c, at, "RefreshNodeSession", "account-token", refresh(owner.refresh), &fleetv1.NodeEnrollmentServiceRefreshNodeSessionResponse{})
	refreshed := capture(c, at, "RefreshNodeSession", "ok", refresh(credentials.GetRefreshToken()), &fleetv1.NodeEnrollmentServiceRefreshNodeSessionResponse{})
	if refreshed.GetError() != nil {
		t.Fatalf("refresh: %s", failure(refreshed.GetError()))
	}
	h.secrets = append(h.secrets, refreshed.GetValue().GetAccessToken(), refreshed.GetValue().GetRefreshToken())
	signOut := &fleetv1.NodeEnrollmentServiceSignOutNodeRequest{Meta: &foundationv1.RequestMeta{CommandId: &foundationv1.Id{Value: bytes.Repeat([]byte{0x04}, 16)}}}
	capture(c, call{h: h, bearer: refreshed.GetValue().GetAccessToken()}, "SignOutNode", "ok", signOut, &fleetv1.NodeEnrollmentServiceSignOutNodeResponse{})
	capture(c, call{h: h, bearer: refreshed.GetValue().GetAccessToken()}, "SignOutNode", "retry-after-revocation", signOut, &fleetv1.NodeEnrollmentServiceSignOutNodeResponse{})
	capture(c, at, "RefreshNodeSession", "spent-token", refresh(credentials.GetRefreshToken()), &fleetv1.NodeEnrollmentServiceRefreshNodeSessionResponse{})
	// The correct code again revokes the family it delivered (last: it ends the node credential).
	complete("code-reused", s, s.code, pkce.Verifier, at)

	// Every required outcome of every node-facing method has a case, and every case has a required outcome.
	for method, outcomes := range requiredOutcomes {
		for _, outcome := range outcomes {
			found := false
			for _, captured := range c.cases {
				found = found || captured.Method == method && captured.Outcome == outcome
			}
			if !found {
				t.Errorf("%s has no case with the outcome %s", method, outcome)
			}
		}
	}
	for name, captured := range c.cases {
		if !slices.Contains(requiredOutcomes[captured.Method], captured.Outcome) {
			t.Errorf("%s has the outcome %s, which no required outcome names", name, captured.Outcome)
		}
	}
	if os.Getenv("ARCFORGES_UPDATE_EXCHANGES") == "1" {
		writeExchanges(t, c.cases)
		return
	}
	committed, err := filepath.Glob(filepath.Join(exchangesDirectory, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(committed) != len(c.cases) {
		t.Errorf("%d committed exchanges, %d captured: run ARCFORGES_UPDATE_EXCHANGES=1 go test -run TestFleetExchangeCapture", len(committed), len(c.cases))
	}
	for _, file := range committed {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var stored exchange
		if err = json.Unmarshal(data, &stored); err != nil {
			t.Fatal(err)
		}
		captured, ok := c.cases[strings.TrimSuffix(filepath.Base(file), ".json")]
		stored.CenterCommit, captured.CenterCommit = "", ""
		if !ok || !equalExchanges(stored, captured) {
			t.Errorf("%s differs from a fresh capture: run ARCFORGES_UPDATE_EXCHANGES=1 go test -run TestFleetExchangeCapture", file)
		}
	}
}

// rpcFrom posts an uncaptured request from a client address and ignores the reply.
func rpcFrom(h *harness, ip, path string, request proto.Message) {
	h.t.Helper()
	client := h.client
	client.ClientIP = ip
	if _, err := client.Post(path, request, ""); err != nil {
		h.t.Fatal(err)
	}
}

func equalExchanges(a, b exchange) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}

// writeExchanges replaces the committed directory with the captures.
func writeExchanges(t *testing.T, cases map[string]exchange) {
	t.Helper()
	if err := os.RemoveAll(exchangesDirectory); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(exchangesDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(cases))
	for name := range cases {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		value := cases[name]
		value.CenterCommit = os.Getenv("ARCFORGES_CENTER_COMMIT")
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(exchangesDirectory, name+".json"), append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
