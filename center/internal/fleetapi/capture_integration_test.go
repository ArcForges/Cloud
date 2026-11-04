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
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// EVIDENCE: REAL PostgreSQL, the REAL center behind its ingress, binary gRPC-Web posted by this harness exactly as a node sends it
// (E1-25, delivery-5): the node-facing exchanges of the browser sign-in and the node credential, captured as the bytes on the wire
// and normalized, for the ArcForges FakeCenter's conformance test (parts N1 and N2 copy the directory verbatim). MOCKED: the node's
// key and PKCE values are fixed by the test, the account's passkey is virtual. Determinism comes from normalization, not from seams:
// no fixed clock and no injected randomness in the center; the volatile fields are replaced by fixed placeholders of the same kind
// and the frames re-encoded, so every frame stays a valid gRPC-Web frame the real generated types parse.

// exchangesDirectory holds one file per captured case.
const exchangesDirectory = "testdata/exchanges"

// exchangeSchemaVersion versions the capture format.
const exchangeSchemaVersion = 1

// normalizationRules are the placeholders of the volatile fields, recorded in every file.
var normalizationRules = []string{
	"meta.correlation_id and every ArcError.correlation_id: 16 bytes of 0xc0",
	"flow_id (request and reply): 16 bytes of 0xf1; authorize_url is rebuilt from the public base URL and that flow ID",
	"installation_id: 16 bytes of 0x1a; account.account_id: 16 bytes of 0xac",
	"access_token: afa1. and 43 A; refresh_token: afr1. and 43 R (the formats of the center's tokens)",
	"code: 43 C; node_key_proof: 64 bytes of 0x50",
	"every Instant: unix_seconds is the offset from the harness clock at the call, rounded to 5 seconds; nanos 0",
}

// exchange is one captured call.
type exchange struct {
	SchemaVersion   int      `json:"schemaVersion"`
	Source          string   `json:"source"`
	ContractsCohort string   `json:"contractsCohort"`
	CenterCommit    string   `json:"centerCommit"`
	Method          string   `json:"method"`
	Case            string   `json:"case"`
	Request         wireCall `json:"request"`
	Reply           wireCall `json:"reply"`
	Normalized      []string `json:"normalized"`
	SHA256          string   `json:"sha256"`
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

// normalize replaces the volatile fields of a message in place (normalizationRules).
func normalize(message protoreflect.Message, base time.Time) {
	fill := func(value byte, size int) []byte { return bytes.Repeat([]byte{value}, size) }
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		name := string(field.Name())
		switch {
		case field.Kind() == protoreflect.MessageKind && field.Message().FullName() == "arcforges.foundation.v1.Id" && !field.IsList():
			placeholder := map[string]byte{"correlation_id": 0xc0, "flow_id": 0xf1, "installation_id": 0x1a, "account_id": 0xac}
			if b, ok := placeholder[name]; ok {
				message.Set(field, protoreflect.ValueOfMessage((&foundationv1.Id{Value: fill(b, 16)}).ProtoReflect()))
			}
		case field.Kind() == protoreflect.MessageKind && field.Message().FullName() == "arcforges.foundation.v1.Instant" && !field.IsList():
			instant := value.Message().Interface().(*foundationv1.Instant)
			at := time.Unix(instant.GetUnixSeconds(), int64(instant.GetNanos()))
			offset := int64(math.Round(at.Sub(base).Seconds()/5) * 5)
			message.Set(field, protoreflect.ValueOfMessage((&foundationv1.Instant{UnixSeconds: proto.Int64(offset), Nanos: proto.Uint32(0)}).ProtoReflect()))
		case field.Kind() == protoreflect.MessageKind && !field.IsList() && !field.IsMap():
			normalize(value.Message(), base)
		case field.Kind() == protoreflect.MessageKind && field.IsList():
			list := value.List()
			for i := 0; i < list.Len(); i++ {
				normalize(list.Get(i).Message(), base)
			}
		case name == "access_token":
			message.Set(field, protoreflect.ValueOfString(session.AccessPrefix+strings.Repeat("A", 43)))
		case name == "refresh_token":
			message.Set(field, protoreflect.ValueOfString(session.RefreshPrefix+strings.Repeat("R", 43)))
		case name == "code":
			if field.ContainingMessage().FullName() == "arcforges.fleet.v1.NodeEnrollmentServiceCompleteNodeSignInRequest" {
				message.Set(field, protoreflect.ValueOfString(strings.Repeat("C", 43)))
			}
		case name == "node_key_proof":
			message.Set(field, protoreflect.ValueOfBytes(fill(0x50, 64)))
		case name == "authorize_url":
			message.Set(field, protoreflect.ValueOfString(nodetest.DerivedAuthorizeURL(publicBaseURL, fill(0xf1, 16))))
		}
		return true
	})
}

// capturer posts calls of a fixed node and records them.
type capturer struct {
	h     *harness
	cases map[string]exchange
}

// capture sends a request as a node does, returns the decoded reply and records the exchange under method-case.
func capture[Response proto.Message](c *capturer, method, name string, request proto.Message, bearer string, response Response) Response {
	c.h.t.Helper()
	base := time.Now()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		c.h.t.Fatal(err)
	}
	httpRequest, err := http.NewRequest(http.MethodPost, c.h.client.URL+"/arcforges.fleet.v1.NodeEnrollmentService/"+method, bytes.NewReader(frame(0, payload)))
	if err != nil {
		c.h.t.Fatal(err)
	}
	httpRequest.Header.Set("Content-Type", "application/grpc-web+proto")
	httpRequest.Header.Set(c.h.client.ClientIPHeader, "198.51.100.7")
	if bearer != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+bearer)
	}
	reply, err := http.DefaultClient.Do(httpRequest)
	if err != nil {
		c.h.t.Fatal(err)
	}
	body, err := io.ReadAll(reply.Body)
	_ = reply.Body.Close()
	if err != nil {
		c.h.t.Fatal(err)
	}
	normalizedRequest := proto.Clone(request)
	normalize(normalizedRequest.ProtoReflect(), base)
	requestBytes, _ := proto.MarshalOptions{Deterministic: true}.Marshal(normalizedRequest)
	result := exchange{SchemaVersion: exchangeSchemaVersion, Source: "TestFleetExchangeCapture", ContractsCohort: "1.0.0-ci.424.1", Method: method, Case: name,
		Request:    wireCall{ContentType: "application/grpc-web+proto", Frames: []string{hex.EncodeToString(frame(0, requestBytes))}},
		Reply:      wireCall{ContentType: reply.Header.Get("Content-Type"), HTTPStatus: reply.StatusCode, Frames: []string{}},
		Normalized: normalizationRules}
	for position := 0; position+5 <= len(body); {
		flag, length := body[position], int(binary.BigEndian.Uint32(body[position+1:position+5]))
		data := body[position+5 : position+5+length]
		position += 5 + length
		if flag&0x80 != 0 {
			result.Reply.Trailers = string(data)
			continue
		}
		if err = proto.Unmarshal(data, response); err != nil {
			c.h.t.Fatal(err)
		}
		normalized := proto.Clone(response)
		normalize(normalized.ProtoReflect(), base)
		encoded, _ := proto.MarshalOptions{Deterministic: true}.Marshal(normalized)
		result.Reply.Frames = append(result.Reply.Frames, hex.EncodeToString(frame(0, encoded)))
	}
	content, _ := json.Marshal(struct {
		Method, Case string
		Request      wireCall
		Reply        wireCall
		Normalized   []string
	}{result.Method, result.Case, result.Request, result.Reply, result.Normalized})
	digest := sha256.Sum256(content)
	result.SHA256 = hex.EncodeToString(digest[:])
	if _, twice := c.cases[method+"-"+name]; twice {
		c.h.t.Fatalf("two captures named %s-%s", method, name)
	}
	c.cases[method+"-"+name] = result
	return response
}

// fixedNode is the capture's node: a fixed node ID and a fixed P-256 key, so its requests are the same on every run.
func fixedNode(t *testing.T) *nodetest.Node {
	t.Helper()
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), bytes.Repeat([]byte{0x2a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &nodetest.Node{ID: platform.ID{0x6e, 0x6f, 0x64, 0x65, 0x2d, 0x69, 0x64, 0x2d, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78}, Key: key, PublicKey: der,
		Name: "buildbox", Version: "0.1.0-dev+15d6717144468ce0be615e8538f858d29b0fed7d", OS: nodev1.OsFamily_OS_FAMILY_LINUX, Arch: nodev1.CpuArchitecture_CPU_ARCHITECTURE_X64}
}

// TestFleetExchangeCapture (E1-25, delivery-5): captures the node-facing exchanges (Begin, Complete, Refresh, ReportNodeInfo,
// SignOutNode, each with its success and its refusals) and compares them with the committed directory; with
// ARCFORGES_UPDATE_EXCHANGES=1 it writes the directory instead (ARCFORGES_CENTER_COMMIT names the commit in the headers). Every
// node-facing served method has a success case and a refusal case, and every file is a case this test produces.
func TestFleetExchangeCapture(t *testing.T) {
	h := newHarness(t, settings{})
	c := &capturer{h: h, cases: map[string]exchange{}}
	owner := h.person(1)
	node := fixedNode(t)
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := sha256.Sum256([]byte(verifier))
	pkce := nodetest.SignIn{Verifier: verifier, Challenge: base64.RawURLEncoding.EncodeToString(challenge[:]), RedirectURI: "http://127.0.0.1:53682/callback",
		State: "node-state-0123456789-abcdefghijklmnop"}

	invalid := node.BeginRequest(pkce)
	invalid.RedirectUri = proto.String("http://localhost:53682/callback")
	capture(c, "BeginNodeSignIn", "invalid-redirect", invalid, "", &fleetv1.NodeEnrollmentServiceBeginNodeSignInResponse{})
	begun := capture(c, "BeginNodeSignIn", "ok", node.BeginRequest(pkce), "", &fleetv1.NodeEnrollmentServiceBeginNodeSignInResponse{})
	if begun.GetError() != nil {
		t.Fatalf("begin: %s", failure(begun.GetError()))
	}
	s := &signIn{node: node, pkce: pkce, flowID: flowIDOf(begun.GetValue().GetFlowId()), value: begun.GetValue()}
	h.approve(owner, s, false)

	wrong := strings.Repeat("W", 43)
	capture(c, "CompleteNodeSignIn", "unauthenticated", node.CompleteRequest(s.flowID, wrong, pkce, node.CompleteProof(publicBaseURL, s.flowID, wrong)), "",
		&fleetv1.NodeEnrollmentServiceCompleteNodeSignInResponse{})
	unknown := platform.ID{0xde, 0xad}
	capture(c, "CompleteNodeSignIn", "not-found", node.CompleteRequest(unknown, s.code, pkce, node.CompleteProof(publicBaseURL, unknown, s.code)), "",
		&fleetv1.NodeEnrollmentServiceCompleteNodeSignInResponse{})
	completed := capture(c, "CompleteNodeSignIn", "ok", node.CompleteRequest(s.flowID, s.code, pkce, node.CompleteProof(publicBaseURL, s.flowID, s.code)), "",
		&fleetv1.NodeEnrollmentServiceCompleteNodeSignInResponse{})
	credentials := completed.GetValue().GetCredentials()
	if completed.GetError() != nil || credentials == nil {
		t.Fatalf("complete: %s", failure(completed.GetError()))
	}
	h.secrets = append(h.secrets, credentials.GetAccessToken(), credentials.GetRefreshToken())
	capture(c, "BeginNodeSignIn", "key-registered", node.BeginRequest(pkce), "", &fleetv1.NodeEnrollmentServiceBeginNodeSignInResponse{})

	report := &fleetv1.NodeEnrollmentServiceReportNodeInfoRequest{Meta: &foundationv1.RequestMeta{CommandId: &foundationv1.Id{Value: bytes.Repeat([]byte{0x01}, 16)}},
		Node: node.Info()}
	capture(c, "ReportNodeInfo", "ok", report, credentials.GetAccessToken(), &fleetv1.NodeEnrollmentServiceReportNodeInfoResponse{})
	mismatch := proto.Clone(report).(*fleetv1.NodeEnrollmentServiceReportNodeInfoRequest)
	mismatch.Meta.CommandId = &foundationv1.Id{Value: bytes.Repeat([]byte{0x02}, 16)}
	mismatch.Node.NodeId = &foundationv1.Id{Value: bytes.Repeat([]byte{0x03}, 16)}
	capture(c, "ReportNodeInfo", "node-id-mismatch", mismatch, credentials.GetAccessToken(), &fleetv1.NodeEnrollmentServiceReportNodeInfoResponse{})

	capture(c, "RefreshNodeSession", "unknown-token", &fleetv1.NodeEnrollmentServiceRefreshNodeSessionRequest{Meta: &foundationv1.RequestMeta{},
		RefreshToken: proto.String(session.RefreshPrefix + strings.Repeat("Q", 43))}, "", &fleetv1.NodeEnrollmentServiceRefreshNodeSessionResponse{})
	refreshed := capture(c, "RefreshNodeSession", "ok", &fleetv1.NodeEnrollmentServiceRefreshNodeSessionRequest{Meta: &foundationv1.RequestMeta{},
		RefreshToken: proto.String(credentials.GetRefreshToken())}, "", &fleetv1.NodeEnrollmentServiceRefreshNodeSessionResponse{})
	if refreshed.GetError() != nil {
		t.Fatalf("refresh: %s", failure(refreshed.GetError()))
	}
	h.secrets = append(h.secrets, refreshed.GetValue().GetAccessToken(), refreshed.GetValue().GetRefreshToken())
	signOut := &fleetv1.NodeEnrollmentServiceSignOutNodeRequest{Meta: &foundationv1.RequestMeta{CommandId: &foundationv1.Id{Value: bytes.Repeat([]byte{0x04}, 16)}}}
	capture(c, "SignOutNode", "ok", signOut, refreshed.GetValue().GetAccessToken(), &fleetv1.NodeEnrollmentServiceSignOutNodeResponse{})
	capture(c, "SignOutNode", "retry-after-revocation", signOut, refreshed.GetValue().GetAccessToken(), &fleetv1.NodeEnrollmentServiceSignOutNodeResponse{})
	capture(c, "RefreshNodeSession", "spent-token", &fleetv1.NodeEnrollmentServiceRefreshNodeSessionRequest{Meta: &foundationv1.RequestMeta{},
		RefreshToken: proto.String(credentials.GetRefreshToken())}, "", &fleetv1.NodeEnrollmentServiceRefreshNodeSessionResponse{})
	capture(c, "CompleteNodeSignIn", "code-reused", node.CompleteRequest(s.flowID, s.code, pkce, node.CompleteProof(publicBaseURL, s.flowID, s.code)), "",
		&fleetv1.NodeEnrollmentServiceCompleteNodeSignInResponse{})

	// Every node-facing served method has a success and at least one refusal.
	for _, method := range []string{"BeginNodeSignIn", "CompleteNodeSignIn", "RefreshNodeSession", "ReportNodeInfo", "SignOutNode"} {
		names := 0
		for key := range c.cases {
			if strings.HasPrefix(key, method+"-") {
				names++
			}
		}
		if _, ok := c.cases[method+"-ok"]; !ok || names < 2 {
			t.Errorf("%s has no success or no refusal case", method)
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
