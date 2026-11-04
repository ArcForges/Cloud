// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"strings"
	"testing"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// EVIDENCE: REAL (the center's request validation) against requests of a MOCKED node (center/internal/nodetest).

// TestBeginValidation (E1-5; CTR4-FLW-01 as amended): every field is checked in order and the first failure is named with its rule.
func TestBeginValidation(t *testing.T) {
	node, err := nodetest.New()
	if err != nil {
		t.Fatal(err)
	}
	valid := func() *fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest {
		return node.BeginRequest(nodetest.NewSignIn())
	}
	if in, err := ParseBegin(valid()); err != nil || in.NodeID != node.ID || in.Node.Version != "0.1.0-dev" || len(in.PublicKey) != NodeKeyLength {
		t.Fatalf("a valid request: %+v %v", in, err)
	}
	for want, change := range map[string]func(*fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest){
		"code_challenge required": func(m *fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest) { m.CodeChallenge = nil },
		"code_challenge pattern": func(m *fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest) {
			m.CodeChallenge = proto.String(strings.Repeat("A", 42) + "=")
		},
		"redirect_uri required": func(m *fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest) { m.RedirectUri = nil },
		"redirect_uri not_admitted": func(m *fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest) {
			m.RedirectUri = proto.String("http://localhost:8080/callback")
		},
		"node required": func(m *fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest) { m.Node = nil },
		"node.node_id required": func(m *fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest) {
			m.Node.NodeId = &foundationv1.Id{Value: make([]byte, 16)}
		},
		"node.name pattern": func(m *fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest) {
			m.Node.Name = proto.String("evil\u202ename")
		},
		"node.os not_admitted": func(m *fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest) { m.Node.Os = nodev1.OsFamily(9).Enum() },
		"node.version pattern": func(m *fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest) { m.Node.Version = proto.String("1.0") },
		"node.role not_admitted": func(m *fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest) {
			m.Node.Role = nodev1.NodeRole_NODE_ROLE_GUEST.Enum()
		},
		"state required":           func(m *fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest) { m.State = nil },
		"state pattern":            func(m *fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest) { m.State = proto.String("short") },
		"node_public_key required": func(m *fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest) { m.NodePublicKey = nil },
		"node_public_key not_p256": func(m *fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest) { m.NodePublicKey = m.NodePublicKey[:90] },
		"code_challenge pattern+rest": func(m *fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest) {
			m.CodeChallenge = proto.String("")
			m.State = nil
		},
	} {
		message := valid()
		change(message)
		_, err := ParseBegin(message)
		if got := key(err); got != violation(strings.TrimSuffix(want, "+rest")) {
			t.Errorf("%s: %s", want, got)
		}
	}
}

// violation is the refusal key of an invalid_argument "<field> <rule>".
func violation(fieldRule string) string {
	field, rule, _ := strings.Cut(fieldRule, " ")
	return "VALIDATION/invalid_argument " + field + "/" + field + ": " + rule
}

// TestCompleteShapeChecks: flow_id, code_verifier and node_key_proof are checked before anything is read; the code is not (a malformed
// code is a failed proof).
func TestCompleteShapeChecks(t *testing.T) {
	flowID := platform.NewID()
	valid := func() *fleetv1.NodeEnrollmentServiceCompleteNodeSignInRequest {
		return &fleetv1.NodeEnrollmentServiceCompleteNodeSignInRequest{FlowId: &foundationv1.Id{Value: flowID[:]}, Code: proto.String("x"),
			CodeVerifier: proto.String(strings.Repeat("v", 43)), NodeKeyProof: make([]byte, 64), Csr: []byte("ignored")}
	}
	if in, err := ParseComplete(valid()); err != nil || in.FlowID != flowID || in.Code != "x" {
		t.Fatalf("a malformed code is not a shape error: %+v %v", in, err)
	}
	for want, change := range map[string]func(*fleetv1.NodeEnrollmentServiceCompleteNodeSignInRequest){
		"flow_id required":       func(m *fleetv1.NodeEnrollmentServiceCompleteNodeSignInRequest) { m.FlowId = nil },
		"code_verifier required": func(m *fleetv1.NodeEnrollmentServiceCompleteNodeSignInRequest) { m.CodeVerifier = nil },
		"code_verifier pattern": func(m *fleetv1.NodeEnrollmentServiceCompleteNodeSignInRequest) {
			m.CodeVerifier = proto.String(strings.Repeat("v", 42))
		},
		"node_key_proof required": func(m *fleetv1.NodeEnrollmentServiceCompleteNodeSignInRequest) { m.NodeKeyProof = nil },
		"node_key_proof length":   func(m *fleetv1.NodeEnrollmentServiceCompleteNodeSignInRequest) { m.NodeKeyProof = make([]byte, 65) },
	} {
		message := valid()
		change(message)
		_, err := ParseComplete(message)
		if key(err) != violation(want) {
			t.Errorf("%s: %s", want, key(err))
		}
	}
}

// TestTheFleetURLsStayWithinTheContract (OQ-13): a public base URL of up to 462 characters keeps every derived URL within 512.
func TestTheFleetURLsStayWithinTheContract(t *testing.T) {
	base := "https://center.example.test/" + strings.Repeat("a", 462-len("https://center.example.test/"))
	if !ValidSignInBaseURL(base) || ValidSignInBaseURL(base+"a") || len(AuthorizeURL(base, platform.NewID())) != MaxDerivedURLLength {
		t.Fatalf("the bound is off: %d", len(AuthorizeURL(base, platform.NewID())))
	}
}
