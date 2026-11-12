// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"crypto/sha256"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// These tests exercise the real decoder and method-bound consumer, not a
// native Node, signed transport, or actual file reads.
func TestCTR06PlanOwnershipInputAuditShapeAndLimit(t *testing.T) {
	method := relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL
	path := &nodev1.FilePath{WorkspaceId: pid(platform.NewID()), Path: proto.String("tree")}
	request := &nodev1.FileServicePlanRemovalRequest{
		Meta:   &foundationv1.RequestMeta{CommandId: pid(platform.NewID())},
		Target: &nodev1.FileServicePlanRemovalRequest_WorkspacePath{WorkspacePath: path},
	}
	digest := sha256.Sum256([]byte("synthetic structural observation"))
	observation := &nodev1.FileAuditObservation{
		Kind: nodev1.FileAuditKind_FILE_AUDIT_KIND_INPUT_BYTES.Enum(), SizeBytes: proto.Uint64(67108864),
		DigestInputBytes: proto.Uint64(67108864), Sha256: digest[:],
	}
	base := limitResponse(method, "removal_ownership_input_bytes", "67108864").(*nodev1.FileServicePlanRemovalResponse)
	base.Audit = &nodev1.FileAuditMetadata{Observations: []*nodev1.FileAuditObservation{observation}}
	original := marshal(t, request)
	if decoded, err := decodeFileResponse(method, marshal(t, base), original); err != nil || !proto.Equal(decoded.GetAudit(), base.Audit) {
		t.Fatalf("valid node input observation: %v", err)
	}

	cases := []struct {
		name   string
		change func(*nodev1.FileServicePlanRemovalResponse)
		valid  bool
	}{
		{"no observation", func(v *nodev1.FileServicePlanRemovalResponse) { v.Audit = nil }, true},
		{"empty metadata", func(v *nodev1.FileServicePlanRemovalResponse) { v.Audit = &nodev1.FileAuditMetadata{} }, true},
		{"one byte", func(v *nodev1.FileServicePlanRemovalResponse) {
			v.Audit.Observations[0].SizeBytes = proto.Uint64(1)
			v.Audit.Observations[0].DigestInputBytes = proto.Uint64(1)
		}, true},
		{"zero input", func(v *nodev1.FileServicePlanRemovalResponse) {
			v.Audit.Observations[0].SizeBytes = proto.Uint64(0)
			v.Audit.Observations[0].DigestInputBytes = proto.Uint64(0)
		}, false},
		{"over input", func(v *nodev1.FileServicePlanRemovalResponse) {
			v.Audit.Observations[0].SizeBytes = proto.Uint64(67108865)
			v.Audit.Observations[0].DigestInputBytes = proto.Uint64(67108865)
		}, false},
		{"unequal counts", func(v *nodev1.FileServicePlanRemovalResponse) {
			v.Audit.Observations[0].DigestInputBytes = proto.Uint64(1)
		}, false},
		{"item count present", func(v *nodev1.FileServicePlanRemovalResponse) {
			v.Audit.Observations[0].ItemCount = proto.Uint32(0)
		}, false},
		{"short hash", func(v *nodev1.FileServicePlanRemovalResponse) {
			v.Audit.Observations[0].Sha256 = make([]byte, 31)
		}, false},
		{"unrelated observation", func(v *nodev1.FileServicePlanRemovalResponse) {
			v.Audit.Observations[0].Kind = nodev1.FileAuditKind_FILE_AUDIT_KIND_OPERATION_METADATA.Enum()
		}, false},
		{"duplicate observation", func(v *nodev1.FileServicePlanRemovalResponse) {
			v.Audit.Observations = append(v.Audit.Observations, proto.Clone(v.Audit.Observations[0]).(*nodev1.FileAuditObservation))
		}, false},
		{"opaque bound", func(v *nodev1.FileServicePlanRemovalResponse) {
			v.GetError().GetDetails().GetLimit().LimitName = proto.String("opaque.64m")
		}, true},
		{"fractional profile limit", func(v *nodev1.FileServicePlanRemovalResponse) {
			v.GetError().GetDetails().GetLimit().Maximum.Value = proto.String("67108864.00")
		}, false},
		{"generic leading zero", func(v *nodev1.FileServicePlanRemovalResponse) {
			v.GetError().GetDetails().GetLimit().Maximum.Value = proto.String("067108864")
		}, false},
		{"wrong maximum", func(v *nodev1.FileServicePlanRemovalResponse) {
			v.GetError().GetDetails().GetLimit().Maximum.Value = proto.String("67108863")
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := proto.Clone(base).(*nodev1.FileServicePlanRemovalResponse)
			tc.change(candidate)
			_, err := decodeFileResponse(method, marshal(t, candidate), original)
			if (err == nil) != tc.valid {
				t.Fatalf("accepted=%v, expected=%v, error=%v", err == nil, tc.valid, err)
			}
		})
	}

	execute := &nodev1.FileServiceExecuteRemovalRequest{PlanId: pid(platform.NewID()), PlanDigest: make([]byte, 32)}
	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{"removal_ownership_input_bytes", false},
		{"removal_total_bytes", true},
		{"opaque.64m", true},
	} {
		response := limitResponse(relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL, tc.name, "67108864")
		_, err := decodeFileResponse(relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL, marshal(t, response), marshal(t, execute))
		if (err == nil) != tc.valid {
			t.Fatalf("execute limit %q accepted=%v, expected=%v: %v", tc.name, err == nil, tc.valid, err)
		}
	}
	if validFileObservation(relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE, observation) {
		t.Fatal("read accepted a PlanRemoval input observation")
	}
	if validFileObservation(relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, observation) {
		t.Fatal("write accepted the larger PlanRemoval input bound")
	}
}
