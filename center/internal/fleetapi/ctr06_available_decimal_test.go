// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The paired Node test runs the exact published 450.1 generated Decimal
// validator; these cases exercise the Center's real response decoder.
func TestCTR06AvailableUsesPublishedDecimalInPlanResponses(t *testing.T) {
	method := relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL
	request := &nodev1.FileServicePlanRemovalRequest{
		Meta: &foundationv1.RequestMeta{CommandId: pid(platform.NewID())},
		Target: &nodev1.FileServicePlanRemovalRequest_WorkspacePath{WorkspacePath: &nodev1.FilePath{
			WorkspaceId: pid(platform.NewID()), Path: proto.String("tree"),
		}},
	}
	base := limitResponse(method, "removal_ownership_input_bytes", "67108864").(*nodev1.FileServicePlanRemovalResponse)
	for _, tc := range []struct {
		name, value string
		present     bool
		hasValue    bool
		valid       bool
	}{
		{"absent", "", false, false, true},
		{"trailing zeros", "1.00", true, true, true},
		{"zero fraction", "0.0", true, true, true},
		{"negative nonzero", "-1.00", true, true, true},
		{"nine zero fractional", "0.000000000", true, true, true},
		{"small fraction", "0.000000001", true, true, true},
		{"28 significant", "9999999999999999999999999999", true, true, true},
		{"empty", "", true, true, false},
		{"value absent", "", true, false, false},
		{"leading zero", "01.0", true, true, false},
		{"negative zero", "-0.0", true, true, false},
		{"plus sign", "+1", true, true, false},
		{"empty fraction", "1.", true, true, false},
		{"ten fractional", "0.0000000001", true, true, false},
		{"29 significant", "99999999999999999999999999999", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := proto.Clone(base).(*nodev1.FileServicePlanRemovalResponse)
			if tc.present {
				candidate.GetError().GetDetails().GetLimit().Available = &foundationv1.Decimal{}
				if tc.hasValue {
					candidate.GetError().GetDetails().GetLimit().Available.Value = proto.String(tc.value)
				}
			}
			raw := marshal(t, candidate)
			_, err := decodeFileResponse(method, raw, marshal(t, request))
			if (err == nil) != tc.valid {
				t.Fatalf("accepted=%v want=%v err=%v", err == nil, tc.valid, err)
			}
		})
	}
}

// Method and observation limits still apply when available is generic-valid.
func TestCTR06AvailableDoesNotChangeWriteEditBounds(t *testing.T) {
	path := &nodev1.FilePath{WorkspaceId: pid(platform.NewID()), Path: proto.String("a")}
	write := &nodev1.FileServiceWriteFileRequest{
		Path: path, Data: []byte("x"),
		Precondition: &nodev1.FileServiceWriteFileRequest_ExpectedAbsent{ExpectedAbsent: true},
	}
	edit := &nodev1.FileServiceEditFileRequest{
		Path: path, OldText: proto.String("a"), NewText: proto.String("b"),
		ExpectedOccurrences: proto.Uint32(1), ExpectedSha256: make([]byte, 32),
	}
	for _, tc := range []struct {
		name    string
		method  relayv1.RoutedMethod
		request proto.Message
	}{
		{"write", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, write},
		{"edit", relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE, edit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := limitResponse(tc.method, "file_existing_bytes", "4194304")
			limit := response.GetError().GetDetails().GetLimit()
			limit.Available = &foundationv1.Decimal{Value: proto.String("1.00")}
			if _, err := decodeFileResponse(tc.method, marshal(t, response), marshal(t, tc.request)); err != nil {
				t.Fatalf("valid available rejected: %v", err)
			}
			limit.Maximum.Value = proto.String("4194304.00")
			if _, err := decodeFileResponse(tc.method, marshal(t, response), marshal(t, tc.request)); err == nil {
				t.Fatal("fractional maximum bypassed the method profile")
			}
			limit.Maximum.Value = proto.String("4194304")
			limit.LimitName = proto.String("removal_ownership_input_bytes")
			if _, err := decodeFileResponse(tc.method, marshal(t, response), marshal(t, tc.request)); err == nil {
				t.Fatal("Plan-only canonical input limit was accepted")
			}
			observation := &nodev1.FileAuditObservation{
				Kind: nodev1.FileAuditKind_FILE_AUDIT_KIND_INPUT_BYTES.Enum(), SizeBytes: proto.Uint64(4194304),
				DigestInputBytes: proto.Uint64(4194304), Sha256: make([]byte, 32),
			}
			if !validFileObservation(tc.method, observation) {
				t.Fatal("4 MiB input observation rejected")
			}
			observation.SizeBytes = proto.Uint64(4194305)
			observation.DigestInputBytes = proto.Uint64(4194305)
			if validFileObservation(tc.method, observation) {
				t.Fatal("input observation exceeded the 4 MiB bound")
			}
		})
	}
}
