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

// This tests the existing stricter AF-CTR-06 maximum helper and nested
// foundation errors. The published 450.1 Decimal shape is checked separately.
func TestCTR06FoundationDecimalAndNestedErrorShapes(t *testing.T) {
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"0", true}, {"-0", false}, {"0.1", true}, {"-0.1", true},
		{"1.01", true}, {"1.0", false}, {"196608.00", false}, {"4194304", true},
		{"01", false}, {"+1", false}, {"1.", false}, {"0.000000001", true},
		{"0.0000000001", false}, {"9999999999999999999999999999", true},
		{"99999999999999999999999999999", false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			if got := validDecimal(&foundationv1.Decimal{Value: proto.String(tc.value)}); got != tc.valid {
				t.Fatalf("validDecimal(%q)=%v, want %v", tc.value, got, tc.valid)
			}
		})
	}
	write := relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE
	q := &nodev1.FileServiceWriteFileRequest{Path: &nodev1.FilePath{WorkspaceId: pid(platform.NewID()), Path: proto.String("a")},
		Data: []byte("x"), Precondition: &nodev1.FileServiceWriteFileRequest_ExpectedAbsent{ExpectedAbsent: true}}
	base := limitResponse(write, "existing_file_size_bytes", "4194304").(*nodev1.FileServiceWriteFileResponse)
	for _, tc := range []struct {
		name   string
		change func(*foundationv1.ArcError)
	}{
		{"missing maximum", func(e *foundationv1.ArcError) { e.GetDetails().GetLimit().Maximum = nil }},
		{"missing name", func(e *foundationv1.ArcError) { e.GetDetails().GetLimit().LimitName = nil }},
		{"bad available decimal", func(e *foundationv1.ArcError) {
			e.GetDetails().GetLimit().Available = &foundationv1.Decimal{Value: proto.String("01.0")}
		}},
		{"missing recovery nanos", func(e *foundationv1.ArcError) {
			e.GetDetails().GetLimit().RecoveryAt = &foundationv1.Instant{UnixSeconds: proto.Int64(1)}
		}},
		{"retry at with never", func(e *foundationv1.ArcError) {
			e.Retry.RetryAt = &foundationv1.Instant{UnixSeconds: proto.Int64(1), Nanos: proto.Uint32(0)}
		}},
		{"nonzero id required", func(e *foundationv1.ArcError) { e.CorrelationId = &foundationv1.Id{Value: make([]byte, 16)} }},
		{"wrong message key", func(e *foundationv1.ArcError) { e.MessageKey = proto.String("error.resource.other") }},
		{"unknown with after time", func(e *foundationv1.ArcError) {
			e.Effect = foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN.Enum()
			e.Retry.Mode = foundationv1.RetryMode_RETRY_MODE_AFTER_TIME.Enum()
			e.Retry.RetryAt = &foundationv1.Instant{UnixSeconds: proto.Int64(1), Nanos: proto.Uint32(0)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := proto.Clone(base).(*nodev1.FileServiceWriteFileResponse)
			tc.change(bad.GetError())
			if _, err := decodeFileResponse(write, marshal(t, bad), marshal(t, q)); err == nil {
				t.Fatal("invalid nested foundation error was accepted")
			}
		})
	}
	approval := fileCatalogueError(foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHORIZATION, "approval_required", "file", "permission")
	approval.Retry.Mode = foundationv1.RetryMode_RETRY_MODE_RECONCILE.Enum()
	approval.Retry.ReconciliationOperation = proto.String("operation with spaces")
	if validFileError(approval) {
		t.Fatal("published reconciliation operation token shape not enforced")
	}
}

// A status contains only original digest and target, not original request
// bytes. The caller-bound router separately verifies ownership and that digest.
func TestCTR06CompletedOperationResourceErrorUsesOriginalMethod(t *testing.T) {
	command := pid(platform.NewID())
	now := &foundationv1.Instant{UnixSeconds: proto.Int64(1700000000), Nanos: proto.Uint32(0)}
	q := &nodev1.FileServiceGetFileOperationRequest{OperationCommandId: command}
	method := relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_FILE_OPERATION
	operation := &nodev1.FileOperation{CommandId: command, Kind: nodev1.FileOperationKind_FILE_OPERATION_KIND_WRITE.Enum(),
		State: nodev1.FileOperationState_FILE_OPERATION_STATE_COMPLETED.Enum(), RequestSha256: make([]byte, 32),
		CreatedAt: now, UpdatedAt: now, Acknowledged: proto.Bool(false), Held: proto.Bool(false),
		Target: &nodev1.FileOperation_WorkspacePath{WorkspacePath: &nodev1.FilePath{WorkspaceId: pid(platform.NewID()), Path: proto.String("a")}}}
	for _, tc := range []struct {
		name           string
		kind           nodev1.FileOperationKind
		limit, maximum string
		valid          bool
		change         func(*nodev1.FileOperation)
	}{
		{"known original write size is unavailable", nodev1.FileOperationKind_FILE_OPERATION_KIND_WRITE, "file_write_bytes", "196608", true, nil},
		{"open original write existing", nodev1.FileOperationKind_FILE_OPERATION_KIND_WRITE, "existing_file_size_bytes", "4194304", true, nil},
		{"known target contradicts path limit", nodev1.FileOperationKind_FILE_OPERATION_KIND_WRITE, "path_bytes", "4096", false, nil},
		{"known target contradicts open path limit", nodev1.FileOperationKind_FILE_OPERATION_KIND_WRITE, "legacy_path_bytes", "4096", false, nil},
		{"open original edit ambiguous", nodev1.FileOperationKind_FILE_OPERATION_KIND_EDIT, "historic_file_bound", "4194304", true, nil},
		{"canonical original edit result", nodev1.FileOperationKind_FILE_OPERATION_KIND_EDIT, "file_edit_result_bytes", "4194304", true, nil},
		{"removal tree bytes", nodev1.FileOperationKind_FILE_OPERATION_KIND_REMOVAL, "removal_total_bytes", "67108864", true, nil},
		{"canonical wrong original kind", nodev1.FileOperationKind_FILE_OPERATION_KIND_WRITE, "file_edit_result_bytes", "4194304", false, nil},
		{"wrong original maximum", nodev1.FileOperationKind_FILE_OPERATION_KIND_WRITE, "existing_file_size_bytes", "3", false, nil},
		{"noncanonical maximum", nodev1.FileOperationKind_FILE_OPERATION_KIND_WRITE, "file_write_bytes", "196608.00", false, nil},
		{"completed acknowledged", nodev1.FileOperationKind_FILE_OPERATION_KIND_WRITE, "file_existing_bytes", "4194304", false, func(op *nodev1.FileOperation) { op.Acknowledged = proto.Bool(true) }},
		{"completed held", nodev1.FileOperationKind_FILE_OPERATION_KIND_WRITE, "file_existing_bytes", "4194304", false, func(op *nodev1.FileOperation) { op.Held = proto.Bool(true) }},
		{"prepared cannot have outcome", nodev1.FileOperationKind_FILE_OPERATION_KIND_WRITE, "file_existing_bytes", "4194304", false, func(op *nodev1.FileOperation) {
			op.State = nodev1.FileOperationState_FILE_OPERATION_STATE_PREPARED.Enum()
		}},
		{"unknown cannot have known-effect limit", nodev1.FileOperationKind_FILE_OPERATION_KIND_WRITE, "file_existing_bytes", "4194304", false, func(op *nodev1.FileOperation) {
			op.State = nodev1.FileOperationState_FILE_OPERATION_STATE_UNKNOWN.Enum()
			op.Held = proto.Bool(true)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op := proto.Clone(operation).(*nodev1.FileOperation)
			op.Kind = tc.kind.Enum()
			original := operationMethod(tc.kind)
			op.Outcome = &nodev1.FileOperation_Error{Error: limitResponse(original, tc.limit, tc.maximum).GetError()}
			if tc.change != nil {
				tc.change(op)
			}
			reply := &nodev1.FileServiceGetFileOperationResponse{Outcome: &nodev1.FileServiceGetFileOperationResponse_Value{
				Value: &nodev1.FileServiceGetFileOperationValue{Operation: op},
			}}
			_, err := decodeFileResponse(method, marshal(t, reply), marshal(t, q))
			if (err == nil) != tc.valid {
				t.Fatalf("accepted=%v, want %v, err=%v", err == nil, tc.valid, err)
			}
		})
	}
}
