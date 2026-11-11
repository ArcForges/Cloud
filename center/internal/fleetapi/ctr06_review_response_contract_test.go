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

func fileCatalogueError(category foundationv1.ErrorCategory, code, state, reason string) *foundationv1.ArcError {
	names := map[foundationv1.ErrorCategory]string{
		foundationv1.ErrorCategory_ERROR_CATEGORY_VALIDATION:    "validation",
		foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHORIZATION: "authorization",
		foundationv1.ErrorCategory_ERROR_CATEGORY_CONFLICT:      "conflict",
		foundationv1.ErrorCategory_ERROR_CATEGORY_STATE:         "state",
		foundationv1.ErrorCategory_ERROR_CATEGORY_RESOURCE:      "resource",
		foundationv1.ErrorCategory_ERROR_CATEGORY_EXECUTION:     "execution",
	}
	e := &foundationv1.ArcError{Category: category.Enum(), Code: proto.String(code), MessageKey: proto.String("error." + names[category] + "." + code),
		Retry:  &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_NEVER.Enum()},
		Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN.Enum(), CorrelationId: pid(platform.NewID())}
	if state != "" || reason != "" {
		e.Details = &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_State{State: &foundationv1.StateFailure{State: proto.String(state), Reason: proto.String(reason)}}}
	}
	return e
}

func TestCTR06CatalogueRequiresCodeSpecificDetails(t *testing.T) {
	method := relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE
	conflict := fileCatalogueError(foundationv1.ErrorCategory_ERROR_CATEGORY_CONFLICT, "file_changed", "file", "hash_mismatch")
	if !validFileError(conflict) || !validFileErrorForMethod(method, conflict) {
		t.Fatal("valid file conflict rejected")
	}
	for name, change := range map[string]func(*foundationv1.ArcError){
		"missing state":         func(e *foundationv1.ArcError) { e.Details = nil },
		"wrong state":           func(e *foundationv1.ArcError) { e.GetDetails().GetState().State = proto.String("request") },
		"unrecognized mismatch": func(e *foundationv1.ArcError) { e.GetDetails().GetState().Reason = proto.String("arbitrary") },
	} {
		t.Run(name, func(t *testing.T) {
			e := proto.Clone(conflict).(*foundationv1.ArcError)
			change(e)
			if validFileError(e) && validFileErrorForMethod(method, e) {
				t.Fatal("contradictory file conflict accepted")
			}
		})
	}

	limit := fileCatalogueError(foundationv1.ErrorCategory_ERROR_CATEGORY_RESOURCE, "too_large", "", "")
	if validFileErrorForMethod(method, limit) {
		t.Fatal("too_large without actual limit accepted")
	}
	limit.Details = &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_Limit{Limit: &foundationv1.LimitFailure{
		LimitName: proto.String("file_write_bytes"), Maximum: &foundationv1.Decimal{Value: proto.String("196608")},
	}}}
	if !validFileError(limit) || !validFileErrorForMethod(method, limit) {
		t.Fatal("bounded too_large rejected")
	}
	limit.GetDetails().GetLimit().Maximum.Value = proto.String("-1")
	if validFileErrorForMethod(method, limit) {
		t.Fatal("negative limit accepted")
	}

	for _, reason := range []string{"file_access_denied", "path_link_or_special", "file_hard_link"} {
		e := fileCatalogueError(foundationv1.ErrorCategory_ERROR_CATEGORY_STATE, "file_access_denied", "file", reason)
		if !validFileError(e) || !validFileErrorForMethod(method, e) {
			t.Fatalf("closed access reason %q rejected", reason)
		}
	}
	for _, reason := range []string{"other", "native_0", "native_13", "native_0001", "native_5000", "workspace_path_invalid", "root_not_directory", "root_operation_refused", "file_identity_changed"} {
		e := fileCatalogueError(foundationv1.ErrorCategory_ERROR_CATEGORY_STATE, "file_access_denied", "file", reason)
		if validFileErrorForMethod(method, e) {
			t.Fatalf("unrecognized access reason %q accepted", reason)
		}
	}
	for _, reason := range []string{"file_guard_unavailable", "path_enforcement_unavailable"} {
		e := fileCatalogueError(foundationv1.ErrorCategory_ERROR_CATEGORY_STATE, "file_access_denied", "file", reason)
		if validFileErrorForMethod(method, e) || !validFileErrorForMethod(relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE, e) {
			t.Fatalf("guard failure %q assigned to wrong effect boundary", reason)
		}
	}
	for _, reason := range []string{"expected_hash_mismatch", "identity_mismatch", "object_replaced", "path_replaced"} {
		e := fileCatalogueError(foundationv1.ErrorCategory_ERROR_CATEGORY_CONFLICT, "file_changed", "file", reason)
		if validFileErrorForMethod(method, e) {
			t.Fatalf("unsupported mismatch alias %q accepted", reason)
		}
	}
	// These six WIP allowances depend on independent approval of the bounded
	// Design erratum; other methods stay constrained by their catalogue.
	identityConflict := proto.Clone(conflict).(*foundationv1.ArcError)
	identityConflict.GetDetails().GetState().Reason = proto.String("workspace_root_changed")
	for _, method := range []relayv1.RoutedMethod{relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE,
		relayv1.RoutedMethod_ROUTED_METHOD_SEARCH_NODE_FILES, relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_DIRECTORY,
		relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL, relayv1.RoutedMethod_ROUTED_METHOD_REGISTER_NODE_WORKSPACE,
		relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_WORKSPACE} {
		if !validFileErrorForMethod(method, identityConflict) {
			t.Fatalf("pending identity conflict not represented for %v", method)
		}
	}
	for _, method := range []relayv1.RoutedMethod{relayv1.RoutedMethod_ROUTED_METHOD_UNREGISTER_NODE_WORKSPACE,
		relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_WORKSPACES, relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_FILE_OPERATION} {
		if validFileErrorForMethod(method, conflict) {
			t.Fatalf("file_changed expanded outside pending erratum: %v", method)
		}
	}
	for _, method := range []relayv1.RoutedMethod{relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE, relayv1.RoutedMethod_ROUTED_METHOD_SEARCH_NODE_FILES,
		relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL, relayv1.RoutedMethod_ROUTED_METHOD_REGISTER_NODE_WORKSPACE} {
		if validFileErrorForMethod(method, conflict) {
			t.Fatalf("method %v cannot claim a nonexistent hash precondition", method)
		}
	}
	absent := proto.Clone(conflict).(*foundationv1.ArcError)
	absent.GetDetails().GetState().Reason = proto.String("expected_absent_conflict")
	if !validFileErrorForMethod(method, absent) || validFileErrorForMethod(relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE, absent) {
		t.Fatal("expected absence must bind to Write")
	}
	for _, code := range []string{"invalid_argument", "path_not_found"} {
		e := fileCatalogueError(foundationv1.ErrorCategory_ERROR_CATEGORY_VALIDATION, code, "", "")
		if validFileErrorForMethod(method, e) {
			t.Fatalf("%s without state accepted", code)
		}
	}
	mismatch := fileCatalogueError(foundationv1.ErrorCategory_ERROR_CATEGORY_CONFLICT, "occurrence_mismatch", "file", "occurrence_mismatch")
	edit := relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE
	if !validFileErrorForMethod(edit, mismatch) {
		t.Fatal("valid occurrence mismatch rejected")
	}
	mismatch.GetDetails().GetState().Reason = proto.String("wrong_count")
	if validFileErrorForMethod(edit, mismatch) {
		t.Fatal("unrecognized occurrence reason accepted")
	}
}

func TestCTR06ReadRequiresProgressBeforeEOF(t *testing.T) {
	path := &nodev1.FilePath{WorkspaceId: pid(platform.NewID()), Path: proto.String("a")}
	q := &nodev1.FileServiceReadFileRequest{Path: path, Offset: proto.Uint64(0), Length: proto.Uint64(10)}
	digest := sha256.Sum256(nil)
	x := &nodev1.FileServiceReadFileResponse{Outcome: &nodev1.FileServiceReadFileResponse_Value{Value: &nodev1.FileServiceReadFileValue{
		Data: []byte{}, Offset: proto.Uint64(0), NextOffset: proto.Uint64(0), Eof: proto.Bool(false), FileSize: proto.Uint64(100), Sha256: digest[:],
	}}, Audit: &nodev1.FileAuditMetadata{Observations: []*nodev1.FileAuditObservation{{Kind: nodev1.FileAuditKind_FILE_AUDIT_KIND_READ_BYTES.Enum(),
		SizeBytes: proto.Uint64(0), DigestInputBytes: proto.Uint64(0), Sha256: digest[:]}}}}
	method := relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE
	if _, err := decodeFileResponse(method, marshal(t, x), marshal(t, q)); err == nil {
		t.Fatal("no progress before EOF accepted")
	}
	data := []byte("x")
	digest = sha256.Sum256(data)
	x.GetValue().Data, x.GetValue().NextOffset, x.GetValue().Sha256 = data, proto.Uint64(1), digest[:]
	x.Audit.Observations[0].SizeBytes, x.Audit.Observations[0].DigestInputBytes, x.Audit.Observations[0].Sha256 = proto.Uint64(1), proto.Uint64(1), digest[:]
	if _, err := decodeFileResponse(method, marshal(t, x), marshal(t, q)); err != nil {
		t.Fatalf("progressing read rejected: %v", err)
	}
	q.Offset, x.GetValue().Offset, x.GetValue().NextOffset, x.GetValue().Eof = proto.Uint64(100), proto.Uint64(100), proto.Uint64(100), proto.Bool(true)
	digest = sha256.Sum256(nil)
	x.GetValue().Data, x.GetValue().Sha256 = []byte{}, digest[:]
	x.Audit.Observations[0].SizeBytes, x.Audit.Observations[0].DigestInputBytes, x.Audit.Observations[0].Sha256 = proto.Uint64(0), proto.Uint64(0), digest[:]
	if _, err := decodeFileResponse(method, marshal(t, x), marshal(t, q)); err != nil {
		t.Fatalf("empty EOF read rejected: %v", err)
	}
}

func TestCTR06UnknownJournalRequiresUncertainFileOutcome(t *testing.T) {
	command := pid(platform.NewID())
	instant := &foundationv1.Instant{UnixSeconds: proto.Int64(1700000000), Nanos: proto.Uint32(0)}
	q := &nodev1.FileServiceGetFileOperationRequest{OperationCommandId: command}
	failure := fileCatalogueError(foundationv1.ErrorCategory_ERROR_CATEGORY_EXECUTION, "operation_failed", "file", "file_outcome_unknown")
	failure.Effect = foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN.Enum()
	op := &nodev1.FileOperation{CommandId: command, Kind: nodev1.FileOperationKind_FILE_OPERATION_KIND_WRITE.Enum(),
		State: nodev1.FileOperationState_FILE_OPERATION_STATE_UNKNOWN.Enum(), RequestSha256: make([]byte, 32),
		CreatedAt: instant, UpdatedAt: instant, Acknowledged: proto.Bool(false), Held: proto.Bool(true),
		Target:  &nodev1.FileOperation_WorkspacePath{WorkspacePath: &nodev1.FilePath{WorkspaceId: pid(platform.NewID()), Path: proto.String("a")}},
		Outcome: &nodev1.FileOperation_Error{Error: failure}}
	x := &nodev1.FileServiceGetFileOperationResponse{Outcome: &nodev1.FileServiceGetFileOperationResponse_Value{Value: &nodev1.FileServiceGetFileOperationValue{Operation: op}}}
	method := relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_FILE_OPERATION
	if _, err := decodeFileResponse(method, marshal(t, x), marshal(t, q)); err != nil {
		t.Fatalf("valid uncertainty rejected: %v", err)
	}
	for name, change := range map[string]func(*foundationv1.ArcError){
		"other reason": func(e *foundationv1.ArcError) { e.GetDetails().GetState().Reason = proto.String("permission_denied") },
		"other category": func(e *foundationv1.ArcError) {
			e.Category = foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHORIZATION.Enum()
			e.Code = proto.String("permission_denied")
			e.MessageKey = proto.String("error.authorization.permission_denied")
		},
		"wrong state": func(e *foundationv1.ArcError) { e.GetDetails().GetState().State = proto.String("task") },
		"retry":       func(e *foundationv1.ArcError) { e.Retry.Mode = foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND.Enum() },
	} {
		t.Run(name, func(t *testing.T) {
			bad := proto.Clone(x).(*nodev1.FileServiceGetFileOperationResponse)
			change(bad.GetValue().GetOperation().GetError())
			if _, err := decodeFileResponse(method, marshal(t, bad), marshal(t, q)); err == nil {
				t.Fatal("contradictory journal uncertainty accepted")
			}
		})
	}
}

func TestCTR06ScalarBoundaryRefusalRequiresScannedAudit(t *testing.T) {
	q := &nodev1.FileServiceSearchFilesRequest{Path: &nodev1.FilePath{WorkspaceId: pid(platform.NewID()), Path: proto.String("a")},
		Pattern: proto.String("."), Mode: nodev1.FileSearchMode_FILE_SEARCH_MODE_REGEX.Enum()}
	e := fileCatalogueError(foundationv1.ErrorCategory_ERROR_CATEGORY_VALIDATION, "invalid_argument", "pattern", "pattern: regex_scalar_boundary")
	x := &nodev1.FileServiceSearchFilesResponse{Outcome: &nodev1.FileServiceSearchFilesResponse_Error{Error: e}}
	method := relayv1.RoutedMethod_ROUTED_METHOD_SEARCH_NODE_FILES
	if _, err := decodeFileResponse(method, marshal(t, x), marshal(t, q)); err == nil {
		t.Fatal("refusal after scanning lacked audit but was accepted")
	}
	x.Audit = &nodev1.FileAuditMetadata{Observations: []*nodev1.FileAuditObservation{{
		Kind: nodev1.FileAuditKind_FILE_AUDIT_KIND_SEARCH_TRANSCRIPT.Enum(), SizeBytes: proto.Uint64(1),
		DigestInputBytes: proto.Uint64(uint64(len("ArcForges search-scan v1\x00") + 14)), ItemCount: proto.Uint32(1), Sha256: make([]byte, 32),
	}}}
	if _, err := decodeFileResponse(method, marshal(t, x), marshal(t, q)); err != nil {
		t.Fatalf("signed scanned audit rejected: %v", err)
	}
	q.Mode = nodev1.FileSearchMode_FILE_SEARCH_MODE_LITERAL.Enum()
	if _, err := decodeFileResponse(method, marshal(t, x), marshal(t, q)); err == nil {
		t.Fatal("literal search cannot report regex scalar boundary")
	}
}

func TestCTR06ConflictBindsActualWritePrecondition(t *testing.T) {
	method := relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE
	q := &nodev1.FileServiceWriteFileRequest{Meta: &foundationv1.RequestMeta{CommandId: pid(platform.NewID())},
		Path: &nodev1.FilePath{WorkspaceId: pid(platform.NewID()), Path: proto.String("a")}, Data: []byte("x"),
		Precondition: &nodev1.FileServiceWriteFileRequest_ExpectedAbsent{ExpectedAbsent: true}}
	failure := fileCatalogueError(foundationv1.ErrorCategory_ERROR_CATEGORY_CONFLICT, "file_changed", "file", "expected_absent_conflict")
	result := &nodev1.FileServiceWriteFileResponse{Outcome: &nodev1.FileServiceWriteFileResponse_Error{Error: failure}}
	if _, err := decodeFileResponse(method, marshal(t, result), marshal(t, q)); err != nil {
		t.Fatalf("valid absence conflict: %v", err)
	}
	failure.GetDetails().GetState().Reason = proto.String("hash_mismatch")
	if _, err := decodeFileResponse(method, marshal(t, result), marshal(t, q)); err == nil {
		t.Fatal("hash mismatch for absence precondition accepted")
	}
	q.Precondition = &nodev1.FileServiceWriteFileRequest_ExpectedSha256{ExpectedSha256: make([]byte, 32)}
	if _, err := decodeFileResponse(method, marshal(t, result), marshal(t, q)); err != nil {
		t.Fatalf("valid hash conflict: %v", err)
	}
	failure.GetDetails().GetState().Reason = proto.String("expected_absent_conflict")
	if _, err := decodeFileResponse(method, marshal(t, result), marshal(t, q)); err == nil {
		t.Fatal("absence conflict for hash precondition accepted")
	}
}
