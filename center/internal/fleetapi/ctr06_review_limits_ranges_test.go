// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"bytes"
	"crypto/sha256"
	"math"
	"strings"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

type scanFixtureFile struct {
	path string
	data []byte
}

func checkedScan(files []scanFixtureFile, matches ...*nodev1.FileMatch) *nodev1.FileServiceSearchFilesResponse {
	var transcript bytes.Buffer
	transcript.WriteString("ArcForges search-scan v1\x00")
	var scanned uint64
	var count uint32
	for _, file := range files {
		if len(file.data) == 0 {
			continue
		}
		appendText(&transcript, file.path)
		appendU64(&transcript, uint64(len(file.data)))
		transcript.Write(file.data)
		scanned += uint64(len(file.data))
		count++
	}
	digest := sha256.Sum256(transcript.Bytes())
	size := uint64(transcript.Len())
	return &nodev1.FileServiceSearchFilesResponse{Outcome: &nodev1.FileServiceSearchFilesResponse_Value{
		Value: &nodev1.FileServiceSearchFilesValue{Matches: matches, VisitedEntries: proto.Uint32(uint32(len(files))),
			ScannedBytes: proto.Uint64(scanned), SkippedFiles: proto.Uint32(0), Truncated: proto.Bool(false),
			ScanDigest: digest[:], ScanTranscriptBytes: proto.Uint64(size), ScanFileCount: proto.Uint32(count)},
	}, Audit: &nodev1.FileAuditMetadata{Observations: []*nodev1.FileAuditObservation{{
		Kind: nodev1.FileAuditKind_FILE_AUDIT_KIND_SEARCH_TRANSCRIPT.Enum(), SizeBytes: proto.Uint64(scanned),
		DigestInputBytes: proto.Uint64(size), ItemCount: proto.Uint32(count), Sha256: digest[:],
	}}}}
}

func scanMatch(path string, offset uint64, length uint32) *nodev1.FileMatch {
	return &nodev1.FileMatch{Path: proto.String(path), ByteOffset: proto.Uint64(offset), ByteLength: proto.Uint32(length)}
}

func TestCTR06SearchRangesBindObservableScanBounds(t *testing.T) {
	method := relayv1.RoutedMethod_ROUTED_METHOD_SEARCH_NODE_FILES
	path := &nodev1.FilePath{WorkspaceId: pid(platform.NewID()), Path: proto.String("")}
	literal := &nodev1.FileServiceSearchFilesRequest{Path: path, Pattern: proto.String("é"), Mode: nodev1.FileSearchMode_FILE_SEARCH_MODE_LITERAL.Enum()}
	regex := &nodev1.FileServiceSearchFilesRequest{Path: path, Pattern: proto.String(".*"), Mode: nodev1.FileSearchMode_FILE_SEARCH_MODE_REGEX.Enum()}
	cases := []struct {
		name     string
		request  *nodev1.FileServiceSearchFilesRequest
		response *nodev1.FileServiceSearchFilesResponse
		valid    bool
	}{
		{"literal on zero bytes", literal, checkedScan([]scanFixtureFile{{"empty", nil}}, scanMatch("empty", 0, 2)), false},
		{"empty file zero-length regex", regex, checkedScan([]scanFixtureFile{{"empty", nil}}, scanMatch("empty", 0, 0)), true},
		{"nonempty regex on zero bytes", regex, checkedScan([]scanFixtureFile{{"empty", nil}}, scanMatch("empty", 0, 1)), false},
		{"zero-length past scanned prefix", regex, checkedScan([]scanFixtureFile{{"a", []byte("ab")}}, scanMatch("a", 3, 0)), false},
		{"offset overflow", regex, checkedScan([]scanFixtureFile{{"a", []byte("ab")}}, scanMatch("a", math.MaxUint64, 2)), false},
		{"literal length mismatch", literal, checkedScan([]scanFixtureFile{{"a", []byte("é")}}, scanMatch("a", 0, 1)), false},
		{"literal UTF-8 bytes", literal, checkedScan([]scanFixtureFile{{"a", []byte("é")}}, scanMatch("a", 0, 2)), true},
		{"overlap same path", regex, checkedScan([]scanFixtureFile{{"a", []byte("abc")}}, scanMatch("a", 0, 2), scanMatch("a", 1, 2), scanMatch("a", 0, 1)), true},
		{"two path lower bounds", regex, checkedScan([]scanFixtureFile{{"a", []byte("abcd")}}, scanMatch("a", 0, 3), scanMatch("b", 0, 2)), false},
		{"distinct paths and unequal ends", regex, checkedScan([]scanFixtureFile{{"a", []byte("abc")}, {"b", []byte("de")}}, scanMatch("a", 1, 2), scanMatch("b", 0, 2)), true},
		{"nonzero paths exceed file count", regex, checkedScan([]scanFixtureFile{{"a", []byte("abcd")}}, scanMatch("a", 0, 1), scanMatch("b", 0, 1)), false},
		{"per-file scan maximum", regex, checkedScan([]scanFixtureFile{{"a", make([]byte, 1048576)}, {"b", []byte("a")}}, scanMatch("a", 1048576, 1)), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeFileResponse(method, marshal(t, tc.response), marshal(t, tc.request))
			if (err == nil) != tc.valid {
				t.Fatalf("accepted=%v, expected %v, err=%v", err == nil, tc.valid, err)
			}
		})
	}
}

func limitResponse(method relayv1.RoutedMethod, name, maximum string) nodeFileResponse {
	failure := fileCatalogueError(foundationv1.ErrorCategory_ERROR_CATEGORY_RESOURCE, "too_large", "", "")
	failure.Details = &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_Limit{Limit: &foundationv1.LimitFailure{
		LimitName: proto.String(name), Maximum: &foundationv1.Decimal{Value: proto.String(maximum)},
	}}}
	switch method {
	case relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE:
		return &nodev1.FileServiceReadFileResponse{Outcome: &nodev1.FileServiceReadFileResponse_Error{Error: failure}}
	case relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE:
		return &nodev1.FileServiceWriteFileResponse{Outcome: &nodev1.FileServiceWriteFileResponse_Error{Error: failure}}
	case relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE:
		return &nodev1.FileServiceEditFileResponse{Outcome: &nodev1.FileServiceEditFileResponse_Error{Error: failure}}
	case relayv1.RoutedMethod_ROUTED_METHOD_SEARCH_NODE_FILES:
		return &nodev1.FileServiceSearchFilesResponse{Outcome: &nodev1.FileServiceSearchFilesResponse_Error{Error: failure}}
	case relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_DIRECTORY:
		return &nodev1.FileServiceListDirectoryResponse{Outcome: &nodev1.FileServiceListDirectoryResponse_Error{Error: failure}}
	case relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL:
		return &nodev1.FileServicePlanRemovalResponse{Outcome: &nodev1.FileServicePlanRemovalResponse_Error{Error: failure}}
	case relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL:
		return &nodev1.FileServiceExecuteRemovalResponse{Outcome: &nodev1.FileServiceExecuteRemovalResponse_Error{Error: failure}}
	case relayv1.RoutedMethod_ROUTED_METHOD_REGISTER_NODE_WORKSPACE:
		return &nodev1.WorkspaceServiceRegisterWorkspaceResponse{Outcome: &nodev1.WorkspaceServiceRegisterWorkspaceResponse_Error{Error: failure}}
	case relayv1.RoutedMethod_ROUTED_METHOD_UNREGISTER_NODE_WORKSPACE:
		return &nodev1.WorkspaceServiceUnregisterWorkspaceResponse{Outcome: &nodev1.WorkspaceServiceUnregisterWorkspaceResponse_Error{Error: failure}}
	case relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_WORKSPACES:
		return &nodev1.WorkspaceServiceListWorkspacesResponse{Outcome: &nodev1.WorkspaceServiceListWorkspacesResponse_Error{Error: failure}}
	case relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_WORKSPACE:
		return &nodev1.WorkspaceServiceGetWorkspaceResponse{Outcome: &nodev1.WorkspaceServiceGetWorkspaceResponse_Error{Error: failure}}
	case relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_FILE_OPERATION:
		return &nodev1.FileServiceGetFileOperationResponse{Outcome: &nodev1.FileServiceGetFileOperationResponse_Error{Error: failure}}
	default:
		panic("unsupported test response")
	}
}

func TestCTR06SignedLimitBindsMethodMaximumAndKnownRequest(t *testing.T) {
	path := &nodev1.FilePath{WorkspaceId: pid(platform.NewID()), Path: proto.String("a")}
	oversizedPath := &nodev1.FilePath{WorkspaceId: path.WorkspaceId, Path: proto.String(strings.Repeat("a", 4097))}
	write := &nodev1.FileServiceWriteFileRequest{Path: path, Data: []byte("x"), Precondition: &nodev1.FileServiceWriteFileRequest_ExpectedSha256{ExpectedSha256: make([]byte, 32)}}
	edit := &nodev1.FileServiceEditFileRequest{Path: path, OldText: proto.String("a"), NewText: proto.String("b"), ExpectedOccurrences: proto.Uint32(1), ExpectedSha256: make([]byte, 32)}
	plan := &nodev1.FileServicePlanRemovalRequest{Target: &nodev1.FileServicePlanRemovalRequest_WorkspacePath{WorkspacePath: path}}
	execute := &nodev1.FileServiceExecuteRemovalRequest{PlanId: pid(platform.NewID()), PlanDigest: make([]byte, 32)}
	read := &nodev1.FileServiceReadFileRequest{Path: oversizedPath, Offset: proto.Uint64(0), Length: proto.Uint64(1)}
	register := &nodev1.WorkspaceServiceRegisterWorkspaceRequest{Path: proto.String("/" + strings.Repeat("a", 4096))}
	overWrite := proto.Clone(write).(*nodev1.FileServiceWriteFileRequest)
	overWrite.Data = make([]byte, 196609)
	overEdit := proto.Clone(edit).(*nodev1.FileServiceEditFileRequest)
	overEdit.NewText = proto.String(strings.Repeat("a", 65537))
	growingEdit := proto.Clone(edit).(*nodev1.FileServiceEditFileRequest)
	growingEdit.NewText = proto.String("bb")
	absent := proto.Clone(write).(*nodev1.FileServiceWriteFileRequest)
	absent.Precondition = &nodev1.FileServiceWriteFileRequest_ExpectedAbsent{ExpectedAbsent: true}
	cases := []struct {
		name, limit, maximum string
		method               relayv1.RoutedMethod
		request              proto.Message
		valid                bool
	}{
		{"known small write false max", "file_write_bytes", "3", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, write, false},
		{"known small write true max", "file_write_bytes", "196608", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, write, false},
		{"oversize write", "file_write_bytes", "196608", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, overWrite, true},
		{"noncanonical decimal", "file_write_bytes", "196608.00", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, overWrite, false},
		{"write existing unknown", "file_existing_bytes", "4194304", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, write, true},
		{"write absent may find existing large file", "file_existing_bytes", "4194304", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, absent, true},
		{"existing wrong maximum", "file_existing_bytes", "3", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, write, false},
		{"edit existing unknown", "file_existing_bytes", "4194304", relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE, edit, true},
		{"fractional existing maximum", "file_existing_bytes", "4194304.1", relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE, edit, false},
		{"growing edit result unknown", "file_edit_result_bytes", "4194304", relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE, growingEdit, true},
		{"non-growing edit result bounded", "file_edit_result_bytes", "4194304", relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE, edit, false},
		{"edit text oversize", "file_edit_text_bytes", "65536", relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE, overEdit, true},
		{"edit text known small", "file_edit_text_bytes", "65536", relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE, edit, false},
		{"wrong method edit result", "file_edit_result_bytes", "4194304", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, write, false},
		{"plan count unknown", "removal_descendants", "1000", relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL, plan, true},
		{"plan bytes unknown", "removal_total_bytes", "67108864", relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL, plan, true},
		{"execute count unknown", "removal_descendants", "1000", relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL, execute, true},
		{"execute bytes unknown", "removal_total_bytes", "67108864", relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL, execute, true},
		{"root is not a descendant", "removal_descendants", "1001", relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL, plan, false},
		{"plan bytes bad max", "removal_total_bytes", "67108863", relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL, plan, false},
		{"wrong method plan", "removal_descendants", "1000", relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE, edit, false},
		{"path oversize", "path_bytes", "4096", relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE, read, true},
		{"root path oversize", "workspace_root_path_bytes", "4096", relayv1.RoutedMethod_ROUTED_METHOD_REGISTER_NODE_WORKSPACE, register, true},
		{"alternate existing size", "existing_file_size_bytes", "4194304", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, write, true},
		{"open legacy spelling", "legacy.actual.limit", "4194304", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, write, true},
		{"bad name characters", "existing file bytes", "4194304", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, write, false},
		{"empty name", "", "4194304", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, write, false},
		{"too long name", strings.Repeat("a", 129), "4194304", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, write, false},
		{"unknown name wrong maximum", "existing_file_size_bytes", "3", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, write, false},
		{"unknown name known small input", "write_payload_limit", "196608", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, write, false},
		{"canonical wrong row no fallback", "file_write_bytes", "4194304", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, write, false},
		{"ambiguous noncanonical edit", "prior_file_limit", "4194304", relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE, edit, true},
		{"canonical result no fallback", "file_edit_result_bytes", "4194304", relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE, edit, false},
		{"wrong method canonical no fallback", "file_edit_result_bytes", "4194304", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, write, false},
		{"operation status has no path bound", "path_bytes", "4096", relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_FILE_OPERATION, &nodev1.FileServiceGetFileOperationRequest{OperationCommandId: pid(platform.NewID())}, false},
		{"unregister has no path bound", "path_bytes", "4096", relayv1.RoutedMethod_ROUTED_METHOD_UNREGISTER_NODE_WORKSPACE, &nodev1.WorkspaceServiceUnregisterWorkspaceRequest{WorkspaceId: path.WorkspaceId}, false},
		{"list workspaces has no root path bound", "workspace_root_path_bytes", "4096", relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_WORKSPACES, &nodev1.WorkspaceServiceListWorkspacesRequest{Kinds: []nodev1.WorkspaceKind{nodev1.WorkspaceKind_WORKSPACE_KIND_REGISTERED}}, false},
		{"get workspace has no root path bound", "workspace_root_path_bytes", "4096", relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_WORKSPACE, &nodev1.WorkspaceServiceGetWorkspaceRequest{WorkspaceId: path.WorkspaceId}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := limitResponse(tc.method, tc.limit, tc.maximum)
			_, err := decodeFileResponse(tc.method, marshal(t, response), marshal(t, tc.request))
			if (err == nil) != tc.valid {
				t.Fatalf("accepted=%v, expected %v, err=%v", err == nil, tc.valid, err)
			}
		})
	}
}

func TestCTR06PathLimitIsBoundToEveryApplicableMethod(t *testing.T) {
	long := &nodev1.FilePath{WorkspaceId: pid(platform.NewID()), Path: proto.String(strings.Repeat("a", 4097))}
	short := &nodev1.FilePath{WorkspaceId: long.WorkspaceId, Path: proto.String("a")}
	for _, tc := range []struct {
		name     string
		method   relayv1.RoutedMethod
		oversize proto.Message
		small    proto.Message
	}{
		{"read", relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE, &nodev1.FileServiceReadFileRequest{Path: long}, &nodev1.FileServiceReadFileRequest{Path: short}},
		{"write", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, &nodev1.FileServiceWriteFileRequest{Path: long}, &nodev1.FileServiceWriteFileRequest{Path: short}},
		{"edit", relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE, &nodev1.FileServiceEditFileRequest{Path: long}, &nodev1.FileServiceEditFileRequest{Path: short}},
		{"search", relayv1.RoutedMethod_ROUTED_METHOD_SEARCH_NODE_FILES, &nodev1.FileServiceSearchFilesRequest{Path: long}, &nodev1.FileServiceSearchFilesRequest{Path: short}},
		{"list", relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_DIRECTORY, &nodev1.FileServiceListDirectoryRequest{Path: long}, &nodev1.FileServiceListDirectoryRequest{Path: short}},
		{"plan", relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL, &nodev1.FileServicePlanRemovalRequest{Target: &nodev1.FileServicePlanRemovalRequest_WorkspacePath{WorkspacePath: long}}, &nodev1.FileServicePlanRemovalRequest{Target: &nodev1.FileServicePlanRemovalRequest_WorkspacePath{WorkspacePath: short}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			good := limitResponse(tc.method, "path_bytes", "4096")
			if _, err := decodeFileResponse(tc.method, marshal(t, good), marshal(t, tc.oversize)); err != nil {
				t.Fatalf("applicable oversize path: %v", err)
			}
			if _, err := decodeFileResponse(tc.method, marshal(t, good), marshal(t, tc.small)); err == nil {
				t.Fatal("small known path accepted as too large")
			}
			bad := limitResponse(tc.method, "path_bytes", "4095")
			if _, err := decodeFileResponse(tc.method, marshal(t, bad), marshal(t, tc.oversize)); err == nil {
				t.Fatal("incorrect path maximum accepted")
			}
		})
	}
	attempt := &nodev1.FileServicePlanRemovalRequest{Target: &nodev1.FileServicePlanRemovalRequest_AttemptId{AttemptId: pid(platform.NewID())}}
	plan := relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL
	if _, err := decodeFileResponse(plan, marshal(t, limitResponse(plan, "path_bytes", "4096")), marshal(t, attempt)); err == nil {
		t.Fatal("attempt target has no caller-supplied path")
	}
}
