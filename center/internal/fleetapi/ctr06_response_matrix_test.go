// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"bytes"
	"crypto/sha256"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

func TestCTR06EveryMethodValidatesItsNestedSuccessAndError(t *testing.T) {
	command, ws, plan := pid(platform.NewID()), pid(platform.NewID()), pid(platform.NewID())
	meta := &foundationv1.RequestMeta{CommandId: command}
	path := &nodev1.FilePath{WorkspaceId: ws, Path: proto.String("doc.txt")}
	body := []byte("content")
	hash := sha256.Sum256(body)
	obs := func(kind nodev1.FileAuditKind, input []byte, count *uint32) *nodev1.FileAuditMetadata {
		digest := sha256.Sum256(input)
		return &nodev1.FileAuditMetadata{Observations: []*nodev1.FileAuditObservation{{Kind: kind.Enum(), SizeBytes: proto.Uint64(uint64(len(input))), DigestInputBytes: proto.Uint64(uint64(len(input))), Sha256: digest[:], ItemCount: count}}}
	}
	readObs := obs(nodev1.FileAuditKind_FILE_AUDIT_KIND_READ_BYTES, body, nil)
	writtenObs := obs(nodev1.FileAuditKind_FILE_AUDIT_KIND_WRITTEN_BYTES, body, nil)
	scanDomain := []byte("ArcForges search-scan v1\x00")
	scanHash := sha256.Sum256(scanDomain)
	scanObs := &nodev1.FileAuditMetadata{Observations: []*nodev1.FileAuditObservation{{Kind: nodev1.FileAuditKind_FILE_AUDIT_KIND_SEARCH_TRANSCRIPT.Enum(), SizeBytes: proto.Uint64(0), DigestInputBytes: proto.Uint64(uint64(len(scanDomain))), Sha256: scanHash[:], ItemCount: proto.Uint32(0)}}}
	dirDomain := []byte("ArcForges directory-list v1\x00")
	dirHash := sha256.Sum256(dirDomain)
	dirObs := obs(nodev1.FileAuditKind_FILE_AUDIT_KIND_DIRECTORY_METADATA, dirDomain, proto.Uint32(0))
	w := &nodev1.Workspace{WorkspaceId: ws, Kind: nodev1.WorkspaceKind_WORKSPACE_KIND_REGISTERED.Enum(), State: nodev1.WorkspaceState_WORKSPACE_STATE_ACTIVE.Enum(), Name: proto.String("workspace"), RootPath: proto.String("/test/workspace")}
	var workspaceTranscript bytes.Buffer
	workspaceTranscript.WriteString("ArcForges workspace-metadata v1\x00")
	workspaceTranscript.Write(ws.Value)
	appendText(&workspaceTranscript, w.GetRootPath())
	appendU32(&workspaceTranscript, uint32(w.GetKind()))
	appendU32(&workspaceTranscript, uint32(w.GetState()))
	appendText(&workspaceTranscript, w.GetName())
	workspaceObs := obs(nodev1.FileAuditKind_FILE_AUDIT_KIND_WORKSPACE_METADATA, workspaceTranscript.Bytes(), proto.Uint32(1))
	now := &foundationv1.Instant{UnixSeconds: proto.Int64(1700000000), Nanos: proto.Uint32(0)}
	written := &nodev1.FileMutationResult{CommandId: command, SizeBytes: proto.Uint64(uint64(len(body))), Sha256: hash[:]}
	edited := proto.Clone(written).(*nodev1.FileMutationResult)
	edited.Replacements = proto.Uint32(1)
	removalPlan := &nodev1.FileRemovalPlan{PlanId: plan, Digest: make([]byte, 32), ExpiresAt: now, Items: []*nodev1.FileRemovalItem{{Path: proto.String("doc.txt"), Kind: nodev1.FileEntryKind_FILE_ENTRY_KIND_FILE.Enum(), SizeBytes: proto.Uint64(1), IdentitySha256: make([]byte, 32), OwnerVerified: proto.Bool(true)}}, TotalBytes: proto.Uint64(1), RequiresApproval: proto.Bool(false), QuarantineAvailable: proto.Bool(true), Risk: nodev1.RiskClass_RISK_CLASS_LOW.Enum(), Target: &nodev1.FileRemovalPlan_WorkspacePath{WorkspacePath: path}}
	operation := &nodev1.FileOperation{CommandId: command, Kind: nodev1.FileOperationKind_FILE_OPERATION_KIND_WRITE.Enum(), State: nodev1.FileOperationState_FILE_OPERATION_STATE_COMPLETED.Enum(), RequestSha256: make([]byte, 32), CreatedAt: now, UpdatedAt: now, Acknowledged: proto.Bool(false), Held: proto.Bool(false), Target: &nodev1.FileOperation_WorkspacePath{WorkspacePath: path}, Outcome: &nodev1.FileOperation_Mutation{Mutation: written}}
	removal := &nodev1.FileRemovalResult{PlanId: plan, Quarantined: proto.Bool(true), QuarantineId: pid(platform.NewID()), PurgeAfter: now, ItemsRemoved: proto.Uint32(1), TotalBytes: proto.Uint64(1)}
	type testCase struct {
		name              string
		method            relayv1.RoutedMethod
		request, response proto.Message
	}
	cases := []testCase{
		{"read", relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE, &nodev1.FileServiceReadFileRequest{Path: path, Offset: proto.Uint64(0), Length: proto.Uint64(20)}, &nodev1.FileServiceReadFileResponse{Outcome: &nodev1.FileServiceReadFileResponse_Value{Value: &nodev1.FileServiceReadFileValue{Data: body, Offset: proto.Uint64(0), NextOffset: proto.Uint64(uint64(len(body))), Eof: proto.Bool(true), Sha256: hash[:], FileSize: proto.Uint64(uint64(len(body)))}}, Audit: readObs}},
		{"write", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, &nodev1.FileServiceWriteFileRequest{Meta: meta, Path: path, Data: body, Precondition: &nodev1.FileServiceWriteFileRequest_ExpectedAbsent{ExpectedAbsent: true}}, &nodev1.FileServiceWriteFileResponse{Outcome: &nodev1.FileServiceWriteFileResponse_Value{Value: &nodev1.FileServiceWriteFileValue{Result: written}}, Audit: writtenObs}},
		{"edit", relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE, &nodev1.FileServiceEditFileRequest{Meta: meta, Path: path, OldText: proto.String("a"), NewText: proto.String("b"), ExpectedOccurrences: proto.Uint32(1), ExpectedSha256: make([]byte, 32)}, &nodev1.FileServiceEditFileResponse{Outcome: &nodev1.FileServiceEditFileResponse_Value{Value: &nodev1.FileServiceEditFileValue{Result: edited}}, Audit: writtenObs}},
		{"search", relayv1.RoutedMethod_ROUTED_METHOD_SEARCH_NODE_FILES, &nodev1.FileServiceSearchFilesRequest{Path: path, Pattern: proto.String("x"), Mode: nodev1.FileSearchMode_FILE_SEARCH_MODE_LITERAL.Enum()}, &nodev1.FileServiceSearchFilesResponse{Outcome: &nodev1.FileServiceSearchFilesResponse_Value{Value: &nodev1.FileServiceSearchFilesValue{VisitedEntries: proto.Uint32(0), ScannedBytes: proto.Uint64(0), SkippedFiles: proto.Uint32(0), Truncated: proto.Bool(false), ScanDigest: scanHash[:], ScanTranscriptBytes: proto.Uint64(uint64(len(scanDomain))), ScanFileCount: proto.Uint32(0)}}, Audit: scanObs}},
		{"list directory", relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_DIRECTORY, &nodev1.FileServiceListDirectoryRequest{Path: path}, &nodev1.FileServiceListDirectoryResponse{Outcome: &nodev1.FileServiceListDirectoryResponse_Value{Value: &nodev1.FileServiceListDirectoryValue{Truncated: proto.Bool(false), SnapshotEntries: proto.Uint32(0), MetadataDigest: dirHash[:], MetadataBytes: proto.Uint64(uint64(len(dirDomain)))}}, Audit: dirObs}},
		{"plan removal", relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL, &nodev1.FileServicePlanRemovalRequest{Meta: meta, Target: &nodev1.FileServicePlanRemovalRequest_WorkspacePath{WorkspacePath: path}}, &nodev1.FileServicePlanRemovalResponse{Outcome: &nodev1.FileServicePlanRemovalResponse_Value{Value: &nodev1.FileServicePlanRemovalValue{Plan: removalPlan}}}},
		{"execute removal", relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL, &nodev1.FileServiceExecuteRemovalRequest{Meta: meta, PlanId: plan, PlanDigest: make([]byte, 32)}, &nodev1.FileServiceExecuteRemovalResponse{Outcome: &nodev1.FileServiceExecuteRemovalResponse_Value{Value: &nodev1.FileServiceExecuteRemovalValue{Result: removal}}}},
		{"operation", relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_FILE_OPERATION, &nodev1.FileServiceGetFileOperationRequest{OperationCommandId: command}, &nodev1.FileServiceGetFileOperationResponse{Outcome: &nodev1.FileServiceGetFileOperationResponse_Value{Value: &nodev1.FileServiceGetFileOperationValue{Operation: operation}}}},
		{"register", relayv1.RoutedMethod_ROUTED_METHOD_REGISTER_NODE_WORKSPACE, &nodev1.WorkspaceServiceRegisterWorkspaceRequest{Meta: meta, Path: proto.String("/test/workspace")}, &nodev1.WorkspaceServiceRegisterWorkspaceResponse{Outcome: &nodev1.WorkspaceServiceRegisterWorkspaceResponse_Value{Value: &nodev1.WorkspaceServiceRegisterWorkspaceValue{Workspace: w}}}},
		{"unregister", relayv1.RoutedMethod_ROUTED_METHOD_UNREGISTER_NODE_WORKSPACE, &nodev1.WorkspaceServiceUnregisterWorkspaceRequest{Meta: meta, WorkspaceId: ws}, &nodev1.WorkspaceServiceUnregisterWorkspaceResponse{Outcome: &nodev1.WorkspaceServiceUnregisterWorkspaceResponse_Value{Value: &nodev1.WorkspaceServiceUnregisterWorkspaceValue{Receipt: &foundationv1.Receipt{CommandId: command, Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED.Enum()}}}}},
		{"list workspace", relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_WORKSPACES, &nodev1.WorkspaceServiceListWorkspacesRequest{Kinds: []nodev1.WorkspaceKind{nodev1.WorkspaceKind_WORKSPACE_KIND_REGISTERED}}, &nodev1.WorkspaceServiceListWorkspacesResponse{Outcome: &nodev1.WorkspaceServiceListWorkspacesResponse_Value{Value: &nodev1.WorkspaceServiceListWorkspacesValue{Workspaces: []*nodev1.Workspace{w}, Page: &foundationv1.PageState{HasMore: proto.Bool(false)}}}, Audit: workspaceObs}},
		{"get workspace", relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_WORKSPACE, &nodev1.WorkspaceServiceGetWorkspaceRequest{WorkspaceId: ws}, &nodev1.WorkspaceServiceGetWorkspaceResponse{Outcome: &nodev1.WorkspaceServiceGetWorkspaceResponse_Value{Value: &nodev1.WorkspaceServiceGetWorkspaceValue{Workspace: w}}, Audit: workspaceObs}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := marshal(t, tc.request)
			if _, err := decodeFileResponse(tc.method, marshal(t, tc.response), request); err != nil {
				t.Fatalf("valid response: %v", err)
			}
			malformed := proto.Clone(tc.response)
			reflected := malformed.ProtoReflect()
			valueField := reflected.Descriptor().Fields().ByName("value")
			reflected.Set(valueField, reflected.NewField(valueField))
			if _, err := decodeFileResponse(tc.method, marshal(t, malformed), request); err == nil {
				t.Fatal("empty nested value accepted")
			}
			// A structurally non-empty result that disagrees with this request, its
			// audit, or its nested state is also invalid for this specific method.
			invalidValue := proto.Clone(tc.response)
			switch value := invalidValue.(type) {
			case *nodev1.FileServiceReadFileResponse:
				value.GetValue().Offset = proto.Uint64(1)
			case *nodev1.FileServiceWriteFileResponse:
				value.GetValue().GetResult().CommandId = pid(platform.NewID())
			case *nodev1.FileServiceEditFileResponse:
				value.GetValue().GetResult().Replacements = proto.Uint32(2)
			case *nodev1.FileServiceSearchFilesResponse:
				value.GetAudit().Observations[0].SizeBytes = proto.Uint64(1)
			case *nodev1.FileServiceListDirectoryResponse:
				value.GetValue().MetadataBytes = proto.Uint64(1)
			case *nodev1.FileServicePlanRemovalResponse:
				value.GetValue().GetPlan().Target = &nodev1.FileRemovalPlan_AttemptId{AttemptId: pid(platform.NewID())}
			case *nodev1.FileServiceExecuteRemovalResponse:
				x := value.GetValue().GetResult()
				x.Quarantined = proto.Bool(false)
				x.QuarantineId = nil
				x.PurgeAfter = nil // request did not authorize direct deletion
			case *nodev1.FileServiceGetFileOperationResponse:
				unknown := &foundationv1.ArcError{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_EXECUTION.Enum(), Code: proto.String("operation_failed"), MessageKey: proto.String("error.execution.operation_failed"), Retry: &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_NEVER.Enum()}, Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN.Enum(), CorrelationId: pid(platform.NewID())}
				value.GetValue().GetOperation().Outcome = &nodev1.FileOperation_Error{Error: unknown} // COMPLETED cannot contain an UNKNOWN outcome
			case *nodev1.WorkspaceServiceRegisterWorkspaceResponse:
				value.GetValue().GetWorkspace().Owner = &nodev1.ActorRef{CenterCaller: &nodev1.CenterCaller{Kind: nodev1.CenterCallerKind_CENTER_CALLER_KIND_ACCOUNT_SESSION.Enum()}}
			case *nodev1.WorkspaceServiceUnregisterWorkspaceResponse:
				value.GetValue().GetReceipt().CommandId = pid(platform.NewID())
			case *nodev1.WorkspaceServiceListWorkspacesResponse:
				value.GetValue().Workspaces[0].Kind = nodev1.WorkspaceKind_WORKSPACE_KIND_REMOTE.Enum()
			case *nodev1.WorkspaceServiceGetWorkspaceResponse:
				value.GetValue().GetWorkspace().WorkspaceId = pid(platform.NewID())
			}
			if _, err := decodeFileResponse(tc.method, marshal(t, invalidValue), request); err == nil {
				t.Fatal("method-specific contradiction accepted")
			}
			denial := arc.PermissionDenied("file.read").ArcError(correlation.New())
			wrapped := newFileResponse(tc.method)
			reflected = wrapped.ProtoReflect()
			errorField := reflected.Descriptor().Fields().ByName("error")
			reflected.Set(errorField, reflected.NewField(errorField))
			proto.Merge(reflected.Mutable(errorField).Message().Interface(), denial)
			if _, err := decodeFileResponse(tc.method, marshal(t, wrapped), request); err != nil {
				t.Fatalf("valid handler error: %v", err)
			}
			invalid := proto.Clone(wrapped).(nodeFileResponse)
			invalid.GetError().CorrelationId = nil
			if _, err := decodeFileResponse(tc.method, marshal(t, invalid), request); err == nil {
				t.Fatal("missing error correlation accepted")
			}
			invalid = proto.Clone(wrapped).(nodeFileResponse)
			invalid.GetError().Effect = foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED.Enum()
			if _, err := decodeFileResponse(tc.method, marshal(t, invalid), request); err == nil {
				t.Fatal("permission denied with happened effect accepted")
			}
		})
	}
}

func TestCTR06NestedErrorAndAuditShapesAreNotTrusted(t *testing.T) {
	base := arc.PermissionDenied("file.read").ArcError(correlation.New())
	if !validFileError(base) {
		t.Fatal("valid error rejected")
	}
	cases := []struct {
		name   string
		change func(*foundationv1.ArcError)
	}{
		{"missing correlation", func(e *foundationv1.ArcError) { e.CorrelationId = nil }},
		{"missing state", func(e *foundationv1.ArcError) { e.GetDetails().GetState().State = nil }},
		{"bad resource", func(e *foundationv1.ArcError) {
			e.GetDetails().GetState().Resource = &foundationv1.AggregateRef{Kind: proto.String("file")}
		}},
		{"negative revision", func(e *foundationv1.ArcError) {
			e.Details = &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_Revision{Revision: &foundationv1.RevisionConflict{Expected: &foundationv1.Revision{Value: proto.Int64(-1)}}}}
		}},
		{"noncanonical decimal", func(e *foundationv1.ArcError) {
			e.Details = &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_Limit{Limit: &foundationv1.LimitFailure{LimitName: proto.String("size"), Maximum: &foundationv1.Decimal{Value: proto.String("01")}}}}
		}},
		{"missing version", func(e *foundationv1.ArcError) {
			e.Details = &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_Upgrade{Upgrade: &foundationv1.VersionFailure{MinReadable: proto.String("1"), MinWritable: proto.String("1")}}}
		}},
		{"unknown effect with after-time", func(e *foundationv1.ArcError) {
			e.Effect = foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN.Enum()
			e.Retry = &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_AFTER_TIME.Enum(), RetryAt: &foundationv1.Instant{UnixSeconds: proto.Int64(1), Nanos: proto.Uint32(0)}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := proto.Clone(base).(*foundationv1.ArcError)
			tc.change(e)
			if validFileError(e) {
				t.Fatal("malformed nested error accepted")
			}
		})
	}
	if validFileResponseMeta(&foundationv1.ResponseMeta{ResultRev: &foundationv1.Revision{Value: proto.Int64(-1)}, CorrelationId: pid(platform.NewID())}) {
		t.Fatal("negative result revision accepted")
	}
	if validFileResponseMeta(&foundationv1.ResponseMeta{}) {
		t.Fatal("response metadata without correlation accepted")
	}
	badObs := &nodev1.FileAuditObservation{Kind: nodev1.FileAuditKind_FILE_AUDIT_KIND_WRITTEN_BYTES.Enum(), SizeBytes: proto.Uint64(1), DigestInputBytes: proto.Uint64(1), Sha256: make([]byte, 32)}
	if validFileObservation(relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE, badObs) {
		t.Fatal("read accepted a write observation")
	}
	if validFileObservation(relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, &nodev1.FileAuditObservation{Kind: nodev1.FileAuditKind_FILE_AUDIT_KIND_WRITTEN_BYTES.Enum(), SizeBytes: proto.Uint64(1), DigestInputBytes: proto.Uint64(2), Sha256: make([]byte, 32)}) {
		t.Fatal("inconsistent digest length accepted")
	}
}
