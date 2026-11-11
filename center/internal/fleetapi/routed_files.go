// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"strings"
	"time"
	"unicode/utf8"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// These methods share the existing verified relay, admission, replay and result path.
// Only typed, bounded metadata is decoded; request and result bodies are never persisted.
const maxFileRequest = 245_760

func fileMethod(method relayv1.RoutedMethod) bool {
	return method >= relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE &&
		method <= relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_WORKSPACE
}
func fileMutation(method relayv1.RoutedMethod) bool {
	switch method {
	case relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE,
		relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE,
		relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL,
		relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL,
		relayv1.RoutedMethod_ROUTED_METHOD_REGISTER_NODE_WORKSPACE,
		relayv1.RoutedMethod_ROUTED_METHOD_UNREGISTER_NODE_WORKSPACE:
		return true
	}
	return false
}

type nodeFileRequest interface {
	proto.Message
	GetMeta() *foundationv1.RequestMeta
}
type nodeFileResponse interface {
	proto.Message
	GetMeta() *foundationv1.ResponseMeta
	GetError() *foundationv1.ArcError
	GetAudit() *nodev1.FileAuditMetadata
}

func newFileRequest(method relayv1.RoutedMethod) nodeFileRequest {
	switch method {
	case relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE:
		return &nodev1.FileServiceReadFileRequest{}
	case relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE:
		return &nodev1.FileServiceWriteFileRequest{}
	case relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE:
		return &nodev1.FileServiceEditFileRequest{}
	case relayv1.RoutedMethod_ROUTED_METHOD_SEARCH_NODE_FILES:
		return &nodev1.FileServiceSearchFilesRequest{}
	case relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_DIRECTORY:
		return &nodev1.FileServiceListDirectoryRequest{}
	case relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL:
		return &nodev1.FileServicePlanRemovalRequest{}
	case relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL:
		return &nodev1.FileServiceExecuteRemovalRequest{}
	case relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_FILE_OPERATION:
		return &nodev1.FileServiceGetFileOperationRequest{}
	case relayv1.RoutedMethod_ROUTED_METHOD_REGISTER_NODE_WORKSPACE:
		return &nodev1.WorkspaceServiceRegisterWorkspaceRequest{}
	case relayv1.RoutedMethod_ROUTED_METHOD_UNREGISTER_NODE_WORKSPACE:
		return &nodev1.WorkspaceServiceUnregisterWorkspaceRequest{}
	case relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_WORKSPACES:
		return &nodev1.WorkspaceServiceListWorkspacesRequest{}
	case relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_WORKSPACE:
		return &nodev1.WorkspaceServiceGetWorkspaceRequest{}
	}
	return nil
}
func newFileResponse(method relayv1.RoutedMethod) nodeFileResponse {
	switch method {
	case relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE:
		return &nodev1.FileServiceReadFileResponse{}
	case relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE:
		return &nodev1.FileServiceWriteFileResponse{}
	case relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE:
		return &nodev1.FileServiceEditFileResponse{}
	case relayv1.RoutedMethod_ROUTED_METHOD_SEARCH_NODE_FILES:
		return &nodev1.FileServiceSearchFilesResponse{}
	case relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_DIRECTORY:
		return &nodev1.FileServiceListDirectoryResponse{}
	case relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL:
		return &nodev1.FileServicePlanRemovalResponse{}
	case relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL:
		return &nodev1.FileServiceExecuteRemovalResponse{}
	case relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_FILE_OPERATION:
		return &nodev1.FileServiceGetFileOperationResponse{}
	case relayv1.RoutedMethod_ROUTED_METHOD_REGISTER_NODE_WORKSPACE:
		return &nodev1.WorkspaceServiceRegisterWorkspaceResponse{}
	case relayv1.RoutedMethod_ROUTED_METHOD_UNREGISTER_NODE_WORKSPACE:
		return &nodev1.WorkspaceServiceUnregisterWorkspaceResponse{}
	case relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_WORKSPACES:
		return &nodev1.WorkspaceServiceListWorkspacesResponse{}
	case relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_WORKSPACE:
		return &nodev1.WorkspaceServiceGetWorkspaceResponse{}
	}
	return nil
}

// Recover only bounded target metadata for a refusal audit. It is never an
// authorization decision and an asserted relay is not attributed without proof.
func fileTargetForAudit(method relayv1.RoutedMethod, payload []byte) inner {
	result := inner{method: method, deadline: routes.RoutedFileDeadline}
	if len(payload) == 0 || len(payload) > 262_144 {
		return result
	}
	v := newFileRequest(method)
	if v == nil || proto.Unmarshal(payload, v) != nil {
		return result
	}
	var path *nodev1.FilePath
	switch x := v.(type) {
	case *nodev1.FileServiceReadFileRequest:
		path = x.Path
	case *nodev1.FileServiceWriteFileRequest:
		path = x.Path
	case *nodev1.FileServiceEditFileRequest:
		path = x.Path
	case *nodev1.FileServiceSearchFilesRequest:
		path = x.Path
	case *nodev1.FileServiceListDirectoryRequest:
		path = x.Path
	case *nodev1.FileServicePlanRemovalRequest:
		path = x.GetWorkspacePath()
		if id, ok := parseID(x.GetAttemptId()); ok {
			result.targetAttemptID = &id
		}
	case *nodev1.WorkspaceServiceRegisterWorkspaceRequest:
		if x.Path != nil && len(x.GetPath()) <= 4096 && utf8.ValidString(x.GetPath()) && !strings.ContainsRune(x.GetPath(), 0) {
			result.path, result.pathKnown = x.GetPath(), true
		}
	case *nodev1.WorkspaceServiceUnregisterWorkspaceRequest:
		if id, ok := parseID(x.WorkspaceId); ok {
			result.workspaceID = &id
		}
	case *nodev1.WorkspaceServiceGetWorkspaceRequest:
		if id, ok := parseID(x.WorkspaceId); ok {
			result.workspaceID = &id
		}
	}
	if path != nil {
		if id, ok := parseID(path.WorkspaceId); ok {
			result.workspaceID = &id
		}
		if path.Path != nil && len(path.GetPath()) <= 4096 && utf8.ValidString(path.GetPath()) && !strings.ContainsRune(path.GetPath(), 0) {
			result.path, result.pathKnown = path.GetPath(), true
		}
	}
	return result
}

// checkFileInner checks the portable wire shape. The target alone decides native
// absolute-path syntax, root identity, permission, filesystem state and all effects.
func checkFileInner(method relayv1.RoutedMethod, payload []byte, command *platform.ID) (inner, error) {
	result := fileTargetForAudit(method, payload)
	bad := func(field, rule string) (inner, error) { return result, arc.InvalidArgument("request."+field, rule) }
	tooLarge := func(name string, maximum int64) (inner, error) {
		return result, &arc.Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_RESOURCE, Code: "too_large", Limit: &arc.Limit{Name: name, Maximum: maximum}}
	}
	// The ingress admits at most 262,144 bytes including the outer frame. A
	// decoded resource bound is classified before the smaller inner-envelope
	// limit; an oversized malformed or impossible outer frame is never decoded.
	if len(payload) < 1 || len(payload) > 262_144 {
		return bad("payload", "length")
	}
	value := newFileRequest(method)
	if value == nil || proto.Unmarshal(payload, value) != nil {
		return bad("payload", "malformed")
	}
	if command != nil {
		got, ok := parseID(value.GetMeta().GetCommandId())
		if !ok || got != *command {
			return bad("meta.command_id", "mismatch")
		}
	} else if value.GetMeta().GetCommandId() != nil {
		return bad("meta.command_id", "not_admitted")
	}
	setWorkspace := func(id *foundationv1.Id) bool {
		parsed, ok := parseID(id)
		if ok {
			result.workspaceID = &parsed
		}
		return ok
	}
	checkPath := func(path *nodev1.FilePath, empty bool, field string) error {
		if path == nil || path.Path == nil || !utf8.ValidString(path.GetPath()) || strings.ContainsRune(path.GetPath(), 0) ||
			(!empty && path.GetPath() == "") || !setWorkspace(path.GetWorkspaceId()) {
			return arc.InvalidArgument("request."+field, "required")
		}
		if len(path.GetPath()) > 4096 {
			return &arc.Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_RESOURCE, Code: "too_large", Limit: &arc.Limit{Name: "path_bytes", Maximum: 4096}}
		}
		result.path = path.GetPath()
		result.pathKnown = true
		return nil
	}
	switch v := value.(type) {
	case *nodev1.FileServiceReadFileRequest:
		if err := checkPath(v.Path, false, "path"); err != nil {
			return result, err
		}
		if v.Offset == nil || v.Length == nil || v.GetLength() < 1 {
			return bad("length", "minimum")
		}
	case *nodev1.FileServiceWriteFileRequest:
		if err := checkPath(v.Path, false, "path"); err != nil {
			return result, err
		}
		if v.Data == nil {
			return bad("data", "required")
		}
		if len(v.Data) > 196_608 {
			return tooLarge("file_write_bytes", 196_608)
		}
		switch precondition := v.Precondition.(type) {
		case *nodev1.FileServiceWriteFileRequest_ExpectedSha256:
			if len(precondition.ExpectedSha256) != 32 {
				return bad("expected_sha256", "length")
			}
		case *nodev1.FileServiceWriteFileRequest_ExpectedAbsent:
			if !precondition.ExpectedAbsent {
				return bad("expected_absent", "must_be_true")
			}
		default:
			return bad("precondition", "required")
		}
	case *nodev1.FileServiceEditFileRequest:
		if err := checkPath(v.Path, false, "path"); err != nil {
			return result, err
		}
		if v.OldText == nil || len(v.GetOldText()) < 1 || v.NewText == nil {
			return bad("text", "length")
		}
		if len(v.GetOldText()) > 65_536 || len(v.GetNewText()) > 65_536 {
			return tooLarge("file_edit_text_bytes", 65_536)
		}
		if v.ExpectedOccurrences == nil || v.GetExpectedOccurrences() < 1 || v.GetExpectedOccurrences() > 1000 {
			return bad("expected_occurrences", "range")
		}
		if len(v.ExpectedSha256) != 32 {
			return bad("expected_sha256", "length")
		}
	case *nodev1.FileServiceSearchFilesRequest:
		if err := checkPath(v.Path, true, "path"); err != nil {
			return result, err
		}
		if v.Pattern == nil || len(v.GetPattern()) < 1 || len(v.GetPattern()) > 1024 {
			return bad("pattern", "length")
		}
		if v.Mode == nil || v.GetMode() < 1 || v.GetMode() > 2 {
			return bad("mode", "range")
		}
		if v.MaxMatches != nil && (v.GetMaxMatches() < 1 || v.GetMaxMatches() > 100) {
			return bad("max_matches", "range")
		}
		if v.MaxScanBytes != nil && (v.GetMaxScanBytes() < 1 || v.GetMaxScanBytes() > 8_388_608) {
			return bad("max_scan_bytes", "range")
		}
	case *nodev1.FileServiceListDirectoryRequest:
		if err := checkPath(v.Path, true, "path"); err != nil {
			return result, err
		}
		if v.PageSize != nil && (v.GetPageSize() < 1 || v.GetPageSize() > 128) {
			return bad("page_size", "range")
		}
		if len(v.GetCursor()) > 2048 {
			return bad("cursor", "length")
		}
	case *nodev1.FileServicePlanRemovalRequest:
		switch target := v.Target.(type) {
		case *nodev1.FileServicePlanRemovalRequest_WorkspacePath:
			if err := checkPath(target.WorkspacePath, false, "workspace_path"); err != nil {
				return result, err
			}
		case *nodev1.FileServicePlanRemovalRequest_AttemptId:
			id, ok := parseID(target.AttemptId)
			if !ok {
				return bad("attempt_id", "required")
			}
			result.targetAttemptID = &id
		default:
			return bad("target", "required")
		}
	case *nodev1.FileServiceExecuteRemovalRequest:
		if _, ok := parseID(v.PlanId); !ok {
			return bad("plan_id", "required")
		}
		if len(v.PlanDigest) != 32 {
			return bad("plan_digest", "length")
		}
	case *nodev1.FileServiceGetFileOperationRequest:
		if _, ok := parseID(v.OperationCommandId); !ok {
			return bad("operation_command_id", "required")
		}
	case *nodev1.WorkspaceServiceRegisterWorkspaceRequest:
		if v.Path == nil || len(v.GetPath()) < 1 || !utf8.ValidString(v.GetPath()) || strings.ContainsRune(v.GetPath(), 0) {
			return bad("path", "length")
		}
		if len(v.GetPath()) > 4096 {
			return tooLarge("workspace_root_path_bytes", 4096)
		}
		result.path = v.GetPath()
		result.pathKnown = true
		if v.Name != nil && (utf8.RuneCountInString(v.GetName()) < 1 || utf8.RuneCountInString(v.GetName()) > 100) {
			return bad("name", "length")
		}
	case *nodev1.WorkspaceServiceUnregisterWorkspaceRequest:
		if !setWorkspace(v.WorkspaceId) {
			return bad("workspace_id", "required")
		}
	case *nodev1.WorkspaceServiceListWorkspacesRequest:
		seen := map[nodev1.WorkspaceKind]bool{}
		for _, kind := range v.Kinds {
			if _, ok := nodev1.WorkspaceKind_name[int32(kind)]; !ok || kind == 0 || seen[kind] {
				return bad("kinds", "unique_defined")
			}
			seen[kind] = true
		}
		if v.Page != nil && (v.Page.GetLimit() < 1 || v.Page.GetLimit() > 500 || len(v.Page.GetCursor()) > 2048) {
			return bad("page", "range")
		}
	case *nodev1.WorkspaceServiceGetWorkspaceRequest:
		if !setWorkspace(v.WorkspaceId) {
			return bad("workspace_id", "required")
		}
	}
	if len(payload) > maxFileRequest {
		return bad("payload", "length")
	}
	return result, nil
}

// decodeFileResponse accepts only the published outcome and bounded signed metadata.
// Unknown protobuf fields are never copied into audit payloads.
func decodeFileResponse(method relayv1.RoutedMethod, payload, request []byte) (nodeFileResponse, error) {
	value := newFileResponse(method)
	if value == nil || len(payload) < 1 || len(payload) > 1_040_384 || proto.Unmarshal(payload, value) != nil {
		return nil, errors.New("malformed node file response")
	}
	reflected := value.ProtoReflect()
	outcome := reflected.Descriptor().Oneofs().ByName("outcome")
	if outcome == nil || reflected.WhichOneof(outcome) == nil {
		return nil, errors.New("missing node file outcome")
	}
	audit := value.GetAudit()
	if len(audit.GetObservations()) > 4 {
		return nil, errors.New("oversize node audit")
	}
	kinds := map[nodev1.FileAuditKind]bool{}
	for _, observation := range audit.GetObservations() {
		if observation == nil || observation.Kind == nil || observation.GetKind() < 1 || observation.GetKind() > 7 || kinds[observation.GetKind()] ||
			observation.SizeBytes == nil || observation.DigestInputBytes == nil || len(observation.Sha256) != 32 ||
			observation.GetItemCount() > 10_001 || !validFileObservation(method, observation) {
			return nil, errors.New("malformed node audit")
		}
		kinds[observation.GetKind()] = true
	}
	if value.GetError() == nil {
		required := nodev1.FileAuditKind(0)
		switch method {
		case relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE:
			required = nodev1.FileAuditKind_FILE_AUDIT_KIND_READ_BYTES
		case relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE:
			required = nodev1.FileAuditKind_FILE_AUDIT_KIND_WRITTEN_BYTES
		case relayv1.RoutedMethod_ROUTED_METHOD_SEARCH_NODE_FILES:
			required = nodev1.FileAuditKind_FILE_AUDIT_KIND_SEARCH_TRANSCRIPT
		case relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_DIRECTORY:
			required = nodev1.FileAuditKind_FILE_AUDIT_KIND_DIRECTORY_METADATA
		case relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_WORKSPACES, relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_WORKSPACE:
			required = nodev1.FileAuditKind_FILE_AUDIT_KIND_WORKSPACE_METADATA
		}
		if required != 0 && !kinds[required] {
			return nil, errors.New("missing required signed observation")
		}
		var size uint64
		var digest []byte
		switch v := value.(type) {
		case *nodev1.FileServiceReadFileResponse:
			read := v.GetValue()
			if read == nil || read.Data == nil || len(read.Data) > 65_536 || read.Offset == nil || read.NextOffset == nil || read.Eof == nil || read.FileSize == nil ||
				uint64(len(read.Data)) > ^uint64(0)-read.GetOffset() || read.GetNextOffset() != read.GetOffset()+uint64(len(read.Data)) {
				return nil, errors.New("malformed read result")
			}
			sum := sha256.Sum256(read.Data)
			size = uint64(len(read.Data))
			digest = sum[:]
			if !bytes.Equal(digest, read.GetSha256()) {
				return nil, errors.New("read digest mismatch")
			}
		case *nodev1.FileServiceWriteFileResponse:
			result := v.GetValue().GetResult()
			if result == nil || result.SizeBytes == nil || result.GetSizeBytes() > 4_194_304 || len(result.Sha256) != 32 {
				return nil, errors.New("malformed write result")
			}
			if _, ok := parseID(result.CommandId); !ok {
				return nil, errors.New("missing write command")
			}
			size, digest = result.GetSizeBytes(), result.GetSha256()
		case *nodev1.FileServiceEditFileResponse:
			result := v.GetValue().GetResult()
			if result == nil || result.SizeBytes == nil || result.GetSizeBytes() > 4_194_304 || len(result.Sha256) != 32 || result.Replacements == nil ||
				result.GetReplacements() < 1 || result.GetReplacements() > 1000 {
				return nil, errors.New("malformed edit result")
			}
			if _, ok := parseID(result.CommandId); !ok {
				return nil, errors.New("missing edit command")
			}
			size, digest = result.GetSizeBytes(), result.GetSha256()
		}
		if digest != nil {
			for _, observation := range audit.GetObservations() {
				if observation.GetKind() == required && (observation.GetSizeBytes() != size || observation.GetDigestInputBytes() != size || !bytes.Equal(observation.Sha256, digest)) {
					return nil, errors.New("signed observation disagrees with result")
				}
			}
		}
	}
	if err := validateFileResult(method, request, value); err != nil {
		return nil, err
	}
	return value, nil
}

func (r *Registry) readNodeFile(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceReadNodeFileRequest) (*fleetv1.FleetServiceReadNodeFileResponse, error) {
	value, nodeID, err := r.routed(ctx, call, message, relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE)
	response := &fleetv1.FleetServiceReadNodeFileResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceReadNodeFileResponse_Error{Error: failure}
	} else {
		response.Outcome = &fleetv1.FleetServiceReadNodeFileResponse_Value{Value: &fleetv1.FleetServiceReadNodeFileValue{Response: value, NodeId: id(nodeID)}}
	}
	return response, nil
}

func (r *Registry) writeNodeFile(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceWriteNodeFileRequest) (*fleetv1.FleetServiceWriteNodeFileResponse, error) {
	value, nodeID, err := r.routed(ctx, call, message, relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE)
	response := &fleetv1.FleetServiceWriteNodeFileResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceWriteNodeFileResponse_Error{Error: failure}
	} else {
		response.Outcome = &fleetv1.FleetServiceWriteNodeFileResponse_Value{Value: &fleetv1.FleetServiceWriteNodeFileValue{Response: value, NodeId: id(nodeID)}}
	}
	return response, nil
}

func (r *Registry) editNodeFile(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceEditNodeFileRequest) (*fleetv1.FleetServiceEditNodeFileResponse, error) {
	value, nodeID, err := r.routed(ctx, call, message, relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE)
	response := &fleetv1.FleetServiceEditNodeFileResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceEditNodeFileResponse_Error{Error: failure}
	} else {
		response.Outcome = &fleetv1.FleetServiceEditNodeFileResponse_Value{Value: &fleetv1.FleetServiceEditNodeFileValue{Response: value, NodeId: id(nodeID)}}
	}
	return response, nil
}

func (r *Registry) searchNodeFiles(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceSearchNodeFilesRequest) (*fleetv1.FleetServiceSearchNodeFilesResponse, error) {
	value, nodeID, err := r.routed(ctx, call, message, relayv1.RoutedMethod_ROUTED_METHOD_SEARCH_NODE_FILES)
	response := &fleetv1.FleetServiceSearchNodeFilesResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceSearchNodeFilesResponse_Error{Error: failure}
	} else {
		response.Outcome = &fleetv1.FleetServiceSearchNodeFilesResponse_Value{Value: &fleetv1.FleetServiceSearchNodeFilesValue{Response: value, NodeId: id(nodeID)}}
	}
	return response, nil
}

func (r *Registry) listNodeDirectory(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceListNodeDirectoryRequest) (*fleetv1.FleetServiceListNodeDirectoryResponse, error) {
	value, nodeID, err := r.routed(ctx, call, message, relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_DIRECTORY)
	response := &fleetv1.FleetServiceListNodeDirectoryResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceListNodeDirectoryResponse_Error{Error: failure}
	} else {
		response.Outcome = &fleetv1.FleetServiceListNodeDirectoryResponse_Value{Value: &fleetv1.FleetServiceListNodeDirectoryValue{Response: value, NodeId: id(nodeID)}}
	}
	return response, nil
}

func (r *Registry) planNodeRemoval(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServicePlanNodeRemovalRequest) (*fleetv1.FleetServicePlanNodeRemovalResponse, error) {
	value, nodeID, err := r.routed(ctx, call, message, relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL)
	response := &fleetv1.FleetServicePlanNodeRemovalResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServicePlanNodeRemovalResponse_Error{Error: failure}
	} else {
		response.Outcome = &fleetv1.FleetServicePlanNodeRemovalResponse_Value{Value: &fleetv1.FleetServicePlanNodeRemovalValue{Response: value, NodeId: id(nodeID)}}
	}
	return response, nil
}

func (r *Registry) executeNodeRemoval(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceExecuteNodeRemovalRequest) (*fleetv1.FleetServiceExecuteNodeRemovalResponse, error) {
	value, nodeID, err := r.routed(ctx, call, message, relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL)
	response := &fleetv1.FleetServiceExecuteNodeRemovalResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceExecuteNodeRemovalResponse_Error{Error: failure}
	} else {
		response.Outcome = &fleetv1.FleetServiceExecuteNodeRemovalResponse_Value{Value: &fleetv1.FleetServiceExecuteNodeRemovalValue{Response: value, NodeId: id(nodeID)}}
	}
	return response, nil
}

func (r *Registry) getNodeFileOperation(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceGetNodeFileOperationRequest) (*fleetv1.FleetServiceGetNodeFileOperationResponse, error) {
	value, nodeID, err := r.routed(ctx, call, message, relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_FILE_OPERATION)
	response := &fleetv1.FleetServiceGetNodeFileOperationResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceGetNodeFileOperationResponse_Error{Error: failure}
	} else {
		response.Outcome = &fleetv1.FleetServiceGetNodeFileOperationResponse_Value{Value: &fleetv1.FleetServiceGetNodeFileOperationValue{Response: value, NodeId: id(nodeID)}}
	}
	return response, nil
}

func (r *Registry) registerNodeWorkspace(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceRegisterNodeWorkspaceRequest) (*fleetv1.FleetServiceRegisterNodeWorkspaceResponse, error) {
	value, nodeID, err := r.routed(ctx, call, message, relayv1.RoutedMethod_ROUTED_METHOD_REGISTER_NODE_WORKSPACE)
	response := &fleetv1.FleetServiceRegisterNodeWorkspaceResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceRegisterNodeWorkspaceResponse_Error{Error: failure}
	} else {
		response.Outcome = &fleetv1.FleetServiceRegisterNodeWorkspaceResponse_Value{Value: &fleetv1.FleetServiceRegisterNodeWorkspaceValue{Response: value, NodeId: id(nodeID)}}
	}
	return response, nil
}

func (r *Registry) unregisterNodeWorkspace(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceUnregisterNodeWorkspaceRequest) (*fleetv1.FleetServiceUnregisterNodeWorkspaceResponse, error) {
	value, nodeID, err := r.routed(ctx, call, message, relayv1.RoutedMethod_ROUTED_METHOD_UNREGISTER_NODE_WORKSPACE)
	response := &fleetv1.FleetServiceUnregisterNodeWorkspaceResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceUnregisterNodeWorkspaceResponse_Error{Error: failure}
	} else {
		response.Outcome = &fleetv1.FleetServiceUnregisterNodeWorkspaceResponse_Value{Value: &fleetv1.FleetServiceUnregisterNodeWorkspaceValue{Response: value, NodeId: id(nodeID)}}
	}
	return response, nil
}

func (r *Registry) listNodeWorkspaces(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceListNodeWorkspacesRequest) (*fleetv1.FleetServiceListNodeWorkspacesResponse, error) {
	value, nodeID, err := r.routed(ctx, call, message, relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_WORKSPACES)
	response := &fleetv1.FleetServiceListNodeWorkspacesResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceListNodeWorkspacesResponse_Error{Error: failure}
	} else {
		response.Outcome = &fleetv1.FleetServiceListNodeWorkspacesResponse_Value{Value: &fleetv1.FleetServiceListNodeWorkspacesValue{Response: value, NodeId: id(nodeID)}}
	}
	return response, nil
}

func (r *Registry) getNodeWorkspace(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceGetNodeWorkspaceRequest) (*fleetv1.FleetServiceGetNodeWorkspaceResponse, error) {
	value, nodeID, err := r.routed(ctx, call, message, relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_WORKSPACE)
	response := &fleetv1.FleetServiceGetNodeWorkspaceResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceGetNodeWorkspaceResponse_Error{Error: failure}
	} else {
		response.Outcome = &fleetv1.FleetServiceGetNodeWorkspaceResponse_Value{Value: &fleetv1.FleetServiceGetNodeWorkspaceValue{Response: value, NodeId: id(nodeID)}}
	}
	return response, nil
}

func fileObservations(audit *nodev1.FileAuditMetadata) []fleet.RoutedObservation {
	observations := make([]fleet.RoutedObservation, 0, len(audit.GetObservations()))
	for _, o := range audit.GetObservations() {
		observations = append(observations, fleet.RoutedObservation{Kind: int32(o.GetKind()), SizeBytes: o.GetSizeBytes(), SHA256: hex.EncodeToString(o.GetSha256()),
			DigestInputBytes: o.GetDigestInputBytes(), ItemCount: o.ItemCount})
	}
	return observations
}

func sameFileTarget(a, b fleet.FileTarget) bool {
	equalID := func(x, y *platform.ID) bool { return x == nil && y == nil || x != nil && y != nil && *x == *y }
	equalPath := func(x, y *string) bool { return x == nil && y == nil || x != nil && y != nil && *x == *y }
	return equalID(a.WorkspaceID, b.WorkspaceID) && equalID(a.AttemptID, b.AttemptID) && equalPath(a.Path, b.Path)
}

// routeFileRead audits the verified signed observations as node-supplied evidence;
// lost/invalid replies explicitly say that these observations are unavailable.
func (r *Registry) routeFileRead(ctx context.Context, call *ingress.Call, routed RoutedCall) ([]byte, error) {
	caller := fleet.RoutedCaller{Kind: fleet.RoutedCallerSession, SessionID: routed.SessionID, Actor: identity.Actor(routed.AccountID)}
	if routed.Relay != nil {
		verified, ok := routed.Relay.(relayed)
		if !ok {
			return nil, arc.Unauthenticated()
		}
		caller = fleet.RoutedCaller{Kind: fleet.RoutedCallerRelay, RelayingNodeID: verified.RelayingNodeID(), LocalOrigin: int16(verified.LocalOrigin()),
			LocalSessionID: verified.LocalSessionID(), Actor: "node:" + verified.RelayingInstallationID().String()}
	}
	result, err := r.routing.router.Route(ctx, routed)
	exact := sha256.Sum256(routed.Payload)
	audit := fleet.RoutedReadAudit{Request: request(call), Caller: caller, AccountID: routed.AccountID, NodeID: routed.TargetNodeID, Method: int16(routed.Method),
		WorkspaceID: routed.WorkspaceID, TargetAttemptID: routed.TargetAttemptID, TargetPath: routed.TargetPath,
		RequestSHA256: exact[:], RequestSize: len(routed.Payload), Outcome: "unavailable", Now: r.clock()}
	if err == nil && result.Outcome == relayv1.RoutedOutcome_ROUTED_OUTCOME_EXECUTED {
		value, decodeErr := decodeFileResponse(routed.Method, result.Response, routed.Payload)
		if decodeErr != nil {
			err = arc.NodeUnreachable(routed.TargetNodeID[:], arc.UnreachableChannelClosed, false)
		} else {
			audit.NodeAuditAvailable = value.GetAudit() != nil
			audit.Observations = fileObservations(value.GetAudit())
			audit.Outcome = "succeeded"
			if value.GetError() != nil {
				audit.Outcome = "refused"
			} else if operation, ok := value.(*nodev1.FileServiceGetFileOperationResponse); ok {
				// The signed status binds its returned target to the requested operation.
				var request nodev1.FileServiceGetFileOperationRequest
				_ = proto.Unmarshal(routed.Payload, &request) // decodeFileResponse already checked it
				op := operation.GetValue().GetOperation()
				var observed fleet.FileTarget
				switch target := op.Target.(type) {
				case *nodev1.FileOperation_WorkspacePath:
					id, _ := parseID(target.WorkspacePath.WorkspaceId)
					path := target.WorkspacePath.GetPath()
					observed.WorkspaceID, observed.Path = &id, &path
				case *nodev1.FileOperation_AttemptId:
					id, _ := parseID(target.AttemptId)
					observed.AttemptID = &id
				}
				known := fleet.FileTarget{WorkspaceID: routed.WorkspaceID, AttemptID: routed.TargetAttemptID, Path: routed.TargetPath}
				id, _ := parseID(request.OperationCommandId)
				// A node signature authenticates the response, not the caller's
				// ownership. Bind it to the caller's original durable mutation and
				// its raw inner-wire SHA-256 (not the domain-separated record digest).
				receipt, receiptErr := fleet.LookupFileOperationReceipt(ctx, r.db, routed.AccountID, routed.TargetNodeID, caller, id)
				if receiptErr != nil || receipt == nil || !bytes.Equal(receipt.RequestSHA256, op.RequestSha256) ||
					operationMethod(op.GetKind()) != relayv1.RoutedMethod(receipt.Method) ||
					((known.WorkspaceID != nil || known.AttemptID != nil) && !sameFileTarget(known, observed)) {
					err = arc.NodeUnreachable(routed.TargetNodeID[:], arc.UnreachableChannelClosed, false)
					audit.Outcome, audit.NodeAuditAvailable, audit.Observations = "unavailable", false, nil
				} else {
					audit.WorkspaceID, audit.TargetAttemptID, audit.TargetPath = observed.WorkspaceID, observed.AttemptID, observed.Path
					audit.OperationTargetID = &id
				}
			}
		}
	} else if err == nil {
		err = refusalOf(result)
		audit.Outcome = "refused"
	}
	if err != nil {
		audit.Refusal, audit.RefusalReason = fileRefusalAudit(err)
		if audit.RefusalReason == "capability_unavailable" {
			audit.Outcome = "refused"
		}
	}
	// Independent bounded context lets a canceled client leave its audit without
	// extending the original read or silently dropping that metadata.
	auditCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	auditErr := fleet.AuditRoutedFileRead(auditCtx, r.db, audit)
	cancel()
	if auditErr != nil {
		r.logger.Warn("a routed file read could not be audited", "correlationId", call.Correlation.CorrelationID, "error", auditErr.Error())
		if err == nil {
			return nil, arc.Unavailable()
		}
	}
	if err != nil {
		return nil, err
	}
	return result.Response, nil
}

// Persist only catalogue keys and closed reasons, never arbitrary node text.
func fileRefusalAudit(failure error) (string, string) {
	key, detail := "other/other", ""
	var refusal *arc.Refusal
	if errors.As(failure, &refusal) {
		key = refusalKey(refusal.Category, refusal.Code)
		if refusal.Code == "invalid_state" && (refusal.Reason == "replay_window_passed" || refusal.Reason == "capability_unavailable") {
			detail = refusal.Reason
		}
	}
	if fleet.RefusalCode(key) == fleet.RefusalOther {
		key = "other/other"
	}
	return key, detail
}

// auditEarlyFileRefusal authenticates a node assertion solely to attribute an
// already rejected outer frame. No verification result authorizes routing. A
// malformed outer command is not trusted: the bounded, signed assertion's own
// command is checked against its signature, method, target and payload digest.
func (r *Registry) auditEarlyFileRefusal(ctx context.Context, call *ingress.Call, message routedRequest, method relayv1.RoutedMethod, failure error) {
	nodeID, ok := parseID(message.GetNodeId())
	if !ok {
		return
	}
	var relay access.Relay
	var signedCommand *platform.ID
	if call.Caller.Scope == "node" {
		caller, raw := message.GetCaller(), message.GetRelayAssertion()
		if caller == nil || caller.GetKind() != fleetv1.CallerKind_CALLER_KIND_NODE_RELAY || len(raw) == 0 || len(raw) > 512 {
			return
		}
		var assertion relayv1.RelayAssertion
		if proto.Unmarshal(raw, &assertion) != nil {
			return
		}
		if assertion.CommandId != nil {
			id, valid := parseID(assertion.CommandId)
			if !valid {
				return
			}
			signedCommand = &id
		}
		relaying, _ := parseID(caller.GetRelayingNodeId())
		digest := sha256.Sum256(message.GetRequest())
		claim := &access.RelayClaim{Assertion: raw, Method: method, RequestSHA256: digest[:], TargetNodeID: &nodeID, CommandID: signedCommand,
			CallerRelayingNodeID: relaying, CallerLocalOrigin: caller.GetLocalOrigin()}
		var err error
		relay, err = r.access.VerifyRelayedForAudit(ctx, call, claim)
		if err != nil {
			return
		}
	}
	var command *platform.ID
	if id, valid := parseID(message.GetMeta().GetCommandId()); valid && (relay == nil || signedCommand != nil && id == *signedCommand) {
		command = &id
	}
	r.auditFileRefusal(call, nodeID, command, method, message.GetRequest(), fileTargetForAudit(method, message.GetRequest()), relay, failure)
}

// fileAuditCaller derives a target-lookup key only from authenticated evidence.
func fileAuditCaller(call *ingress.Call, relay access.Relay) (fleet.RoutedCaller, platform.ID, bool) {
	if !call.Caller.IsAuthenticated() {
		return fleet.RoutedCaller{}, platform.ID{}, false
	}
	account, ok := textID(call.Caller.UserID)
	if !ok {
		return fleet.RoutedCaller{}, platform.ID{}, false
	}
	if relay != nil {
		verified, ok := relay.(relayed)
		if !ok || !verified.Verified() || call.Caller.Scope != "node" {
			return fleet.RoutedCaller{}, platform.ID{}, false
		}
		return fleet.RoutedCaller{Kind: fleet.RoutedCallerRelay, RelayingNodeID: verified.RelayingNodeID(), LocalOrigin: int16(verified.LocalOrigin()),
			LocalSessionID: verified.LocalSessionID(), Actor: "node:" + verified.RelayingInstallationID().String()}, account, true
	}
	if call.Caller.Scope != "account" && call.Caller.Scope != "mobile.limited" {
		return fleet.RoutedCaller{}, platform.ID{}, false
	}
	sessionID, ok := textID(call.Caller.SessionID)
	if !ok {
		return fleet.RoutedCaller{}, platform.ID{}, false
	}
	return fleet.RoutedCaller{Kind: fleet.RoutedCallerSession, SessionID: sessionID, Actor: identity.Actor(account)}, account, true
}

// resolveFileTarget consults only a previously bound account/node/caller key;
// foreign or unknown identifiers yield no metadata, never a guessed path.
func (r *Registry) resolveFileTarget(ctx context.Context, call *ingress.Call, nodeID platform.ID, method relayv1.RoutedMethod,
	payload []byte, checked inner, relay access.Relay) (inner, error) {
	if method != relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL && method != relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_FILE_OPERATION {
		return checked, nil
	}
	if len(payload) == 0 || len(payload) > 262_144 {
		return checked, nil
	}
	value := newFileRequest(method)
	if value == nil || proto.Unmarshal(payload, value) != nil {
		return checked, nil
	}
	var id platform.ID
	var ok bool
	var kind fleet.FileTargetKind
	switch v := value.(type) {
	case *nodev1.FileServiceExecuteRemovalRequest:
		id, ok = parseID(v.PlanId)
		kind = fleet.FileTargetPlan
	case *nodev1.FileServiceGetFileOperationRequest:
		id, ok = parseID(v.OperationCommandId)
		kind = fleet.FileTargetOperation
	}
	caller, account, verified := fileAuditCaller(call, relay)
	if !ok || !verified {
		return checked, nil
	}
	target, err := fleet.LookupFileTarget(ctx, r.db, account, nodeID, caller, kind, id)
	if err != nil || target == nil {
		return checked, err
	}
	checked.workspaceID, checked.targetAttemptID = target.WorkspaceID, target.AttemptID
	if target.Path != nil {
		checked.path, checked.pathKnown = *target.Path, true
	}
	return checked, nil
}

// auditFileRefusal uses only an authenticated account session or an already
// verified relay. Never attribute a merely claimed relay identity to an actor.
func (r *Registry) auditFileRefusal(call *ingress.Call, nodeID platform.ID, commandID *platform.ID, method relayv1.RoutedMethod,
	payload []byte, checked inner, relay access.Relay, failure error) {
	caller, _, ok := fileAuditCaller(call, relay)
	if !ok {
		return
	}
	lookupCtx, lookupCancel := context.WithTimeout(context.Background(), time.Second)
	resolved, err := r.resolveFileTarget(lookupCtx, call, nodeID, method, payload, checked, relay)
	lookupCancel()
	if err == nil {
		checked = resolved
	} else {
		r.logger.Warn("a refused file target could not be resolved", "error", err.Error())
	}

	refusal, refusalReason := fileRefusalAudit(failure)
	hash := sha256.Sum256(payload)
	var path *string
	if checked.pathKnown {
		path = &checked.path
	}
	audit := fleet.RoutedFileRefusalAudit{RoutedReadAudit: fleet.RoutedReadAudit{Request: request(call), Caller: caller, NodeID: nodeID,
		Method: int16(method), WorkspaceID: checked.workspaceID, TargetAttemptID: checked.targetAttemptID, TargetPath: path,
		RequestSHA256: hash[:], RequestSize: len(payload), Now: r.clock(), Refusal: refusal, RefusalReason: refusalReason}, CommandID: commandID}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := fleet.AuditRoutedFileRefusal(ctx, r.db, audit); err != nil {
		r.logger.Warn("a refused routed file call could not be audited", "correlationId", call.Correlation.CorrelationID, "error", err.Error())
	}
}
