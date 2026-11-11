// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/fleet"
)

var (
	safeErrorToken = regexp.MustCompile(`^[A-Za-z0-9._:/ -]{1,256}$`)
	contractToken  = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)
	decimalToken   = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]{1,9})?$`)
)

func validRevision(v *foundationv1.Revision) bool {
	return v != nil && v.Value != nil && v.GetValue() >= 0
}

func validDecimal(v *foundationv1.Decimal) bool {
	if v == nil || v.Value == nil || !decimalToken.MatchString(v.GetValue()) ||
		(strings.Contains(v.GetValue(), ".") && strings.HasSuffix(v.GetValue(), "0")) {
		return false
	}
	n := strings.TrimLeft(strings.ReplaceAll(strings.TrimPrefix(v.GetValue(), "-"), ".", ""), "0")
	return len(n) <= 28 && !(strings.HasPrefix(v.GetValue(), "-") && n == "")
}

func validFileResponseMeta(v *foundationv1.ResponseMeta) bool {
	if v == nil {
		return true
	} // File response meta is optional; its nested fields are not.
	if _, ok := parseID(v.CorrelationId); !ok {
		return false
	}
	if v.ResultRev != nil && !validRevision(v.ResultRev) {
		return false
	}
	for _, warning := range v.Warnings {
		if !utf8.ValidString(warning) {
			return false
		}
	}
	return true
}

func validFileInstant(v *foundationv1.Instant) bool {
	return v != nil && v.UnixSeconds != nil && v.Nanos != nil && v.GetUnixSeconds() >= -62135596800 && v.GetUnixSeconds() <= 253402300799 && v.GetNanos() <= 999999999
}

// File handler errors have the ordinary ArcError shape, not the narrower
// relay-header refusal shape. Check the catalogue, retry/effect relationship
// and bounded detail rather than letting an empty or arbitrary error settle.
func validFileError(e *foundationv1.ArcError) bool {
	if e == nil || e.Category == nil || e.GetCategory() < 1 || e.GetCategory() > 9 || e.Code == nil || !safeErrorToken.MatchString(e.GetCode()) ||
		e.MessageKey == nil || e.Retry == nil || e.Retry.Mode == nil || e.GetRetry().GetMode() < 1 || e.GetRetry().GetMode() > 4 ||
		e.Effect == nil || e.GetEffect() < 1 || e.GetEffect() > 3 || proto.Size(e) > 4096 {
		return false
	}
	category := strings.ToLower(strings.TrimPrefix(e.GetCategory().String(), "ERROR_CATEGORY_"))
	if fleet.RefusalCode(category+"/"+e.GetCode()) == fleet.RefusalOther || e.GetMessageKey() != "error."+category+"."+e.GetCode() {
		return false
	}
	if _, ok := parseID(e.CorrelationId); !ok {
		return false
	}
	retry := e.GetRetry()
	if (retry.GetMode() == foundationv1.RetryMode_RETRY_MODE_AFTER_TIME) != (retry.RetryAt != nil) ||
		(retry.GetMode() == foundationv1.RetryMode_RETRY_MODE_RECONCILE) != (retry.ReconciliationOperation != nil) ||
		(retry.RetryAt != nil && !validFileInstant(retry.RetryAt)) ||
		(retry.ReconciliationOperation != nil && !contractToken.MatchString(retry.GetReconciliationOperation())) ||
		(e.GetEffect() == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN && retry.GetMode() == foundationv1.RetryMode_RETRY_MODE_AFTER_TIME) {
		return false
	}
	if e.Details != nil {
		switch detail := e.Details.Detail.(type) {
		case *foundationv1.ErrorDetails_State:
			v := detail.State
			if v == nil || v.State == nil || !contractToken.MatchString(v.GetState()) || v.Reason == nil || !safeErrorToken.MatchString(v.GetReason()) {
				return false
			}
			if v.Resource != nil {
				if v.Resource.Kind == nil || !contractToken.MatchString(v.Resource.GetKind()) {
					return false
				}
				if _, ok := parseID(v.Resource.Id); !ok {
					return false
				}
			}
			if v.Native != nil && v.Native.Value == nil {
				return false
			}
		case *foundationv1.ErrorDetails_Revision:
			v := detail.Revision
			if v == nil || v.Expected != nil && !validRevision(v.Expected) || v.Actual != nil && !validRevision(v.Actual) {
				return false
			}
			if v.ConflictId != nil {
				if _, ok := parseID(v.ConflictId); !ok {
					return false
				}
			}
		case *foundationv1.ErrorDetails_Limit:
			v := detail.Limit
			if v == nil || v.LimitName == nil || !contractToken.MatchString(v.GetLimitName()) || v.Maximum != nil && !validDecimal(v.Maximum) || v.Available != nil && !validDecimal(v.Available) || v.RecoveryAt != nil && !validFileInstant(v.RecoveryAt) {
				return false
			}
		case *foundationv1.ErrorDetails_Upgrade:
			v := detail.Upgrade
			if v == nil || v.MinReadable == nil || !contractToken.MatchString(v.GetMinReadable()) || v.MinWritable == nil || !contractToken.MatchString(v.GetMinWritable()) || v.Received == nil || !contractToken.MatchString(v.GetReceived()) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// Each catalogue row that names a detail must carry it. These reasons are
// fixed machine values, never paths, file content or arbitrary OS messages.
func validFileCatalogueDetails(key string, e *foundationv1.ArcError) bool {
	state := e.GetDetails().GetState()
	switch key {
	case "validation/invalid_argument":
		return state != nil && strings.Contains(state.GetReason(), ": ")
	case "validation/path_not_found", "authorization/permission_denied", "authorization/approval_required",
		"state/invalid_state", "state/in_use", "resource/enforcement_unavailable":
		return state != nil
	case "state/not_found":
		return state != nil && state.Resource != nil
	case "resource/too_large":
		limit := e.GetDetails().GetLimit()
		return limit != nil && limit.Maximum != nil && validDecimal(limit.Maximum) && !strings.HasPrefix(limit.Maximum.GetValue(), "-")
	case "conflict/file_changed":
		return state != nil && state.GetState() == "file" && validFileMismatchReason(state.GetReason())
	case "conflict/occurrence_mismatch":
		return state != nil && state.GetState() == "file" && state.GetReason() == "occurrence_mismatch"
	case "state/file_access_denied":
		return state != nil && state.GetState() == "file" && validFileAccessReason(state.GetReason())
	case "execution/operation_failed":
		if state == nil || state.GetState() != "file" {
			return false
		}
		return e.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN || state.GetReason() == "file_outcome_unknown"
	default:
		return true
	}
}

// The accepted mismatch names cover the current registered-root/path guards and
// the file precondition, object, parent and planned-tree checks. Both sides of
// the wire must use this closed set; unrecognized free-form reasons are refused.
func validFileMismatchReason(reason string) bool {
	switch reason {
	case "workspace_root_changed", "workspace_path_conflict", "workspace_identity_conflict", "workspace_registration_changed",
		"legacy_snapshot_changed", "file_identity_changed", "directory_identity_changed", "directory_changed", "root_changed",
		"file_changed_while_reading", "hash_mismatch", "expected_absent_conflict", "parent_identity_changed", "planned_tree_changed":
		return true
	default:
		return false
	}
}

func validFileAccessReason(reason string) bool {
	switch reason {
	case "file_access_denied", "file_hard_link", "file_metadata_unavailable", "canonical_path_unavailable", "case_semantics_unavailable",
		"directory_entry_invalid", "directory_enumeration_failed", "directory_enumeration_unavailable", "file_guard_unavailable",
		"identity_filesystem_unavailable", "identity_handle_unavailable", "identity_unavailable", "identity_unavailable_or_reparse",
		"mount_crossing", "path_enforcement_unavailable", "path_link_or_special", "procfs_unavailable", "root_not_supported":
		return true
	default:
		return false
	}
}

func validUnknownFileOperationError(e *foundationv1.ArcError) bool {
	return validFileError(e) && e.GetCategory() == foundationv1.ErrorCategory_ERROR_CATEGORY_EXECUTION &&
		e.GetCode() == "operation_failed" && e.GetEffect() == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN &&
		e.GetRetry().GetMode() == foundationv1.RetryMode_RETRY_MODE_NEVER && validFileCatalogueDetails("execution/operation_failed", e)
}

func operationMethod(kind nodev1.FileOperationKind) relayv1.RoutedMethod {
	switch kind {
	case nodev1.FileOperationKind_FILE_OPERATION_KIND_WRITE:
		return relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE
	case nodev1.FileOperationKind_FILE_OPERATION_KIND_EDIT:
		return relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE
	case nodev1.FileOperationKind_FILE_OPERATION_KIND_REMOVAL:
		return relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL
	default:
		return relayv1.RoutedMethod_ROUTED_METHOD_UNSPECIFIED
	}
}

// File errors are catalogue outcomes, not an arbitrary signed category/effect.
// A malformed combination cannot finalize a routing receipt.
func validFileErrorForMethod(method relayv1.RoutedMethod, e *foundationv1.ArcError) bool {
	key := strings.ToLower(strings.TrimPrefix(e.GetCategory().String(), "ERROR_CATEGORY_")) + "/" + e.GetCode()
	// Six native-checking file/workspace methods' file_changed entries depend
	// on a bounded Design erratum under review; this WIP must not ship until approved.
	allowed := map[relayv1.RoutedMethod]string{
		relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE:            " validation/path_not_found validation/invalid_argument conflict/file_changed resource/too_large state/file_access_denied authorization/permission_denied ",
		relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE:           " validation/path_not_found validation/invalid_argument conflict/file_changed conflict/command_id_reused resource/too_large resource/enforcement_unavailable state/file_access_denied state/invalid_state authorization/permission_denied authorization/approval_required execution/operation_failed ",
		relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE:            " validation/path_not_found validation/invalid_argument conflict/file_changed conflict/occurrence_mismatch conflict/command_id_reused resource/too_large resource/enforcement_unavailable state/file_access_denied state/invalid_state authorization/permission_denied authorization/approval_required execution/operation_failed ",
		relayv1.RoutedMethod_ROUTED_METHOD_SEARCH_NODE_FILES:         " conflict/file_changed validation/path_not_found validation/invalid_argument resource/too_large state/file_access_denied authorization/permission_denied ",
		relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_DIRECTORY:       " conflict/file_changed validation/invalid_cursor validation/path_not_found validation/invalid_argument resource/too_large state/file_access_denied authorization/permission_denied ",
		relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL:         " conflict/file_changed validation/path_not_found validation/invalid_argument state/not_found state/in_use conflict/command_id_reused resource/too_large state/file_access_denied authorization/permission_denied ",
		relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL:      " validation/invalid_argument state/not_found conflict/digest_mismatch conflict/file_changed conflict/command_id_reused state/in_use resource/too_large resource/enforcement_unavailable state/expired state/invalid_state authorization/permission_denied authorization/approval_required state/file_access_denied execution/operation_failed ",
		relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_FILE_OPERATION:   " validation/invalid_argument state/not_found authorization/permission_denied ",
		relayv1.RoutedMethod_ROUTED_METHOD_REGISTER_NODE_WORKSPACE:   " conflict/file_changed validation/path_not_found validation/invalid_argument resource/too_large state/file_access_denied authorization/permission_denied conflict/command_id_reused ",
		relayv1.RoutedMethod_ROUTED_METHOD_UNREGISTER_NODE_WORKSPACE: " state/not_found state/in_use validation/invalid_argument authorization/permission_denied conflict/command_id_reused ",
		relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_WORKSPACES:      " validation/invalid_cursor validation/invalid_argument authorization/permission_denied ",
		relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_WORKSPACE:        " conflict/file_changed state/not_found validation/invalid_argument state/file_access_denied authorization/permission_denied ",
	}
	if !strings.Contains(allowed[method], " "+key+" ") && key != "internal/internal" && key != "internal/store_corrupt" && key != "resource/overloaded" {
		return false
	}
	if !validFileCatalogueDetails(key, e) {
		return false
	}
	if key == "conflict/file_changed" {
		reason := e.GetDetails().GetState().GetReason()
		switch reason {
		case "hash_mismatch":
			if method != relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE && method != relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE {
				return false
			}
		case "expected_absent_conflict":
			if method != relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE {
				return false
			}
		case "planned_tree_changed":
			if method != relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL {
				return false
			}
		}
	}
	// Native exclusion guards are mandatory for these effects. Failure to establish
	// one is RESOURCE/enforcement_unavailable, not a generic access refusal.
	if key == "state/file_access_denied" && (method == relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE ||
		method == relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE || method == relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL) {
		reason := e.GetDetails().GetState().GetReason()
		if reason == "file_guard_unavailable" || reason == "path_enforcement_unavailable" {
			return false
		}
	}
	mode, effect := e.GetRetry().GetMode(), e.GetEffect()
	if !fileMutation(method) && effect != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN {
		return false
	}
	switch key {
	case "execution/operation_failed":
		return fileMutation(method) && (effect == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN && mode == foundationv1.RetryMode_RETRY_MODE_NEVER || effect == foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED && (mode == foundationv1.RetryMode_RETRY_MODE_NEVER || mode == foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND))
	case "internal/internal":
		return effect == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN && mode == foundationv1.RetryMode_RETRY_MODE_NEVER || effect != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN && mode == foundationv1.RetryMode_RETRY_MODE_AFTER_TIME
	case "state/in_use", "resource/overloaded":
		return effect == foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN && mode == foundationv1.RetryMode_RETRY_MODE_AFTER_TIME
	case "authorization/approval_required":
		state := e.GetDetails().GetState()
		return effect == foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN && mode == foundationv1.RetryMode_RETRY_MODE_RECONCILE && e.GetRetry().GetReconciliationOperation() == "arcforges.node.v1.ApprovalService/GetApproval" && state.GetResource().GetKind() == "approval"
	default:
		return effect == foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN && mode == foundationv1.RetryMode_RETRY_MODE_NEVER
	}
}

func validFilePath(p *nodev1.FilePath, empty bool) bool {
	if p == nil || p.Path == nil || len(p.GetPath()) > 4096 || !utf8.ValidString(p.GetPath()) || strings.ContainsRune(p.GetPath(), 0) || (!empty && p.GetPath() == "") {
		return false
	}
	_, ok := parseID(p.WorkspaceId)
	return ok
}

func sameID(a, b *foundationv1.Id) bool {
	_, okA := parseID(a)
	_, okB := parseID(b)
	return okA && okB && bytes.Equal(a.Value, b.Value)
}

func validOptionalID(v *foundationv1.Id) bool {
	if v == nil {
		return true
	}
	_, ok := parseID(v)
	return ok
}

func validActor(v *nodev1.ActorRef) bool {
	if v == nil {
		return true
	}
	if v.Origin != nil && (v.GetOrigin() < 1 || v.GetOrigin() > 8) || v.ClientKind != nil && (v.GetClientKind() < 1 || v.GetClientKind() > 7) {
		return false
	}
	for _, id := range []*foundationv1.Id{v.SessionId, v.PeerNodeId, v.RemoteCommandId} {
		if !validOptionalID(id) {
			return false
		}
	}
	for _, value := range []*string{v.AgentId, v.OsUser, v.ClientName} {
		if value != nil && (!utf8.ValidString(*value) || len(*value) > 4096 || strings.ContainsRune(*value, 0)) {
			return false
		}
	}
	if c := v.CenterCaller; c != nil {
		if c.Kind == nil || !validOptionalID(c.UserId) || !validOptionalID(c.SessionId) || !validOptionalID(c.RelayingNodeId) || !validOptionalID(c.LocalSessionId) {
			return false
		}
		if _, ok := parseID(c.AccountId); !ok {
			return false
		}
		switch c.GetKind() {
		case nodev1.CenterCallerKind_CENTER_CALLER_KIND_ACCOUNT_SESSION:
			if c.UserId == nil || c.SessionId == nil || c.RelayingNodeId != nil || c.LocalOrigin != nil || c.LocalSessionId != nil {
				return false
			}
		case nodev1.CenterCallerKind_CENTER_CALLER_KIND_NODE_RELAY:
			if c.UserId != nil || c.SessionId != nil || c.RelayingNodeId == nil || c.LocalOrigin == nil || c.GetLocalOrigin() < 1 || c.GetLocalOrigin() > 3 || c.LocalSessionId == nil {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validWorkspace(w *nodev1.Workspace) bool {
	if w == nil || w.Kind == nil || w.GetKind() < 1 || w.GetKind() > 3 || w.State == nil || w.GetState() < 1 || w.GetState() > 7 ||
		w.Name == nil || !utf8.ValidString(w.GetName()) || utf8.RuneCountInString(w.GetName()) < 1 || utf8.RuneCountInString(w.GetName()) > 100 ||
		w.RootPath == nil || len(w.GetRootPath()) < 1 || len(w.GetRootPath()) > 4096 || !utf8.ValidString(w.GetRootPath()) || strings.ContainsRune(w.GetRootPath(), 0) {
		return false
	}
	if !validActor(w.Owner) {
		return false
	}
	if _, ok := parseID(w.WorkspaceId); !ok {
		return false
	}
	for _, value := range []*foundationv1.Id{w.BaseWorkspaceId, w.OriginNodeId, w.LeasedByAttemptId} {
		if value != nil {
			if _, ok := parseID(value); !ok {
				return false
			}
		}
	}
	for _, value := range []*string{w.RepositoryIdentity, w.BaseRef} {
		if value != nil && (!utf8.ValidString(*value) || len(*value) > 4096 || strings.ContainsRune(*value, 0)) {
			return false
		}
	}
	if w.RoutingMode != nil && (w.GetRoutingMode() < 1 || w.GetRoutingMode() > 4) || w.ConcurrencyMode != nil && (w.GetConcurrencyMode() < 1 || w.GetConcurrencyMode() > 3) {
		return false
	}
	if w.GetKind() == nodev1.WorkspaceKind_WORKSPACE_KIND_REGISTERED && w.GetState() != nodev1.WorkspaceState_WORKSPACE_STATE_ACTIVE {
		return false
	}
	if w.CreatedAt != nil && !validFileInstant(w.CreatedAt) || w.LastUsedAt != nil && !validFileInstant(w.LastUsedAt) {
		return false
	}
	if g := w.Git; g != nil {
		for _, text := range []*string{g.Branch, g.Head} {
			if text != nil && (!utf8.ValidString(*text) || len(*text) > 4096 || strings.ContainsRune(*text, 0)) {
				return false
			}
		}
		if g.Quality == nil || g.GetQuality() < 1 || g.GetQuality() > 3 {
			return false
		}
		if g.GetQuality() == nodev1.GitStatusQuality_GIT_STATUS_QUALITY_COMPLETE {
			if g.Dirty == nil || g.ModifiedFiles == nil || g.UntrackedFiles == nil || g.Locked == nil {
				return false
			}
		} else if g.Dirty != nil || g.ModifiedFiles != nil || g.UntrackedFiles != nil || g.Ahead != nil || g.Behind != nil || g.MergedIntoBase != nil || g.UpstreamDeleted != nil || g.Locked != nil {
			return false
		}
	}
	return true
}

func appendU32(buf *bytes.Buffer, n uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	buf.Write(b[:])
}
func appendU64(buf *bytes.Buffer, n uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	buf.Write(b[:])
}
func appendText(buf *bytes.Buffer, s string) { appendU32(buf, uint32(len(s))); buf.WriteString(s) }

// Only observations meaningful for this method can enter the durable audit.
// For signed search evidence the center can check framing bounds and agreement,
// but cannot recompute a digest of bytes it did not read.
func validFileObservation(method relayv1.RoutedMethod, o *nodev1.FileAuditObservation) bool {
	kind := o.GetKind()
	switch kind {
	case nodev1.FileAuditKind_FILE_AUDIT_KIND_READ_BYTES:
		return method == relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE && o.GetSizeBytes() <= 65536 && o.GetDigestInputBytes() == o.GetSizeBytes()
	case nodev1.FileAuditKind_FILE_AUDIT_KIND_INPUT_BYTES, nodev1.FileAuditKind_FILE_AUDIT_KIND_WRITTEN_BYTES:
		return (method == relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE || method == relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE) && o.GetSizeBytes() <= 4194304 && o.GetDigestInputBytes() == o.GetSizeBytes()
	case nodev1.FileAuditKind_FILE_AUDIT_KIND_SEARCH_TRANSCRIPT:
		if method != relayv1.RoutedMethod_ROUTED_METHOD_SEARCH_NODE_FILES || o.ItemCount == nil || o.GetItemCount() > 10000 || o.GetSizeBytes() > 8388608 || (o.GetSizeBytes() == 0) != (o.GetItemCount() == 0) {
			return false
		}
		minimum := uint64(len("ArcForges search-scan v1\x00")) + o.GetSizeBytes() + uint64(o.GetItemCount())*12
		maximum := minimum + uint64(o.GetItemCount())*4096
		return o.GetDigestInputBytes() >= minimum && o.GetDigestInputBytes() <= maximum
	case nodev1.FileAuditKind_FILE_AUDIT_KIND_DIRECTORY_METADATA:
		return method == relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_DIRECTORY && o.ItemCount != nil && o.GetItemCount() <= 128 && o.GetSizeBytes() <= 131072 && o.GetDigestInputBytes() == o.GetSizeBytes()
	case nodev1.FileAuditKind_FILE_AUDIT_KIND_WORKSPACE_METADATA:
		return (method == relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_WORKSPACES || method == relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_WORKSPACE || method == relayv1.RoutedMethod_ROUTED_METHOD_REGISTER_NODE_WORKSPACE || method == relayv1.RoutedMethod_ROUTED_METHOD_UNREGISTER_NODE_WORKSPACE) && o.ItemCount != nil && o.GetItemCount() <= 500 && o.GetSizeBytes() <= 131072 && o.GetDigestInputBytes() == o.GetSizeBytes()
	case nodev1.FileAuditKind_FILE_AUDIT_KIND_OPERATION_METADATA:
		return (method == relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_FILE_OPERATION || method == relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL || method == relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL) && o.GetSizeBytes() <= 131072 && o.GetDigestInputBytes() == o.GetSizeBytes()
	default:
		return false
	}
}

func observation(a *nodev1.FileAuditMetadata, kind nodev1.FileAuditKind) *nodev1.FileAuditObservation {
	for _, o := range a.GetObservations() {
		if o.GetKind() == kind {
			return o
		}
	}
	return nil
}
func observationEqual(o *nodev1.FileAuditObservation, count uint32, size uint64, transcript []byte, digest []byte) bool {
	if o == nil || o.ItemCount == nil || o.GetItemCount() != count || o.GetSizeBytes() != size || o.GetDigestInputBytes() != uint64(len(transcript)) || !bytes.Equal(o.GetSha256(), digest) {
		return false
	}
	sum := sha256.Sum256(transcript)
	return bytes.Equal(sum[:], digest)
}

func validWorkspaceTranscript(a *nodev1.FileAuditMetadata, records []*nodev1.Workspace) bool {
	var transcript bytes.Buffer
	transcript.WriteString("ArcForges workspace-metadata v1\x00")
	for _, w := range records {
		if !validWorkspace(w) {
			return false
		}
		transcript.Write(w.WorkspaceId.Value)
		appendText(&transcript, w.GetRootPath())
		appendU32(&transcript, uint32(w.GetKind()))
		appendU32(&transcript, uint32(w.GetState()))
		appendText(&transcript, w.GetName())
	}
	o := observation(a, nodev1.FileAuditKind_FILE_AUDIT_KIND_WORKSPACE_METADATA)
	return o != nil && observationEqual(o, uint32(len(records)), uint64(transcript.Len()), transcript.Bytes(), o.GetSha256())
}

func validRemovalResult(r *nodev1.FileRemovalResult) bool {
	if r == nil || r.Quarantined == nil || r.ItemsRemoved == nil || r.GetItemsRemoved() < 1 || r.GetItemsRemoved() > 1001 || r.TotalBytes == nil || r.GetTotalBytes() > 67108864 {
		return false
	}
	if _, ok := parseID(r.PlanId); !ok {
		return false
	}
	if r.GetQuarantined() {
		if _, ok := parseID(r.QuarantineId); !ok || !validFileInstant(r.PurgeAfter) {
			return false
		}
	} else if r.QuarantineId != nil || r.PurgeAfter != nil {
		return false
	}
	return true
}

func validMutation(r *nodev1.FileMutationResult, command *foundationv1.Id, edit bool) bool {
	if r == nil || !sameID(r.CommandId, command) || r.SizeBytes == nil || r.GetSizeBytes() > 4194304 || len(r.Sha256) != 32 {
		return false
	}
	if edit {
		return r.Replacements != nil && r.GetReplacements() >= 1 && r.GetReplacements() <= 1000
	}
	return r.Replacements == nil
}

// These canonical producer names retain their own meanings even where two
// bounds have the same maximum. Other 450.1-valid names remain open strings.
var fileResourceMaximums = map[string]string{
	"path_bytes":                "4096",
	"workspace_root_path_bytes": "4096",
	"file_write_bytes":          "196608",
	"file_edit_text_bytes":      "65536",
	"file_existing_bytes":       "4194304",
	"file_edit_result_bytes":    "4194304",
	"removal_descendants":       "1000",
	"removal_total_bytes":       "67108864",
}

// possibleFileResourceBound checks only what this method and the original
// request make observable. A nil request means the original bytes were not
// retained, as for a caller-bound operation status; it never means empty input.
func possibleFileResourceBound(method relayv1.RoutedMethod, request proto.Message, knownTarget *nodev1.FilePath, name string) bool {
	switch name {
	case "path_bytes":
		// A status may retain the caller-bound original workspace target even
		// though its request body is gone. That path is a known fact, not the
		// status request's own size. Authorization checks the binding later.
		if request == nil && knownTarget != nil {
			switch method {
			case relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE:
				return len(knownTarget.GetPath()) > 4096
			}
		}
		switch method {
		case relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE:
			if request == nil {
				return true
			}
			q, ok := request.(*nodev1.FileServiceReadFileRequest)
			return ok && len(q.GetPath().GetPath()) > 4096
		case relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE:
			if request == nil {
				return true
			}
			q, ok := request.(*nodev1.FileServiceWriteFileRequest)
			return ok && len(q.GetPath().GetPath()) > 4096
		case relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE:
			if request == nil {
				return true
			}
			q, ok := request.(*nodev1.FileServiceEditFileRequest)
			return ok && len(q.GetPath().GetPath()) > 4096
		case relayv1.RoutedMethod_ROUTED_METHOD_SEARCH_NODE_FILES:
			if request == nil {
				return true
			}
			q, ok := request.(*nodev1.FileServiceSearchFilesRequest)
			return ok && len(q.GetPath().GetPath()) > 4096
		case relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_DIRECTORY:
			if request == nil {
				return true
			}
			q, ok := request.(*nodev1.FileServiceListDirectoryRequest)
			return ok && len(q.GetPath().GetPath()) > 4096
		case relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL:
			if request == nil {
				return true
			}
			q, ok := request.(*nodev1.FileServicePlanRemovalRequest)
			return ok && len(q.GetWorkspacePath().GetPath()) > 4096
		}
	case "workspace_root_path_bytes":
		if method != relayv1.RoutedMethod_ROUTED_METHOD_REGISTER_NODE_WORKSPACE {
			return false
		}
		if request == nil {
			return true
		}
		q, ok := request.(*nodev1.WorkspaceServiceRegisterWorkspaceRequest)
		return ok && len(q.GetPath()) > 4096
	case "file_write_bytes":
		if method != relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE {
			return false
		}
		if request == nil {
			return true
		}
		q, ok := request.(*nodev1.FileServiceWriteFileRequest)
		return ok && len(q.GetData()) > 196608
	case "file_edit_text_bytes":
		if method != relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE {
			return false
		}
		if request == nil {
			return true
		}
		q, ok := request.(*nodev1.FileServiceEditFileRequest)
		return ok && (len(q.GetOldText()) > 65536 || len(q.GetNewText()) > 65536)
	case "file_existing_bytes":
		switch method {
		case relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE:
			if request == nil {
				return true
			}
			_, ok := request.(*nodev1.FileServiceWriteFileRequest)
			return ok
		case relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE:
			if request == nil {
				return true
			}
			_, ok := request.(*nodev1.FileServiceEditFileRequest)
			return ok
		}
	case "file_edit_result_bytes":
		if method != relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE {
			return false
		}
		if request == nil {
			return true
		}
		q, ok := request.(*nodev1.FileServiceEditFileRequest)
		// Exact non-growing replacement cannot exceed the bounded original.
		return ok && q.OldText != nil && q.NewText != nil && len(q.GetNewText()) > len(q.GetOldText())
	case "removal_descendants", "removal_total_bytes":
		switch method {
		case relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL:
			if request == nil {
				return true
			}
			_, ok := request.(*nodev1.FileServicePlanRemovalRequest)
			return ok
		case relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL:
			if request == nil {
				return true
			}
			_, ok := request.(*nodev1.FileServiceExecuteRemovalRequest)
			return ok
		}
	}
	return false
}

// validFileResourceLimit preserves the open published name vocabulary. A
// canonical name is never reinterpreted. For another valid name, retain every
// method/value candidate until actual known request facts rule it out; this
// does not assert what the node observed or what the label itself means.
func validFileResourceLimit(method relayv1.RoutedMethod, request proto.Message, knownTarget *nodev1.FilePath, limit *foundationv1.LimitFailure) bool {
	if limit == nil || limit.LimitName == nil || !contractToken.MatchString(limit.GetLimitName()) ||
		!validDecimal(limit.Maximum) {
		return false
	}
	name, maximum := limit.GetLimitName(), limit.Maximum.GetValue()
	if expected, canonical := fileResourceMaximums[name]; canonical {
		return maximum == expected && possibleFileResourceBound(method, request, knownTarget, name)
	}
	for candidate, expected := range fileResourceMaximums {
		if maximum == expected && possibleFileResourceBound(method, request, knownTarget, candidate) {
			return true
		}
	}
	return false
}

// validateFileResult binds a signed handler response to its original request.
// It does not claim that the center itself opened the filesystem object.
func validateFileResult(method relayv1.RoutedMethod, request []byte, response nodeFileResponse) error {
	bad := func() error { return errors.New("invalid node file response or request binding") }
	v := newFileRequest(method)
	if v == nil || len(request) == 0 || proto.Unmarshal(request, v) != nil {
		return bad()
	}
	if !validFileResponseMeta(response.GetMeta()) {
		return bad()
	}
	if failure := response.GetError(); failure != nil {
		if !validFileError(failure) || !validFileErrorForMethod(method, failure) {
			return bad()
		}
		if failure.GetCategory() == foundationv1.ErrorCategory_ERROR_CATEGORY_RESOURCE &&
			failure.GetCode() == "too_large" && !validFileResourceLimit(method, v, nil, failure.GetDetails().GetLimit()) {
			return bad()
		}
		if method == relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE && failure.GetCode() == "file_changed" {
			q := v.(*nodev1.FileServiceWriteFileRequest)
			switch failure.GetDetails().GetState().GetReason() {
			case "hash_mismatch":
				if _, ok := q.Precondition.(*nodev1.FileServiceWriteFileRequest_ExpectedSha256); !ok {
					return bad()
				}
			case "expected_absent_conflict":
				p, ok := q.Precondition.(*nodev1.FileServiceWriteFileRequest_ExpectedAbsent)
				if !ok || !p.ExpectedAbsent {
					return bad()
				}
			}
		}
		if method == relayv1.RoutedMethod_ROUTED_METHOD_SEARCH_NODE_FILES && failure.GetCode() == "invalid_argument" &&
			failure.GetDetails().GetState().GetReason() == "pattern: regex_scalar_boundary" {
			q := v.(*nodev1.FileServiceSearchFilesRequest)
			o := observation(response.GetAudit(), nodev1.FileAuditKind_FILE_AUDIT_KIND_SEARCH_TRANSCRIPT)
			if q.GetMode() != nodev1.FileSearchMode_FILE_SEARCH_MODE_REGEX || o == nil || o.GetSizeBytes() == 0 {
				return bad()
			}
		}
		return nil
	}
	audit := response.GetAudit()
	switch r := response.(type) {
	case *nodev1.FileServiceReadFileResponse:
		q := v.(*nodev1.FileServiceReadFileRequest)
		x := r.GetValue()
		if x == nil || q.Offset == nil || q.Length == nil || x.GetOffset() != q.GetOffset() || uint64(len(x.GetData())) > min(q.GetLength(), uint64(65536)) ||
			(x.GetOffset() >= x.GetFileSize() && (len(x.GetData()) != 0 || !x.GetEof())) ||
			(x.GetOffset() < x.GetFileSize() && (len(x.GetData()) == 0 || x.GetNextOffset() > x.GetFileSize() || x.GetEof() != (x.GetNextOffset() == x.GetFileSize()))) {
			return bad()
		}
	case *nodev1.FileServiceWriteFileResponse:
		q := v.(*nodev1.FileServiceWriteFileRequest)
		x := r.GetValue().GetResult()
		if !validMutation(x, q.GetMeta().GetCommandId(), false) || x.GetSizeBytes() != uint64(len(q.GetData())) {
			return bad()
		}
		sum := sha256.Sum256(q.GetData())
		if !bytes.Equal(sum[:], x.GetSha256()) {
			return bad()
		}
	case *nodev1.FileServiceEditFileResponse:
		q := v.(*nodev1.FileServiceEditFileRequest)
		x := r.GetValue().GetResult()
		if !validMutation(x, q.GetMeta().GetCommandId(), true) || x.GetReplacements() != q.GetExpectedOccurrences() {
			return bad()
		}
	case *nodev1.FileServiceSearchFilesResponse:
		q := v.(*nodev1.FileServiceSearchFilesRequest)
		x := r.GetValue()
		if x == nil || proto.Size(r) > 131072 || x.VisitedEntries == nil || x.ScannedBytes == nil || x.SkippedFiles == nil || x.Truncated == nil ||
			x.ScanTranscriptBytes == nil || x.ScanFileCount == nil || len(x.ScanDigest) != 32 || len(x.Matches) > 100 || len(x.Problems) > 10000 ||
			x.GetVisitedEntries() > 10000 || x.GetScannedBytes() > 8388608 || x.GetScanFileCount() > x.GetVisitedEntries() ||
			(q.MaxMatches != nil && uint32(len(x.Matches)) > q.GetMaxMatches()) || (q.MaxScanBytes != nil && x.GetScannedBytes() > q.GetMaxScanBytes()) ||
			(x.GetTruncated() && (x.TruncationReason == nil || !safeErrorToken.MatchString(x.GetTruncationReason()))) || (!x.GetTruncated() && x.TruncationReason != nil) {
			return bad()
		}
		// A reported file is scanned from its beginning. Across distinct paths,
		// each largest match end is a necessary lower bound on bytes actually read.
		// The center cannot verify content or UTF-8 boundaries it did not read.
		ends := make(map[string]uint64)
		var required uint64
		for _, match := range x.Matches {
			if match == nil || match.Path == nil || len(match.GetPath()) > 4096 || !utf8.ValidString(match.GetPath()) || strings.ContainsRune(match.GetPath(), 0) || match.ByteOffset == nil || match.ByteLength == nil {
				return bad()
			}
			start, length := match.GetByteOffset(), uint64(match.GetByteLength())
			if start > x.GetScannedBytes() || length > x.GetScannedBytes()-start ||
				start > 1048576 || length > 1048576-start ||
				(q.GetMode() == nodev1.FileSearchMode_FILE_SEARCH_MODE_LITERAL && length != uint64(len(q.GetPattern()))) {
				return bad()
			}
			end := start + length // the preceding subtraction checks prevent overflow
			if end > ends[match.GetPath()] {
				increase := end - ends[match.GetPath()]
				if increase > x.GetScannedBytes()-required {
					return bad()
				}
				required += increase
				ends[match.GetPath()] = end
			}
		}
		if uint32(len(ends)) > x.GetScanFileCount() {
			return bad()
		}
		for _, problem := range x.Problems {
			if problem == nil || problem.Path == nil || len(problem.GetPath()) > 4096 || problem.Reason == nil || !safeErrorToken.MatchString(problem.GetReason()) {
				return bad()
			}
		}
		o := observation(audit, nodev1.FileAuditKind_FILE_AUDIT_KIND_SEARCH_TRANSCRIPT)
		if o == nil || o.ItemCount == nil || o.GetItemCount() != x.GetScanFileCount() || o.GetSizeBytes() != x.GetScannedBytes() || o.GetDigestInputBytes() != x.GetScanTranscriptBytes() || !bytes.Equal(o.GetSha256(), x.GetScanDigest()) ||
			(x.GetScanFileCount() == 0) != (x.GetScannedBytes() == 0) || x.GetScanTranscriptBytes() < uint64(len("ArcForges search-scan v1\x00")) {
			return bad()
		}
		if x.GetScannedBytes() == 0 {
			sum := sha256.Sum256([]byte("ArcForges search-scan v1\x00"))
			if x.GetScanTranscriptBytes() != uint64(len("ArcForges search-scan v1\x00")) || !bytes.Equal(sum[:], x.GetScanDigest()) {
				return bad()
			}
		}
	case *nodev1.FileServiceListDirectoryResponse:
		q := v.(*nodev1.FileServiceListDirectoryRequest)
		x := r.GetValue()
		if x == nil || proto.Size(r) > 131072 || x.Truncated == nil || x.SnapshotEntries == nil || x.GetSnapshotEntries() > 10000 || uint32(len(x.Entries)) > x.GetSnapshotEntries() || len(x.Entries) > 128 || len(x.GetNextCursor()) > 2048 || len(x.MetadataDigest) != 32 || x.MetadataBytes == nil || (q.PageSize != nil && uint32(len(x.Entries)) > q.GetPageSize()) {
			return bad()
		}
		for _, problem := range x.Problems {
			if problem == nil || problem.Path == nil || len(problem.GetPath()) > 4096 || !utf8.ValidString(problem.GetPath()) || strings.ContainsRune(problem.GetPath(), 0) || problem.Reason == nil || !safeErrorToken.MatchString(problem.GetReason()) {
				return bad()
			}
		}
		var transcript bytes.Buffer
		transcript.WriteString("ArcForges directory-list v1\x00")
		for _, e := range x.Entries {
			if e == nil || e.Name == nil || len(e.GetName()) < 1 || len(e.GetName()) > 4096 || !utf8.ValidString(e.GetName()) || strings.ContainsAny(e.GetName(), "/\\\x00") || e.Kind == nil || e.GetKind() < 1 || e.GetKind() > 4 {
				return bad()
			}
			appendText(&transcript, e.GetName())
			appendU32(&transcript, uint32(e.GetKind()))
			if e.SizeBytes == nil {
				transcript.WriteByte(0)
			} else {
				transcript.WriteByte(1)
				appendU64(&transcript, e.GetSizeBytes())
			}
		}
		if x.GetMetadataBytes() != uint64(transcript.Len()) || !observationEqual(observation(audit, nodev1.FileAuditKind_FILE_AUDIT_KIND_DIRECTORY_METADATA), uint32(len(x.Entries)), uint64(transcript.Len()), transcript.Bytes(), x.GetMetadataDigest()) {
			return bad()
		}
	case *nodev1.FileServicePlanRemovalResponse:
		q := v.(*nodev1.FileServicePlanRemovalRequest)
		p := r.GetValue().GetPlan()
		if p == nil || len(p.Digest) != 32 || !validFileInstant(p.ExpiresAt) || p.TotalBytes == nil || p.GetTotalBytes() > 67108864 || p.RequiresApproval == nil || p.QuarantineAvailable == nil || p.Risk == nil || p.GetRisk() < 1 || p.GetRisk() > 3 || len(p.Items) < 1 || len(p.Items) > 1001 {
			return bad()
		}
		if _, ok := parseID(p.PlanId); !ok {
			return bad()
		}
		switch target := q.Target.(type) {
		case *nodev1.FileServicePlanRemovalRequest_WorkspacePath:
			if !validFilePath(p.GetWorkspacePath(), false) || !proto.Equal(target.WorkspacePath, p.GetWorkspacePath()) {
				return bad()
			}
		case *nodev1.FileServicePlanRemovalRequest_AttemptId:
			if !sameID(target.AttemptId, p.GetAttemptId()) {
				return bad()
			}
		default:
			return bad()
		}
		seenPaths := make(map[string]bool, len(p.Items))
		for _, item := range p.Items {
			if item == nil || item.Path == nil || len(item.GetPath()) > 4096 || !utf8.ValidString(item.GetPath()) || strings.ContainsRune(item.GetPath(), 0) || seenPaths[item.GetPath()] || item.Kind == nil || item.GetKind() < 1 || item.GetKind() > 4 || item.SizeBytes == nil || len(item.IdentitySha256) != 32 || item.OwnerVerified == nil || (item.Sha256 != nil && len(item.Sha256) != 32) {
				return bad()
			}
			seenPaths[item.GetPath()] = true
		}
	case *nodev1.FileServiceExecuteRemovalResponse:
		q := v.(*nodev1.FileServiceExecuteRemovalRequest)
		x := r.GetValue().GetResult()
		if !validRemovalResult(x) || !sameID(x.PlanId, q.PlanId) || (!x.GetQuarantined() && !q.GetDeleteWithoutQuarantine()) {
			return bad()
		}
	case *nodev1.FileServiceGetFileOperationResponse:
		q := v.(*nodev1.FileServiceGetFileOperationRequest)
		x := r.GetValue().GetOperation()
		if x == nil || !sameID(x.CommandId, q.OperationCommandId) || x.Kind == nil || x.GetKind() < 1 || x.GetKind() > 3 || x.State == nil || x.GetState() < 1 || x.GetState() > 3 || len(x.RequestSha256) != 32 || !validFileInstant(x.CreatedAt) || !validFileInstant(x.UpdatedAt) || x.Acknowledged == nil || x.Held == nil {
			return bad()
		}
		if x.GetUpdatedAt().GetUnixSeconds() < x.GetCreatedAt().GetUnixSeconds() || x.GetUpdatedAt().GetUnixSeconds() == x.GetCreatedAt().GetUnixSeconds() && x.GetUpdatedAt().GetNanos() < x.GetCreatedAt().GetNanos() {
			return bad()
		}
		switch target := x.Target.(type) {
		case *nodev1.FileOperation_WorkspacePath:
			if !validFilePath(target.WorkspacePath, false) {
				return bad()
			}
		case *nodev1.FileOperation_AttemptId:
			if _, ok := parseID(target.AttemptId); !ok {
				return bad()
			}
		default:
			return bad()
		}
		switch x.GetState() {
		case nodev1.FileOperationState_FILE_OPERATION_STATE_PREPARED:
			if x.Outcome != nil || x.GetAcknowledged() {
				return bad()
			}
		case nodev1.FileOperationState_FILE_OPERATION_STATE_UNKNOWN:
			if !validUnknownFileOperationError(x.GetError()) || x.GetHeld() == x.GetAcknowledged() {
				return bad()
			}
		case nodev1.FileOperationState_FILE_OPERATION_STATE_COMPLETED:
			if x.GetHeld() || x.GetAcknowledged() {
				return bad()
			}
			if x.GetError() != nil {
				failure, original := x.GetError(), operationMethod(x.GetKind())
				if !validFileError(failure) || !validFileErrorForMethod(original, failure) || failure.GetEffect() == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN {
					return bad()
				}
				if failure.GetCategory() == foundationv1.ErrorCategory_ERROR_CATEGORY_RESOURCE &&
					failure.GetCode() == "too_large" && !validFileResourceLimit(original, nil, x.GetWorkspacePath(), failure.GetDetails().GetLimit()) {
					return bad()
				}
			} else if x.GetKind() == nodev1.FileOperationKind_FILE_OPERATION_KIND_REMOVAL {
				if !validRemovalResult(x.GetRemoval()) {
					return bad()
				}
			} else if !validMutation(x.GetMutation(), x.CommandId, x.GetKind() == nodev1.FileOperationKind_FILE_OPERATION_KIND_EDIT) {
				return bad()
			}
		}
	case *nodev1.WorkspaceServiceRegisterWorkspaceResponse:
		x := r.GetValue().GetWorkspace()
		if !validWorkspace(x) || x.GetKind() != nodev1.WorkspaceKind_WORKSPACE_KIND_REGISTERED || (observation(audit, nodev1.FileAuditKind_FILE_AUDIT_KIND_WORKSPACE_METADATA) != nil && !validWorkspaceTranscript(audit, []*nodev1.Workspace{x})) {
			return bad()
		}
	case *nodev1.WorkspaceServiceUnregisterWorkspaceResponse:
		q := v.(*nodev1.WorkspaceServiceUnregisterWorkspaceRequest)
		receipt := r.GetValue().GetReceipt()
		if receipt == nil || !sameID(receipt.CommandId, q.GetMeta().GetCommandId()) || receipt.Effect == nil || receipt.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED || receipt.ResultRevision != nil && !validRevision(receipt.ResultRevision) {
			return bad()
		}
	case *nodev1.WorkspaceServiceListWorkspacesResponse:
		q := v.(*nodev1.WorkspaceServiceListWorkspacesRequest)
		x := r.GetValue()
		if x == nil || proto.Size(r) > 131072 || x.Page == nil || x.Page.HasMore == nil || len(x.Page.GetNextCursor()) > 2048 || (x.Page.GetHasMore() != (x.Page.GetNextCursor() != "")) || len(x.Workspaces) > 500 || (q.Page != nil && int32(len(x.Workspaces)) > q.Page.GetLimit()) || !validWorkspaceTranscript(audit, x.Workspaces) {
			return bad()
		}
		if len(q.Kinds) > 0 {
			for _, w := range x.Workspaces {
				found := false
				for _, kind := range q.Kinds {
					if w.GetKind() == kind {
						found = true
						break
					}
				}
				if !found {
					return bad()
				}
			}
		}
	case *nodev1.WorkspaceServiceGetWorkspaceResponse:
		q := v.(*nodev1.WorkspaceServiceGetWorkspaceRequest)
		x := r.GetValue().GetWorkspace()
		if !validWorkspace(x) || !sameID(x.WorkspaceId, q.WorkspaceId) || !validWorkspaceTranscript(audit, []*nodev1.Workspace{x}) {
			return bad()
		}
	default:
		return bad()
	}
	return nil
}
