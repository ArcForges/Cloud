// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"regexp"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"
)

// The shape rules of the routed-call messages (Contracts relay.proto, "Verifier pre-conditions" and the validate comments of
// CallHeader, ResultHeader, RelayAssertion and the rule routedRefusal; C2 review N-11). Go has no generated validators, so these are a
// hand-written mirror of the C# validators of ArcForges.Contracts.Relay (ProtoValidation.g.cs at Contracts e67a6b0), each checked
// against the C2 validator vectors in shape_test.go. They run before anything is built from a message: every ID present where the
// layout names it, exactly 16 bytes and not all zero; every digest and nonce exactly 32 bytes, every signature 64; the enums in their
// ranges; nanos 0..999,999,999; the windows (a call at most 300 s, an assertion at most 120 s). Nothing is padded, truncated or
// re-encoded to fit.

// The windows of the contract: a call expires at most 300 s after it is issued, a relay assertion at most 120 s (AD-0021 section 10).
const (
	CallWindowSeconds      = 300
	AssertionWindowSeconds = 120
)

// The byte bounds of the contract.
const (
	// MaxCallPayload is the largest ChannelCall payload and CallHeader.request_size (253,952 bytes).
	MaxCallPayload = 253_952
	// MaxResultPayload is the largest ChannelResult payload and ResultHeader.response_size (1,040,384 bytes).
	MaxResultPayload = 1_040_384
	// MaxSignedHeader is the largest SignedHeader.header (2,048 bytes).
	MaxSignedHeader = 2048
	// MaxRefusalBytes bounds a routed refusal (ResultHeader.error) in all (512 bytes).
	MaxRefusalBytes = 512
	// SignatureBytes is an ES256 signature in P1363 form, r||s.
	SignatureBytes = 64
	// DigestBytes is a SHA-256 digest; RelayNonceBytes a relay nonce.
	DigestBytes     = 32
	RelayNonceBytes = 32
)

// The routed methods (relay.proto RoutedMethod): 1..6 are the routed task methods a call names; 7 and 8 only a relay assertion.
const (
	MethodSubmitNodeTask       = relayv1.RoutedMethod_ROUTED_METHOD_SUBMIT_NODE_TASK
	MethodGetNodeTask          = relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_TASK
	MethodListNodeTasks        = relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_TASKS
	MethodWaitNodeTask         = relayv1.RoutedMethod_ROUTED_METHOD_WAIT_NODE_TASK
	MethodReadNodeTaskOutput   = relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_TASK_OUTPUT
	MethodCancelNodeTask       = relayv1.RoutedMethod_ROUTED_METHOD_CANCEL_NODE_TASK
	MethodListNodes            = relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODES
	MethodGetNode              = relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE
	maxCallMethod              = MethodCancelNodeTask
	maxAssertionMethod         = MethodGetNode
	approvalReconcileOperation = "arcforges.node.v1.ApprovalService/GetApproval"
)

// Mutation reports a routed method that names a command (SubmitNodeTask, CancelNodeTask): the only ones whose call carries a
// command_id, and whose delivered call has an unknown effect once its result is lost.
func Mutation(method relayv1.RoutedMethod) bool {
	return method == MethodSubmitNodeTask || method == MethodCancelNodeTask
}

var (
	kidPattern        = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	refusalCode       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	refusalToken      = regexp.MustCompile(`^[a-z0-9_.]{1,64}$`)
	contractToken     = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)
	refusalCategories = []string{"", "validation", "authentication", "authorization", "entitlement", "conflict", "state", "resource", "execution", "internal"}
)

// validID is a foundation Id: present, exactly 16 bytes, not all zero.
func validID(value *foundationv1.Id) bool {
	if value == nil || len(value.Value) != 16 {
		return false
	}
	for _, b := range value.Value {
		if b != 0 {
			return true
		}
	}
	return false
}

// validInstant is a foundation Instant: both members present, the seconds within years 1..9999, nanos 0..999,999,999.
func validInstant(value *foundationv1.Instant) bool {
	return value != nil && value.UnixSeconds != nil && value.Nanos != nil && *value.UnixSeconds >= -62135596800 && *value.UnixSeconds <= 253402300799 &&
		*value.Nanos <= 999_999_999
}

// before reports a < b for valid instants (nanos are normalized, so the pair orders them).
func before(a, b *foundationv1.Instant) bool {
	return a.GetUnixSeconds() < b.GetUnixSeconds() || (a.GetUnixSeconds() == b.GetUnixSeconds() && a.GetNanos() < b.GetNanos())
}

// window reports issued < expires <= issued + seconds (to the nanosecond).
func window(issued, expires *foundationv1.Instant, seconds int64) bool {
	limit := &foundationv1.Instant{UnixSeconds: proto.Int64(issued.GetUnixSeconds() + seconds), Nanos: proto.Uint32(issued.GetNanos())}
	return before(issued, expires) && !before(limit, expires)
}

// validCenterCaller is CenterCaller's rule: an ACCOUNT_SESSION names its user and session and nothing of a relay; a NODE_RELAY names
// its relaying node, local origin (HUMAN, SCRIPT or AGENT) and local session and nothing of a session; AGENT_GRANT is reserved.
func validCenterCaller(value *nodev1.CenterCaller) bool {
	if value == nil || value.Kind == nil || !validID(value.AccountId) {
		return false
	}
	optionalID := func(id *foundationv1.Id) bool { return id == nil || validID(id) }
	if !optionalID(value.UserId) || !optionalID(value.SessionId) || !optionalID(value.RelayingNodeId) || !optionalID(value.LocalSessionId) {
		return false
	}
	if value.LocalOrigin != nil && (*value.LocalOrigin < 1 || *value.LocalOrigin > 3) {
		return false
	}
	switch *value.Kind {
	case nodev1.CenterCallerKind_CENTER_CALLER_KIND_ACCOUNT_SESSION:
		return value.UserId != nil && value.SessionId != nil && value.RelayingNodeId == nil && value.LocalOrigin == nil && value.LocalSessionId == nil
	case nodev1.CenterCallerKind_CENTER_CALLER_KIND_NODE_RELAY:
		return value.UserId == nil && value.SessionId == nil && value.RelayingNodeId != nil && value.LocalOrigin != nil && value.LocalSessionId != nil
	}
	return false
}

// validCallHeader is CallHeader's rule (CTR5-SIG-01, PN-9).
func validCallHeader(value *relayv1.CallHeader) bool {
	if value == nil || !validID(value.CallId) || value.Kid == nil || !kidPattern.MatchString(*value.Kid) || len(value.CenterUrlSha256) != DigestBytes ||
		value.CenterUrlSha256 == nil || !validID(value.AccountId) || !validID(value.TargetNodeId) || !validCenterCaller(value.Caller) {
		return false
	}
	if value.CommandId != nil && !validID(value.CommandId) {
		return false
	}
	if value.Method == nil || *value.Method < MethodSubmitNodeTask || *value.Method > maxCallMethod || len(value.RequestSha256) != DigestBytes ||
		value.RequestSize == nil || *value.RequestSize < 1 || *value.RequestSize > MaxCallPayload {
		return false
	}
	if !validInstant(value.IssuedAt) || !validInstant(value.ExpiresAt) || !validInstant(value.Deadline) {
		return false
	}
	if value.RelayAssertionSha256 != nil && len(value.RelayAssertionSha256) != DigestBytes {
		return false
	}
	if (value.CommandId != nil) != Mutation(*value.Method) || !proto.Equal(value.Caller.AccountId, value.AccountId) {
		return false
	}
	if (value.RelayAssertionSha256 != nil) != (value.Caller.GetKind() == nodev1.CenterCallerKind_CENTER_CALLER_KIND_NODE_RELAY) {
		return false
	}
	return window(value.IssuedAt, value.ExpiresAt, CallWindowSeconds) && before(value.IssuedAt, value.Deadline) && !before(value.ExpiresAt, value.Deadline)
}

// validSignedHeader is SignedHeader's rule; withKid is ChannelCall's (a kid required) or ChannelResult's (no kid) relation.
func validSignedHeader(value *relayv1.SignedHeader, withKid bool) bool {
	if value == nil || value.Header == nil || len(value.Header) < 1 || len(value.Header) > MaxSignedHeader || len(value.Signature) != SignatureBytes ||
		value.Algorithm == nil || *value.Algorithm != "ES256" {
		return false
	}
	if value.Kid != nil && !kidPattern.MatchString(*value.Kid) {
		return false
	}
	return (value.Kid != nil) == withKid
}

// validChannelCall is ChannelCall's rule.
func validChannelCall(value *relayv1.ChannelCall) bool {
	return value != nil && validID(value.CallId) && validSignedHeader(value.Header, true) && value.Payload != nil && len(value.Payload) >= 1 &&
		len(value.Payload) <= MaxCallPayload
}

// validChannelResult is ChannelResult's rule.
func validChannelResult(value *relayv1.ChannelResult) bool {
	return value != nil && validID(value.CallId) && validSignedHeader(value.Header, false) && len(value.Payload) <= MaxResultPayload
}

// validResultHeader is ResultHeader's rule, the rule routedRefusal of its error included.
func validResultHeader(value *relayv1.ResultHeader) bool {
	if value == nil || !validID(value.CallId) || !validID(value.NodeId) || !validInstant(value.ExecutedAt) || value.Outcome == nil ||
		*value.Outcome < relayv1.RoutedOutcome_ROUTED_OUTCOME_EXECUTED || *value.Outcome > relayv1.RoutedOutcome_ROUTED_OUTCOME_EXPIRED {
		return false
	}
	if value.CommandId != nil && !validID(value.CommandId) {
		return false
	}
	if value.Method != nil && (*value.Method < MethodSubmitNodeTask || *value.Method > maxCallMethod) {
		return false
	}
	if (value.RequestSha256 != nil && len(value.RequestSha256) != DigestBytes) || (value.ResponseSha256 != nil && len(value.ResponseSha256) != DigestBytes) {
		return false
	}
	if value.ResponseSize != nil && (*value.ResponseSize < 1 || *value.ResponseSize > MaxResultPayload) {
		return false
	}
	verified := *value.Outcome != relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_VERIFICATION
	if (value.Method != nil) != verified || (value.RequestSha256 != nil) != verified || (!verified && value.CommandId != nil) {
		return false
	}
	executed := *value.Outcome == relayv1.RoutedOutcome_ROUTED_OUTCOME_EXECUTED
	if (value.ResponseSha256 != nil) != executed || (value.ResponseSize != nil) != executed || (value.Error == nil) != executed {
		return false
	}
	return value.Error == nil || (validArcError(value.Error) && routedRefusal(value.Error))
}

// validArcError is ArcError's rule as the contract requires it of every refusal (foundation-baseline.json), for the snake_case codes
// of the catalogue: a code, a category 1..9, a message key, a retry advice (a mode 1..4, retry_at exactly with AFTER_TIME, a
// reconciliation operation exactly with RECONCILE), an effect 1..3 (never UNKNOWN with AFTER_TIME), a correlation ID and, when
// present, one detail.
func validArcError(value *foundationv1.ArcError) bool {
	if value == nil || value.Code == nil || value.Category == nil || *value.Category < 1 || *value.Category > 9 || value.MessageKey == nil ||
		!contractToken.MatchString(*value.MessageKey) || value.Retry == nil || value.Effect == nil || *value.Effect < 1 || *value.Effect > 3 ||
		!validID(value.CorrelationId) {
		return false
	}
	retry := value.Retry
	if retry.Mode == nil || *retry.Mode < 1 || *retry.Mode > 4 || (retry.RetryAt != nil && !validInstant(retry.RetryAt)) {
		return false
	}
	if retry.ReconciliationOperation != nil && !contractToken.MatchString(*retry.ReconciliationOperation) {
		return false
	}
	if (*retry.Mode == foundationv1.RetryMode_RETRY_MODE_AFTER_TIME) != (retry.RetryAt != nil) ||
		(*retry.Mode == foundationv1.RetryMode_RETRY_MODE_RECONCILE) != (retry.ReconciliationOperation != nil) {
		return false
	}
	if *value.Effect == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN && *retry.Mode == foundationv1.RetryMode_RETRY_MODE_AFTER_TIME {
		return false
	}
	if value.Details != nil {
		state, ok := value.Details.Detail.(*foundationv1.ErrorDetails_State)
		if value.Details.Detail == nil {
			return false
		}
		if ok && (state.State == nil || state.State.State == nil || !contractToken.MatchString(*state.State.State) || state.State.Reason == nil) {
			return false
		}
		if ok && state.State.Resource != nil && (state.State.Resource.Kind == nil || !contractToken.MatchString(*state.State.Resource.Kind) ||
			!validID(state.State.Resource.Id)) {
			return false
		}
	}
	return true
}

// routedRefusal is the rule routedRefusal of ResultHeader.error (Plan PN-6; review A B-1 and N-9): closed identifier fields only, at
// most 512 bytes in all; the code catalogued under its category (fixtures/public/af-con-01-error-catalogue.json) and the message key
// exactly error.<category>.<code>; a reconciliation operation only the approval's GetApproval; details absent or the state only, with
// state and reason closed tokens, no native revision, and a resource only as the approval of AUTHORIZATION/approval_required.
func routedRefusal(value *foundationv1.ArcError) bool {
	if proto.Size(value) > MaxRefusalBytes || !refusalCode.MatchString(value.GetCode()) {
		return false
	}
	category := int(value.GetCategory())
	if category < 1 || category > 9 || value.GetMessageKey() != "error."+refusalCategories[category]+"."+value.GetCode() {
		return false
	}
	if !catalogued(refusalCategories[category] + "/" + value.GetCode()) {
		return false
	}
	if value.GetRetry().ReconciliationOperation != nil && value.GetRetry().GetReconciliationOperation() != approvalReconcileOperation {
		return false
	}
	if value.Details == nil {
		return true
	}
	state, ok := value.Details.Detail.(*foundationv1.ErrorDetails_State)
	if !ok || state.State == nil {
		return false
	}
	failure := state.State
	if !refusalToken.MatchString(failure.GetState()) || !refusalToken.MatchString(failure.GetReason()) || failure.Native != nil {
		return false
	}
	return failure.Resource == nil || (category == int(foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHORIZATION) && value.GetCode() == "approval_required" &&
		failure.Resource.GetKind() == "approval")
}

// validRelayAssertion is RelayAssertion's rule (D0-B1, C-N1; relay.proto RelayAssertion).
func validRelayAssertion(value *relayv1.RelayAssertion) bool {
	if value == nil || !validID(value.RelayingNodeId) || !validID(value.RelayingInstallationId) || value.LocalOrigin == nil || *value.LocalOrigin < 1 ||
		*value.LocalOrigin > 3 || !validID(value.LocalSessionId) || value.Method == nil || *value.Method < MethodSubmitNodeTask ||
		*value.Method > maxAssertionMethod || len(value.RequestSha256) != DigestBytes {
		return false
	}
	if (value.TargetNodeId != nil && !validID(value.TargetNodeId)) || (value.CommandId != nil && !validID(value.CommandId)) {
		return false
	}
	if len(value.RelayNonce) != RelayNonceBytes || !validInstant(value.IssuedAt) || !validInstant(value.ExpiresAt) || len(value.Signature) != SignatureBytes {
		return false
	}
	if (value.TargetNodeId == nil) != (*value.Method == MethodListNodes) || (value.CommandId != nil) != Mutation(*value.Method) {
		return false
	}
	return window(value.IssuedAt, value.ExpiresAt, AssertionWindowSeconds)
}

// validRelayNonceRequest is RelayNonceRequest's rule: its request ID.
func validRelayNonceRequest(value *relayv1.RelayNonceRequest) bool {
	return value != nil && validID(value.RequestId)
}
