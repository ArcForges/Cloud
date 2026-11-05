// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// The Go mirror of the C# validators (C2 review N-11; EVIDENCE: REAL, the vectors' messages and the cases of Contracts
// tests/StructureTests/NodeChannelCases.cs at e67a6b0, "Validators" and "RoutedRefusals", restated case by case with the same expected
// verdicts). Go has no generated validators, so each rule the center relies on is checked here against the contract's own cases.

func at(from *foundationv1.Instant, seconds int64, nanos uint32) *foundationv1.Instant {
	total := uint64(from.GetNanos()) + uint64(nanos)
	return &foundationv1.Instant{UnixSeconds: proto.Int64(from.GetUnixSeconds() + seconds + int64(total/1_000_000_000)), Nanos: proto.Uint32(uint32(total % 1_000_000_000))}
}

type shapeCase[T proto.Message] struct {
	name   string
	change func(T)
	valid  bool
}

func checkShapes[T proto.Message](t *testing.T, base T, valid func(T) bool, cases []shapeCase[T]) {
	t.Helper()
	if !valid(base) {
		t.Fatalf("the base %T is valid", base)
	}
	for _, c := range cases {
		value := clone(base)
		c.change(value)
		if valid(value) != c.valid {
			t.Errorf("%s: valid=%v, the contract says %v", c.name, !c.valid, c.valid)
		}
	}
}

func TestTheCallHeaderRulesAreTheContracts(t *testing.T) {
	vectors := loadVectors(t)
	var call relayv1.CallHeader
	if err := proto.Unmarshal(vectors.RoutedCall.CallHeader, &call); err != nil {
		t.Fatal(err)
	}
	session := &nodev1.CenterCaller{Kind: nodev1.CenterCallerKind_CENTER_CALLER_KIND_ACCOUNT_SESSION.Enum(), AccountId: call.AccountId, UserId: call.CallId,
		SessionId: call.TargetNodeId}
	checkShapes(t, &call, validCallHeader, []shapeCase[*relayv1.CallHeader]{
		{"call without kid", func(c *relayv1.CallHeader) { c.Kid = nil }, false},
		{"call kid shorter than 8", func(c *relayv1.CallHeader) { c.Kid = proto.String("short") }, false},
		{"center_url_sha256 of 31 bytes", func(c *relayv1.CallHeader) { c.CenterUrlSha256 = make([]byte, 31) }, false},
		{"call without call_id", func(c *relayv1.CallHeader) { c.CallId = nil }, false},
		{"a call_id of 15 bytes", func(c *relayv1.CallHeader) { c.CallId = &foundationv1.Id{Value: make([]byte, 15)} }, false},
		{"a zero call_id", func(c *relayv1.CallHeader) { c.CallId = &foundationv1.Id{Value: make([]byte, 16)} }, false},
		{"call without account", func(c *relayv1.CallHeader) { c.AccountId = nil }, false},
		{"call without target", func(c *relayv1.CallHeader) { c.TargetNodeId = nil }, false},
		{"call without caller", func(c *relayv1.CallHeader) { c.Caller = nil }, false},
		{"a call never names LIST_NODES", func(c *relayv1.CallHeader) { c.Method = MethodListNodes.Enum() }, false},
		{"call without request digest", func(c *relayv1.CallHeader) { c.RequestSha256 = nil }, false},
		{"request_size 0", func(c *relayv1.CallHeader) { c.RequestSize = proto.Uint32(0) }, false},
		{"request_size above 253,952", func(c *relayv1.CallHeader) { c.RequestSize = proto.Uint32(253_953) }, false},
		{"request_size 253,952", func(c *relayv1.CallHeader) { c.RequestSize = proto.Uint32(253_952) }, true},
		{"a submit call without command_id", func(c *relayv1.CallHeader) { c.CommandId = nil }, false},
		{"a read call with command_id", func(c *relayv1.CallHeader) { c.Method = MethodGetNodeTask.Enum() }, false},
		{"a read call without command_id", func(c *relayv1.CallHeader) { c.Method, c.CommandId = MethodGetNodeTask.Enum(), nil }, true},
		{"expires_at = issued_at + 300 s", func(c *relayv1.CallHeader) { c.ExpiresAt = at(c.IssuedAt, 300, 0) }, true},
		{"expires_at one nanosecond past issued_at + 300 s", func(c *relayv1.CallHeader) { c.ExpiresAt = at(c.IssuedAt, 300, 1) }, false},
		{"expires_at = issued_at", func(c *relayv1.CallHeader) { c.ExpiresAt = at(c.IssuedAt, 0, 0) }, false},
		{"a deadline after expires_at", func(c *relayv1.CallHeader) { c.Deadline = at(c.ExpiresAt, 0, 1) }, false},
		{"a deadline at issued_at", func(c *relayv1.CallHeader) { c.Deadline = at(c.IssuedAt, 0, 0) }, false},
		{"nanos of 1e9", func(c *relayv1.CallHeader) {
			c.IssuedAt = &foundationv1.Instant{UnixSeconds: c.IssuedAt.UnixSeconds, Nanos: proto.Uint32(1_000_000_000)}
		}, false},
		{"a NODE_RELAY call without the assertion digest", func(c *relayv1.CallHeader) { c.RelayAssertionSha256 = nil }, false},
		{"an assertion digest of 31 bytes", func(c *relayv1.CallHeader) { c.RelayAssertionSha256 = make([]byte, 31) }, false},
		{"a caller of another account than the header's", func(c *relayv1.CallHeader) { c.Caller.AccountId = c.TargetNodeId }, false},
		{"an account-session call without an assertion digest", func(c *relayv1.CallHeader) { c.Caller, c.RelayAssertionSha256 = clone(session), nil }, true},
		{"an account-session call with an assertion digest", func(c *relayv1.CallHeader) { c.Caller = clone(session) }, false},
	})
	relayed := call.Caller
	for name, change := range map[string]func(*nodev1.CenterCaller){
		"an account session naming a relaying node": func(s *nodev1.CenterCaller) { *s = *clone(session); s.RelayingNodeId = relayed.RelayingNodeId },
		"an account session without user":           func(s *nodev1.CenterCaller) { *s = *clone(session); s.UserId = nil },
		"a node relay without local session":        func(s *nodev1.CenterCaller) { s.LocalSessionId = nil },
		"a node relay without local origin":         func(s *nodev1.CenterCaller) { s.LocalOrigin = nil },
		"a node relay with origin REMOTE":           func(s *nodev1.CenterCaller) { s.LocalOrigin = nodev1.Origin_ORIGIN_REMOTE.Enum() },
		"a node relay naming a center session":      func(s *nodev1.CenterCaller) { s.SessionId = relayed.LocalSessionId },
		"AGENT_GRANT is reserved":                   func(s *nodev1.CenterCaller) { s.Kind = nodev1.CenterCallerKind_CENTER_CALLER_KIND_AGENT_GRANT.Enum() },
		"a caller without account":                  func(s *nodev1.CenterCaller) { s.AccountId = nil },
	} {
		value := clone(relayed)
		change(value)
		if validCenterCaller(value) {
			t.Errorf("%s is valid", name)
		}
	}
	if !validCenterCaller(session) || !validCenterCaller(relayed) {
		t.Error("an account session and a node relay are valid callers")
	}
}

func TestTheResultHeaderAndRoutedRefusalRulesAreTheContracts(t *testing.T) {
	vectors := loadVectors(t)
	var result relayv1.ResultHeader
	if err := proto.Unmarshal(vectors.RoutedResult.ResultHeader, &result); err != nil {
		t.Fatal(err)
	}
	refusal := &foundationv1.ArcError{Code: proto.String("permission_denied"), Category: foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHORIZATION.Enum(),
		MessageKey: proto.String("error.authorization.permission_denied"), Retry: &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_NEVER.Enum()},
		Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN.Enum(), CorrelationId: result.CallId}
	unexecuted := func(r *relayv1.ResultHeader, outcome relayv1.RoutedOutcome) {
		r.Outcome, r.ResponseSha256, r.ResponseSize, r.Error = outcome.Enum(), nil, nil, clone(refusal)
	}
	checkShapes(t, &result, validResultHeader, []shapeCase[*relayv1.ResultHeader]{
		{"an executed result without a response digest", func(r *relayv1.ResultHeader) { r.ResponseSha256 = nil }, false},
		{"an executed result without a response size", func(r *relayv1.ResultHeader) { r.ResponseSize = nil }, false},
		{"an executed result with an error", func(r *relayv1.ResultHeader) { r.Error = clone(refusal) }, false},
		{"a response above 1,040,384 bytes", func(r *relayv1.ResultHeader) { r.ResponseSize = proto.Uint32(1_040_385) }, false},
		{"a result without outcome", func(r *relayv1.ResultHeader) { r.Outcome = nil }, false},
		{"a result without node", func(r *relayv1.ResultHeader) { r.NodeId = nil }, false},
		{"a result without executed_at", func(r *relayv1.ResultHeader) { r.ExecutedAt = nil }, false},
		{"a policy refusal", func(r *relayv1.ResultHeader) { unexecuted(r, relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_BY_POLICY) }, true},
		{"a policy refusal without its error", func(r *relayv1.ResultHeader) {
			unexecuted(r, relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_BY_POLICY)
			r.Error = nil
		}, false},
		{"a verification refusal echoes nothing it could not verify", func(r *relayv1.ResultHeader) {
			unexecuted(r, relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_VERIFICATION)
			r.Method, r.RequestSha256, r.CommandId = nil, nil, nil
		}, true},
		{"a verification refusal echoing the method", func(r *relayv1.ResultHeader) {
			unexecuted(r, relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_VERIFICATION)
		}, false},
		{"an expired result without method", func(r *relayv1.ResultHeader) {
			unexecuted(r, relayv1.RoutedOutcome_ROUTED_OUTCOME_EXPIRED)
			r.Method = nil
		}, false},
		{"a method out of range", func(r *relayv1.ResultHeader) { r.Method = MethodListNodes.Enum() }, false},
		{"a request digest of 33 bytes", func(r *relayv1.ResultHeader) { r.RequestSha256 = make([]byte, 33) }, false},
	})

	// The rule routedRefusal (relay.proto; NodeChannelCases.RoutedRefusals): every case on a REFUSED_BY_POLICY result.
	policy := clone(&result)
	unexecuted(policy, relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_BY_POLICY)
	state := func(s, reason string) *foundationv1.ErrorDetails {
		return &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_State{State: &foundationv1.StateFailure{State: proto.String(s), Reason: proto.String(reason)}}}
	}
	approval := &foundationv1.ArcError{Code: proto.String("approval_required"), Category: foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHORIZATION.Enum(),
		MessageKey: proto.String("error.authorization.approval_required"), Retry: &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_RECONCILE.Enum(),
			ReconciliationOperation: proto.String("arcforges.node.v1.ApprovalService/GetApproval")}, Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN.Enum(),
		CorrelationId: refusal.CorrelationId, Details: &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_State{State: &foundationv1.StateFailure{
			State: proto.String("task.cancel_others"), Reason: proto.String("approval_required"), Resource: &foundationv1.AggregateRef{Kind: proto.String("approval"),
				Id: refusal.CorrelationId}}}}}
	checkShapes(t, policy, validResultHeader, []shapeCase[*relayv1.ResultHeader]{
		{"a refusal without details", func(*relayv1.ResultHeader) {}, true},
		{"a refusal with a closed state", func(r *relayv1.ResultHeader) { r.Error.Details = state("task.submit", "relay_own_node_only") }, true},
		{"a path-like reason", func(r *relayv1.ResultHeader) {
			r.Error.Details = state("task.submit", "/home/u/.ssh/id_ed25519: permission denied")
		}, false},
		{"a reason outside the closed pattern", func(r *relayv1.ResultHeader) { r.Error.Details = state("task.submit", "Relay_own_node_only") }, false},
		{"a state outside the closed pattern", func(r *relayv1.ResultHeader) { r.Error.Details = state("task submit", "relay_own_node_only") }, false},
		{"a reason of 65 characters", func(r *relayv1.ResultHeader) { r.Error.Details = state("task.submit", strings.Repeat("a", 65)) }, false},
		{"details.limit", func(r *relayv1.ResultHeader) {
			r.Error.Details = &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_Limit{Limit: &foundationv1.LimitFailure{LimitName: proto.String("routed_calls_per_account")}}}
		}, false},
		{"details.revision", func(r *relayv1.ResultHeader) {
			r.Error.Details = &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_Revision{Revision: &foundationv1.RevisionConflict{}}}
		}, false},
		{"details.upgrade", func(r *relayv1.ResultHeader) {
			r.Error.Details = &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_Upgrade{Upgrade: &foundationv1.VersionFailure{MinReadable: proto.String("1.0.0"),
				MinWritable: proto.String("1.0.0"), Received: proto.String("0.9.0")}}}
		}, false},
		{"state.resource on a permission refusal", func(r *relayv1.ResultHeader) {
			r.Error.Details = state("task.submit", "relay_own_node_only")
			r.Error.Details.GetState().Resource = &foundationv1.AggregateRef{Kind: proto.String("task"), Id: refusal.CorrelationId}
		}, false},
		{"state.native", func(r *relayv1.ResultHeader) {
			r.Error.Details = state("task.submit", "relay_own_node_only")
			r.Error.Details.GetState().Native = &foundationv1.NativeContentRev{Value: proto.Uint64(1)}
		}, false},
		{"a free-text code", func(r *relayv1.ResultHeader) { r.Error.Code = proto.String("Permission denied") }, false},
		{"a dotted code", func(r *relayv1.ResultHeader) { r.Error.Code = proto.String("authorization.permission_denied") }, false},
		{"a message key that is not the code's", func(r *relayv1.ResultHeader) { r.Error.MessageKey = proto.String("error.authorization.something_else") }, false},
		{"a path as message key", func(r *relayv1.ResultHeader) { r.Error.MessageKey = proto.String("/srv/build") }, false},
		{"a code under another category than its catalogue's", func(r *relayv1.ResultHeader) {
			r.Error.Category, r.Error.MessageKey = foundationv1.ErrorCategory_ERROR_CATEGORY_STATE.Enum(), proto.String("error.state.permission_denied")
		}, false},
		{"a code outside the catalogue", func(r *relayv1.ResultHeader) {
			r.Error.Code, r.Error.MessageKey = proto.String("not_a_catalogue_code"), proto.String("error.authorization.not_a_catalogue_code")
		}, false},
		{"approval_required with its approval resource and GetApproval", func(r *relayv1.ResultHeader) { r.Error = clone(approval) }, true},
		{"approval_required with another resource kind", func(r *relayv1.ResultHeader) {
			r.Error = clone(approval)
			r.Error.Details.GetState().Resource.Kind = proto.String("task")
		}, false},
		{"the approval resource under another category", func(r *relayv1.ResultHeader) {
			r.Error = clone(approval)
			r.Error.Category, r.Error.MessageKey = foundationv1.ErrorCategory_ERROR_CATEGORY_STATE.Enum(), proto.String("error.state.approval_required")
		}, false},
		{"another reconciliation operation", func(r *relayv1.ResultHeader) {
			r.Error = clone(approval)
			r.Error.Retry.ReconciliationOperation = proto.String("arcforges.node.v1.TaskService/GetTask")
		}, false},
		// ArcError's own rule, which the contract requires of every refusal.
		{"no correlation ID", func(r *relayv1.ResultHeader) { r.Error.CorrelationId = nil }, false},
		{"AFTER_TIME without retry_at", func(r *relayv1.ResultHeader) {
			r.Error.Retry.Mode = foundationv1.RetryMode_RETRY_MODE_AFTER_TIME.Enum()
		}, false},
		{"UNKNOWN with AFTER_TIME", func(r *relayv1.ResultHeader) {
			r.Error.Retry = &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_AFTER_TIME.Enum(), RetryAt: r.ExecutedAt}
			r.Error.Effect = foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN.Enum()
		}, false},
		// An unknown field is no closed field: it counts toward the 512 bytes, so free text cannot ride on one past the bound.
		{"a refusal of 513 bytes", func(r *relayv1.ResultHeader) { padTo(r.Error, 513) }, false},
		{"a refusal of 512 bytes", func(r *relayv1.ResultHeader) { padTo(r.Error, 512) }, true},
	})
}

// padTo grows a refusal to an exact size with an unknown field (field 15, bytes).
func padTo(value *foundationv1.ArcError, size int) {
	base := proto.Size(value)
	for n := 0; n < size; n++ {
		raw := protowire.AppendBytes(protowire.AppendTag(nil, 15, protowire.BytesType), make([]byte, n))
		value.ProtoReflect().SetUnknown(raw)
		if proto.Size(value) == size {
			return
		}
		if base+len(raw) > size {
			break
		}
	}
	panic("padTo: no exact size")
}

func TestTheRelayAssertionRulesAreTheContracts(t *testing.T) {
	vectors := loadVectors(t)
	var assertion relayv1.RelayAssertion
	if err := proto.Unmarshal(vectors.RelayAssertions[0].Assertion, &assertion); err != nil {
		t.Fatal(err)
	}
	checkShapes(t, &assertion, validRelayAssertion, []shapeCase[*relayv1.RelayAssertion]{
		{"an assertion expiring 120 s after issue", func(a *relayv1.RelayAssertion) { a.ExpiresAt = at(a.IssuedAt, 120, 0) }, true},
		{"an assertion expiring past 120 s", func(a *relayv1.RelayAssertion) { a.ExpiresAt = at(a.IssuedAt, 120, 1) }, false},
		{"an assertion expiring at issue", func(a *relayv1.RelayAssertion) { a.ExpiresAt = at(a.IssuedAt, 0, 0) }, false},
		{"a LIST_NODES assertion naming a target", func(a *relayv1.RelayAssertion) { a.Method = MethodListNodes.Enum() }, false},
		{"a LIST_NODES assertion", func(a *relayv1.RelayAssertion) {
			a.Method, a.TargetNodeId, a.CommandId = MethodListNodes.Enum(), nil, nil
		}, true},
		{"a GET_NODE assertion without target", func(a *relayv1.RelayAssertion) {
			a.Method, a.TargetNodeId, a.CommandId = MethodGetNode.Enum(), nil, nil
		}, false},
		{"a read assertion naming a command", func(a *relayv1.RelayAssertion) { a.Method = MethodGetNodeTask.Enum() }, false},
		{"a submit assertion without command", func(a *relayv1.RelayAssertion) { a.CommandId = nil }, false},
		{"an assertion with origin REMOTE", func(a *relayv1.RelayAssertion) { a.LocalOrigin = nodev1.Origin_ORIGIN_REMOTE.Enum() }, false},
		{"an assertion without method", func(a *relayv1.RelayAssertion) { a.Method = nil }, false},
		{"a method 9", func(a *relayv1.RelayAssertion) { a.Method = relayv1.RoutedMethod(9).Enum() }, false},
		{"an assertion without nonce", func(a *relayv1.RelayAssertion) { a.RelayNonce = nil }, false},
		{"a nonce of 31 bytes", func(a *relayv1.RelayAssertion) { a.RelayNonce = a.RelayNonce[:31] }, false},
		{"an assertion without signature", func(a *relayv1.RelayAssertion) { a.Signature = nil }, false},
		{"a signature of 63 bytes", func(a *relayv1.RelayAssertion) { a.Signature = a.Signature[:63] }, false},
		{"an assertion without installation", func(a *relayv1.RelayAssertion) { a.RelayingInstallationId = nil }, false},
		{"an assertion without local session", func(a *relayv1.RelayAssertion) { a.LocalSessionId = nil }, false},
		{"a relaying node of 15 bytes", func(a *relayv1.RelayAssertion) {
			a.RelayingNodeId = &foundationv1.Id{Value: a.RelayingNodeId.Value[:15]}
		}, false},
		{"a request digest of 33 bytes", func(a *relayv1.RelayAssertion) { a.RequestSha256 = append(a.RequestSha256, 0) }, false},
	})
}

func TestTheChannelFrameRulesAreTheContracts(t *testing.T) {
	vectors := loadVectors(t)
	var call, answer relayv1.RelayFrame
	if proto.Unmarshal(vectors.RoutedCall.Frame, &call) != nil || proto.Unmarshal(vectors.RoutedResult.Frame, &answer) != nil {
		t.Fatal("the frames")
	}
	checkShapes(t, call.GetCall(), validChannelCall, []shapeCase[*relayv1.ChannelCall]{
		{"a call without kid", func(c *relayv1.ChannelCall) { c.Header.Kid = nil }, false},
		{"a call with an empty payload", func(c *relayv1.ChannelCall) { c.Payload = []byte{} }, false},
		{"a call payload above 253,952 bytes", func(c *relayv1.ChannelCall) { c.Payload = make([]byte, 253_953) }, false},
		{"a signature of 63 bytes", func(c *relayv1.ChannelCall) { c.Header.Signature = make([]byte, 63) }, false},
		{"another algorithm", func(c *relayv1.ChannelCall) { c.Header.Algorithm = proto.String("ES384") }, false},
		{"a header above 2,048 bytes", func(c *relayv1.ChannelCall) { c.Header.Header = make([]byte, 2049) }, false},
		{"an empty header", func(c *relayv1.ChannelCall) { c.Header.Header = []byte{} }, false},
		{"a call frame without call_id", func(c *relayv1.ChannelCall) { c.CallId = nil }, false},
	})
	checkShapes(t, answer.GetCallResult(), validChannelResult, []shapeCase[*relayv1.ChannelResult]{
		{"a result naming a kid", func(r *relayv1.ChannelResult) { r.Header.Kid = proto.String("cmd-test-2026-11") }, false},
		{"a result payload above 1,040,384 bytes", func(r *relayv1.ChannelResult) { r.Payload = make([]byte, 1_040_385) }, false},
		{"an empty result payload (a refusal)", func(r *relayv1.ChannelResult) { r.Payload = []byte{} }, true},
	})
}

// TestTheRefusalCatalogueIsTheContracts compares the catalogue the rule routedRefusal ties to with the vendored Contracts fixture.
func TestTheRefusalCatalogueIsTheContracts(t *testing.T) {
	data, err := os.ReadFile(catalogueFile)
	if err != nil {
		t.Fatal(err)
	}
	var catalogue struct {
		Codes []struct{ Category, Code string } `json:"codes"`
	}
	if err := json.Unmarshal(data, &catalogue); err != nil {
		t.Fatal(err)
	}
	var fixture, ours []string
	for _, code := range catalogue.Codes {
		fixture = append(fixture, strings.ToLower(code.Category)+"/"+code.Code)
	}
	for key := range refusalCatalogue {
		ours = append(ours, key)
	}
	slices.Sort(fixture)
	slices.Sort(ours)
	if !slices.Equal(fixture, ours) || len(ours) == 0 {
		t.Fatalf("the catalogue differs from the Contracts fixture:\nfixture %v\ncenter  %v", fixture, ours)
	}
}
