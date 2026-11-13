// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// These are synthetic producer bytes, exercising the real Go consumer. They
// make no assertion about native Node observation, ownership or cleanup.
func attemptQualificationFixture(reason string) (*nodev1.FileServicePlanRemovalRequest, *nodev1.FileServicePlanRemovalResponse) {
	correlation := pid(platform.NewID())
	q := &nodev1.FileServicePlanRemovalRequest{
		Meta:   &foundationv1.RequestMeta{CommandId: pid(platform.NewID()), CorrelationId: correlation},
		Target: &nodev1.FileServicePlanRemovalRequest_AttemptId{AttemptId: pid(platform.NewID())},
	}
	failure := fileCatalogueError(foundationv1.ErrorCategory_ERROR_CATEGORY_STATE, "invalid_state", "file", reason)
	failure.CorrelationId = correlation
	return q, &nodev1.FileServicePlanRemovalResponse{
		Meta:    &foundationv1.ResponseMeta{CorrelationId: correlation},
		Outcome: &nodev1.FileServicePlanRemovalResponse_Error{Error: failure},
		Audit:   &nodev1.FileAuditMetadata{},
	}
}

func TestCTR06AttemptQualificationExactProfile(t *testing.T) {
	method := relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL
	for _, reason := range []string{"attempt_references_unverified", "attempt_tracking_unverified"} {
		t.Run(reason, func(t *testing.T) {
			q, response := attemptQualificationFixture(reason)
			raw, wire := marshal(t, q), marshal(t, response)
			if _, err := decodeFileResponse(method, wire, raw); err != nil {
				t.Fatalf("exact attempt qualification refused: %v", err)
			}
			answer := answerOf(method, RoutedResult{Outcome: relayv1.RoutedOutcome_ROUTED_OUTCOME_EXECUTED, Response: wire}, nil, raw)
			if !answer.HandlerError || answer.Effect != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN ||
				answer.Refusal != "state/invalid_state" || answer.ComparableReplay() || answer.PlanID != nil || len(answer.Observations) != 0 {
				t.Fatalf("qualification must stay a content-free handler refusal: %+v", answer)
			}
			for name, change := range map[string]func(*nodev1.FileServicePlanRemovalRequest, *nodev1.FileServicePlanRemovalResponse){
				"workspace selector": func(q *nodev1.FileServicePlanRemovalRequest, _ *nodev1.FileServicePlanRemovalResponse) {
					q.Target = &nodev1.FileServicePlanRemovalRequest_WorkspacePath{WorkspacePath: &nodev1.FilePath{WorkspaceId: pid(platform.NewID()), Path: proto.String("fixture")}}
				},
				"missing selector": func(q *nodev1.FileServicePlanRemovalRequest, _ *nodev1.FileServicePlanRemovalResponse) {
					q.Target = nil
				},
				"invalid attempt": func(q *nodev1.FileServicePlanRemovalRequest, _ *nodev1.FileServicePlanRemovalResponse) {
					q.Target = &nodev1.FileServicePlanRemovalRequest_AttemptId{AttemptId: &foundationv1.Id{Value: []byte{1}}}
				},
				"wrong state": func(_ *nodev1.FileServicePlanRemovalRequest, x *nodev1.FileServicePlanRemovalResponse) {
					x.GetError().GetDetails().GetState().State = proto.String("task")
				},
				"wrong reason": func(_ *nodev1.FileServicePlanRemovalRequest, x *nodev1.FileServicePlanRemovalResponse) {
					x.GetError().GetDetails().GetState().Reason = proto.String("arbitrary")
				},
				"other code": func(_ *nodev1.FileServicePlanRemovalRequest, x *nodev1.FileServicePlanRemovalResponse) {
					x.GetError().Code = proto.String("file_access_denied")
					x.GetError().MessageKey = proto.String("error.state.file_access_denied")
				},
				"other category": func(_ *nodev1.FileServicePlanRemovalRequest, x *nodev1.FileServicePlanRemovalResponse) {
					x.GetError().Category = foundationv1.ErrorCategory_ERROR_CATEGORY_CONFLICT.Enum()
					x.GetError().MessageKey = proto.String("error.conflict.invalid_state")
				},
				"happened": func(_ *nodev1.FileServicePlanRemovalRequest, x *nodev1.FileServicePlanRemovalResponse) {
					x.GetError().Effect = foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED.Enum()
				},
				"unknown": func(_ *nodev1.FileServicePlanRemovalRequest, x *nodev1.FileServicePlanRemovalResponse) {
					x.GetError().Effect = foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN.Enum()
				},
				"same command": func(_ *nodev1.FileServicePlanRemovalRequest, x *nodev1.FileServicePlanRemovalResponse) {
					x.GetError().Retry.Mode = foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND.Enum()
				},
				"retry at": func(_ *nodev1.FileServicePlanRemovalRequest, x *nodev1.FileServicePlanRemovalResponse) {
					x.GetError().Retry.RetryAt = &foundationv1.Instant{UnixSeconds: proto.Int64(1800000000), Nanos: proto.Uint32(0)}
				},
				"reconciliation": func(_ *nodev1.FileServicePlanRemovalRequest, x *nodev1.FileServicePlanRemovalResponse) {
					x.GetError().Retry.ReconciliationOperation = proto.String("arbitrary")
				},
				"resource": func(_ *nodev1.FileServicePlanRemovalRequest, x *nodev1.FileServicePlanRemovalResponse) {
					s := x.GetError().GetDetails().GetState().ProtoReflect()
					s.Mutable(s.Descriptor().Fields().ByName(protoreflect.Name("resource")))
				},
				"native": func(_ *nodev1.FileServicePlanRemovalRequest, x *nodev1.FileServicePlanRemovalResponse) {
					s := x.GetError().GetDetails().GetState().ProtoReflect()
					s.Mutable(s.Descriptor().Fields().ByName(protoreflect.Name("native")))
				},
				"wrong error correlation": func(_ *nodev1.FileServicePlanRemovalRequest, x *nodev1.FileServicePlanRemovalResponse) {
					x.GetError().CorrelationId = pid(platform.NewID())
				},
				"wrong response correlation": func(_ *nodev1.FileServicePlanRemovalRequest, x *nodev1.FileServicePlanRemovalResponse) {
					x.Meta.CorrelationId = pid(platform.NewID())
				},
				"invalid request correlation": func(q *nodev1.FileServicePlanRemovalRequest, _ *nodev1.FileServicePlanRemovalResponse) {
					q.Meta.CorrelationId = &foundationv1.Id{Value: []byte{1}}
				},
				"invalid error correlation": func(_ *nodev1.FileServicePlanRemovalRequest, x *nodev1.FileServicePlanRemovalResponse) {
					x.GetError().CorrelationId = &foundationv1.Id{Value: []byte{1}}
				},
				"content observation": func(_ *nodev1.FileServicePlanRemovalRequest, x *nodev1.FileServicePlanRemovalResponse) {
					x.Audit.Observations = []*nodev1.FileAuditObservation{{Kind: nodev1.FileAuditKind_FILE_AUDIT_KIND_INPUT_BYTES.Enum(), SizeBytes: proto.Uint64(1), DigestInputBytes: proto.Uint64(1), Sha256: make([]byte, 32)}}
				},
			} {
				t.Run(name, func(t *testing.T) {
					badQ, badX := proto.Clone(q).(*nodev1.FileServicePlanRemovalRequest), proto.Clone(response).(*nodev1.FileServicePlanRemovalResponse)
					change(badQ, badX)
					raw, wire := marshal(t, badQ), marshal(t, badX)
					if _, err := decodeFileResponse(method, wire, raw); err == nil {
						t.Fatal("contradictory qualification accepted")
					}
					answer := answerOf(method, RoutedResult{Outcome: relayv1.RoutedOutcome_ROUTED_OUTCOME_EXECUTED, Response: wire}, nil, raw)
					if !answer.HandlerError || answer.Effect != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN || answer.ComparableReplay() || answer.PlanID != nil {
						t.Fatalf("malformed signed inner settled: %+v", answer)
					}
				})
			}
			// Optional ResponseMeta stays optional; a supplied one must agree.
			response.Meta = nil
			if _, err := decodeFileResponse(method, marshal(t, response), raw); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCTR06AttemptQualificationOptionalCorrelationReplay(t *testing.T) {
	q, response := attemptQualificationFixture("attempt_references_unverified")
	q.Meta.CorrelationId = nil
	// The synthetic first producer uses its call ID. Replay keeps these bytes;
	// there is no evidence that a later call ID was the original inner ID.
	firstCall := pid(platform.NewID())
	response.GetError().CorrelationId, response.Meta.CorrelationId = firstCall, firstCall
	wire, raw := marshal(t, response), marshal(t, q)
	for range 2 {
		if _, err := decodeFileResponse(relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL, wire, raw); err != nil {
			t.Fatal(err)
		}
	}
	response.Meta.CorrelationId = pid(platform.NewID())
	if _, err := decodeFileResponse(relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL, marshal(t, response), raw); err == nil {
		t.Fatal("inconsistent replay inner correlation accepted")
	}
	response.Meta = nil
	response.GetError().CorrelationId = nil
	if _, err := decodeFileResponse(relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL, marshal(t, response), raw); err == nil {
		t.Fatal("missing correlation accepted")
	}
}

func TestCTR06AttemptQualificationDoesNotWidenOtherMethods(t *testing.T) {
	_, response := attemptQualificationFixture("attempt_tracking_unverified")
	failure := response.GetError()
	if !validFileError(failure) {
		t.Fatal("generic published shape must remain distinct")
	}
	for method := relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE; method <= relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_WORKSPACE; method++ {
		if method != relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL && fileMethod(method) && validFileErrorForMethod(method, failure) {
			t.Fatalf("qualification widened to %v", method)
		}
	}
	q, _ := attemptQualificationFixture("attempt_tracking_unverified")
	for _, tc := range []struct {
		category     foundationv1.ErrorCategory
		code, reason string
	}{
		{foundationv1.ErrorCategory_ERROR_CATEGORY_STATE, "file_access_denied", "file_access_denied"},
		{foundationv1.ErrorCategory_ERROR_CATEGORY_CONFLICT, "file_changed", "planned_tree_changed"},
	} {
		response.Outcome = &nodev1.FileServicePlanRemovalResponse_Error{Error: fileCatalogueError(tc.category, tc.code, "file", tc.reason)}
		if _, err := decodeFileResponse(relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL, marshal(t, response), marshal(t, q)); err != nil {
			t.Fatalf("distinct actual-failure contract rejected: %v", err)
		}
	}
	if validFileErrorForMethod(relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE, response.GetError()) {
		t.Fatal("planned tree conflict widened outside Plan/Execute")
	}
	if !validFileErrorForMethod(relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL, response.GetError()) {
		t.Fatal("existing Execute tree conflict regressed")
	}
}
