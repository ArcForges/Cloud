// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// Real ES256 verification and call binding, with a synthetic node key/header.
// Generic 450.1 shape remains separate from handler-specific qualification.
func TestCTR06AttemptQualificationCannotBeAnOuterRefusal(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	node, call, command := platform.NewID(), platform.NewID(), platform.NewID()
	digest := sha256.Sum256([]byte("synthetic-exact-plan-request"))
	p := &pending{callID: call, method: relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL, commandID: &command, requestSHA256: digest[:]}
	for _, reason := range []string{"attempt_references_unverified", "attempt_tracking_unverified", "capability_unavailable", "replay_window_passed"} {
		t.Run(reason, func(t *testing.T) {
			failure := &foundationv1.ArcError{
				Category: foundationv1.ErrorCategory_ERROR_CATEGORY_STATE.Enum(), Code: proto.String("invalid_state"),
				MessageKey: proto.String("error.state.invalid_state"), CorrelationId: idValue(call),
				Effect:  foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN.Enum(),
				Retry:   &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_NEVER.Enum()},
				Details: &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_State{State: &foundationv1.StateFailure{State: proto.String("file"), Reason: proto.String(reason)}}},
			}
			header := &relayv1.ResultHeader{CallId: idValue(call), NodeId: idValue(node), CommandId: idValue(command), Method: p.method.Enum(),
				RequestSha256: digest[:], ExecutedAt: instant(time.Now()), Outcome: relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_BY_POLICY.Enum(), Error: failure}
			if !validArcError(failure) || !routedRefusal(failure) || !validResultHeader(header) {
				t.Fatal("generic published shape was narrowed")
			}
			wire, err := proto.Marshal(header)
			if err != nil {
				t.Fatal(err)
			}
			signature, err := signES256(key, resultSigningInput(wire))
			if err != nil {
				t.Fatal(err)
			}
			frame := resultFrame{CallID: call, CallOK: true, Shaped: true, Algorithm: "ES256", Header: wire, Signature: signature}
			verified, problem := verifyResult(public, frame)
			if problem != "" {
				t.Fatal(problem)
			}
			want := ""
			if reason == "attempt_references_unverified" || reason == "attempt_tracking_unverified" {
				want = "result_mismatch"
			}
			if got := bindResult(p, verified, nil, node); got != want {
				t.Fatalf("binding=%q want=%q", got, want)
			}
			bad := frame
			bad.Signature = bytes.Clone(signature)
			bad.Signature[0] ^= 1
			if _, got := verifyResult(public, bad); got != "result_signature" {
				t.Fatal("forged header signature accepted")
			}
			bad = frame
			bad.CallID = platform.NewID()
			if _, got := verifyResult(public, bad); got != "result_other_call" {
				t.Fatal("wrong outer call accepted")
			}
			if want == "" {
				for name, other := range map[string]*pending{
					"method":    {callID: call, method: relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL, commandID: &command, requestSHA256: digest[:]},
					"raw bytes": {callID: call, method: p.method, commandID: &command, requestSHA256: make([]byte, 32)},
				} {
					if got := bindResult(other, verified, nil, node); got != "result_mismatch" {
						t.Fatalf("%s did not bind", name)
					}
				}
				if got := bindResult(p, verified, nil, platform.NewID()); got != "result_mismatch" {
					t.Fatal("foreign node accepted")
				}
			}
		})
	}
}
