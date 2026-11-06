// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// Units of the signed calls (EVIDENCE: REAL code, no store): the shape rules come before any signing input, a node's refusal is
// rebuilt from its closed fields, and the keyring picks the newest valid held key.

func TestAMalformedMessageNeverReachesASigningInput(t *testing.T) {
	vectors := loadVectors(t)
	frame, err := RelayCodec{}.Decode(vectors.RoutedResult.Frame)
	if err != nil {
		t.Fatal(err)
	}
	node := vectors.Keys["node"].SPKI
	before := signingInputs.Load()
	for name, change := range map[string]func(*resultFrame){
		"a 63-byte signature": func(f *resultFrame) { f.Signature = f.Signature[:63] },
		"a 65-byte signature": func(f *resultFrame) { f.Signature = append(bytes.Clone(f.Signature), 0) },
		"no call ID":          func(f *resultFrame) { f.CallOK = false },
		"a header of 2,049":   func(f *resultFrame) { f.Header, f.Shaped = make([]byte, 2049), false },
		"a kid":               func(f *resultFrame) { f.HasKid = true },
	} {
		changed := frame.result
		change(&changed)
		if _, failure := verifyResult(node, changed); failure != "result_malformed" {
			t.Errorf("%s: %q", name, failure)
		}
	}
	// A call that breaks its shape is refused before a header is built or signed.
	h := New(Options{Settings: Settings{MaxInFlightCalls: 8, MaxInFlightPerCenter: 8}})
	id := platform.NewID()
	session := &SessionCaller{UserID: platform.NewID(), SessionID: platform.NewID()}
	verified := &VerifiedRelay{RelayingNodeID: id, LocalSessionID: id, LocalOrigin: nodev1.Origin_ORIGIN_SCRIPT, AssertionSHA256: make([]byte, 32), verified: true}
	unverified := &VerifiedRelay{RelayingNodeID: id, LocalSessionID: id, LocalOrigin: nodev1.Origin_ORIGIN_SCRIPT, AssertionSHA256: make([]byte, 32)}
	remote := &VerifiedRelay{RelayingNodeID: id, LocalSessionID: id, LocalOrigin: nodev1.Origin_ORIGIN_REMOTE, AssertionSHA256: make([]byte, 32), verified: true}
	short := &VerifiedRelay{RelayingNodeID: id, LocalSessionID: id, LocalOrigin: nodev1.Origin_ORIGIN_SCRIPT, AssertionSHA256: make([]byte, 31), verified: true}
	for name, call := range map[string]Call{
		"no payload":                  {AccountID: id, TargetNodeID: id, Method: MethodGetNodeTask, Deadline: time.Second, Session: session},
		"a payload too large":         {AccountID: id, TargetNodeID: id, Method: MethodGetNodeTask, Payload: make([]byte, MaxCallPayload+1), Deadline: time.Second, Session: session},
		"a submit without command":    {AccountID: id, TargetNodeID: id, Method: MethodSubmitNodeTask, Payload: []byte{1}, Deadline: time.Second, Session: session},
		"a read with a command":       {AccountID: id, TargetNodeID: id, Method: MethodGetNodeTask, CommandID: &id, Payload: []byte{1}, Deadline: time.Second, Session: session},
		"LIST_NODES":                  {AccountID: id, TargetNodeID: id, Method: MethodListNodes, Payload: []byte{1}, Deadline: time.Second, Session: session},
		"a zero target":               {AccountID: id, Method: MethodGetNodeTask, Payload: []byte{1}, Deadline: time.Second, Session: session},
		"a deadline past 300 s":       {AccountID: id, TargetNodeID: id, Method: MethodGetNodeTask, Payload: []byte{1}, Deadline: 301 * time.Second, Session: session},
		"no caller":                   {AccountID: id, TargetNodeID: id, Method: MethodGetNodeTask, Payload: []byte{1}, Deadline: time.Second},
		"both callers":                {AccountID: id, TargetNodeID: id, Method: MethodGetNodeTask, Payload: []byte{1}, Deadline: time.Second, Session: session, Relay: verified},
		"a relay built by hand":       {AccountID: id, TargetNodeID: id, Method: MethodGetNodeTask, Payload: []byte{1}, Deadline: time.Second, Relay: unverified},
		"a relay with a short digest": {AccountID: id, TargetNodeID: id, Method: MethodGetNodeTask, Payload: []byte{1}, Deadline: time.Second, Relay: short},
		"origin REMOTE":               {AccountID: id, TargetNodeID: id, Method: MethodGetNodeTask, Payload: []byte{1}, Deadline: time.Second, Relay: remote},
		"a session without its user":  {AccountID: id, TargetNodeID: id, Method: MethodGetNodeTask, Payload: []byte{1}, Deadline: time.Second, Session: &SessionCaller{SessionID: id}},
	} {
		if _, err := h.Call(t.Context(), call); err == nil || err.Error() != "refused: VALIDATION/invalid_argument" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if signingInputs.Load() != before {
		t.Fatal("a malformed message reached a signing input")
	}
}

// TestALostCallsEffectIsItsDeliveryStates (errors.md STATE/node_unreachable): a mutation whose frame the writer started to write is
// UNKNOWN with SAME_COMMAND; a mutation never written and every read are DID_NOT_HAPPEN with AFTER_TIME.
func TestALostCallsEffectIsItsDeliveryStates(t *testing.T) {
	node := platform.NewID()
	for _, c := range []struct {
		method    relayv1.RoutedMethod
		delivered bool
		unknown   bool
	}{
		{MethodSubmitNodeTask, true, true}, {MethodCancelNodeTask, true, true}, {MethodSubmitNodeTask, false, false}, {MethodGetNodeTask, true, false},
		{MethodWaitNodeTask, true, false}, {MethodReadNodeTaskOutput, false, false},
	} {
		p := &pending{method: c.method}
		if c.delivered {
			p.state.Store(callDelivered)
		} else {
			p.state.Store(callAbandoned)
		}
		refusal := p.unreachable(node, "channel_closed")
		unknown := refusal.Effect == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN
		retry := foundationv1.RetryMode_RETRY_MODE_AFTER_TIME
		if c.unknown {
			retry = foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND
		}
		if unknown != c.unknown || refusal.Retry != retry || refusal.Key() != "STATE/node_unreachable" || !bytes.Equal(refusal.Resource.ID, node[:]) {
			t.Errorf("%v delivered=%v: %+v", c.method, c.delivered, refusal)
		}
	}
}

func TestANodesRefusalIsRebuiltFromItsClosedFields(t *testing.T) {
	nodeCorrelation, approvalID := platform.NewID(), platform.NewID()
	node := &foundationv1.ArcError{Code: proto.String("approval_required"), Category: foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHORIZATION.Enum(),
		MessageKey: proto.String("error.authorization.approval_required"), Retry: &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_RECONCILE.Enum(),
			ReconciliationOperation: proto.String(approvalReconcileOperation)}, Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN.Enum(),
		CorrelationId: idValue(nodeCorrelation), Details: &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_State{State: &foundationv1.StateFailure{
			State: proto.String("task.cancel_others"), Reason: proto.String("approval_required"), Resource: &foundationv1.AggregateRef{Kind: proto.String("approval"),
				Id: idValue(approvalID)}}}}}
	// An unknown field the node added (within the bound) never reaches the caller.
	node.ProtoReflect().SetUnknown(protowire.AppendBytes(protowire.AppendTag(nil, 15, protowire.BytesType), []byte("/srv/secret")))
	if !validArcError(node) || !routedRefusal(node) {
		t.Fatal("the node's refusal is a valid routed refusal")
	}
	call := correlation.New()
	rendered := rebuildRefusal(node).ArcError(call)
	want := proto.Clone(node).(*foundationv1.ArcError)
	want.ProtoReflect().SetUnknown(nil)
	want.CorrelationId = &foundationv1.Id{Value: correlation.IDBytes(call.CorrelationID)}
	if !proto.Equal(rendered, want) {
		t.Fatalf("the rebuilt refusal:\n%v\nwant\n%v", rendered, want)
	}
	if len(rendered.ProtoReflect().GetUnknown()) != 0 || bytes.Contains(must(proto.Marshal(rendered)), nodeCorrelation[:]) {
		t.Fatal("the node's bytes or correlation reached the caller")
	}
	// AFTER_TIME keeps its instant; the node's own fields only.
	retryAt := time.Date(2026, 11, 5, 12, 0, 1, 500_000_000, time.UTC)
	later := &foundationv1.ArcError{Code: proto.String("queue_full"), Category: foundationv1.ErrorCategory_ERROR_CATEGORY_RESOURCE.Enum(),
		MessageKey: proto.String("error.resource.queue_full"), Retry: &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_AFTER_TIME.Enum(),
			RetryAt: instant(retryAt)}, Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN.Enum(), CorrelationId: idValue(nodeCorrelation)}
	refusal := rebuildRefusal(later)
	if !refusal.RetryAt.Equal(retryAt) || refusal.Key() != "RESOURCE/queue_full" || refusal.Reason != "" || refusal.Resource != nil {
		t.Fatalf("the rebuilt AFTER_TIME refusal: %+v", refusal)
	}
}

func must(data []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return data
}

func TestTheKeyringPicksTheNewestValidHeldKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	successor, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	retired := now.Add(3 * time.Hour)
	h := &Hub{}
	h.keys.refreshed = now
	h.keys.private = map[string]*ecdsa.PrivateKey{"A": key, "B": successor}
	h.keys.rows = []platform.SigningKey{
		{KID: "cmd-current", SecretBinding: "A", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), RetiredAt: &retired},
		{KID: "cmd-successor", SecretBinding: "B", NotBefore: now.Add(time.Hour), NotAfter: now.Add(24 * time.Hour)},
	}
	for _, c := range []struct {
		at   time.Time
		kid  string
		held *ecdsa.PrivateKey
	}{
		{now, "cmd-current", key},
		{now.Add(2 * time.Hour), "cmd-successor", successor}, // across the successor's not_before
		{now.Add(30 * time.Hour), "", nil},                   // the successor expired, the current one is retired
		{now.Add(-2 * time.Hour), "", nil},                   // before any key
	} {
		h.keys.refreshed = c.at // a fresh read at each instant
		kid, signer, ok := h.signingKey(c.at)
		if kid != c.kid || signer != c.held || ok != (c.kid != "") {
			t.Errorf("at %s: %q %v", c.at, kid, ok)
		}
		if kids := h.validKids(c.at); (len(kids) > 0 && kids[0] != kid) || (len(kids) == 0) != (kid == "") {
			t.Errorf("at %s: signing_kids %v disagree with the signing kid %q", c.at, kids, kid)
		}
	}
	h.keys.refreshed = now.Add(48 * time.Hour)
	if _, _, ok := h.signingKey(now.Add(48 * time.Hour)); ok {
		t.Error("an expired key signs")
	}
	// Both keys valid: signing_kids lists them newest first, the signing kid first.
	h.keys.rows[0].RetiredAt, h.keys.refreshed = nil, now.Add(2*time.Hour)
	if kids := h.validKids(now.Add(2 * time.Hour)); len(kids) != 2 || kids[0] != "cmd-successor" || kids[1] != "cmd-current" {
		t.Errorf("signing_kids with both keys valid: %v", kids)
	}
	// A stale keyring signs nothing: KeyStalePeriods periods without a successful read (review A N-2, B B-3).
	h.keys.refreshed = now
	if _, _, ok := h.signingKey(now.Add(KeyStalePeriods * DefaultKeyRefresh)); !ok {
		t.Error("the keyring is stale before its bound")
	}
	if _, _, ok := h.signingKey(now.Add(KeyStalePeriods*DefaultKeyRefresh + time.Nanosecond)); ok || len(h.validKids(now.Add(4*time.Minute))) != 0 {
		t.Error("a stale keyring signs")
	}
}

// TestARoutedRefusalOverItsBoundIsRefused pins the bound of the rule to the encoded size, unknown fields included.
func TestARoutedRefusalOverItsBoundIsRefused(t *testing.T) {
	value := &foundationv1.ArcError{Code: proto.String("expired"), Category: foundationv1.ErrorCategory_ERROR_CATEGORY_STATE.Enum(),
		MessageKey: proto.String("error.state.expired"), Retry: &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_NEVER.Enum()},
		Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN.Enum(), CorrelationId: idValue(platform.NewID())}
	if !routedRefusal(value) {
		t.Fatal("STATE/expired is a routed refusal")
	}
	padTo(value, MaxRefusalBytes+1)
	if routedRefusal(value) {
		t.Fatal("a refusal over 512 bytes")
	}
}
