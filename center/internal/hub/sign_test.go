// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"testing"

	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// E1-13 and the signature half of SEC-08 (EVIDENCE: REAL, the Contracts golden vectors byte for byte, Go's crypto/ecdsa): the center's
// call header, signing input and frame equal the vectors' bytes, and every signature check refuses what the contract refuses.

func platformID(t *testing.T, text string) platform.ID {
	t.Helper()
	var id platform.ID
	copy(id[:], mustID(t, text).Value)
	return id
}

func TestTheDomainStringsAreTheContracts(t *testing.T) {
	vectors := loadVectors(t)
	for name, domain := range map[string]string{"call": CallDomain, "result": ResultDomain, "hello": HelloDomain, "origin": OriginDomain} {
		if vectors.Domains[name] != domain {
			t.Errorf("the %s domain string is %q, the contract's %q", name, domain, vectors.Domains[name])
		}
	}
	if len(CallDomain) != 24 || len(ResultDomain) != 26 || len(HelloDomain) != 25 || len(OriginDomain) != 26 {
		t.Error("the domain strings' lengths")
	}
	domains := []string{CallDomain, ResultDomain, HelloDomain, OriginDomain}
	for i := range domains {
		for j := range domains {
			if i != j && bytes.HasPrefix([]byte(domains[i]), []byte(domains[j])) {
				t.Errorf("%q starts with %q", domains[i], domains[j])
			}
		}
	}
}

func TestCallHeaderSignatureVerifiesInGoAndAgainstTheVector(t *testing.T) {
	vectors := loadVectors(t)
	vector := vectors.RoutedCall
	var frame relayv1.RelayFrame
	if err := proto.Unmarshal(vector.Frame, &frame); err != nil || frame.GetCall() == nil || frame.GetFrameSeq() != vector.FrameSeq {
		t.Fatalf("the call frame: %v", err)
	}
	if again, _ := proto.Marshal(&frame); !bytes.Equal(again, vector.Frame) || !validChannelCall(frame.GetCall()) {
		t.Fatal("the call frame re-encodes byte for byte and is valid")
	}
	call := frame.GetCall()
	header := call.GetHeader().GetHeader()
	if !bytes.Equal(header, vector.CallHeader) || !bytes.Equal(callSigningInput(header), vector.SigningInput) {
		t.Fatal("the routed-call signing input is the domain string and the exact header bytes")
	}
	center, otherCenter := vectors.Keys["center"].SPKI, vectors.Keys["otherCenter"].SPKI
	if !verifyES256(center, vector.SigningInput, vector.Signature) {
		t.Fatal("the vector's call signature verifies in Go")
	}
	flipped := bytes.Clone(vector.SigningInput)
	flipped[len(flipped)-1] ^= 1
	for name, refused := range map[string]bool{
		"over the bare header":         verifyES256(center, header, vector.Signature),
		"under the result domain":      verifyES256(center, append([]byte(ResultDomain), header...), vector.Signature),
		"under the hello domain":       verifyES256(center, append([]byte(HelloDomain), header...), vector.Signature),
		"under the origin domain":      verifyES256(center, append([]byte(OriginDomain), header...), vector.Signature),
		"a high-S signature":           verifyES256(center, vector.SigningInput, vector.HighS),
		"another center's command key": verifyES256(otherCenter, vector.SigningInput, vector.Signature),
		"a flipped header byte":        verifyES256(center, flipped, vector.Signature),
	} {
		if refused {
			t.Errorf("a call signature %s verified", name)
		}
	}
	var decoded relayv1.CallHeader
	if err := proto.Unmarshal(header, &decoded); err != nil || !validCallHeader(&decoded) {
		t.Fatal("the vector call header is valid")
	}

	// The center builds the same bytes from the same fields: the header, then the frame.
	issued, deadline := vectorInstant(vector.IssuedAt), vectorInstant(vector.Deadline)
	now := timeOf(issued)
	command := platformID(t, vectors.IDs["command"])
	relay := &VerifiedRelay{relayingNodeID: platformID(t, vectors.IDs["node"]), localOrigin: nodev1.Origin(vector.Caller.LocalOrigin),
		localSessionID: platformID(t, vectors.IDs["localSession"]), assertionSHA256: vector.RelayAssertionSHA256, verified: true}
	routed := Call{AccountID: platformID(t, vectors.IDs["account"]), TargetNodeID: platformID(t, vectors.IDs["node"]), Relay: relay,
		CommandID: &command, Method: relayv1.RoutedMethod(vector.Method), Payload: vector.Payload, Deadline: timeOf(deadline).Sub(now)}
	verified, ok := routed.callerOf()
	if !ok || verified.kind != nodev1.CenterCallerKind(vector.Caller.Kind) {
		t.Fatal("the vector's caller is a verified node relay")
	}
	built := callHeader(routed, verified, platformID(t, vectors.IDs["call"]), vector.KID, vectors.Audience, vector.PayloadSHA256, now)
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(built)
	if err != nil || !bytes.Equal(data, vector.CallHeader) {
		t.Fatalf("the center's call header is not the vector's bytes:\n%x\n%x", data, vector.CallHeader)
	}
	encoded, err := RelayCodec{}.Call(vector.FrameSeq, platformID(t, vectors.IDs["call"]), data, vector.Signature, vector.KID, vector.Payload)
	if err != nil || !bytes.Equal(encoded, vector.Frame) {
		t.Fatal("the center's call frame is not the vector's bytes")
	}
	if sum := sha256.Sum256(vector.Payload); !bytes.Equal(sum[:], vector.PayloadSHA256) || uint32(len(vector.Payload)) != vector.RequestSize {
		t.Fatal("the payload's digest and size")
	}

	// The center's own signature: low-S, and it verifies against the key's public half only under the call domain.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	for range 32 {
		signature, err := signES256(key, callSigningInput(data))
		if err != nil {
			t.Fatal(err)
		}
		if new(big.Int).SetBytes(signature[32:]).Cmp(p256HalfOrder) > 0 || !verifyES256(public, callSigningInput(data), signature) ||
			verifyES256(public, data, signature) {
			t.Fatal("the center's signature is low-S and verifies over the domain string and the header only")
		}
	}
}

func TestTheResultVectorVerifiesAndIsBoundToItsCall(t *testing.T) {
	vectors := loadVectors(t)
	vector := vectors.RoutedResult
	node, other := vectors.Keys["node"].SPKI, vectors.Keys["otherInstallation"].SPKI
	frame, err := RelayCodec{}.Decode(vector.Frame)
	if err != nil || frame.kind != inboundResult {
		t.Fatalf("the result frame decodes as a result: %v", err)
	}
	if !bytes.Equal(resultSigningInput(frame.result.Header), vector.SigningInput) {
		t.Fatal("the routed-result signing input")
	}
	header, failure := verifyResult(node, frame.result)
	if failure != "" {
		t.Fatalf("the vector result: %s", failure)
	}
	command := platformID(t, vectors.IDs["command"])
	p := &pending{callID: platformID(t, vectors.IDs["call"]), method: MethodSubmitNodeTask, commandID: &command, requestSHA256: vectors.RoutedCall.PayloadSHA256}
	if failure := bindResult(p, header, frame.result.Payload, platformID(t, vectors.IDs["node"])); failure != "" {
		t.Fatalf("the vector result binds to its call: %s", failure)
	}
	if sum := sha256.Sum256(frame.result.Payload); !bytes.Equal(sum[:], vector.PayloadSHA256) {
		t.Fatal("the response digest")
	}
	cases := map[string]func(*resultFrame) ([]byte, string){
		"a high-S signature": func(f *resultFrame) ([]byte, string) { f.Signature = vector.HighS; return node, "result_signature" },
		"another installation's key": func(*resultFrame) ([]byte, string) {
			return other, "result_signature"
		},
		"a flipped header byte": func(f *resultFrame) ([]byte, string) {
			f.Header = bytes.Clone(f.Header)
			f.Header[0] ^= 1
			return node, "result_signature"
		},
		"a kid on the result":          func(f *resultFrame) ([]byte, string) { f.HasKid = true; return node, "result_malformed" },
		"another algorithm":            func(f *resultFrame) ([]byte, string) { f.Algorithm = "ES384"; return node, "result_malformed" },
		"a 63-byte signature":          func(f *resultFrame) ([]byte, string) { f.Signature = f.Signature[:63]; return node, "result_malformed" },
		"an empty header":              func(f *resultFrame) ([]byte, string) { f.Header = nil; return node, "result_malformed" },
		"no call ID":                   func(f *resultFrame) ([]byte, string) { f.CallOK = false; return node, "result_malformed" },
		"another call ID on the frame": func(f *resultFrame) ([]byte, string) { f.CallID = platform.NewID(); return node, "result_other_call" },
	}
	for name, change := range cases {
		changed := frame.result
		key, want := change(&changed)
		if _, failure := verifyResult(key, changed); failure != want {
			t.Errorf("%s: %q, want %q", name, failure, want)
		}
	}
	if verifyES256(node, frame.result.Header, vector.Signature) || verifyES256(node, append([]byte(CallDomain), frame.result.Header...), vector.Signature) {
		t.Error("a result signature verified over the bare header or under the call domain")
	}
	// The bindings: another node, another method, digest or command, a changed payload.
	other1, nodeID := platform.NewID(), platformID(t, vectors.IDs["node"])
	for name, failure := range map[string]string{
		"another node":    bindResult(p, header, frame.result.Payload, other1),
		"another method":  bindResult(&pending{callID: p.callID, method: MethodCancelNodeTask, commandID: &command, requestSHA256: p.requestSHA256}, header, frame.result.Payload, nodeID),
		"another digest":  bindResult(&pending{callID: p.callID, method: p.method, commandID: &command, requestSHA256: make([]byte, 32)}, header, frame.result.Payload, nodeID),
		"another command": bindResult(&pending{callID: p.callID, method: p.method, commandID: &other1, requestSHA256: p.requestSHA256}, header, frame.result.Payload, nodeID),
		"a read's result": bindResult(&pending{callID: p.callID, method: p.method, requestSHA256: p.requestSHA256}, header, frame.result.Payload, nodeID),
		"another payload": bindResult(p, header, append(bytes.Clone(frame.result.Payload), 0), nodeID),
		"a payload byte":  bindResult(p, header, flip(frame.result.Payload), nodeID),
	} {
		if failure != "result_mismatch" {
			t.Errorf("%s: %q", name, failure)
		}
	}
}

func flip(data []byte) []byte {
	out := bytes.Clone(data)
	out[len(out)-1] ^= 1
	return out
}

func TestTheRelayAssertionVectorsVerify(t *testing.T) {
	vectors := loadVectors(t)
	node, other := vectors.Keys["node"].SPKI, vectors.Keys["otherInstallation"].SPKI
	var audience [32]byte
	copy(audience[:], vectors.AudienceSHA256)
	if len(vectors.RelayAssertions) != 3 {
		t.Fatal("three assertion vectors")
	}
	for _, vector := range vectors.RelayAssertions {
		var assertion relayv1.RelayAssertion
		if err := proto.Unmarshal(vector.Assertion, &assertion); err != nil || !validRelayAssertion(&assertion) {
			t.Fatalf("%s: the assertion is valid", vector.ID)
		}
		input := originSigningInput(audience, &assertion)
		if len(input) != OriginMessageBytes || !bytes.Equal(input, vector.SigningInput) {
			t.Fatalf("%s: the canonical relay-origin bytes", vector.ID)
		}
		if !bytes.Equal(assertion.Signature, vector.Signature) || !verifyES256(node, input, assertion.Signature) {
			t.Fatalf("%s: the assertion signature verifies", vector.ID)
		}
		if verifyES256(node, input[len(OriginDomain):], assertion.Signature) || verifyES256(node, append([]byte(CallDomain), input[len(OriginDomain):]...), assertion.Signature) ||
			verifyES256(node, input, vector.HighS) || verifyES256(other, input, assertion.Signature) {
			t.Errorf("%s: a bare, other-domain, high-S or other-key signature verified", vector.ID)
		}
		if vector.ListNodesRequestWithoutAssertion != nil {
			if sum := sha256.Sum256(*vector.ListNodesRequestWithoutAssertion); !bytes.Equal(sum[:], vector.RequestSHA256) {
				t.Errorf("%s: the ListNodes request digest", vector.ID)
			}
		}
	}
}

func TestTheRelayNonceFramesAreTheVectors(t *testing.T) {
	vectors := loadVectors(t)
	request, err := RelayCodec{}.Decode(vectors.RelayNonce.RequestFrame)
	if err != nil || request.kind != inboundNonceRequest || !request.requestOK || request.requestID != platformID(t, vectors.IDs["nonceRequest"]) {
		t.Fatalf("the nonce request decodes with its request ID: %v", err)
	}
	var frame relayv1.RelayFrame
	if err := proto.Unmarshal(vectors.RelayNonce.Frame, &frame); err != nil || frame.GetRelayNonce() == nil {
		t.Fatal("the relay nonce frame")
	}
	expires := timeOf(frame.GetRelayNonce().GetExpiresAt())
	encoded, err := RelayCodec{}.RelayNonce(frame.GetFrameSeq(), request.requestID, vectors.RelayNonce.Nonce, expires)
	if err != nil || !bytes.Equal(encoded, vectors.RelayNonce.Frame) {
		t.Fatalf("the center's relay nonce frame is not the vector's bytes")
	}
	// A request without its request ID is a malformed request (a violation), never answered.
	malformed, _ := proto.Marshal(&relayv1.RelayFrame{FrameVersion: proto.Uint32(1), FrameSeq: proto.Uint64(1),
		Frame: &relayv1.RelayFrame_RelayNonceRequest{RelayNonceRequest: &relayv1.RelayNonceRequest{}}})
	if value, err := (RelayCodec{}).Decode(malformed); err != nil || value.requestOK {
		t.Fatal("a nonce request without request_id")
	}
}
