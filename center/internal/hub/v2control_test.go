// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/management"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

const v2ControlVectorDeadline = 1780000000000

func TestV2ControlStoreSnapshotUsesDecodedCredential(t *testing.T) {
	secret := session.Secret{1, 2, 3}
	textHash := sha256.Sum256([]byte(secret.Token(session.AccessPrefix)))
	storedHash := secret.Digest()
	if textHash == storedHash {
		t.Fatal("the fixture did not distinguish the wire and stored representations")
	}
	c := conn{hub: &Hub{}, tokenDigest: textHash, v2AccessHash: storedHash}
	snapshot, err := c.checkV2ControlStore(context.Background(), management.V2ControlAuthority{})
	if snapshot != storedHash || err != management.ErrV2ControlUnavailable {
		t.Fatal("control did not sample the stored form of the bound access credential")
	}
}

func v2ControlVectorID(value byte) platform.ID {
	var id platform.ID
	for i := range id {
		id[i] = value
	}
	return id
}

func v2ControlVectorRequest() v2ControlRequest {
	return v2ControlRequest{
		CallID: v2ControlVectorID(0x11), Selector: v2ControlStartRun, AccountID: v2ControlVectorID(0x22),
		ActorID: v2ControlVectorID(0x33), NodeID: v2ControlVectorID(0x44), EnrollmentID: v2ControlVectorID(0x55),
		ProtocolEpoch: v2ControlVectorID(0x66), ConnectionID: v2ControlVectorID(0x77), OriginalOwnerEpoch: v2ControlVectorID(0x88),
		CommandID: v2ControlVectorID(0x99), GrantID: v2ControlVectorID(0xaa), GrantRevision: 0x0102030405060708, HubFence: 19,
		DeadlineUnixMillis: v2ControlVectorDeadline, KID: "relay.fixture-1", Body: []byte{0x0a, 0x02, 0x0a, 0x00},
		AudienceSHA256: sha256.Sum256([]byte("https://center.example.test/managed")),
	}
}

func v2ControlInertSignature([]byte) ([]byte, error) {
	signature := make([]byte, 64)
	signature[31], signature[63] = 1, 2
	return signature, nil
}

func TestV2ControlWireMatchesExactPeerVector(t *testing.T) {
	const wantBinding = "3701dce54ed2deef91eb714b0fb51df87bc918a6ce4f8a65a91f5ca6999b0253"
	const wantResultInput = "ebe5152f7615826cf8c3b1c6b33f405962e296b2108e90893d6be421105f895a"
	const wantRequestFrame = "18e679c4a39177c99326ff11a1f12118443d06689993850147a3c89faa5b79ce"
	const wantResultFrame = "d27efbd9ce723c7e19cb1dde666d9f8f60945a0ca77487f2b2e760347b7ce063"
	request := v2ControlVectorRequest()
	now := time.UnixMilli(v2ControlVectorDeadline - 1)
	frame, binding, err := encodeV2ControlRequest(3, request, 1024, now, func(input []byte) ([]byte, error) {
		if hash := fmt.Sprintf("%x", sha256.Sum256(input)); hash != wantBinding {
			t.Fatalf("request signer got metadata hash %s", hash)
		}
		return v2ControlInertSignature(input)
	})
	if err != nil || fmt.Sprintf("%x", binding) != wantBinding || fmt.Sprintf("%x", sha256.Sum256(frame)) != wantRequestFrame {
		t.Fatalf("request bytes did not match the peer vector: binding %x, frame hash %x, %v", binding, sha256.Sum256(frame), err)
	}
	decoded, err := decodeV2ControlRequest(frame, 3, len(frame), now)
	signature, _ := v2ControlInertSignature(nil)
	if err != nil || !reflect.DeepEqual(decoded.v2ControlRequest, request) || decoded.RequestBinding != binding ||
		decoded.BodySHA256 != sha256.Sum256(request.Body) || !bytes.Equal(decoded.Signature[:], signature) || sha256.Sum256(decoded.SigningInput) != binding {
		t.Fatalf("request observation did not match signed bytes: %v", err)
	}

	result := v2ControlResult{CallID: request.CallID, RequestBinding: binding, Body: []byte{0x12, 0x00}}
	resultFrame, err := encodeV2ControlResult(9, v2ControlStartRun, result, 1024, func(input []byte) ([]byte, error) {
		if hash := fmt.Sprintf("%x", sha256.Sum256(input)); hash != wantResultInput {
			t.Fatalf("result signer got metadata hash %s", hash)
		}
		return v2ControlInertSignature(input)
	})
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(resultFrame)) != wantResultFrame {
		t.Fatalf("result bytes did not match the peer vector: frame hash %x, %v", sha256.Sum256(resultFrame), err)
	}
	observed, err := decodeV2ControlResult(resultFrame, v2ControlResultKind, 9, len(resultFrame))
	if err != nil || !reflect.DeepEqual(observed.v2ControlResult, result) || observed.BodySHA256 != sha256.Sum256(result.Body) ||
		!bytes.Equal(observed.Signature[:], signature) || fmt.Sprintf("%x", sha256.Sum256(observed.SigningInput)) != wantResultInput {
		t.Fatalf("result observation did not match signed bytes: %v", err)
	}
	clear(resultFrame)
	if !bytes.Equal(observed.Body, result.Body) || fmt.Sprintf("%x", sha256.Sum256(observed.SigningInput)) != wantResultInput {
		t.Fatal("received bytes changed after the validated frame was released")
	}
}

func TestV2ControlWireChecksDirectionFrameBoundAndExactBody(t *testing.T) {
	now := time.UnixMilli(v2ControlVectorDeadline - 1000)
	request := v2ControlVectorRequest()
	frame, binding, err := encodeV2ControlRequest(3, request, 1024, now, v2ControlInertSignature)
	if err != nil {
		t.Fatal(err)
	}
	const header = 10
	for _, tc := range []struct {
		name string
		edit func([]byte)
	}{
		{"version", func(value []byte) { value[0] = 1 }},
		{"direction", func(value []byte) { value[1] = 8 }},
		{"sequence", func(value []byte) { binary.BigEndian.PutUint64(value[2:10], 2) }},
		{"unknown method", func(value []byte) { value[header+16] = byte(v2DataCloseTransfer + 1) }},
		{"zero grant revision", func(value []byte) { clear(value[header+161 : header+169]) }},
		{"unsigned grant revision", func(value []byte) { value[header+161] = 0x80 }},
		{"unsigned fence", func(value []byte) { value[header+169] = 0x80 }},
		{"negative deadline", func(value []byte) { value[header+177] = 0x80 }},
		{"empty kid", func(value []byte) { value[header+249] = 0 }},
		{"oversize kid", func(value []byte) { value[header+249] = 65 }},
		{"bad kid", func(value []byte) { value[header+250] = '/' }},
		{"wrong request digest", func(value []byte) { value[header+217] ^= 1 }},
		{"wrong request body", func(value []byte) { value[len(value)-64-1] ^= 1 }},
		{"zero declared length", func(value []byte) { clear(value[header+250+len(request.KID) : header+254+len(request.KID)]) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := bytes.Clone(frame)
			tc.edit(changed)
			if _, err := decodeV2ControlRequest(changed, 3, len(changed), now); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	for _, offset := range []int{0, 17, 33, 49, 65, 81, 97, 113, 129, 145} {
		changed := bytes.Clone(frame)
		clear(changed[header+offset : header+offset+16])
		if _, err := decodeV2ControlRequest(changed, 3, len(changed), now); err == nil {
			t.Fatalf("zero request ID at metadata offset %d accepted", offset)
		}
	}
	if _, err := decodeV2ControlRequest(frame, 3, len(frame)-1, now); err == nil {
		t.Fatal("the request exceeded the negotiated full-frame bound")
	}
	if _, err := decodeV2ControlRequest(frame, 3, len(frame), time.UnixMilli(v2ControlVectorDeadline)); err == nil {
		t.Fatal("the request was admitted at its expiry time")
	}
	if _, _, err := encodeV2ControlRequest(3, request, len(frame)-1, now, v2ControlInertSignature); err == nil {
		t.Fatal("request encoder exceeded the negotiated full-frame bound")
	}

	result := v2ControlResult{CallID: request.CallID, RequestBinding: binding, Body: []byte{0x12, 0}}
	resultFrame, err := encodeV2ControlResult(9, v2ControlStartRun, result, 1024, v2ControlInertSignature)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func([]byte)
	}{
		{"direction", func(value []byte) { value[1] = 7 }},
		{"sequence", func(value []byte) { binary.BigEndian.PutUint64(value[2:10], 8) }},
		{"call ID", func(value []byte) { clear(value[header : header+16]) }},
		{"length", func(value []byte) { binary.BigEndian.PutUint32(value[header+48:header+52], 0xffffffff) }},
		{"digest", func(value []byte) { value[header+52] ^= 1 }},
		{"body", func(value []byte) { value[header+84] ^= 1 }},
	} {
		t.Run("result "+tc.name, func(t *testing.T) {
			changed := bytes.Clone(resultFrame)
			tc.edit(changed)
			if _, err := decodeV2ControlResult(changed, v2ControlResultKind, 9, len(changed)); err == nil {
				t.Fatal("invalid result accepted")
			}
		})
	}
	if _, err := decodeV2ControlResult(append(bytes.Clone(resultFrame), 0), v2ControlResultKind, 9, 1024); err == nil {
		t.Fatal("result accepted with trailing bytes")
	}
	if _, err := encodeV2ControlResult(9, v2ControlStartRun, result, len(resultFrame)-1, v2ControlInertSignature); err == nil {
		t.Fatal("result encoder exceeded the negotiated full-frame bound")
	}
	if _, err := encodeV2ControlResult(9, v2ControlStartRun, result, 1024, func([]byte) ([]byte, error) { return make([]byte, 63), nil }); err == nil {
		t.Fatal("encoder accepted a short P1363 signature")
	}
}

func TestV2ControlWireRequiresSelectorSpecificCommandID(t *testing.T) {
	now := time.UnixMilli(v2ControlVectorDeadline - 1000)
	for selector, requiresID := range []bool{
		true, false, true, true, true, false, false, true, true, false, false, false, true,
	} {
		request := v2ControlVectorRequest()
		request.Selector = v2ControlSelector(selector + 1)
		if !requiresID {
			request.CommandID = platform.ID{}
		}
		frame, _, err := encodeV2ControlRequest(3, request, 1024, now, v2ControlInertSignature)
		if err != nil {
			t.Fatalf("selector %d refused its allowed command ID: %v", selector+1, err)
		}
		const commandOffset = 10 + 129
		if requiresID {
			clear(frame[commandOffset : commandOffset+16])
		} else {
			frame[commandOffset] = 1
		}
		if _, err := decodeV2ControlRequest(frame, 3, len(frame), now); err == nil {
			t.Fatalf("selector %d accepted a command ID with wrong presence", selector+1)
		}
	}
}

func TestV2ControlWireLeavesKeyVerificationToCaller(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(v2ControlVectorDeadline - 1)
	frame, binding, err := encodeV2ControlRequest(3, v2ControlVectorRequest(), 1024, now,
		func(message []byte) ([]byte, error) { return signES256(key, message) })
	if err != nil {
		t.Fatal(err)
	}
	request, err := decodeV2ControlRequest(frame, 3, len(frame), now)
	if err != nil || request.RequestBinding != binding || !verifyES256(public, request.SigningInput, request.Signature[:]) {
		t.Fatalf("verified key did not bind the request bytes: %v", err)
	}
	frame[10+17] ^= 1 // metadata stays structurally legal and keeps the same body digest
	altered, err := decodeV2ControlRequest(frame, 3, len(frame), now)
	if err != nil || altered.RequestBinding == binding || verifyES256(public, altered.SigningInput, altered.Signature[:]) {
		t.Fatal("structural parsing was mistaken for authority over altered metadata")
	}
}
