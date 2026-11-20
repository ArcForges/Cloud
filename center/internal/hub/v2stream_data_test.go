// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

func TestV2StreamAndDataWireMatchExactPeerVectors(t *testing.T) {
	for _, tc := range []struct {
		name             string
		selector         v2ControlSelector
		command          platform.ID
		resultBody       []byte
		requestKind      byte
		resultKind       byte
		binding          string
		resultInputHash  string
		requestFrameHash string
		resultFrameHash  string
	}{
		{
			name: "watch", selector: v2ControlWatchOutput, resultBody: []byte{1, 0x12, 0},
			requestKind: 7, resultKind: 8,
			binding:          "126d9abbf208582a45af1a64831f3d508accafad031a28b0193fbdf43f17cec0",
			resultInputHash:  "bb4a129c0297685688cc1547dcc549b83438ce91b071e55c720a8cb7d5e97c79",
			requestFrameHash: "8c3a206c07f116b8f39d5e3a54b21c30eb006df8c710eb5ed6aadbe4c502b5bf",
			resultFrameHash:  "c6cf764758ba96b0d060bc991f2549c7af324828681d6b64a5e131490ba3f6a3",
		},
		{
			name: "write", selector: v2DataWriteImport, command: v2ControlVectorID(0x99),
			resultBody: []byte{0x12, 0}, requestKind: 9, resultKind: 10,
			binding:          "f1df16e94a6af0236165eaad1c48ea4467b5c36cc476e0149c743ea8404f6319",
			resultInputHash:  "98825bf4f44e3207968563b8ea7c4854cb97adce6c095b92cc571caf9c000d1b",
			requestFrameHash: "0d6a92fda4dc338186c9c6aced5a5fc00a5223b0397d3d5d0acd657076fbba5f",
			resultFrameHash:  "4f767da3383510e52f4f58fcd42d68a72f3b2ce4464fac99d77846f168a3bc5e",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := v2ControlVectorRequest()
			request.Selector, request.CommandID = tc.selector, tc.command
			now := time.UnixMilli(v2ControlVectorDeadline - 1)
			frame, binding, err := encodeV2ControlRequest(3, request, 1024, now, v2ControlInertSignature)
			if err != nil || frame[1] != tc.requestKind || fmt.Sprintf("%x", binding) != tc.binding ||
				fmt.Sprintf("%x", sha256.Sum256(frame)) != tc.requestFrameHash {
				t.Fatalf("request differs from vector: %x %x %v", binding, sha256.Sum256(frame), err)
			}
			decoded, err := decodeV2ControlRequest(frame, 3, 1024, now)
			if err != nil || decoded.Selector != tc.selector || decoded.RequestBinding != binding {
				t.Fatalf("request could not be read: %v", err)
			}
			changed := bytes.Clone(frame)
			changed[1] = tc.resultKind
			if _, err := decodeV2ControlRequest(changed, 3, 1024, now); err == nil {
				t.Fatal("a result kind was accepted in the request direction")
			}
			result := v2ControlResult{CallID: request.CallID, RequestBinding: binding, Body: tc.resultBody}
			frame, err = encodeV2ControlResult(9, tc.selector, result, 1024, v2ControlInertSignature)
			if err != nil || frame[1] != tc.resultKind || fmt.Sprintf("%x", sha256.Sum256(frame)) != tc.resultFrameHash {
				t.Fatalf("result differs from vector: %x %v", sha256.Sum256(frame), err)
			}
			reply, err := decodeV2ControlResult(frame, tc.resultKind, 9, 1024)
			if err != nil || !bytes.Equal(reply.Body, tc.resultBody) ||
				fmt.Sprintf("%x", sha256.Sum256(reply.SigningInput)) != tc.resultInputHash {
				t.Fatalf("result could not be read: %v", err)
			}
		})
	}
}

func TestV2DataChunkBoundsApplyOnlyToWriteImportAndReadExport(t *testing.T) {
	const ordinary = 1 << 20
	request := v2ControlVectorRequest()
	request.Selector, request.Body = v2DataWriteImport, make([]byte, v2DataMaxBody)
	now := time.UnixMilli(v2ControlVectorDeadline - 1)
	frame, binding, err := encodeV2ControlRequest(3, request, ordinary, now, v2ControlInertSignature)
	if err != nil || len(frame) <= ordinary || len(frame) > v2DataMaxFrame {
		t.Fatalf("maximum WriteImport body: len %d, error %v", len(frame), err)
	}
	if _, err := decodeV2ControlRequest(frame, 3, ordinary, now); err != nil {
		t.Fatal(err)
	}
	frame[v2HeaderBytes+v2ControlIDSize] = byte(v2DataBeginImport)
	if _, err := decodeV2ControlRequest(frame, 3, ordinary, now); err == nil {
		t.Fatal("BeginImport accepted the WriteImport size")
	}
	request.Body = append(request.Body, 0)
	if _, _, err := encodeV2ControlRequest(3, request, ordinary, now, v2ControlInertSignature); err == nil {
		t.Fatal("oversize WriteImport body accepted")
	}

	result := v2ControlResult{CallID: request.CallID, RequestBinding: binding, Body: make([]byte, v2DataMaxBody)}
	frame, err = encodeV2ControlResult(1, v2DataReadExport, result, ordinary, v2ControlInertSignature)
	if err != nil || len(frame) <= ordinary || len(frame) > v2DataMaxFrame {
		t.Fatalf("maximum ReadExport body: len %d, error %v", len(frame), err)
	}
	if _, err := encodeV2ControlResult(1, v2DataWriteImport, result, ordinary, v2ControlInertSignature); err == nil {
		t.Fatal("WriteImport result accepted the ReadExport size")
	}
	c := &conn{hub: &Hub{settings: Settings{MaxFrameBytes: ordinary}}, v2: &v2Codec{maxFrameBytes: ordinary}, v2Ready: true,
		capabilities: map[string]bool{v2ControlCapability: true, v2StreamDataCapability: true}}
	pending := &pendingV2Control{id: result.CallID, started: true, binding: binding, selector: v2DataReadExport}
	c.v2Calls = map[platform.ID]*pendingV2Control{pending.id: pending}
	reader := bytes.NewReader(frame)
	if observed, err := c.readNodeFrame(reader, true); err != nil || !bytes.Equal(observed, frame) || reader.Len() != 0 {
		t.Fatalf("exact pending ReadExport: remaining %d, error %v", reader.Len(), err)
	}
	delete(c.v2Calls, pending.id)
	c.v2Late = []lateV2Control{{id: pending.id, binding: binding, selector: pending.selector}}
	if _, err := c.readNodeFrame(bytes.NewReader(frame), true); err != nil {
		t.Fatalf("exact late ReadExport could not be drained: %v", err)
	}
	c.v2Late = nil

	const prefixBytes = v2HeaderBytes + v2ControlResultLengthOffset + 4
	assertPrefixOnly := func(want error) {
		t.Helper()
		reader.Reset(frame)
		if _, err := c.readNodeFrame(reader, true); err != want || reader.Len() != len(frame)-prefixBytes {
			t.Fatalf("refusal read beyond bound: error %v, consumed %d", err, len(frame)-reader.Len())
		}
	}
	assertPrefixOnly(errFrame)
	c.v2Calls[pending.id] = pending
	pending.selector = v2DataWriteImport
	assertPrefixOnly(errNodeFrameTooLarge)
	pending.selector = v2DataReadExport
	pending.binding[0] ^= 1
	assertPrefixOnly(errFrame)
	pending.binding = binding
	delete(c.capabilities, v2StreamDataCapability)
	assertPrefixOnly(errFrame)
}

func TestV2WatchResultRequiresExactIdleOrFrameMarker(t *testing.T) {
	for _, bad := range [][]byte{nil, {0, 0x12}, {1}, {2, 0x12}} {
		if v2ControlWatchUsage.validResultBody(bad) {
			t.Fatalf("invalid result marker accepted: %x", bad)
		}
	}
	for _, good := range [][]byte{{0}, {1, 0x12}} {
		if !v2ControlWatchUsage.validResultBody(good) {
			t.Fatalf("valid result marker refused: %x", good)
		}
	}
}
