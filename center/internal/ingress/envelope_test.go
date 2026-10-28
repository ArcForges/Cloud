// SPDX-License-Identifier: AGPL-3.0-only

package ingress

import (
	"bytes"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/correlation"
)

var (
	correlationBytes = []byte{0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36}
	workspaceBytes   = []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x4d, 0xef, 0x80, 0x00, 0, 0, 0, 0, 0, 0x01}
)

// request is a request message whose field 1 is meta, followed by one unrelated field, as generated requests are.
func request(meta []byte) []byte {
	message := protowire.AppendTag(nil, metaField, protowire.BytesType)
	message = protowire.AppendBytes(message, meta)
	message = protowire.AppendTag(message, 2, protowire.BytesType)
	return protowire.AppendString(message, "payload")
}

func marshal(t testing.TB, message proto.Message) []byte {
	t.Helper()
	data, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func idField(field protowire.Number, value []byte) []byte {
	id := protowire.AppendTag(nil, idValueField, protowire.BytesType)
	id = protowire.AppendBytes(id, value)
	data := protowire.AppendTag(nil, field, protowire.BytesType)
	return protowire.AppendBytes(data, id)
}

// repeatedIDValue is a correlation Id whose value field occurs twice.
func repeatedIDValue() []byte {
	value := protowire.AppendBytes(protowire.AppendTag(nil, idValueField, protowire.BytesType), correlationBytes)
	id := append(append([]byte(nil), value...), value...)
	return protowire.AppendBytes(protowire.AppendTag(nil, correlationField, protowire.BytesType), id)
}

func TestTheEnvelopeIsReadFromTheGeneratedBytes(t *testing.T) {
	generation := uint64(7)
	meta := marshal(t, &foundationv1.RequestMeta{
		CommandId:          &foundationv1.Id{Value: workspaceBytes},
		CorrelationId:      &foundationv1.Id{Value: correlationBytes},
		WorkspaceId:        &foundationv1.Id{Value: workspaceBytes},
		RecoveryGeneration: &generation,
		ApplicationScope:   &foundationv1.ApplicationScope{},
	})
	envelope, ok := ReadEnvelope(request(meta))
	if !ok {
		t.Fatal("a generated envelope was refused")
	}
	if envelope.CorrelationID != "4bf92f35-77b3-4da6-a3ce-929d0e0e4736" || envelope.WorkspaceID != correlation.FormatID(workspaceBytes) ||
		!envelope.HasRecoveryGeneration || envelope.RecoveryGeneration != 7 {
		t.Fatalf("envelope: %+v", envelope)
	}
	if empty, ok := ReadEnvelope(protowire.AppendString(protowire.AppendTag(nil, 2, protowire.BytesType), "x")); !ok || empty != (Envelope{}) {
		t.Fatal("a message without meta has an empty envelope")
	}
}

func TestAMalformedEnvelopeIsRefused(t *testing.T) {
	valid := idField(correlationField, correlationBytes)
	cases := map[string][]byte{
		"repeated meta":            append(request(valid), request(valid)...),
		"meta of the wrong wire":   protowire.AppendVarint(protowire.AppendTag(nil, metaField, protowire.VarintType), 1),
		"repeated correlation":     request(append(append([]byte(nil), valid...), valid...)),
		"short correlation":        request(idField(correlationField, correlationBytes[:15])),
		"long correlation":         request(idField(correlationField, append(append([]byte(nil), correlationBytes...), 1))),
		"nil correlation":          request(idField(correlationField, make([]byte, 16))),
		"repeated workspace":       request(append(idField(workspaceField, workspaceBytes), idField(workspaceField, workspaceBytes)...)),
		"repeated generation":      request(protowire.AppendVarint(protowire.AppendTag(protowire.AppendVarint(protowire.AppendTag(nil, recoveryGenerationField, protowire.VarintType), 1), recoveryGenerationField, protowire.VarintType), 1)),
		"generation as bytes":      request(protowire.AppendBytes(protowire.AppendTag(nil, recoveryGenerationField, protowire.BytesType), []byte{1})),
		"group":                    request(protowire.AppendTag(nil, 9, protowire.StartGroupType)),
		"truncated length":         {0x0a, 0x05, 0x1a},
		"truncated varint":         {0x10, 0x80},
		"field number zero":        {0x00, 0x01},
		"eleven byte varint":       append([]byte{0x10}, bytes.Repeat([]byte{0xff}, 10)...),
		"varint over 64 bits":      {0x10, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02},
		"repeated id value":        request(repeatedIDValue()),
		"fixed32 cut short":        {0x15, 0x01, 0x02},
		"fixed64 cut short":        {0x11, 0x01, 0x02, 0x03, 0x04},
		"field number over int32":  protowire.AppendVarint(nil, uint64(1)<<34),
		"unknown wire type 6 or 7": {0x0e},
	}
	for name, message := range cases {
		if _, ok := ReadEnvelope(message); ok {
			t.Errorf("%s was accepted", name)
		}
	}
	// A correlation id carried with an unknown field inside the Id is still read.
	extended := protowire.AppendTag(nil, 2, protowire.VarintType)
	extended = protowire.AppendVarint(extended, 5)
	extended = protowire.AppendTag(extended, idValueField, protowire.BytesType)
	extended = protowire.AppendBytes(extended, correlationBytes)
	meta := protowire.AppendBytes(protowire.AppendTag(nil, correlationField, protowire.BytesType), extended)
	if envelope, ok := ReadEnvelope(request(meta)); !ok || envelope.CorrelationID == "" {
		t.Fatal("an unknown field inside the Id refused the envelope")
	}
	// The largest generation that fits 64 bits is read.
	maximum := request(protowire.AppendVarint(protowire.AppendTag(nil, recoveryGenerationField, protowire.VarintType), ^uint64(0)))
	if envelope, ok := ReadEnvelope(maximum); !ok || envelope.RecoveryGeneration != ^uint64(0) {
		t.Fatal("the largest generation was refused")
	}
}

// FuzzReadEnvelope checks that the strict reader never panics, never yields an invalid identity, and agrees with the generated
// protobuf decoder whenever both accept the same bytes.
func FuzzReadEnvelope(f *testing.F) {
	generation := uint64(3)
	f.Add(request(marshal(f, &foundationv1.RequestMeta{CorrelationId: &foundationv1.Id{Value: correlationBytes}, WorkspaceId: &foundationv1.Id{Value: workspaceBytes}, RecoveryGeneration: &generation})))
	f.Add(request(idField(correlationField, make([]byte, 16))))
	f.Add([]byte{0x0a, 0x00})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, message []byte) {
		envelope, ok := ReadEnvelope(message)
		if !ok {
			return
		}
		for _, id := range []string{envelope.CorrelationID, envelope.WorkspaceID} {
			if id != "" && !correlation.IsValidID(id) {
				t.Fatalf("invalid identity %q", id)
			}
		}
		position := 0
		for position < len(message) {
			field, wire, _ := readTag(message, &position)
			if field != metaField {
				skip(message, &position, wire)
				continue
			}
			meta, _ := readLengthDelimited(message, &position)
			var decoded foundationv1.RequestMeta
			if proto.Unmarshal(meta, &decoded) != nil {
				return // the generated decoder also validates nested messages the reader skips
			}
			if got := decoded.GetCorrelationId().GetValue(); envelope.CorrelationID != "" && correlation.FormatID(got) != envelope.CorrelationID {
				t.Fatalf("correlation differs from the generated decoder")
			}
			if got := decoded.GetWorkspaceId().GetValue(); envelope.WorkspaceID != "" && correlation.FormatID(got) != envelope.WorkspaceID {
				t.Fatalf("workspace differs from the generated decoder")
			}
			if envelope.HasRecoveryGeneration != (decoded.RecoveryGeneration != nil) || envelope.RecoveryGeneration != decoded.GetRecoveryGeneration() {
				t.Fatalf("generation differs from the generated decoder")
			}
		}
	})
}
