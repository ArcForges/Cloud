// SPDX-License-Identifier: AGPL-3.0-only

package ingress

import (
	"math"

	"github.com/ArcForges/Cloud/center/internal/correlation"
)

// The fields the pipeline reads (wire registry 04): RequestMeta is field 1 of every generated request message that carries
// one; its correlation id, workspace id and recovery generation are fields 3, 4 and 7; an Id's value is its field 1.
const (
	metaField               = 1
	correlationField        = 3
	workspaceField          = 4
	recoveryGenerationField = 7
	idValueField            = 1
	idByteLength            = 16
)

// Protobuf wire types.
const (
	wireVarint          = 0
	wireFixed64         = 1
	wireLengthDelimited = 2
	wireFixed32         = 5
)

// Envelope is what the pipeline needs from the request envelope: the addressed workspace, the caller-stated recovery
// generation and the caller-stated correlation id (canonical lowercase UUID, validated). The correlation id is diagnostic
// only and never an input to the owner decision.
type Envelope struct {
	WorkspaceID           string
	RecoveryGeneration    uint64
	HasRecoveryGeneration bool
	CorrelationID         string
}

// ReadEnvelope reads RequestMeta straight from the protobuf bytes of a request message, so the owner gate needs no
// per-method generated type. It is strict, exactly as the C# RequestEnvelopeReader: a repeated meta, a repeated workspace,
// generation or correlation id, an Id that is not exactly 16 nonzero bytes, a group, a truncated field or a wrong wire type
// is malformed. Other fields are skipped.
func ReadEnvelope(message []byte) (Envelope, bool) {
	var envelope Envelope
	seenMeta := false
	position := 0
	for position < len(message) {
		field, wire, ok := readTag(message, &position)
		if !ok {
			return Envelope{}, false
		}
		if field != metaField {
			if !skip(message, &position, wire) {
				return Envelope{}, false
			}
			continue
		}
		if wire != wireLengthDelimited || seenMeta {
			return Envelope{}, false
		}
		meta, ok := readLengthDelimited(message, &position)
		if !ok {
			return Envelope{}, false
		}
		if envelope, ok = readMeta(meta); !ok {
			return Envelope{}, false
		}
		seenMeta = true
	}
	return envelope, true
}

func readMeta(meta []byte) (Envelope, bool) {
	var envelope Envelope
	seenCorrelation, seenWorkspace := false, false
	position := 0
	for position < len(meta) {
		field, wire, ok := readTag(meta, &position)
		if !ok {
			return Envelope{}, false
		}
		switch field {
		case correlationField:
			if wire != wireLengthDelimited || seenCorrelation {
				return Envelope{}, false
			}
			id, ok := readLengthDelimited(meta, &position)
			if !ok {
				return Envelope{}, false
			}
			if envelope.CorrelationID, ok = readID(id); !ok {
				return Envelope{}, false
			}
			seenCorrelation = true
		case workspaceField:
			if wire != wireLengthDelimited || seenWorkspace {
				return Envelope{}, false
			}
			id, ok := readLengthDelimited(meta, &position)
			if !ok {
				return Envelope{}, false
			}
			if envelope.WorkspaceID, ok = readID(id); !ok {
				return Envelope{}, false
			}
			seenWorkspace = true
		case recoveryGenerationField:
			if wire != wireVarint || envelope.HasRecoveryGeneration {
				return Envelope{}, false
			}
			value, ok := readVarint(meta, &position)
			if !ok {
				return Envelope{}, false
			}
			envelope.RecoveryGeneration, envelope.HasRecoveryGeneration = value, true
		default:
			if !skip(meta, &position, wire) {
				return Envelope{}, false
			}
		}
	}
	return envelope, true
}

func readID(id []byte) (string, bool) {
	var value []byte
	seen := false
	position := 0
	for position < len(id) {
		field, wire, ok := readTag(id, &position)
		if !ok {
			return "", false
		}
		if field != idValueField {
			if !skip(id, &position, wire) {
				return "", false
			}
			continue
		}
		if wire != wireLengthDelimited || seen {
			return "", false
		}
		if value, ok = readLengthDelimited(id, &position); !ok {
			return "", false
		}
		seen = true
	}
	if len(value) != idByteLength || allZero(value) {
		return "", false
	}
	return correlation.FormatID(value), true
}

// readTag reads a field tag; a field number of zero or above the int32 range is refused.
func readTag(data []byte, position *int) (field int, wire int, ok bool) {
	tag, ok := readVarint(data, position)
	if !ok || tag>>3 == 0 || tag>>3 > math.MaxInt32 {
		return 0, 0, false
	}
	return int(tag >> 3), int(tag & 7), true
}

// readVarint reads a base-128 varint of at most ten bytes whose value fits 64 bits.
func readVarint(data []byte, position *int) (uint64, bool) {
	var value uint64
	for shift := 0; shift < 70; shift += 7 {
		if *position >= len(data) {
			return 0, false
		}
		b := data[*position]
		*position++
		if shift == 63 && b > 1 {
			return 0, false
		}
		value |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return value, true
		}
	}
	return 0, false
}

func readLengthDelimited(data []byte, position *int) ([]byte, bool) {
	length, ok := readVarint(data, position)
	if !ok || length > uint64(len(data)-*position) {
		return nil, false
	}
	body := data[*position : *position+int(length)]
	*position += int(length)
	return body, true
}

// skip passes over one field of a known wire type; groups and unknown wire types are refused.
func skip(data []byte, position *int, wire int) bool {
	switch wire {
	case wireVarint:
		_, ok := readVarint(data, position)
		return ok
	case wireFixed64:
		return advance(data, position, 8)
	case wireLengthDelimited:
		_, ok := readLengthDelimited(data, position)
		return ok
	case wireFixed32:
		return advance(data, position, 4)
	default:
		return false
	}
}

func advance(data []byte, position *int, count int) bool {
	if len(data)-*position < count {
		return false
	}
	*position += count
	return true
}

func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}
