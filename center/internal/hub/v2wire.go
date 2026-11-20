// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// Each private V2 channel message has version, kind and a direction-local
// uint64 sequence before its enrollment, lifecycle or typed control payload.
const (
	v2Challenge byte = iota + 1
	v2Hello
	v2Accepted
	v2Heartbeat
	v2Refresh
	v2Close
)

const (
	v2Version       = 2
	v2HeaderBytes   = 10
	v2SignatureSize = 64
	v2HelloDomain   = "ArcForges relay-hello v2\n"
	v2Cohort        = "cohort-ci.481.1"
)

var (
	v2NodeEpoch = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	errNoV2Call = errors.New("the V2 enrollment channel does not carry routed effects")
)

type v2Codec struct {
	enrollment, epoch, account platform.ID
	fence                      int64
	challenge                  []byte
	inboundSeq                 uint64
	maxFrameBytes              int
}

func (v *v2Codec) Decode(data []byte) (inbound, error) {
	if len(data) < v2HeaderBytes || data[0] != v2Version || v.inboundSeq == math.MaxUint64 ||
		binary.BigEndian.Uint64(data[2:10]) != v.inboundSeq+1 {
		return inbound{}, errFrame
	}
	v.inboundSeq++
	body := data[v2HeaderBytes:]
	switch data[1] {
	case v2Hello:
		claim, ok := decodeV2Hello(body)
		if !ok {
			return inbound{}, errFrame
		}
		return inbound{kind: inboundHello, hello: claim}, nil
	case v2Heartbeat:
		if len(body) != 8 || binary.BigEndian.Uint64(body) == 0 {
			return inbound{}, errFrame
		}
		return inbound{kind: inboundHeartbeat}, nil
	case v2Refresh:
		if len(body) == 0 || len(body) > maxTokenBytes || !visibleASCII(body) {
			return inbound{}, errFrame
		}
		return inbound{kind: inboundTokenRefresh, token: string(body)}, nil
	case v2Close:
		if len(body) < 8 || len(body) > 72 || !visibleASCII(body[8:]) {
			return inbound{}, errFrame
		}
		return inbound{kind: inboundClose, closeCode: binary.BigEndian.Uint32(body[:4])}, nil
	case v2ControlResultKind, v2DataResultKind:
		kind, limit := data[1], v.maxFrameBytes
		if kind == v2DataResultKind {
			// The live reader already enforced the exact pending selector's bound.
			limit = v2DataMaxFrame
		}
		result, err := decodeV2ControlResult(data, kind, v.inboundSeq, limit)
		if err != nil {
			return inbound{}, err
		}
		return inbound{kind: inboundV2ControlResult, v2Result: result}, nil
	default:
		return inbound{}, errFrame
	}
}

func decodeV2Hello(body []byte) (hello, bool) {
	if len(body) < 51+v2SignatureSize {
		return hello{}, false
	}
	intent, signature := body[:len(body)-v2SignatureSize], body[len(body)-v2SignatureSize:]
	var claim hello
	copy(claim.NodeID[:], intent[:16])
	copy(claim.InstallationID[:], intent[16:32])
	copy(claim.ownerEpoch[:], intent[32:48])
	epochLen := int(intent[48])
	if claim.NodeID == (platform.ID{}) || claim.InstallationID == (platform.ID{}) || claim.ownerEpoch == (platform.ID{}) || epochLen == 0 ||
		len(intent) < 51+epochLen {
		return hello{}, false
	}
	claim.nodeEpoch = string(intent[49 : 49+epochLen])
	if !v2NodeEpoch.MatchString(claim.nodeEpoch) {
		return hello{}, false
	}
	switch intent[49+epochLen] {
	case 1:
		claim.os = "windows"
	case 2:
		claim.os = "linux"
	default:
		return hello{}, false
	}
	count := int(intent[50+epochLen])
	if count > 16 {
		return hello{}, false
	}
	rest := intent[51+epochLen:]
	claim.Capabilities = make([]string, 0, count)
	for range count {
		if len(rest) == 0 || int(rest[0])+1 > len(rest) {
			return hello{}, false
		}
		end := int(rest[0]) + 1
		claim.Capabilities = append(claim.Capabilities, string(rest[1:end]))
		rest = rest[end:]
	}
	if len(rest) != 0 || !validCapabilities(claim.Capabilities) {
		return hello{}, false
	}
	claim.Signature, claim.v2Intent = signature, intent
	return claim, true
}

func visibleASCII(value []byte) bool {
	for _, ch := range value {
		if ch < 0x21 || ch > 0x7e {
			return false
		}
	}
	return true
}

func (v *v2Codec) helloMessage(centerURL string, intent []byte) []byte {
	audience := sha256.Sum256([]byte(centerURL))
	signed := make([]byte, 0, len(v2HelloDomain)+len(v.challenge)+len(audience)+len(intent))
	signed = append(signed, v2HelloDomain...)
	signed = append(signed, v.challenge...)
	signed = append(signed, audience[:]...)
	return append(signed, intent...)
}

func v2QualifiedClaims(claim hello) ([]string, bool) {
	cohort := false
	var qualified []string
	for _, capability := range claim.Capabilities {
		switch {
		case capability == v2Cohort:
			cohort = true
		case strings.HasPrefix(capability, "required."):
			return nil, false
		case claim.os == "windows" && (capability == "windows-process-executor-v1" || capability == "win-wrapper-local-v1"):
			qualified = append(qualified, capability)
		case claim.os == "linux" && capability == "linux-bubblewrap-sdk-v1":
			qualified = append(qualified, capability)
		}
	}
	return qualified, cohort
}

func v2Header(kind byte, seq uint64) []byte {
	return binary.BigEndian.AppendUint64([]byte{v2Version, kind}, seq)
}

func (v *v2Codec) Challenge(seq uint64, nonce []byte, connectionID platform.ID, deadline time.Time) ([]byte, error) {
	body := make([]byte, 0, 112)
	body = append(body, nonce...)
	body = append(body, connectionID[:]...)
	body = append(body, v.enrollment[:]...)
	body = append(body, v.epoch[:]...)
	body = append(body, v.account[:]...)
	body = binary.BigEndian.AppendUint64(body, uint64(v.fence))
	body = binary.BigEndian.AppendUint64(body, uint64(deadline.UnixMilli()))
	v.challenge = body
	return append(v2Header(v2Challenge, seq), body...), nil
}

func (v *v2Codec) Accepted(seq uint64, connectionID platform.ID, _ string, limits Limits, _ []string) ([]byte, error) {
	data := append(v2Header(v2Accepted, seq), connectionID[:]...)
	data = append(data, v.enrollment[:]...)
	data = append(data, v.epoch[:]...)
	data = binary.BigEndian.AppendUint64(data, uint64(v.fence))
	data = binary.BigEndian.AppendUint32(data, uint32(limits.MaxFrameBytes))
	data = binary.BigEndian.AppendUint32(data, uint32(limits.Heartbeat.Milliseconds()))
	return binary.BigEndian.AppendUint32(data, uint32(limits.HeartbeatDeadline.Milliseconds())), nil
}

func (*v2Codec) Heartbeat(seq uint64, at time.Time) ([]byte, error) {
	return binary.BigEndian.AppendUint64(v2Header(v2Heartbeat, seq), uint64(at.UnixMilli())), nil
}

func (*v2Codec) Close(seq uint64, code uint32, reason string, reconnectAfter time.Duration) ([]byte, error) {
	if len(reason) > 64 || !visibleASCII([]byte(reason)) {
		return nil, errFrame
	}
	data := binary.BigEndian.AppendUint32(v2Header(v2Close, seq), code)
	data = binary.BigEndian.AppendUint32(data, uint32(reconnectAfter.Milliseconds()))
	return append(data, reason...), nil
}

func (*v2Codec) Call(uint64, platform.ID, []byte, []byte, string, []byte) ([]byte, error) {
	return nil, errNoV2Call
}

func (*v2Codec) RelayNonce(uint64, platform.ID, []byte, time.Time) ([]byte, error) {
	return nil, errNoV2Call
}
