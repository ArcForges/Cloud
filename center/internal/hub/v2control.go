// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

const (
	v2ControlRequestKind        byte = 7
	v2ControlResultKind         byte = 8
	v2DataRequestKind           byte = 9
	v2DataResultKind            byte = 10
	v2ControlCapability              = "center-control-v2"
	v2StreamDataCapability           = "center-stream-data-v2"
	v2ControlRequestDomain           = "ArcForges relay-control-request v2\n"
	v2ControlResultDomain            = "ArcForges relay-control-result v2\n"
	v2ControlIDSize                  = len(platform.ID{})
	v2ControlMaxKID                  = 64
	v2ControlRequestKIDOffset        = 10*v2ControlIDSize + 1 + 3*8 + 2*sha256.Size
	v2ControlRequestFixed            = v2ControlRequestKIDOffset + 1 + 4
	v2ControlResultLengthOffset      = v2ControlIDSize + sha256.Size
	v2ControlResultDigestOffset      = v2ControlResultLengthOffset + 4
	v2ControlResultFixed             = v2ControlResultDigestOffset + sha256.Size
	v2DataMaxBody                    = 2 << 20
	v2DataMaxFrame                   = v2DataMaxBody + 512
)

type v2ControlSelector byte

const (
	v2ControlGetOperation v2ControlSelector = iota + 1
	v2ControlListRemoteGrants
	v2ControlRevokeRemoteGrant
	v2ControlCreateSandbox
	v2ControlConfigureSandbox
	v2ControlListSandboxes
	v2ControlInspectSandbox
	v2ControlStartRun
	v2ControlStopRun
	v2ControlListRuns
	v2ControlInspectRun
	v2ControlGetBudget
	v2ControlSetPolicy
	v2ControlWatchOutput
	v2ControlWatchEvents
	v2ControlWatchUsage
	v2DataBeginImport
	v2DataWriteImport
	v2DataCommitImport
	v2DataBeginExport
	v2DataReadExport
	v2DataInspectTransfer
	v2DataCloseTransfer
)

func (s v2ControlSelector) known() bool {
	return s >= v2ControlGetOperation && s <= v2DataCloseTransfer
}

func (s v2ControlSelector) watch() bool {
	return s >= v2ControlWatchOutput && s <= v2ControlWatchUsage
}

func (s v2ControlSelector) data() bool {
	return s >= v2DataBeginImport && s <= v2DataCloseTransfer
}

func (s v2ControlSelector) requestKind() byte {
	if s.data() {
		return v2DataRequestKind
	}
	return v2ControlRequestKind
}

func (s v2ControlSelector) resultKind() byte {
	if s.data() {
		return v2DataResultKind
	}
	return v2ControlResultKind
}

func (s v2ControlSelector) requestLimit(ordinaryLimit int) int {
	if s == v2DataWriteImport {
		return v2DataMaxFrame
	}
	return ordinaryLimit
}

func (s v2ControlSelector) resultLimit(ordinaryLimit int) int {
	if s == v2DataReadExport {
		return v2DataMaxFrame
	}
	return ordinaryLimit
}

func (s v2ControlSelector) validResultBody(body []byte) bool {
	if !s.watch() {
		return len(body) != 0
	}
	return len(body) == 1 && body[0] == 0 || len(body) > 1 && body[0] == 1
}

func (s v2ControlSelector) requiresCommandID() bool {
	switch s {
	case v2ControlGetOperation, v2ControlRevokeRemoteGrant, v2ControlCreateSandbox, v2ControlConfigureSandbox,
		v2ControlStartRun, v2ControlStopRun, v2ControlSetPolicy, v2DataBeginImport, v2DataWriteImport,
		v2DataCommitImport, v2DataBeginExport, v2DataCloseTransfer:
		return true
	default:
		return false
	}
}

type v2ControlRequest struct {
	CallID             platform.ID
	Selector           v2ControlSelector
	AccountID          platform.ID
	ActorID            platform.ID
	NodeID             platform.ID
	EnrollmentID       platform.ID
	ProtocolEpoch      platform.ID
	ConnectionID       platform.ID
	OriginalOwnerEpoch platform.ID
	CommandID          platform.ID
	GrantID            platform.ID
	GrantRevision      int64
	HubFence           int64
	DeadlineUnixMillis int64
	AudienceSHA256     [sha256.Size]byte
	KID                string
	Body               []byte
}

type v2ControlResult struct {
	CallID         platform.ID
	RequestBinding [sha256.Size]byte
	Body           []byte
}

// A decoded frame has passed structural and body-digest checks only. The caller must verify the
// signature over SigningInput with the expected key and bind all claims to its live authority.
type v2SignedControlRequest struct {
	v2ControlRequest
	BodySHA256     [sha256.Size]byte
	RequestBinding [sha256.Size]byte
	SigningInput   []byte
	Signature      [v2SignatureSize]byte
}

type v2SignedControlResult struct {
	v2ControlResult
	Kind         byte
	BodySHA256   [sha256.Size]byte
	SigningInput []byte
	Signature    [v2SignatureSize]byte
}

func (r v2ControlRequest) validMetadata(now time.Time) bool {
	zero := platform.ID{}
	return r.Selector.known() &&
		r.Selector.requiresCommandID() == (r.CommandID != zero) &&
		r.CallID != zero && r.AccountID != zero && r.ActorID != zero && r.NodeID != zero &&
		r.EnrollmentID != zero && r.ProtocolEpoch != zero && r.ConnectionID != zero &&
		r.OriginalOwnerEpoch != zero && r.GrantID != zero && r.GrantRevision > 0 && r.HubFence > 0 &&
		!now.IsZero() && r.DeadlineUnixMillis > 0 && r.DeadlineUnixMillis > now.UnixMilli() && validV2ControlKID(r.KID)
}

func validV2ControlKID(kid string) bool {
	if len(kid) == 0 || len(kid) > v2ControlMaxKID {
		return false
	}
	for i := range len(kid) {
		ch := kid[i]
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' ||
			ch == '.' || ch == '_' || ch == '-') {
			return false
		}
	}
	return true
}

func encodeV2ControlRequest(seq uint64, request v2ControlRequest, maxFrameBytes int, now time.Time,
	sign func([]byte) ([]byte, error)) ([]byte, [sha256.Size]byte, error) {
	if seq == 0 || sign == nil || !request.validMetadata(now) ||
		!v2ControlFrameFits(request.Selector.requestLimit(maxFrameBytes), v2ControlRequestFixed+len(request.KID), len(request.Body)) {
		return nil, [sha256.Size]byte{}, errFrame
	}
	body := bytes.Clone(request.Body)
	digest := sha256.Sum256(body)
	metadata := make([]byte, 0, v2ControlRequestFixed+len(request.KID))
	metadata = append(metadata, request.CallID[:]...)
	metadata = append(metadata, byte(request.Selector))
	for _, id := range [...]platform.ID{request.AccountID, request.ActorID, request.NodeID, request.EnrollmentID,
		request.ProtocolEpoch, request.ConnectionID, request.OriginalOwnerEpoch, request.CommandID, request.GrantID} {
		metadata = append(metadata, id[:]...)
	}
	metadata = binary.BigEndian.AppendUint64(metadata, uint64(request.GrantRevision))
	metadata = binary.BigEndian.AppendUint64(metadata, uint64(request.HubFence))
	metadata = binary.BigEndian.AppendUint64(metadata, uint64(request.DeadlineUnixMillis))
	metadata = append(metadata, request.AudienceSHA256[:]...)
	metadata = append(metadata, digest[:]...)
	metadata = append(metadata, byte(len(request.KID)))
	metadata = append(metadata, request.KID...)
	metadata = binary.BigEndian.AppendUint32(metadata, uint32(len(body)))
	input := v2ControlSigningInput(v2ControlRequestDomain, metadata)
	binding := sha256.Sum256(input)
	frame, err := encodeV2SignedControlFrame(request.Selector.requestKind(), seq, metadata, body, input, sign)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	return frame, binding, nil
}

func decodeV2ControlRequest(frame []byte, expectedSequence uint64, maxFrameBytes int, now time.Time) (v2SignedControlRequest, error) {
	if len(frame) < v2HeaderBytes+v2ControlIDSize+1 {
		return v2SignedControlRequest{}, errFrame
	}
	selector := v2ControlSelector(frame[v2HeaderBytes+v2ControlIDSize])
	payload, ok := v2ControlPayload(frame, selector.requestKind(), expectedSequence, selector.requestLimit(maxFrameBytes), v2ControlRequestFixed+1)
	if !ok {
		return v2SignedControlRequest{}, errFrame
	}
	kidLen := int(payload[v2ControlRequestKIDOffset])
	metadataLen := v2ControlRequestFixed + kidLen
	if kidLen == 0 || kidLen > v2ControlMaxKID || len(payload) < metadataLen+v2SignatureSize+1 {
		return v2SignedControlRequest{}, errFrame
	}
	metadata := payload[:metadataLen]
	body, signature, ok := splitV2ControlPayload(payload, metadataLen, binary.BigEndian.Uint32(metadata[metadataLen-4:]))
	if !ok {
		return v2SignedControlRequest{}, errFrame
	}
	request := v2ControlRequest{Selector: selector,
		KID: string(metadata[v2ControlRequestKIDOffset+1 : metadataLen-4])}
	copy(request.CallID[:], metadata[:v2ControlIDSize])
	offset := v2ControlIDSize + 1
	for _, id := range [...]*platform.ID{&request.AccountID, &request.ActorID, &request.NodeID, &request.EnrollmentID,
		&request.ProtocolEpoch, &request.ConnectionID, &request.OriginalOwnerEpoch, &request.CommandID, &request.GrantID} {
		copy(id[:], metadata[offset:offset+v2ControlIDSize])
		offset += v2ControlIDSize
	}
	request.GrantRevision = int64(binary.BigEndian.Uint64(metadata[offset:]))
	request.HubFence = int64(binary.BigEndian.Uint64(metadata[offset+8:]))
	request.DeadlineUnixMillis = int64(binary.BigEndian.Uint64(metadata[offset+16:]))
	copy(request.AudienceSHA256[:], metadata[offset+24:offset+24+sha256.Size])
	if !request.validMetadata(now) || len(body) > v2DataMaxBody {
		return v2SignedControlRequest{}, errFrame
	}
	digest := sha256.Sum256(body)
	if !bytes.Equal(digest[:], metadata[v2ControlRequestKIDOffset-sha256.Size:v2ControlRequestKIDOffset]) {
		return v2SignedControlRequest{}, errFrame
	}
	request.Body = bytes.Clone(body)
	input := v2ControlSigningInput(v2ControlRequestDomain, metadata)
	return v2SignedControlRequest{v2ControlRequest: request, BodySHA256: digest, RequestBinding: sha256.Sum256(input),
		SigningInput: input, Signature: [v2SignatureSize]byte(signature)}, nil
}

func encodeV2ControlResult(seq uint64, selector v2ControlSelector, result v2ControlResult, maxFrameBytes int,
	sign func([]byte) ([]byte, error)) ([]byte, error) {
	if seq == 0 || sign == nil || result.CallID == (platform.ID{}) || !selector.known() || !selector.validResultBody(result.Body) ||
		!v2ControlFrameFits(selector.resultLimit(maxFrameBytes), v2ControlResultFixed, len(result.Body)) {
		return nil, errFrame
	}
	body := bytes.Clone(result.Body)
	digest := sha256.Sum256(body)
	metadata := make([]byte, 0, v2ControlResultFixed)
	metadata = append(metadata, result.CallID[:]...)
	metadata = append(metadata, result.RequestBinding[:]...)
	metadata = binary.BigEndian.AppendUint32(metadata, uint32(len(body)))
	metadata = append(metadata, digest[:]...)
	return encodeV2SignedControlFrame(selector.resultKind(), seq, metadata, body,
		v2ControlSigningInput(v2ControlResultDomain, metadata), sign)
}

func decodeV2ControlResult(frame []byte, kind byte, expectedSequence uint64, maxFrameBytes int) (v2SignedControlResult, error) {
	if kind != v2ControlResultKind && kind != v2DataResultKind {
		return v2SignedControlResult{}, errFrame
	}
	payload, ok := v2ControlPayload(frame, kind, expectedSequence, maxFrameBytes, v2ControlResultFixed)
	if !ok {
		return v2SignedControlResult{}, errFrame
	}
	metadata := payload[:v2ControlResultFixed]
	body, signature, ok := splitV2ControlPayload(payload, v2ControlResultFixed,
		binary.BigEndian.Uint32(metadata[v2ControlResultLengthOffset:]))
	result := v2ControlResult{CallID: platform.ID(metadata[:v2ControlIDSize])}
	if !ok || len(body) > v2DataMaxBody || result.CallID == (platform.ID{}) {
		return v2SignedControlResult{}, errFrame
	}
	digest := sha256.Sum256(body)
	if !bytes.Equal(digest[:], metadata[v2ControlResultDigestOffset:]) {
		return v2SignedControlResult{}, errFrame
	}
	copy(result.RequestBinding[:], metadata[v2ControlIDSize:v2ControlResultLengthOffset])
	result.Body = bytes.Clone(body)
	return v2SignedControlResult{v2ControlResult: result, Kind: kind, BodySHA256: digest,
		SigningInput: v2ControlSigningInput(v2ControlResultDomain, metadata), Signature: [v2SignatureSize]byte(signature)}, nil
}

func v2ControlFrameFits(maxFrameBytes, metadataLen, bodyLen int) bool {
	overhead := v2HeaderBytes + metadataLen + v2SignatureSize
	return bodyLen > 0 && bodyLen <= v2DataMaxBody && maxFrameBytes >= overhead && bodyLen <= maxFrameBytes-overhead
}

func v2ControlPayload(frame []byte, kind byte, expectedSequence uint64, maxFrameBytes, minimumMetadataLen int) ([]byte, bool) {
	if len(frame) > maxFrameBytes || len(frame) < v2HeaderBytes+minimumMetadataLen+v2SignatureSize+1 ||
		expectedSequence == 0 || frame[0] != v2Version || frame[1] != kind || binary.BigEndian.Uint64(frame[2:v2HeaderBytes]) != expectedSequence {
		return nil, false
	}
	return frame[v2HeaderBytes:], true
}

func splitV2ControlPayload(payload []byte, metadataLen int, declaredBodyLen uint32) ([]byte, []byte, bool) {
	bodyEnd := len(payload) - v2SignatureSize
	if declaredBodyLen == 0 || bodyEnd < metadataLen || uint64(bodyEnd-metadataLen) != uint64(declaredBodyLen) {
		return nil, nil, false
	}
	return payload[metadataLen:bodyEnd], payload[bodyEnd:], true
}

func v2ControlSigningInput(domain string, metadata []byte) []byte {
	input := make([]byte, 0, len(domain)+len(metadata))
	input = append(input, domain...)
	return append(input, metadata...)
}

func encodeV2SignedControlFrame(kind byte, seq uint64, metadata, body, input []byte,
	sign func([]byte) ([]byte, error)) ([]byte, error) {
	signature, err := sign(input)
	if err != nil {
		return nil, err
	}
	if len(signature) != v2SignatureSize {
		return nil, errFrame
	}
	frame := make([]byte, 0, v2HeaderBytes+len(metadata)+len(body)+v2SignatureSize)
	frame = append(frame, v2Header(kind, seq)...)
	frame = append(frame, metadata...)
	frame = append(frame, body...)
	return append(frame, signature...), nil
}
