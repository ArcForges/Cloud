// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"errors"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// FrameVersion is the RelayFrame frame_version of the node channel.
const FrameVersion = 1

// RelayCodec is the relay.v1 codec of the channel (Contracts relay.proto, AF-CTR-05 C2): one RelayFrame per binary message, with
// frame_version 1 and frame_seq per connection and direction. On this channel a node sends node_hello, heartbeat, token_refresh,
// close, relay_nonce_request and call_result; the center sends challenge, accepted, heartbeat, close, call and relay_nonce. Every
// other member belongs to the unserved FleetHub relay of AD-0009.
type RelayCodec struct{}

// maxTokenBytes bounds a TokenRefresh token before it is verified (the ingress's bearer bound).
const maxTokenBytes = 4096

// errFrame is a node frame the hub cannot read.
var errFrame = errors.New("not a node channel frame")

// Decode reads one node frame: a frame of another version, without a member, or that does not decode is refused.
func (RelayCodec) Decode(data []byte) (inbound, error) {
	var frame relayv1.RelayFrame
	if err := proto.Unmarshal(data, &frame); err != nil || frame.GetFrameVersion() != FrameVersion {
		return inbound{}, errFrame
	}
	switch member := frame.GetFrame().(type) {
	case *relayv1.RelayFrame_NodeHello:
		value := member.NodeHello
		nodeID, okNode := idOf(value.GetNodeId())
		installationID, okInstallation := idOf(value.GetInstallationId())
		signature := value.GetHelloSignature()
		// The shape checks come before anything is built from the fields (C2 review N-4): an absent or wrong-length ID or signature is a
		// malformed hello, closed 4403 without a signing input.
		malformed := !okNode || !okInstallation || len(signature) != 64
		return inbound{kind: inboundHello, hello: hello{NodeID: nodeID, InstallationID: installationID, Signature: signature, Malformed: malformed}}, nil
	case *relayv1.RelayFrame_Heartbeat:
		return inbound{kind: inboundHeartbeat}, nil
	case *relayv1.RelayFrame_TokenRefresh:
		token := member.TokenRefresh.GetToken()
		if token == "" || len(token) > maxTokenBytes {
			return inbound{}, errFrame
		}
		return inbound{kind: inboundTokenRefresh, token: token}, nil
	case *relayv1.RelayFrame_Close:
		return inbound{kind: inboundClose, closeCode: member.Close.GetCode()}, nil
	case *relayv1.RelayFrame_RelayNonceRequest:
		requestID, ok := idOf(member.RelayNonceRequest.GetRequestId())
		return inbound{kind: inboundNonceRequest, requestID: requestID, requestOK: ok && validRelayNonceRequest(member.RelayNonceRequest)}, nil
	case *relayv1.RelayFrame_CallResult:
		value := member.CallResult
		callID, ok := idOf(value.GetCallId())
		header := value.GetHeader()
		return inbound{kind: inboundResult, result: resultFrame{CallID: callID, CallOK: ok, Header: header.GetHeader(), Signature: header.GetSignature(),
			HasKid: header.Kid != nil, Algorithm: header.GetAlgorithm(), Payload: value.GetPayload(), Shaped: validChannelResult(value)}}, nil
	case nil:
		return inbound{}, errFrame
	}
	return inbound{kind: inboundOther}, nil
}

// Challenge is the center's first frame (PB-4, D0-B2): the nonce, the connection ID and the hello deadline.
func (RelayCodec) Challenge(seq uint64, nonce []byte, connectionID platform.ID, deadline time.Time) ([]byte, error) {
	return marshal(seq, &relayv1.RelayFrame_Challenge{Challenge: &relayv1.ChannelChallenge{Nonce: nonce, ConnectionId: idValue(connectionID),
		HelloDeadline: instant(deadline)}})
}

// Accepted is ChannelAccepted: the connection ID, the limits and the command keys calls may be signed with.
func (RelayCodec) Accepted(seq uint64, connectionID platform.ID, limits Limits, kids []string) ([]byte, error) {
	return marshal(seq, &relayv1.RelayFrame_Accepted{Accepted: &relayv1.ChannelAccepted{ConnectionId: idValue(connectionID),
		Limits: &relayv1.ChannelLimits{
			MaxFrameBytes: proto.Uint32(uint32(limits.MaxFrameBytes)), MaxInFlightCalls: proto.Uint32(uint32(limits.MaxInFlightCalls)),
			HeartbeatIntervalMs: proto.Uint32(uint32(limits.Heartbeat / time.Millisecond)), HeartbeatDeadlineMs: proto.Uint32(uint32(limits.HeartbeatDeadline / time.Millisecond)),
			MaxRelayNonces: proto.Uint32(uint32(limits.MaxRelayNonces)),
		}, SigningKids: kids}})
}

// Heartbeat is the center's ChannelHeartbeat; its seq is the frame's.
func (RelayCodec) Heartbeat(seq uint64, at time.Time) ([]byte, error) {
	return marshal(seq, &relayv1.RelayFrame_Heartbeat{Heartbeat: &relayv1.ChannelHeartbeat{SentAt: instant(at), Seq: proto.Uint64(seq)}})
}

// MaxReconnectAfter is RelayClose.reconnect_after_ms's bound (0..300,000 ms).
const MaxReconnectAfter = 300 * time.Second

// Close is RelayClose: the code, the closed reason and, with 4500 only, the jittered reconnect hint in reconnect_after_ms (Plan
// CTR5-HUB-11; the field is meaningful with 4500 only, so another code never carries it).
func (RelayCodec) Close(seq uint64, code uint32, reason string, reconnectAfter time.Duration) ([]byte, error) {
	value := &relayv1.RelayClose{Code: proto.Uint32(code), Reason: proto.String(reason)}
	if code == CloseShuttingDown && reconnectAfter > 0 {
		value.ReconnectAfterMs = proto.Uint32(uint32(min(reconnectAfter, MaxReconnectAfter) / time.Millisecond))
	}
	return marshal(seq, &relayv1.RelayFrame_Close{Close: value})
}

// Call is ChannelCall (Plan CTR5-SIG-01): the call ID, the SignedHeader of the CallHeader bytes (with the command key's kid and
// "ES256") and the payload, as given.
func (RelayCodec) Call(seq uint64, callID platform.ID, header, signature []byte, kid string, payload []byte) ([]byte, error) {
	return marshal(seq, &relayv1.RelayFrame_Call{Call: &relayv1.ChannelCall{CallId: idValue(callID), Header: &relayv1.SignedHeader{Header: header,
		Signature: signature, Kid: proto.String(kid), Algorithm: proto.String("ES256")}, Payload: payload}})
}

// RelayNonce is RelayNonce (Plan addendum C-N2): the request ID it answers, the nonce and its expiry.
func (RelayCodec) RelayNonce(seq uint64, requestID platform.ID, nonce []byte, expires time.Time) ([]byte, error) {
	return marshal(seq, &relayv1.RelayFrame_RelayNonce{RelayNonce: &relayv1.RelayNonce{RequestId: idValue(requestID), Nonce: nonce, ExpiresAt: instant(expires)}})
}

func marshal(seq uint64, member any) ([]byte, error) {
	frame := &relayv1.RelayFrame{FrameVersion: proto.Uint32(FrameVersion), FrameSeq: proto.Uint64(seq)}
	switch value := member.(type) {
	case *relayv1.RelayFrame_Challenge:
		frame.Frame = value
	case *relayv1.RelayFrame_Accepted:
		frame.Frame = value
	case *relayv1.RelayFrame_Heartbeat:
		frame.Frame = value
	case *relayv1.RelayFrame_Close:
		frame.Frame = value
	case *relayv1.RelayFrame_Call:
		frame.Frame = value
	case *relayv1.RelayFrame_RelayNonce:
		frame.Frame = value
	default:
		return nil, errFrame
	}
	return proto.Marshal(frame)
}

func idOf(value *foundationv1.Id) (platform.ID, bool) {
	var id platform.ID
	if raw := value.GetValue(); len(raw) == len(id) {
		copy(id[:], raw)
		return id, id != platform.ID{}
	}
	return id, false
}

func idValue(id platform.ID) *foundationv1.Id {
	return &foundationv1.Id{Value: append([]byte(nil), id[:]...)}
}

func instant(at time.Time) *foundationv1.Instant {
	return &foundationv1.Instant{UnixSeconds: proto.Int64(at.Unix()), Nanos: proto.Uint32(uint32(at.Nanosecond()))}
}
