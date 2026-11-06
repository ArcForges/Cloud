// SPDX-License-Identifier: AGPL-3.0-only

package nodetest

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The MOCKED node's side of routed calls (AF-CTR-05 E1b): it reads the center's signed calls, answers with results signed by its node
// key under the routed-result domain string (or with whatever a hostile node sends), asks for relay nonces and signs relay assertions
// under the relay-origin domain string. The real node's verification of calls is ArcForges part N1.

// The domain strings of the node's signatures (Contracts relay.proto, "Signatures of the node channel").
const (
	ResultDomain = "ArcForges relay-result v1\n"
	OriginDomain = "ArcForges relay-origin v1\n"
)

// NextCall reads frames until the center's next ChannelCall, answering heartbeats.
func (c *Channel) NextCall(ctx context.Context) (*relayv1.ChannelCall, error) {
	for {
		frame, err := c.Next(ctx)
		if err != nil {
			return nil, err
		}
		switch {
		case frame.GetCall() != nil:
			return frame.GetCall(), nil
		case frame.GetHeartbeat() != nil:
			_ = c.Heartbeat(ctx, frame.GetHeartbeat().GetSeq())
		case frame.GetClose() != nil:
			return nil, errors.New("closed: " + frame.GetClose().GetReason())
		}
	}
}

// Executed is the ResultHeader of an EXECUTED answer to a call, echoing its call ID, command, method and request digest, with the
// response's digest and size.
func (n *Node) Executed(call *relayv1.ChannelCall, response []byte) *relayv1.ResultHeader {
	header := n.echo(call)
	digest := sha256.Sum256(response)
	header.Outcome = relayv1.RoutedOutcome_ROUTED_OUTCOME_EXECUTED.Enum()
	header.ResponseSha256, header.ResponseSize = digest[:], proto.Uint32(uint32(len(response)))
	return header
}

// Refused is the ResultHeader of a refusing answer (REFUSED_BY_POLICY or EXPIRED) with the node's refusal.
func (n *Node) Refused(call *relayv1.ChannelCall, outcome relayv1.RoutedOutcome, refusal *foundationv1.ArcError) *relayv1.ResultHeader {
	header := n.echo(call)
	header.Outcome, header.Error = outcome.Enum(), refusal
	return header
}

// echo is a result header echoing a call's header.
func (n *Node) echo(call *relayv1.ChannelCall) *relayv1.ResultHeader {
	var sent relayv1.CallHeader
	_ = proto.Unmarshal(call.GetHeader().GetHeader(), &sent)
	now := time.Now()
	return &relayv1.ResultHeader{CallId: sent.CallId, CommandId: sent.CommandId, NodeId: id(n.ID), Method: sent.Method, RequestSha256: sent.RequestSha256,
		ExecutedAt: &foundationv1.Instant{UnixSeconds: proto.Int64(now.Unix()), Nanos: proto.Uint32(uint32(now.Nanosecond()))}}
}

// SignResult is the node's signature of a result header's bytes under the routed-result domain string (lowS false gives the high-S
// twin a verifier must refuse).
func (n *Node) SignResult(header []byte, lowS bool) []byte {
	return n.SignMessage(append([]byte(ResultDomain), header...), lowS)
}

// Answer sends a result: the header serialized and signed by the node key, with the payload.
func (c *Channel) Answer(ctx context.Context, node *Node, callID *foundationv1.Id, header *relayv1.ResultHeader, payload []byte) error {
	data, err := proto.Marshal(header)
	if err != nil {
		return err
	}
	return c.SendResult(ctx, callID, &relayv1.SignedHeader{Header: data, Signature: node.SignResult(data, true), Algorithm: proto.String("ES256")}, payload)
}

// SendResult sends a ChannelResult as given (a hostile node signs what it likes, with what it holds).
func (c *Channel) SendResult(ctx context.Context, callID *foundationv1.Id, header *relayv1.SignedHeader, payload []byte) error {
	return c.Send(ctx, &relayv1.RelayFrame{Frame: &relayv1.RelayFrame_CallResult{CallResult: &relayv1.ChannelResult{CallId: callID, Header: header, Payload: payload}}})
}

// RelayNonce asks for a relay nonce and reads until the center's answer, answering heartbeats.
func (c *Channel) RelayNonce(ctx context.Context) (*relayv1.RelayNonce, error) {
	requestID := platform.NewID()
	if err := c.Send(ctx, &relayv1.RelayFrame{Frame: &relayv1.RelayFrame_RelayNonceRequest{RelayNonceRequest: &relayv1.RelayNonceRequest{RequestId: id(requestID)}}}); err != nil {
		return nil, err
	}
	for {
		frame, err := c.Next(ctx)
		if err != nil {
			return nil, err
		}
		switch {
		case frame.GetRelayNonce() != nil:
			if !proto.Equal(frame.GetRelayNonce().GetRequestId(), id(requestID)) {
				return nil, errors.New("a relay nonce for another request")
			}
			return frame.GetRelayNonce(), nil
		case frame.GetHeartbeat() != nil:
			_ = c.Heartbeat(ctx, frame.GetHeartbeat().GetSeq())
		case frame.GetClose() != nil:
			return nil, errors.New("closed: " + frame.GetClose().GetReason())
		}
	}
}

// Relay is what a relaying node states in its relay assertion.
type Relay struct {
	InstallationID platform.ID
	LocalOrigin    nodev1.Origin
	LocalSession   platform.ID
	Method         relayv1.RoutedMethod
	RequestSHA256  []byte
	Target         *platform.ID
	Command        *platform.ID
	Nonce          []byte
	IssuedAt       time.Time
	Lifetime       time.Duration
}

// Assertion is a relay assertion of this node, signed by its key under the relay-origin domain string for a center URL.
func (n *Node) Assertion(audience string, relay Relay) *relayv1.RelayAssertion {
	issued := relay.IssuedAt
	if issued.IsZero() {
		issued = time.Now()
	}
	lifetime := relay.Lifetime
	if lifetime == 0 {
		lifetime = time.Minute
	}
	value := &relayv1.RelayAssertion{RelayingNodeId: id(n.ID), RelayingInstallationId: id(relay.InstallationID), LocalOrigin: relay.LocalOrigin.Enum(),
		LocalSessionId: id(relay.LocalSession), Method: relay.Method.Enum(), RequestSha256: relay.RequestSHA256, RelayNonce: relay.Nonce,
		IssuedAt: instantOf(issued), ExpiresAt: instantOf(issued.Add(lifetime))}
	if relay.Target != nil {
		value.TargetNodeId = id(*relay.Target)
	}
	if relay.Command != nil {
		value.CommandId = id(*relay.Command)
	}
	value.Signature = n.SignMessage(OriginMessage(audience, value), true)
	return value
}

// OriginMessage is a relay assertion's signed message: the domain string, the audience digest and the fixed-length fields (relay.proto).
func OriginMessage(audience string, value *relayv1.RelayAssertion) []byte {
	digest := sha256.Sum256([]byte(audience))
	message := append([]byte(OriginDomain), digest[:]...)
	message = append(message, value.GetRelayingNodeId().GetValue()...)
	message = append(message, value.GetRelayingInstallationId().GetValue()...)
	message = append(message, byte(value.GetLocalOrigin()))
	message = append(message, value.GetLocalSessionId().GetValue()...)
	message = append(message, byte(value.GetMethod()))
	message = append(message, value.GetRequestSha256()...)
	message = append(message, orZero(value.GetTargetNodeId())...)
	message = append(message, orZero(value.GetCommandId())...)
	message = append(message, value.GetRelayNonce()...)
	message = append(message, canonical(value.GetIssuedAt())...)
	return append(message, canonical(value.GetExpiresAt())...)
}

func orZero(value *foundationv1.Id) []byte {
	if value == nil {
		return make([]byte, 16)
	}
	return value.GetValue()
}

func canonical(value *foundationv1.Instant) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint64(out, uint64(value.GetUnixSeconds()))
	binary.BigEndian.PutUint32(out[8:], value.GetNanos())
	return out
}

func instantOf(at time.Time) *foundationv1.Instant {
	return &foundationv1.Instant{UnixSeconds: proto.Int64(at.Unix()), Nanos: proto.Uint32(uint32(at.Nanosecond()))}
}
