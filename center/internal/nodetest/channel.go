// SPDX-License-Identifier: AGPL-3.0-only

package nodetest

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The node channel client (AF-CTR-05 E1a; the Plan task's fakes_allowed: "nodetest channel client (Go, center tests: a MOCKED node with
// software keys, for the center's channel, routing and hostile-node cases; never an end-to-end claim)"): it opens GET /fleet/v1/node
// with the node's bearer and the subprotocol, reads the center's challenge, proves the hello with the node's software key (or a
// hostile one), answers heartbeats and sends whatever frame a test needs. The real node is the ArcForges CloudLink (part N1).

// ChannelPath and ChannelSubprotocol are the node channel's route and subprotocol (routes.NodeChannelPath, NodeChannelSubprotocol).
const (
	ChannelPath        = "/fleet/v1/node"
	ChannelSubprotocol = "arcforges.relay.v1"
	// HelloDomain is the channel hello proof's domain string (25 bytes; Design 11 section 3).
	HelloDomain = "ArcForges relay-hello v1\n"
)

// Channel is one open channel of a MOCKED node.
type Channel struct {
	WS *websocket.Conn
	// Challenge is the center's first frame.
	Challenge *relayv1.ChannelChallenge
	// Response is the upgrade's HTTP response (its status and headers).
	Response *http.Response

	// Record, when set, receives every message as transmitted: the center's (fromCenter) as Next reads them and the node's as Send
	// writes them (the exchange captures of N1's FakeCenter, AF-CTR-05 E1-26).
	Record func(fromCenter bool, data []byte)

	mu  sync.Mutex
	seq uint64
}

// DialOptions are what a test changes about the upgrade.
type DialOptions struct {
	// Header adds request headers (a cookie, a client address); Bearer is the access token, empty for none.
	Header http.Header
	Bearer string
	// Subprotocols replaces the one subprotocol offered.
	Subprotocols []string
	// Record is the channel's recorder from its first frame on.
	Record func(fromCenter bool, data []byte)
}

// Dial opens the channel at a center's base URL (http or https; the path is appended) and reads the challenge. A refused upgrade
// returns the response with its status, its ArcForges-Refusal header and its body unread, and an error.
func Dial(ctx context.Context, base string, options DialOptions) (*Channel, error) {
	header := http.Header{}
	for name, values := range options.Header {
		header[name] = append([]string(nil), values...)
	}
	if options.Bearer != "" {
		header.Set("Authorization", "Bearer "+options.Bearer)
	}
	subprotocols := options.Subprotocols
	if subprotocols == nil {
		subprotocols = []string{ChannelSubprotocol}
	}
	url := "ws" + strings.TrimPrefix(base, "http") + ChannelPath
	ws, response, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: header, Subprotocols: subprotocols,
		CompressionMode: websocket.CompressionDisabled})
	channel := &Channel{WS: ws, Response: response, Record: options.Record}
	if err != nil {
		return channel, err
	}
	ws.SetReadLimit(-1)
	frame, err := channel.Next(ctx)
	if err != nil {
		return channel, err
	}
	if channel.Challenge = frame.GetChallenge(); channel.Challenge == nil {
		return channel, errors.New("the center's first frame is not the challenge")
	}
	return channel, nil
}

// Next reads the next frame.
func (c *Channel) Next(ctx context.Context) (*relayv1.RelayFrame, error) {
	kind, data, err := c.WS.Read(ctx)
	if err != nil {
		return nil, err
	}
	if kind != websocket.MessageBinary {
		return nil, errors.New("a text message on the channel")
	}
	if c.Record != nil {
		c.Record(true, data)
	}
	var frame relayv1.RelayFrame
	if err := proto.Unmarshal(data, &frame); err != nil {
		return nil, err
	}
	return &frame, nil
}

// Send writes a frame of a member with the next sequence number.
func (c *Channel) Send(ctx context.Context, frame *relayv1.RelayFrame) error {
	c.mu.Lock()
	c.seq++
	frame.FrameVersion, frame.FrameSeq = proto.Uint32(1), proto.Uint64(c.seq)
	c.mu.Unlock()
	data, err := proto.Marshal(frame)
	if err != nil {
		return err
	}
	if c.Record != nil {
		c.Record(false, data)
	}
	return c.WS.Write(ctx, websocket.MessageBinary, data)
}

// HelloMessage is the channel hello proof's signed message over this connection's challenge.
func (c *Channel) HelloMessage(audience string, nodeID, installationID platform.ID) []byte {
	digest := sha256.Sum256([]byte(audience))
	message := append([]byte(HelloDomain), c.Challenge.GetNonce()...)
	message = append(message, c.Challenge.GetConnectionId().GetValue()...)
	message = append(message, digest[:]...)
	message = append(message, nodeID[:]...)
	return append(message, installationID[:]...)
}

// Hello sends NodeHello for a node and installation, signed with the node's key over this connection's challenge.
func (c *Channel) Hello(ctx context.Context, node *Node, installationID platform.ID, audience string) error {
	return c.SendHello(ctx, node.ID, installationID, node.SignMessage(c.HelloMessage(audience, node.ID, installationID), true))
}

// SendHello sends a NodeHello as given (a hostile node names what it likes and signs with what it holds).
func (c *Channel) SendHello(ctx context.Context, nodeID, installationID platform.ID, signature []byte) error {
	return c.SendHelloCapabilities(ctx, nodeID, installationID, signature, []string{"routed.v1"})
}

// SendHelloCapabilities supplies an explicit declaration for connection negotiation tests.
func (c *Channel) SendHelloCapabilities(ctx context.Context, nodeID, installationID platform.ID, signature []byte, capabilities []string) error {
	return c.Send(ctx, &relayv1.RelayFrame{Frame: &relayv1.RelayFrame_NodeHello{NodeHello: &relayv1.NodeHello{NodeId: id(nodeID), InstallationId: id(installationID),
		HelloSignature: signature, Version: proto.String("0.1.0"), ContractVersion: proto.String("1.0.0"), Capabilities: capabilities}}})
}

// Heartbeat answers a heartbeat with its seq.
func (c *Channel) Heartbeat(ctx context.Context, seq uint64) error {
	now := time.Now()
	return c.Send(ctx, &relayv1.RelayFrame{Frame: &relayv1.RelayFrame_Heartbeat{Heartbeat: &relayv1.ChannelHeartbeat{Seq: proto.Uint64(seq),
		SentAt: &foundationv1.Instant{UnixSeconds: proto.Int64(now.Unix()), Nanos: proto.Uint32(uint32(now.Nanosecond()))}}}})
}

// TokenRefresh sends a new access token on the channel.
func (c *Channel) TokenRefresh(ctx context.Context, token string) error {
	return c.Send(ctx, &relayv1.RelayFrame{Frame: &relayv1.RelayFrame_TokenRefresh{TokenRefresh: &relayv1.TokenRefresh{Token: proto.String(token)}}})
}

// Accept reads until ChannelAccepted, answering heartbeats.
func (c *Channel) Accept(ctx context.Context) (*relayv1.ChannelAccepted, error) {
	for {
		frame, err := c.Next(ctx)
		if err != nil {
			return nil, err
		}
		switch {
		case frame.GetAccepted() != nil:
			return frame.GetAccepted(), nil
		case frame.GetClose() != nil:
			return nil, errors.New("closed: " + frame.GetClose().GetReason())
		}
	}
}

// Closed is how the center ended a channel: the RelayClose frame it sent (zero when none) and the WebSocket close status.
type Closed struct {
	Code   uint32
	Reason string
	// ReconnectAfter is RelayClose.reconnect_after_ms (a 4500's hint), zero when absent.
	ReconnectAfter time.Duration
	Status         websocket.StatusCode
}

// AwaitClose reads until the center closes the channel, answering heartbeats when answer is true, and reports how it closed.
func (c *Channel) AwaitClose(ctx context.Context, answer bool) Closed {
	var closed Closed
	for {
		frame, err := c.Next(ctx)
		if err != nil {
			closed.Status = websocket.CloseStatus(err)
			return closed
		}
		if value := frame.GetClose(); value != nil {
			closed.Code, closed.Reason = value.GetCode(), value.GetReason()
			closed.ReconnectAfter = time.Duration(value.GetReconnectAfterMs()) * time.Millisecond
		}
		if beat := frame.GetHeartbeat(); beat != nil && answer {
			_ = c.Heartbeat(ctx, beat.GetSeq())
		}
	}
}

func id(value platform.ID) *foundationv1.Id {
	return &foundationv1.Id{Value: append([]byte(nil), value[:]...)}
}
