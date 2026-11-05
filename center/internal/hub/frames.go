// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"crypto/sha256"
	"time"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The hub reads and writes relay.v1 RelayFrames (Contracts, internal relay.proto) through a Codec, so its decisions never depend on the
// generated types: wire.go is the one place that maps them. Every frame of the channel is one binary WebSocket message.

// inboundKind is the kind of a frame a node sends.
type inboundKind int

// The frames a node may send on the channel in AF-CTR-05 E1a; any other member is a violation (calls and results are E1b's).
const (
	// inboundOther is a frame member the hub does not take from a node: a protocol violation (close 4403).
	inboundOther inboundKind = iota
	inboundHello
	inboundHeartbeat
	inboundTokenRefresh
	inboundClose
	// inboundNonceRequest is a RelayNonceRequest: relay nonces are served from AF-CTR-05 E2, so E1a leaves it unanswered.
	inboundNonceRequest
)

// inbound is one decoded frame of a node.
type inbound struct {
	kind      inboundKind
	hello     hello
	token     string
	closeCode uint32
}

// hello is a node's NodeHello as the hub needs it: the node and installation it claims and its signature over the channel hello proof.
type hello struct {
	NodeID         platform.ID
	InstallationID platform.ID
	Signature      []byte
	Version        string
	// Malformed is a hello that fails the shape checks the generated validators would make (C2 review N-4; Go has none): a node or
	// installation ID that is absent, not 16 bytes or the zero ID, or a signature that is not 64 bytes. The hub refuses it (4403)
	// before it builds any fixed-length signing input.
	Malformed bool
}

// Limits are what ChannelAccepted tells the node (Plan CTR5-HUB-03): the largest frame, the heartbeat interval and deadline.
type Limits struct {
	MaxFrameBytes     int
	MaxInFlightCalls  int
	Heartbeat         time.Duration
	HeartbeatDeadline time.Duration
	MaxRelayNonces    int
}

// Codec maps the hub's frames to relay.v1 RelayFrame bytes and back. seq is the frame's frame_seq, per connection and direction.
type Codec interface {
	// Decode reads one node frame; an error is a frame the hub cannot read (a protocol violation).
	Decode(data []byte) (inbound, error)
	// Challenge is the center's hello challenge: the one-use nonce and the connection ID (Plan PB-4, D0-B2).
	Challenge(seq uint64, nonce []byte, connectionID platform.ID, deadline time.Time) ([]byte, error)
	// Accepted is ChannelAccepted: the connection ID, the limits and the kids of the command keys calls may be signed with.
	Accepted(seq uint64, connectionID platform.ID, limits Limits, kids []string) ([]byte, error)
	// Heartbeat is the center's heartbeat.
	Heartbeat(seq uint64, at time.Time) ([]byte, error)
	// Close is RelayClose: the close code, its closed reason and, for a center that is going away (4500), how long the node waits
	// before it reconnects.
	Close(seq uint64, code uint32, reason string, reconnectAfter time.Duration) ([]byte, error)
}

// HelloDomain is the leading domain string of the channel hello proof (ArcForges-Design 11 section 3, "Signature domain strings";
// Plan PB-3, PB-4): 25 bytes of ASCII, used by no other signature of the node key.
const HelloDomain = "ArcForges relay-hello v1\n"

// NonceBytes is the length of the center's hello nonce: at least 16 random bytes (D0-B2); the hub sends 32.
const NonceBytes = 32

// HelloMessage is the signed message of the channel hello proof: the domain string, then the center's nonce, the connection ID's 16
// bytes, the SHA-256 of the canonical center URL (the center's own public base URL, never a value the node sends), the node ID's 16
// bytes and the installation ID's 16 bytes. Every field after the domain has a fixed length.
func HelloMessage(nonce []byte, connectionID platform.ID, centerURL string, nodeID, installationID platform.ID) []byte {
	audience := sha256.Sum256([]byte(centerURL))
	message := make([]byte, 0, len(HelloDomain)+len(nonce)+16+len(audience)+16+16)
	message = append(message, HelloDomain...)
	message = append(message, nonce...)
	message = append(message, connectionID[:]...)
	message = append(message, audience[:]...)
	message = append(message, nodeID[:]...)
	return append(message, installationID[:]...)
}
