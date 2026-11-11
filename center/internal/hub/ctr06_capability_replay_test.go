// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

func TestCTR06HelloCapabilityShape(t *testing.T) {
	node, install := platform.NewID(), platform.NewID()
	base := &relayv1.RelayFrame{FrameVersion: proto.Uint32(FrameVersion), Frame: &relayv1.RelayFrame_NodeHello{NodeHello: &relayv1.NodeHello{
		NodeId: idValue(node), InstallationId: idValue(install), HelloSignature: make([]byte, 64),
	}}}
	for _, tc := range []struct {
		name         string
		capabilities []string
		malformed    bool
	}{
		{"legacy", []string{"routed.v1"}, false},
		{"current", []string{"routed.v1", FilesCapability}, false},
		{"duplicate", []string{FilesCapability, FilesCapability}, true},
		{"invalid", []string{"FILES.v1"}, true},
		{"too long", []string{"abcdefghijklmnopqrstuvwxyz1234567"}, true},
		{"too many", []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base.GetNodeHello().Capabilities = tc.capabilities
			wire, err := proto.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			got, err := (RelayCodec{}).Decode(wire)
			if err != nil || got.hello.Malformed != tc.malformed {
				t.Fatalf("hello=%+v error=%v", got.hello, err)
			}
		})
	}
}

func TestCTR06ReplayFenceCheckedWhenWriterDelivers(t *testing.T) {
	deadline := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		now     time.Time
		deliver bool
	}{
		{"before", deadline.Add(-time.Nanosecond), true},
		{"at", deadline, false},
		{"after", deadline.Add(time.Nanosecond), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := platform.NewID()
			p := &pending{callID: id, replayUntil: deadline, done: make(chan outcome, 1)}
			c := &conn{hub: &Hub{clock: func() time.Time { return tc.now }}, calls: map[platform.ID]*pending{id: p}}
			if got := c.deliver(p); got != tc.deliver {
				t.Fatalf("delivered=%v", got)
			}
			if !tc.deliver {
				answer := <-p.done
				if answer.refusal == nil || answer.refusal.Code != "invalid_state" || answer.refusal.Reason != "replay_window_passed" {
					t.Fatalf("missing replay refusal: %+v", answer)
				}
				if p.state.Load() != callAbandoned || len(c.calls) != 0 {
					t.Fatal("expired frame remains eligible")
				}
				if answer.refusal.ArcError(correlation.Context{}).GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN {
					t.Fatal("this delivery must not be reported as having occurred")
				}
			}
		})
	}
}
