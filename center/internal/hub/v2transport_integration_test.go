// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/hub"
	"github.com/ArcForges/Cloud/center/internal/management"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

type v2ControlCallResult struct {
	body []byte
	err  error
}

func TestV2ControlChannelBindsClaimAndSignedResult(t *testing.T) {
	h := newHarness(t, settings{tune: func(s *hub.Settings) {
		s.Heartbeat, s.HeartbeatDeadline = time.Minute, 2*time.Minute
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	node := h.enroll()
	ownerEpoch := platform.NewID()
	awaitAuthority := func(channel *v2TestChallenge) (management.V2ControlAuthority, error) {
		for {
			authority, err := h.center.Hub.V2ControlAuthority(ctx, node.user, node.node.ID, channel.enrollment, channel.epoch)
			if !errors.Is(err, management.ErrV2ControlUnavailable) {
				return authority, err
			}
			select {
			case <-ctx.Done():
				return management.V2ControlAuthority{}, ctx.Err()
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	old := h.dialV2(ctx, node.access)
	old.sendHello(t, ctx, node, ownerEpoch, "1", "cohort-ci.481.1", "linux-bubblewrap-sdk-v1")
	old.accept(t, ctx)
	if _, err := awaitAuthority(old); !errors.Is(err, management.ErrV2ControlUpgradeRequired) {
		t.Fatalf("unnegotiated control peer: %v", err)
	}
	peer := h.dialV2(ctx, node.access)
	peer.sendHello(t, ctx, node, ownerEpoch, "2", "cohort-ci.481.1", "linux-bubblewrap-sdk-v1", "center-control-v2")
	peer.accept(t, ctx)
	readV2TestClose(t, ctx, old.socket, 3, hub.CloseReplaced, "replaced")
	authority, err := awaitAuthority(peer)
	if err != nil || authority.AccountID != node.user || authority.NodeID != node.node.ID || authority.EnrollmentID != peer.enrollment ||
		authority.ProtocolEpoch != peer.epoch || authority.ConnectionID != peer.connection || authority.NodeOwnerEpoch != ownerEpoch ||
		authority.HubHolder != h.center.Hub.Lease().Holder() || authority.HubFence != peer.fence {
		t.Fatalf("the live control authority did not match the proved peer: %v", err)
	}
	if presence, ok := h.center.Hub.V2Presence(node.user, peer.enrollment, node.node.ID, peer.epoch); !ok ||
		len(presence.Capabilities) != 1 || presence.Capabilities[0] != "linux-bubblewrap-sdk-v1" {
		t.Fatal("private control capability changed the public platform projection")
	}
	call := management.V2ControlCall{Selector: 9, ActorID: node.user, OriginalOwnerEpoch: ownerEpoch,
		CommandID: platform.NewID(), GrantID: platform.NewID(), GrantRevision: 17,
		Deadline: time.Now().Add(8 * time.Second), Body: []byte{0x0a, 0x02, 0x0a, 0x00}}
	if _, err = h.center.Hub.CallV2(ctx, authority, call, nil); !errors.Is(err, management.ErrV2ControlUnavailable) {
		t.Fatalf("mutation without a claim callback: %v", err)
	}
	if _, err = h.center.Hub.CallV2(ctx, authority, call, func(context.Context, management.V2ControlAuthority) (bool, error) {
		return false, nil
	}); !errors.Is(err, management.ErrV2ControlNotClaimed) {
		t.Fatalf("a declined mutation claim was not refused: %v", err)
	}
	claimFailure := errors.New("fixture claim refused")
	if _, err = h.center.Hub.CallV2(ctx, authority, call, func(context.Context, management.V2ControlAuthority) (bool, error) {
		return true, claimFailure
	}); !errors.Is(err, claimFailure) {
		t.Fatalf("a failed mutation claim was not refused: %v", err)
	}

	receipts := management.New(h.db.Runtime)
	lease := management.Lease{Holder: authority.HubHolder, ChannelEpoch: authority.ConnectionID,
		ProtocolEpoch: authority.ProtocolEpoch, Fence: authority.HubFence}
	identity := management.Identity{Account: node.user, Actor: call.ActorID, Command: call.CommandID, Enrollment: authority.EnrollmentID,
		Node: authority.NodeID, Grant: call.GrantID, GrantRevision: call.GrantRevision, OwnerEpoch: [16]byte(ownerEpoch),
		IntentSHA256: sha256.Sum256(call.Body), Method: "RunService.Stop", CreatedAt: time.Now(), ReplayUntil: time.Now().Add(time.Minute)}
	reserved, inserted, err := receipts.Reserve(ctx, identity, lease)
	if err != nil || !inserted {
		t.Fatalf("fixture did not reserve the actual durable operation: %v", err)
	}
	returned := make(chan v2ControlCallResult, 1)
	call.Deadline = time.Now().Add(8 * time.Second)
	go func() {
		body, err := h.center.Hub.CallV2(ctx, authority, call, func(claimCtx context.Context, exact management.V2ControlAuthority) (bool, error) {
			if exact != authority {
				return false, errors.New("unexpected fixture authority")
			}
			_, claimed, err := receipts.MarkPossiblyDelivered(claimCtx, identity, lease, reserved)
			return claimed, err
		})
		returned <- v2ControlCallResult{body: body, err: err}
	}()
	request := readV2TestFrame(t, ctx, peer.socket, 7, 3)
	callID, binding := proveV2ControlRequest(t, h, request, call)
	_, receipt, err := receipts.InspectOriginal(ctx, management.Authority{Account: identity.Account, Actor: identity.Actor,
		Enrollment: identity.Enrollment, Node: identity.Node, Grant: identity.Grant, GrantRevision: identity.GrantRevision}, call.CommandID)
	if err != nil || !receipt.MayHaveDelivered || receipt.DeliveryCount != 1 {
		t.Fatalf("control frame preceded the committed delivery claim: %v", err)
	}
	response := []byte{0x12, 0x00}
	writeV2ControlResult(t, ctx, peer, node, 2, callID, binding, response)
	select {
	case observed := <-returned:
		if observed.err != nil || !bytes.Equal(observed.body, response) {
			t.Fatalf("the exact signed response was unavailable: %v", observed.err)
		}
	case <-ctx.Done():
		t.Fatal("no result for the exact control request")
	}

	client := nodetest.Client{URL: h.url, ClientIPHeader: config.ClientIPHeader}
	reply, err := client.Post("/arcforges.fleet.v1.NodeEnrollmentService/RefreshNodeSession", &fleetv1.NodeEnrollmentServiceRefreshNodeSessionRequest{
		Meta: &foundationv1.RequestMeta{}, RefreshToken: proto.String(node.result.Session.RefreshToken)}, "")
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := nodetest.Decode(reply, &fleetv1.NodeEnrollmentServiceRefreshNodeSessionResponse{})
	if err != nil || refreshed.GetValue().GetAccessToken() == "" {
		t.Fatalf("the enrolled node could not rotate its access credential: %v", err)
	}
	rotated := refreshed.GetValue()
	h.secrets = append(h.secrets, rotated.GetAccessToken(), rotated.GetRefreshToken())
	if _, err = h.center.Hub.V2ControlAuthority(ctx, node.user, node.node.ID, peer.enrollment, peer.epoch); !errors.Is(err, management.ErrV2ControlUnavailable) {
		t.Fatalf("the connection's replaced credential still admitted control: %v", err)
	}
	writeV2TestFrame(t, ctx, peer.socket, 5, 3, []byte(rotated.GetAccessToken()))
	if after, err := awaitAuthority(peer); err != nil || after != authority {
		t.Fatalf("refresh did not restore the same proved V2 control connection: %v", err)
	}

	call.Selector, call.CommandID, call.Deadline = 6, platform.ID{}, time.Now().Add(8*time.Second)
	go func() {
		body, err := h.center.Hub.CallV2(ctx, authority, call, nil)
		returned <- v2ControlCallResult{body: body, err: err}
	}()
	request = readV2TestFrame(t, ctx, peer.socket, 7, 4)
	callID, binding = proveV2ControlRequest(t, h, request, call)
	writeV2ControlResult(t, ctx, peer, node, 4, callID, binding, response)
	select {
	case observed := <-returned:
		if observed.err != nil || !bytes.Equal(observed.body, response) {
			t.Fatalf("post-refresh control response was unavailable: %v", observed.err)
		}
	case <-ctx.Done():
		t.Fatal("no authenticated control result after refresh")
	}

	call.Deadline = time.Now().Add(8 * time.Second)
	go func() {
		body, err := h.center.Hub.CallV2(ctx, authority, call, nil)
		returned <- v2ControlCallResult{body: body, err: err}
	}()
	request = readV2TestFrame(t, ctx, peer.socket, 7, 5)
	callID, binding = proveV2ControlRequest(t, h, request, call)
	binding[0] ^= 1
	// Even this enrolled peer's correctly signed response is invalid for a different request binding.
	writeV2ControlResult(t, ctx, peer, node, 5, callID, binding, response)
	select {
	case observed := <-returned:
		if !errors.Is(observed.err, management.ErrV2ControlUncertain) || observed.body != nil {
			t.Fatalf("an unbound signed response settled the call: %v", observed.err)
		}
	case <-ctx.Done():
		t.Fatal("unbound response did not settle the channel wait")
	}
	readV2TestClose(t, ctx, peer.socket, 6, hub.CloseRefused, "result_mismatch")
}

func proveV2ControlRequest(t *testing.T, h *harness, request []byte, call management.V2ControlCall) (platform.ID, [32]byte) {
	t.Helper()
	if len(request) < 255+64+1 {
		t.Fatal("short emitted control frame")
	}
	metadataLen := 254 + int(request[249])
	bodyEnd := len(request) - 64
	if metadataLen < 255 || metadataLen >= bodyEnd || !bytes.Equal(request[metadataLen:bodyEnd], call.Body) ||
		request[16] != byte(call.Selector) || !bytes.Equal(request[129:145], call.CommandID[:]) || string(request[250:metadataLen-4]) != h.kid {
		t.Fatal("control frame did not preserve the exact call bytes")
	}
	key, err := x509.ParsePKIXPublicKey(h.commandKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	input := append([]byte("ArcForges relay-control-request v2\n"), request[:metadataLen]...)
	binding := sha256.Sum256(input)
	signature := request[bodyEnd:]
	if !ecdsa.Verify(key.(*ecdsa.PublicKey), binding[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		t.Fatal("control request did not use the configured command key")
	}
	return platform.ID(request[:16]), binding
}

func writeV2ControlResult(t *testing.T, ctx context.Context, peer *v2TestChallenge, node *enrolled,
	sequence uint64, callID platform.ID, binding [32]byte, body []byte) {
	t.Helper()
	metadata := append([]byte{}, callID[:]...)
	metadata = append(metadata, binding[:]...)
	metadata = binary.BigEndian.AppendUint32(metadata, uint32(len(body)))
	digest := sha256.Sum256(body)
	metadata = append(metadata, digest[:]...)
	input := append([]byte("ArcForges relay-control-result v2\n"), metadata...)
	packet := append(metadata, body...)
	packet = append(packet, node.node.SignMessage(input, true)...)
	writeV2TestFrame(t, ctx, peer.socket, 8, sequence, packet)
}
