// SPDX-License-Identifier: AGPL-3.0-only

package pages_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/hub"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// TestRevokingANodesDeviceOnTheDevicesPageClosesItsChannel (AF-CTR-05 E1a, bullet 3 the center half; CTR5-HUB-08): the account's own
// revoke path, end to end through the composed center (EVIDENCE: REAL PostgreSQL, the account pages with a virtual passkey's
// step-up, the identity service's device revocation and its cascade, the real WebSocket server; MOCKED: the node, nodetest's channel
// client). The node's device is revoked from the devices page with evidence; once that revocation commits, the hub's cascade
// participant closes the node's open channel 4401 revoked, and the node's next upgrade is refused credential_revoked.
func TestRevokingANodesDeviceOnTheDevicesPageClosesItsChannel(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy, surfaces: "identity,pages,fleet,relay", relay: true})
	who := h.seedAccount(1)
	a := h.newBrowser()
	a.mustSignIn(who)
	state := a.bootstrapState()
	node, err := nodetest.New()
	if err != nil {
		t.Fatal(err)
	}
	info, err := fleet.ParseNodeInfo(node.Info())
	if err != nil {
		t.Fatal(err)
	}
	var enrolled fleet.Enrolled
	if err = h.center.Store.InTx(context.Background(), "enroll", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		enrolled, err = fleet.Enroll(ctx, tx, config.DefaultIdentityPolicy(), fleet.EnrollRequest{UserID: who.id, Approver: fleet.Approver{
			SessionID: idOf(t, state.Session.SessionID), AuthMethod: 1, AuthenticatedAt: h.clock.Now().Add(-time.Minute)}, NodeID: node.ID, Node: info,
			PublicKey: node.PublicKey, Flow: fleet.FlowDevice}, h.clock.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	h.remember(enrolled.Session.AccessToken, enrolled.Session.RefreshToken)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	header := http.Header{config.ClientIPHeader: {"198.51.100.7"}}
	channel, err := nodetest.Dial(ctx, h.url, nodetest.DialOptions{Bearer: enrolled.Session.AccessToken, Header: header})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = channel.WS.CloseNow() }()
	if err := channel.Hello(ctx, node, enrolled.InstallationID, publicBaseURL); err != nil {
		t.Fatal(err)
	}
	accepted, err := channel.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(accepted.GetSigningKids()) != 1 {
		t.Fatalf("ChannelAccepted lists the test's command key: %v", accepted.GetSigningKids())
	}
	closed := make(chan nodetest.Closed, 1)
	go func() { closed <- channel.AwaitClose(ctx, true) }()
	// The devices page's revoke form of the node's device, with step-up evidence for it.
	devices := a.page("/account/devices")
	var form formSpec
	found := false
	for _, candidate := range formsTo(t, devices, "/account/devices/revoke") {
		if candidate.fields.Get("device_id") == uuid(enrolled.DeviceID) {
			form, found = candidate, true
		}
	}
	if !found {
		t.Fatalf("the devices page has no revoke form for the node's device:\n%s", devices.text())
	}
	a.mustStepUp(who, identity.ClassRevokeDevice, enrolled.DeviceID)
	if revoked := a.submit(form, nil); revoked.status != http.StatusSeeOther {
		t.Fatalf("the node's device revocation: %d %s", revoked.status, revoked.text())
	}
	select {
	case result := <-closed:
		if result.Code != hub.CloseCredential || result.Reason != "revoked" {
			t.Fatalf("the channel's close: %+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("revoking the node's device on the devices page left its channel open")
	}
	refused, err := nodetest.Dial(ctx, h.url, nodetest.DialOptions{Bearer: enrolled.Session.AccessToken, Header: header})
	if err == nil || refused.Response == nil || refused.Response.Header.Get("ArcForges-Refusal") != "AUTHENTICATION/credential_revoked" {
		t.Fatalf("the revoked node's next upgrade: %v", err)
	}
}
