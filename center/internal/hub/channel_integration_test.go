// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"github.com/coder/websocket"
	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/hub"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

func background() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// TestHelloMustNameTheEnrolledNode is E1-6 (CTR5-HUB-03, D0-B2): the challenge carries a 32-byte nonce, the connection ID and the hello
// deadline; a hello proved with the node's own key that names another node or another installation is closed 4403 (hello_mismatch),
// and the proved hello of the enrolled node is accepted with the limits, the node then online.
func TestHelloMustNameTheEnrolledNode(t *testing.T) {
	h := newHarness(t, settings{})
	node := h.enroll()
	for name, claim := range map[string]func() (platform.ID, platform.ID){
		"another node":         func() (platform.ID, platform.ID) { return platform.NewID(), node.result.InstallationID },
		"another installation": func() (platform.ID, platform.ID) { return node.node.ID, platform.NewID() },
	} {
		channel, err := h.dial(node.access, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(channel.Challenge.GetNonce()) != hub.NonceBytes || len(channel.Challenge.GetConnectionId().GetValue()) != 16 ||
			channel.Challenge.GetHelloDeadline() == nil {
			t.Fatalf("the challenge: %v", channel.Challenge)
		}
		nodeID, installationID := claim()
		ctx, cancel := background()
		if err := channel.SendHello(ctx, nodeID, installationID, node.node.SignMessage(channel.HelloMessage(publicBaseURL, nodeID, installationID), true)); err != nil {
			t.Fatal(err)
		}
		closed := channel.AwaitClose(ctx, false)
		cancel()
		if closed.Code != hub.CloseRefused || closed.Reason != "hello_mismatch" || closed.Status != hub.CloseRefused {
			t.Errorf("%s: %+v", name, closed)
		}
	}
	if h.center.Hub.Connected(node.node.ID) {
		t.Fatal("a mismatched hello made the connection the node's")
	}
	channel := h.connect(node)
	_ = channel
	if !h.center.Hub.Connected(node.node.ID) {
		t.Fatal("the proved hello did not make the connection the node's")
	}
	ctx, cancel := background()
	defer cancel()
	state, _, err := h.center.Hub.Presence(ctx, node.node.ID)
	if err != nil || state != hub.Online {
		t.Fatalf("presence %v %v", state, err)
	}
	if h.audits("fleet.channel.violation") != 2 || h.audits("fleet.channel.accepted") != 1 {
		t.Fatalf("violations %d, accepted %d", h.audits("fleet.channel.violation"), h.audits("fleet.channel.accepted"))
	}
}

// TestAHelloSignedByAnotherInstallationsKeyIsRefused (T-11, D0-B2; mutation "the hello verified against the named installation's
// key"): a stolen token of node A with the key of node B, enrolled in another account. A hello that names B's node and installation and
// is signed with B's own key fails the signature check against A's registered key (hello_signature), as does one that names A and is
// signed with B's key. The key that verifies is always the bearer credential's installation's, never the one the hello names.
func TestAHelloSignedByAnotherInstallationsKeyIsRefused(t *testing.T) {
	h := newHarness(t, settings{})
	a, b := h.enroll(), h.enroll()
	for name, claim := range map[string][2]platform.ID{
		"naming B": {b.node.ID, b.result.InstallationID},
		"naming A": {a.node.ID, a.result.InstallationID},
	} {
		channel, err := h.dial(a.access, nil)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := background()
		if err := channel.SendHello(ctx, claim[0], claim[1], b.node.SignMessage(channel.HelloMessage(publicBaseURL, claim[0], claim[1]), true)); err != nil {
			t.Fatal(err)
		}
		closed := channel.AwaitClose(ctx, false)
		cancel()
		if closed.Code != hub.CloseRefused || closed.Reason != "hello_signature" {
			t.Errorf("%s: %+v", name, closed)
		}
	}
	if h.center.Hub.Connected(a.node.ID) || h.center.Hub.Connected(b.node.ID) {
		t.Fatal("a hello with another installation's key was accepted")
	}
	// A high-S signature by the right key is refused too (the node normalizes s).
	channel, err := h.dial(a.access, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := background()
	defer cancel()
	ids := [2]platform.ID{a.node.ID, a.result.InstallationID}
	if err := channel.SendHello(ctx, ids[0], ids[1], a.node.SignMessage(channel.HelloMessage(publicBaseURL, ids[0], ids[1]), false)); err != nil {
		t.Fatal(err)
	}
	if closed := channel.AwaitClose(ctx, false); closed.Reason != "hello_signature" {
		t.Errorf("a high-S hello: %+v", closed)
	}
}

// TestATokenWithoutTheNodeKeyCannotReplaceTheChannel (PB-4; mutation "replacement before proof"): node A's channel is open; a second
// connection with A's token whose hello is not proved by A's key is closed 4403, and A's first channel stays the node's and open.
func TestATokenWithoutTheNodeKeyCannotReplaceTheChannel(t *testing.T) {
	h := newHarness(t, settings{})
	a := h.enroll()
	first := h.connect(a)
	firstClosed := answer(first)
	thief, err := h.dial(a.access, nil)
	if err != nil {
		t.Fatal(err)
	}
	stolen, err := nodetest.New()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := background()
	defer cancel()
	ids := [2]platform.ID{a.node.ID, a.result.InstallationID}
	if err := thief.SendHello(ctx, ids[0], ids[1], stolen.SignMessage(thief.HelloMessage(publicBaseURL, ids[0], ids[1]), true)); err != nil {
		t.Fatal(err)
	}
	if closed := thief.AwaitClose(ctx, false); closed.Code != hub.CloseRefused {
		t.Fatalf("the thief: %+v", closed)
	}
	if !stillOpen(firstClosed, 500*time.Millisecond) {
		t.Fatal("a token without the node key closed the live channel")
	}
	if !h.center.Hub.Connected(a.node.ID) || h.audits("fleet.channel.accepted") != 1 {
		t.Fatal("the live channel is no longer the node's")
	}
}

// TestTheHelloNonceIsOneUseAndVoidAtTheDeadline (D0-B2; mutation "a replayed nonce accepted"): a hello proved over connection 1's
// challenge, replayed on connection 2, fails there (each connection has its own nonce); a second hello on an accepted connection is a
// violation; and a connection that sends no hello is closed 4408 at the hello deadline.
func TestTheHelloNonceIsOneUseAndVoidAtTheDeadline(t *testing.T) {
	h := newHarness(t, settings{tune: func(s *hub.Settings) { s.HelloDeadline = 400 * time.Millisecond }})
	a := h.enroll()
	one, err := h.dial(a.access, nil)
	if err != nil {
		t.Fatal(err)
	}
	two, err := h.dial(a.access, nil)
	if err != nil {
		t.Fatal(err)
	}
	ids := [2]platform.ID{a.node.ID, a.result.InstallationID}
	signature := a.node.SignMessage(one.HelloMessage(publicBaseURL, ids[0], ids[1]), true)
	ctx, cancel := background()
	defer cancel()
	if err := two.SendHello(ctx, ids[0], ids[1], signature); err != nil {
		t.Fatal(err)
	}
	if closed := two.AwaitClose(ctx, false); closed.Reason != "hello_signature" {
		t.Fatalf("a hello replayed on another connection: %+v", closed)
	}
	// Connection 1 sends nothing: its nonce is void at the deadline.
	if closed := one.AwaitClose(ctx, false); closed.Code != hub.CloseDeadline || closed.Reason != "hello_deadline" {
		t.Fatalf("no hello: %+v", closed)
	}
	// A hello on an accepted connection is a violation.
	three := h.connect(a)
	if err := three.Hello(ctx, a.node, a.result.InstallationID, publicBaseURL); err != nil {
		t.Fatal(err)
	}
	if closed := three.AwaitClose(ctx, true); closed.Code != hub.CloseRefused || closed.Reason != "unexpected_frame" {
		t.Fatalf("a second hello: %+v", closed)
	}
}

// TestANewConnectionReplacesTheOldAndBothAreAudited is E1-7 (CTR5-HUB-04, SEC-09): a second proved connection of the node replaces the
// first, which is closed 4409 after the newer one is accepted; both acceptances are audited, the second naming the one it replaced.
func TestANewConnectionReplacesTheOldAndBothAreAudited(t *testing.T) {
	h := newHarness(t, settings{})
	a := h.enroll()
	first := h.connect(a)
	firstClosed := answer(first)
	h.connect(a)
	if closed := closedWithin(t, firstClosed, 3*time.Second); closed.Code != hub.CloseReplaced || closed.Status != hub.CloseReplaced {
		t.Fatalf("the replaced channel: %+v", closed)
	}
	if h.audits("fleet.channel.accepted") != 2 || h.center.Hub.Count() != 1 {
		t.Fatalf("accepted %d, connected %d", h.audits("fleet.channel.accepted"), h.center.Hub.Count())
	}
	var replaced bool
	if err := h.db.Migration.QueryRow(context.Background(), "SELECT (convert_from(payload, 'UTF8')::jsonb->>'replaced')::boolean FROM audit.audit_event WHERE event_type = 'fleet.channel.accepted' ORDER BY sequence DESC LIMIT 1").
		Scan(&replaced); err != nil || !replaced {
		t.Fatalf("the second acceptance names the replaced connection: %v %v", replaced, err)
	}
	// The replaced connection's close does not clear the node's presence: the newer connection holds it.
	ctx, cancel := background()
	defer cancel()
	if !eventually(t, 2*time.Second, func() bool {
		return h.count("SELECT count(*) FROM fleet.node WHERE node_id = $1 AND connection_id IS NOT NULL", a.node.ID) == 1
	}) {
		t.Fatal("the newer connection's presence was cleared")
	}
	if state, _, err := h.center.Hub.Presence(ctx, a.node.ID); err != nil || state != hub.Online {
		t.Fatalf("presence %v %v", state, err)
	}
}

// TestHeartbeatDeadlineMarksTheNodeOffline is E1-8 (CTR5-HUB-06, Plan risk 1; mutation "heartbeat deadline ignored"): a node that stops
// answering (a half-open connection: it neither reads nor writes) is closed 4408 at the heartbeat deadline, and its presence is offline.
// A node that answers stays open well past the deadline.
func TestHeartbeatDeadlineMarksTheNodeOffline(t *testing.T) {
	h := newHarness(t, settings{})
	alive, silent := h.enroll(), h.enroll()
	aliveClosed := answer(h.connect(alive))
	h.connect(silent)
	// The silent node reads nothing and sends nothing.
	if !eventually(t, 3*time.Second, func() bool { return !h.center.Hub.Connected(silent.node.ID) }) {
		t.Fatal("the heartbeat deadline did not close the silent node")
	}
	ctx, cancel := background()
	defer cancel()
	if !eventually(t, 2*time.Second, func() bool {
		state, _, err := h.center.Hub.Presence(ctx, silent.node.ID)
		return err == nil && state == hub.Offline
	}) {
		t.Fatal("the silent node is not offline")
	}
	if !eventually(t, 3*time.Second, func() bool {
		return h.center.Metrics.ChannelCount("heartbeat", "missed") != 0 && h.center.Metrics.ChannelCount("closed", "4408") != 0
	}) {
		t.Fatalf("the deadline was not counted: %v", h.center.Metrics.Summary())
	}
	if !stillOpen(aliveClosed, 1500*time.Millisecond) || !h.center.Hub.Connected(alive.node.ID) {
		t.Fatal("a node that answers its heartbeats was closed")
	}
}

// TestPresenceWritesAreBounded is E1-9 (CTR5-HUB-06): heartbeats move last_heartbeat_at at most once per presence interval.
func TestPresenceWritesAreBounded(t *testing.T) {
	for name, interval := range map[string]time.Duration{"an hour": time.Hour, "300 ms": 300 * time.Millisecond} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, settings{tune: func(s *hub.Settings) { s.PresenceInterval = interval }})
			node := h.enroll()
			answer(h.connect(node))
			var first time.Time
			if err := h.db.Migration.QueryRow(context.Background(), "SELECT last_heartbeat_at FROM fleet.node WHERE node_id = $1", node.node.ID).Scan(&first); err != nil {
				t.Fatal(err)
			}
			time.Sleep(1200 * time.Millisecond)
			var last time.Time
			if err := h.db.Migration.QueryRow(context.Background(), "SELECT last_heartbeat_at FROM fleet.node WHERE node_id = $1", node.node.ID).Scan(&last); err != nil {
				t.Fatal(err)
			}
			moved := last.After(first)
			if moved != (interval < time.Second) {
				t.Fatalf("interval %s: the heartbeat moved %v (%s to %s)", interval, moved, first, last)
			}
		})
	}
}

// TestTokenRefreshRebindsAndExpiryCloses is E1-10 (CTR5-HUB-07): a connection whose bound access token expired is closed 4401 once the
// grace passed without a TokenRefresh; a TokenRefresh with the node's new access token rebinds it (the connection then stays open past
// the old token's expiry); a token of another session closes it 4401.
func TestTokenRefreshRebindsAndExpiryCloses(t *testing.T) {
	h := newHarness(t, settings{})
	expiring, refreshed, crossed := h.enroll(), h.enroll(), h.enroll()
	soon := func(node *enrolled) {
		h.db.Exec("UPDATE identity.session SET access_expires_at = now() + interval '1 second' WHERE installation_id = '" + node.result.InstallationID.String() + "'")
	}
	soon(expiring)
	soon(refreshed)
	expiringClosed := answer(h.connect(expiring))
	refreshedChannel := h.connect(refreshed)
	refreshedClosed := answer(refreshedChannel)
	// The node refreshes over gRPC-Web, as it does today (here: in the store), and sends the new token on the channel.
	newToken := h.rotate(refreshed)
	ctx, cancel := background()
	defer cancel()
	if err := refreshedChannel.TokenRefresh(ctx, newToken); err != nil {
		t.Fatal(err)
	}
	if closed := closedWithin(t, expiringClosed, 5*time.Second); closed.Code != hub.CloseCredential || closed.Reason != "token_expired" {
		t.Fatalf("the expired channel: %+v", closed)
	}
	if !stillOpen(refreshedClosed, 1500*time.Millisecond) {
		t.Fatal("the rebound channel was closed")
	}
	if h.center.Metrics.ChannelCount("token", "rebound") != 1 {
		t.Fatal("the rebind was not counted")
	}
	crossedChannel := h.connect(crossed)
	crossedClosed := answer(crossedChannel)
	if err := crossedChannel.TokenRefresh(ctx, refreshed.access); err != nil {
		t.Fatal(err)
	}
	// Another node's (and installation's) token: 4403, so the connection's installation key never changes (relay.proto TokenRefresh).
	if closed := closedWithin(t, crossedClosed, 3*time.Second); closed.Code != hub.CloseRefused || closed.Reason != "installation_mismatch" {
		t.Fatalf("another installation's token: %+v", closed)
	}
}

// rotate gives a node's session a new access token (as RefreshNodeSession does) and returns it.
func (h *harness) rotate(node *enrolled) string {
	h.t.Helper()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	token := session.AccessPrefix + base64.RawURLEncoding.EncodeToString(raw)
	secret, ok := session.ParseToken(session.AccessPrefix, token)
	if !ok {
		h.t.Fatal("the test token is not a token")
	}
	digest := secret.Digest()
	if _, err := h.db.Migration.Exec(context.Background(), "UPDATE identity.session SET access_token_hash = $2, access_expires_at = now() + interval '1 hour' WHERE installation_id = $1",
		node.result.InstallationID, digest[:]); err != nil {
		h.t.Fatal(err)
	}
	node.access = token
	return token
}

// TestDeviceRevocationClosesTheChannelAndRefusesNewCalls is E1-11 (bullet 3, the center half; CTR5-HUB-08, SEC-16; mutation
// "revocation not closing the channel"): the device revocation cascade (the hub's participant after fleet.NodeParticipant) closes the
// node's channel 4401 once it commits; a revocation that rolls back closes nothing; SignOutNode and the operator's revocation of the
// account's sessions close it through the session notice; a revocation committed by another process (here: directly in the store) is
// found by the periodic re-check. A revoked node's next upgrade is refused.
func TestDeviceRevocationClosesTheChannelAndRefusesNewCalls(t *testing.T) {
	// The periodic re-check is out of the way here (an hour), so each close below is the notice's or the participant's.
	h := newHarness(t, settings{})
	ctx, cancel := background()
	defer cancel()
	revokeDevice := func(node *enrolled, commit bool) error {
		participants := []device.Participant{fleet.NodeParticipant{}, h.center.Hub.Participant()}
		err := h.db.Runtime.InTx(ctx, "revoke a device", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
			if _, err := device.Revoke(ctx, tx, node.user, node.result.DeviceID, device.RevokedByOwner, participants, time.Now()); err != nil {
				return err
			}
			if !commit {
				return errRolledBack
			}
			return nil
		})
		return err
	}
	// A revocation that rolls back closes nothing.
	kept := h.enroll()
	keptClosed := answer(h.connect(kept))
	if err := revokeDevice(kept, false); err != errRolledBack {
		t.Fatal(err)
	}
	// The device cascade.
	revoked := h.enroll()
	revokedClosed := answer(h.connect(revoked))
	if err := revokeDevice(revoked, true); err != nil {
		t.Fatal(err)
	}
	if closed := closedWithin(t, revokedClosed, 2*time.Second); closed.Code != hub.CloseCredential || closed.Reason != "revoked" {
		t.Fatalf("the device cascade: %+v", closed)
	}
	if !stillOpen(keptClosed, 700*time.Millisecond) {
		t.Fatal("a revocation that rolled back closed a channel")
	}
	channel, err := h.dial(revoked.access, nil)
	if got := refusalOf(t, channel, err); got.reason != "AUTHENTICATION/credential_revoked" {
		t.Fatalf("the revoked node's next upgrade: %+v", got)
	}
	// SignOutNode (fleet.Service.SignOut's session notice).
	signedOut := h.enroll()
	signedOutClosed := answer(h.connect(signedOut))
	if err := h.db.Runtime.InTx(ctx, "sign out", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "UPDATE identity.session SET revoked_at = now(), revoke_reason = 1, rev = rev + 1 WHERE session_id = $1", signedOut.result.Session.SessionID); err != nil {
			return err
		}
		session.Announce(ctx, session.Revocation{Sessions: []platform.ID{signedOut.result.Session.SessionID}})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if closed := closedWithin(t, signedOutClosed, 2*time.Second); closed.Code != hub.CloseCredential {
		t.Fatalf("the sign-out: %+v", closed)
	}
	// The operator's revocation of an account's sessions (admin revoke-sessions, here in this process).
	operated := h.enroll()
	operatedClosed := answer(h.connect(operated))
	operator := store.New(pgtest.Pool(t, h.db.URL, 2))
	if err := operator.InTx(ctx, "revoke by operator", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := session.RevokeByOperator(ctx, tx, &operated.user, time.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if closed := closedWithin(t, operatedClosed, 2*time.Second); closed.Code != hub.CloseCredential {
		t.Fatalf("the operator's revocation: %+v", closed)
	}
	// Another process: no notice reaches this one; the periodic re-check closes it.
	h = newHarness(t, settings{tune: func(s *hub.Settings) { s.SessionRecheck = 300 * time.Millisecond }})
	elsewhere := h.enroll()
	elsewhereClosed := answer(h.connect(elsewhere))
	h.db.Exec("UPDATE identity.session SET revoked_at = now(), revoke_reason = 6 WHERE installation_id = '" + elsewhere.result.InstallationID.String() + "'")
	if closed := closedWithin(t, elsewhereClosed, 3*time.Second); closed.Code != hub.CloseCredential || closed.Reason != "revoked" {
		t.Fatalf("a revocation of another process: %+v", closed)
	}
}

type rolledBack struct{}

func (rolledBack) Error() string { return "rolled back on purpose" }

var errRolledBack error = rolledBack{}

// TestAnOversizedFrameClosesTheChannel is E1-19 (CTR5-HUB-10, SEC-14): a frame over the bound closes 4413, a node over the frame rate
// 4429, and a frame a node may not send (the center's own challenge) 4403.
func TestAnOversizedFrameClosesTheChannel(t *testing.T) {
	h := newHarness(t, settings{tune: func(s *hub.Settings) { s.InboundFramesPerSecond = 20 }})
	ctx, cancel := background()
	defer cancel()
	large := h.connect(h.enroll())
	if err := large.WS.Write(ctx, websocket.MessageBinary, make([]byte, 1<<20+1)); err != nil {
		t.Fatal(err)
	}
	if closed := large.AwaitClose(ctx, false); closed.Code != hub.CloseTooLarge || closed.Status != hub.CloseTooLarge {
		t.Fatalf("an oversized frame: %+v", closed)
	}
	fast := h.connect(h.enroll())
	for range 30 {
		if err := fast.Heartbeat(ctx, 1); err != nil {
			break
		}
	}
	if closed := fast.AwaitClose(ctx, false); closed.Code != hub.CloseRateLimited {
		t.Fatalf("a node over the frame rate: %+v", closed)
	}
	wrong := h.connect(h.enroll())
	if err := wrong.Send(ctx, &relayv1.RelayFrame{Frame: &relayv1.RelayFrame_Challenge{Challenge: &relayv1.ChannelChallenge{Nonce: make([]byte, 32)}}}); err != nil {
		t.Fatal(err)
	}
	if closed := wrong.AwaitClose(ctx, false); closed.Code != hub.CloseRefused || closed.Reason != "unexpected_frame" {
		t.Fatalf("a frame a node may not send: %+v", closed)
	}
	text := h.connect(h.enroll())
	if err := text.WS.Write(ctx, websocket.MessageText, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if closed := text.AwaitClose(ctx, false); closed.Code != hub.CloseRefused {
		t.Fatalf("a text frame: %+v", closed)
	}
	// A relay nonce request is not answered in E1a, and closes nothing.
	nonce := h.connect(h.enroll())
	nonceClosed := answer(nonce)
	if err := nonce.Send(ctx, &relayv1.RelayFrame{Frame: &relayv1.RelayFrame_RelayNonceRequest{RelayNonceRequest: &relayv1.RelayNonceRequest{}}}); err != nil {
		t.Fatal(err)
	}
	if !stillOpen(nonceClosed, 500*time.Millisecond) {
		t.Fatal("a relay nonce request closed the channel")
	}
}

// TestGracefulShutdownClosesWith4500 is E1-20 (CTR5-HUB-11, PB-5): the hub's stop closes every channel 4500 with a jittered reconnect
// hint in the reason, refuses new upgrades, and releases the lease, which another process then takes over at once.
func TestGracefulShutdownClosesWith4500(t *testing.T) {
	h := newHarness(t, settings{})
	first, second := h.enroll(), h.enroll()
	closed := []<-chan nodetest.Closed{answer(h.connect(first)), answer(h.connect(second))}
	stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h.center.Hub.Stop(stop)
	for _, done := range closed {
		result := closedWithin(t, done, 3*time.Second)
		if result.Code != hub.CloseShuttingDown || result.Status != hub.CloseShuttingDown || result.Reason != "shutting_down" || result.ReconnectAfter < time.Second ||
			result.ReconnectAfter > 2*time.Second {
			t.Fatalf("%+v", result)
		}
	}
	channel, err := h.dial(first.access, nil)
	if got := refusalOf(t, channel, err); got.status != 503 {
		t.Fatalf("an upgrade after the stop: %+v", got)
	}
	next := hub.NewLease(h.db.Runtime, platform.NewID(), 30*time.Second, nil)
	if _, err := next.Acquire(stop); err != nil {
		t.Fatalf("the next process takes the released lease: %v", err)
	}
}

// TestAMalformedHelloIsRefusedBeforeAnySigningInput (C2 review N-4: Go has no generated validators): a hello without node_id, with an
// installation ID or a node ID of the wrong length or the zero ID, or with a signature that is not 64 bytes, is closed 4403
// hello_malformed, before the hub builds the fixed-length hello message; a TokenRefresh without a token is unreadable (4403).
func TestAMalformedHelloIsRefusedBeforeAnySigningInput(t *testing.T) {
	h := newHarness(t, settings{})
	node := h.enroll()
	good := func(channel *nodetest.Channel) []byte {
		return node.node.SignMessage(channel.HelloMessage(publicBaseURL, node.node.ID, node.result.InstallationID), true)
	}
	for name, build := range map[string]func(*nodetest.Channel) *relayv1.NodeHello{
		"no node_id": func(c *nodetest.Channel) *relayv1.NodeHello {
			return &relayv1.NodeHello{InstallationId: idOf(node.result.InstallationID[:]), HelloSignature: good(c)}
		},
		"a short node_id": func(c *nodetest.Channel) *relayv1.NodeHello {
			return &relayv1.NodeHello{NodeId: idOf(node.node.ID[:15]), InstallationId: idOf(node.result.InstallationID[:]), HelloSignature: good(c)}
		},
		"a zero installation_id": func(c *nodetest.Channel) *relayv1.NodeHello {
			return &relayv1.NodeHello{NodeId: idOf(node.node.ID[:]), InstallationId: idOf(make([]byte, 16)), HelloSignature: good(c)}
		},
		"a 63-byte signature": func(c *nodetest.Channel) *relayv1.NodeHello {
			return &relayv1.NodeHello{NodeId: idOf(node.node.ID[:]), InstallationId: idOf(node.result.InstallationID[:]), HelloSignature: good(c)[:63]}
		},
	} {
		channel, err := h.dial(node.access, nil)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := background()
		if err := channel.Send(ctx, &relayv1.RelayFrame{Frame: &relayv1.RelayFrame_NodeHello{NodeHello: build(channel)}}); err != nil {
			t.Fatal(err)
		}
		if closed := channel.AwaitClose(ctx, false); closed.Code != hub.CloseRefused || closed.Reason != "hello_malformed" {
			t.Errorf("%s: %+v", name, closed)
		}
		cancel()
	}
	channel := h.connect(node)
	ctx, cancel := background()
	defer cancel()
	if err := channel.Send(ctx, &relayv1.RelayFrame{Frame: &relayv1.RelayFrame_TokenRefresh{TokenRefresh: &relayv1.TokenRefresh{}}}); err != nil {
		t.Fatal(err)
	}
	if closed := channel.AwaitClose(ctx, true); closed.Code != hub.CloseRefused || closed.Reason != "unreadable_frame" {
		t.Errorf("an empty token refresh: %+v", closed)
	}
}

func idOf(raw []byte) *foundationv1.Id { return &foundationv1.Id{Value: append([]byte(nil), raw...)} }
