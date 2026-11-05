// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"strings"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/hub"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
)

// The fix round of Cloud #144 (reviews A and B; EVIDENCE: REAL PostgreSQL, the composed center, the real WebSocket server; MOCKED: the
// node, nodetest's channel client).

// TestTokenRefreshHasItsOwnBound is review A B-1 (CTR5-SEC-14): a TokenRefresh costs store work, so it has its own bound before any of
// it. The token the connection is bound to is answered without the store; a new token is admitted once per TokenRefreshInterval after
// the first refresh, and one more within it closes 4429 token_refresh_rate. A burst of refreshes on a connection therefore reaches the
// store at most once before the close.
func TestTokenRefreshHasItsOwnBound(t *testing.T) {
	h := newHarness(t, settings{tune: func(s *hub.Settings) { s.TokenRefreshInterval = 400 * time.Millisecond }})
	node := h.enroll()
	channel := h.connect(node)
	closed := answer(channel)
	ctx, cancel := background()
	defer cancel()
	metrics := h.center.Metrics
	if err := channel.TokenRefresh(ctx, node.access); err != nil {
		t.Fatal(err)
	}
	if !eventually(t, 2*time.Second, func() bool { return metrics.ChannelCount("token", "unchanged") == 1 }) || metrics.ChannelCount("token", "rebound") != 0 {
		t.Fatal("the bound token was not answered without the store")
	}
	time.Sleep(450 * time.Millisecond)
	token := h.rotate(node)
	if err := channel.TokenRefresh(ctx, token); err != nil {
		t.Fatal(err)
	}
	if !eventually(t, 2*time.Second, func() bool { return metrics.ChannelCount("token", "rebound") == 1 }) || !stillOpen(closed, 100*time.Millisecond) {
		t.Fatal("a refresh after the interval was not admitted")
	}
	if err := channel.TokenRefresh(ctx, token); err != nil {
		t.Fatal(err)
	}
	if result := closedWithin(t, closed, 3*time.Second); result.Code != hub.CloseRateLimited || result.Reason != "token_refresh_rate" {
		t.Fatalf("a refresh within the interval: %+v", result)
	}
	// A burst: fifty refreshes with a new token at once; one reaches the store, the second closes the connection.
	burst := h.enroll()
	burstChannel := h.connect(burst)
	burstClosed := answer(burstChannel)
	fresh := h.rotate(burst)
	for range 50 {
		if burstChannel.TokenRefresh(ctx, fresh) != nil {
			break
		}
	}
	if result := closedWithin(t, burstClosed, 3*time.Second); result.Code != hub.CloseRateLimited || result.Reason != "token_refresh_rate" {
		t.Fatalf("a burst of refreshes: %+v", result)
	}
	if rebound := metrics.ChannelCount("token", "rebound"); rebound != 2 {
		t.Fatalf("the burst reached the store %d times", rebound-1)
	}
	if metrics.ChannelCount("token", "rate") != 2 {
		t.Fatal("the refresh rate closes were not counted")
	}
}

// TestABarredAccountsRefreshCloses4403 is review A N-5: a TokenRefresh of an account that may no longer sign in closes 4403
// account_state, as the periodic re-check answers it, not 4401 (a node would retry a refresh that cannot succeed).
func TestABarredAccountsRefreshCloses4403(t *testing.T) {
	h := newHarness(t, settings{})
	node := h.enroll()
	channel := h.connect(node)
	closed := answer(channel)
	token := h.rotate(node)
	h.db.Exec("UPDATE identity.user SET state = 3 WHERE user_id = '" + node.user.String() + "'")
	ctx, cancel := background()
	defer cancel()
	if err := channel.TokenRefresh(ctx, token); err != nil {
		t.Fatal(err)
	}
	if result := closedWithin(t, closed, 3*time.Second); result.Code != hub.CloseRefused || result.Reason != "account_state" {
		t.Fatalf("a barred account's refresh: %+v", result)
	}
}

// TestALateHelloIsRefusedByItsNonce is review A N-1 (D0-B2: the nonce is void at the deadline): a correctly signed hello read at or
// after the hello deadline closes 4408 hello_deadline by the hello's own check, before the supervisor's tick (here a second) could.
func TestALateHelloIsRefusedByItsNonce(t *testing.T) {
	h := newHarness(t, settings{tune: func(s *hub.Settings) {
		s.HelloDeadline, s.Heartbeat, s.HeartbeatDeadline = 150*time.Millisecond, 10*time.Second, 30*time.Second
	}})
	node := h.enroll()
	started := time.Now()
	channel, err := h.dial(node.access, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = channel.WS.CloseNow() }()
	time.Sleep(300 * time.Millisecond)
	ctx, cancel := background()
	defer cancel()
	if err := channel.Hello(ctx, node.node, node.result.InstallationID, publicBaseURL); err != nil {
		t.Fatal(err)
	}
	result := channel.AwaitClose(ctx, false)
	if result.Code != hub.CloseDeadline || result.Reason != "hello_deadline" {
		t.Fatalf("a late hello: %+v", result)
	}
	if elapsed := time.Since(started); elapsed >= 900*time.Millisecond {
		t.Fatalf("the late hello was closed only by the supervisor's tick (%s)", elapsed)
	}
	if h.center.Hub.Connected(node.node.ID) || h.audits("fleet.channel.accepted") != 0 {
		t.Fatal("a late hello was accepted")
	}
}

// TestARevocationBeforeTheHelloIsFound is review A N-2: a revocation that commits after the admission and before the connection is
// tracked reaches no revocation hook (here: committed by another process, straight in the store), so the hello re-reads the credential
// before the connection becomes the node's: it closes 4401 revoked, and nothing is accepted.
func TestARevocationBeforeTheHelloIsFound(t *testing.T) {
	h := newHarness(t, settings{})
	node := h.enroll()
	channel, err := h.dial(node.access, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = channel.WS.CloseNow() }()
	h.db.Exec("UPDATE identity.session SET revoked_at = now(), revoke_reason = 6 WHERE installation_id = '" + node.result.InstallationID.String() + "'")
	ctx, cancel := background()
	defer cancel()
	if err := channel.Hello(ctx, node.node, node.result.InstallationID, publicBaseURL); err != nil {
		t.Fatal(err)
	}
	if result := channel.AwaitClose(ctx, false); result.Code != hub.CloseCredential || result.Reason != "revoked" {
		t.Fatalf("a hello after the revocation: %+v", result)
	}
	if h.center.Hub.Connected(node.node.ID) || h.audits("fleet.channel.accepted") != 0 {
		t.Fatal("a revoked credential's hello was accepted")
	}
}

// TestAHelloUnderAStaleFenceIsClosedNotAccepted is review B B-1: a proved hello whose presence write the lease refuses (the fence the
// upgrade was admitted under is no longer the live one) closes 4500 lease_lost without ChannelAccepted, and the node's older
// connection keeps the node: it is neither replaced nor closed by it. A node row revoked since the admission closes 4401 revoked (a live
// fence, not a fenced write).
func TestAHelloUnderAStaleFenceIsClosedNotAccepted(t *testing.T) {
	// The lease loop is out of the way (an hour), so the only one to find the stale fence is the hello.
	h := newHarness(t, settings{tune: func(s *hub.Settings) { s.LeaseRenew = time.Hour }})
	node := h.enroll()
	older := answer(h.connect(node))
	accepted := h.audits("fleet.channel.accepted")
	newer, err := h.dial(node.access, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = newer.WS.CloseNow() }()
	// Another process takes the lease over under a higher fence.
	h.db.Exec("UPDATE fleet.hub_lease SET fence = fence + 1, holder = gen_random_uuid()")
	ctx, cancel := background()
	defer cancel()
	if err := newer.Hello(ctx, node.node, node.result.InstallationID, publicBaseURL); err != nil {
		t.Fatal(err)
	}
	result := newer.AwaitClose(ctx, false)
	if result.Code != hub.CloseShuttingDown || result.Reason != "lease_lost" || result.ReconnectAfter <= 0 {
		t.Fatalf("a hello under a stale fence: %+v", result)
	}
	if !stillOpen(older, 500*time.Millisecond) || !h.center.Hub.Connected(node.node.ID) || h.audits("fleet.channel.accepted") != accepted {
		t.Fatal("the stale-fenced hello displaced the older connection or was accepted")
	}
	if h.center.Metrics.ChannelCount("hello", "fenced") != 1 {
		t.Fatal("the fenced hello was not counted")
	}
	// A live fence over a node row revoked since the admission.
	fresh := newHarness(t, settings{})
	gone := fresh.enroll()
	channel, err := fresh.dial(gone.access, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = channel.WS.CloseNow() }()
	fresh.db.Exec("UPDATE fleet.node SET revoked_at = now(), revoke_reason = 1, rev = rev + 1 WHERE installation_id = '" + gone.result.InstallationID.String() + "'")
	if err := channel.Hello(ctx, gone.node, gone.result.InstallationID, publicBaseURL); err != nil {
		t.Fatal(err)
	}
	if result := channel.AwaitClose(ctx, false); result.Code != hub.CloseCredential || result.Reason != "revoked" {
		t.Fatalf("a hello of a node revoked since the admission: %+v", result)
	}
	if fresh.center.Metrics.ChannelCount("hello", "node_gone") != 1 || fresh.center.Metrics.ChannelCount("hello", "fenced") != 0 {
		t.Fatal("the gone node was taken for a fenced write")
	}
}

// TestAHubWhoseRenewalsFailStandsDown is review B B-1 and its confirmation (A B-3, B C-B1; PB-5), at the production ratio of the time
// to live to the renewal interval (3 : 1; here 3 s and 1 s for PB-5's 30 s and 10 s): a hub whose lease renewals fail fast (the
// runtime role may no longer update the lease row) gives its claim up at the claim's local expiry itself, the time to live less a sixth
// after its last successful renewal: the loop wakes then, not on its next renewal tick, so admission stops and the channel's close
// starts there, and the channel is closed before the database's expiry (a sixth later) lets another process take the lease. Once the
// store answers again the hub takes its own lapsed row over under a higher fence (it never takes it for another process's) and serves
// again.
func TestAHubWhoseRenewalsFailStandsDown(t *testing.T) {
	h := newHarness(t, settings{tune: func(s *hub.Settings) { s.LeaseTTL, s.LeaseRenew = 3*time.Second, time.Second }})
	node := h.enroll()
	closed := answer(h.connect(node))
	fence, _ := h.center.Hub.Lease().Fence()
	role := `"` + h.db.Name + `_runtime"`
	h.db.Exec("REVOKE UPDATE ON fleet.hub_lease FROM " + role)
	// A renewal in flight at the revoke may still have succeeded; past one renewal interval the local expiry no longer moves.
	time.Sleep(1100 * time.Millisecond)
	until, held := h.center.Hub.Lease().ValidUntil()
	if !held || !time.Now().Before(until) {
		t.Fatal("the claim lapsed before the test read its local expiry")
	}
	result := closedWithin(t, closed, 5*time.Second)
	closedAt := time.Now()
	if result.Code != hub.CloseShuttingDown || result.Reason != "lease_lost" {
		t.Fatalf("a hub whose renewals fail: %+v", result)
	}
	// The database's expiry is at least a sixth of the time to live (500 ms) after the local expiry; the close is done well before it.
	if late := closedAt.Sub(until); late > 300*time.Millisecond {
		t.Fatalf("the channel closed %s after the local expiry (the database's expiry is 500 ms after it)", late)
	}
	if h.center.Metrics.ChannelCount("lease", "renewal_failed") == 0 || h.center.Metrics.ChannelCount("lease", "lost") != 1 {
		t.Fatal("the failed renewals and the loss were not counted")
	}
	if _, held := h.center.Hub.Lease().Fence(); held {
		t.Fatal("the hub still holds a fence")
	}
	channel, err := h.dial(node.access, nil)
	if got := refusalOf(t, channel, err); got.status != 503 {
		t.Fatalf("an upgrade while the hub holds no lease: %+v", got)
	}
	// The store answers again: the hub takes its own row over under a higher fence, and admits the node again. Its own lapsed row is
	// never logged or counted as another process's (review B C-N1).
	h.db.Exec("GRANT UPDATE ON fleet.hub_lease TO " + role)
	if !eventually(t, 8*time.Second, func() bool { next, held := h.center.Hub.Lease().Fence(); return held && next > fence }) {
		t.Fatal("the hub did not take the lease over again")
	}
	if h.center.Metrics.ChannelCount("lease", "held_elsewhere") != 0 || strings.Contains(h.logs.String(), "another center process holds") {
		t.Fatal("the hub took its own lapsed lease for another process's")
	}
	answer(h.connect(node))
}

// TestALeaseTakenOverClosesTheChannels is review B B-1: a renewal that finds the lease another process's closes every channel 4500
// lease_lost with a reconnect hint.
func TestALeaseTakenOverClosesTheChannels(t *testing.T) {
	h := newHarness(t, settings{tune: func(s *hub.Settings) { s.LeaseRenew = 200 * time.Millisecond }})
	first, second := h.enroll(), h.enroll()
	closed := []<-chan nodetest.Closed{answer(h.connect(first)), answer(h.connect(second))}
	h.db.Exec("UPDATE fleet.hub_lease SET fence = fence + 1, holder = gen_random_uuid()")
	for _, done := range closed {
		if result := closedWithin(t, done, 3*time.Second); result.Code != hub.CloseShuttingDown || result.Reason != "lease_lost" || result.ReconnectAfter <= 0 {
			t.Fatalf("a channel of a hub whose lease was taken over: %+v", result)
		}
	}
}

// TestNoValidCommandKeyNeverSendsEmptySigningKids is review B N-3: ChannelAccepted lists at least one kid (the contract's bound). When
// no command key the center holds is valid any more (here: retired while it runs), a proved hello closes 4500 no_signing_key instead.
func TestNoValidCommandKeyNeverSendsEmptySigningKids(t *testing.T) {
	h := newHarness(t, settings{})
	node := h.enroll()
	h.db.Exec("UPDATE fleet.signing_key SET retired_at = now() WHERE kid = '" + h.kid + "'")
	channel, err := h.dial(node.access, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = channel.WS.CloseNow() }()
	ctx, cancel := background()
	defer cancel()
	if err := channel.Hello(ctx, node.node, node.result.InstallationID, publicBaseURL); err != nil {
		t.Fatal(err)
	}
	if result := channel.AwaitClose(ctx, false); result.Code != hub.CloseShuttingDown || result.Reason != "no_signing_key" {
		t.Fatalf("a hello without a valid command key: %+v", result)
	}
	if h.center.Hub.Connected(node.node.ID) {
		t.Fatal("a channel was accepted without a signing kid")
	}
}
