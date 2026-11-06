// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"sync"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/hub"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The fix round of Cloud #145 (reviews A and B; EVIDENCE: REAL PostgreSQL, the composed center, its hub and the real WebSocket server;
// MOCKED: the node, nodetest with a software key; the writer is held by hub.StallWrites, a test hook that holds a connection's writer
// after it takes a frame).

// quietHeartbeats keeps the heartbeat deadline out of the way while a writer is held.
func quietHeartbeats(s *hub.Settings) { s.Heartbeat, s.HeartbeatDeadline = time.Second, 20*time.Second }

// callWith makes a call under a context the test controls.
func (h *harness) callWith(ctx context.Context, call hub.Call) <-chan called {
	done := make(chan called, 1)
	go func() {
		result, err := h.center.Hub.Call(ctx, call)
		done <- called{result, err}
	}()
	return done
}

// noCallArrives reports that a channel receives no call frame within a while (the read's end closes the channel, which is fine at the
// end of a case).
func noCallArrives(t *testing.T, channel *nodetest.Channel, within time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	if call, err := channel.NextCall(ctx); err == nil {
		t.Fatalf("the node received a call that was answered DID_NOT_HAPPEN (kid %s)", call.GetHeader().GetKid())
	}
}

func didNotHappen(t *testing.T, err error, reason string) {
	t.Helper()
	refusal := refused(t, err)
	if refusal.Key() != "STATE/node_unreachable" || refusal.Reason != reason || refusal.Effect == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN ||
		refusal.Retry != foundationv1.RetryMode_RETRY_MODE_AFTER_TIME {
		t.Fatalf("a queued call: %+v", refusal)
	}
}

// TestAQueuedCallWhoseCallerGoesAwayIsNeverWritten is review A B-1 / B B-1: a Submit still queued when its caller goes away is answered
// DID_NOT_HAPPEN, and its frame is skipped, never written.
func TestAQueuedCallWhoseCallerGoesAwayIsNeverWritten(t *testing.T) {
	h := newHarness(t, settings{tune: quietHeartbeats})
	node := h.enroll()
	channel := h.connect(node)
	release := h.center.Hub.StallWrites(node.node.ID)
	ctx, cancel := context.WithCancel(context.Background())
	done := h.callWith(ctx, sessionCall(node, hub.MethodSubmitNodeTask, []byte{1}))
	if !eventually(t, 2*time.Second, func() bool { return h.center.Hub.CallsSent() == 1 }) {
		t.Fatal("the call was not queued")
	}
	cancel()
	didNotHappen(t, await(t, done).err, arc.UnreachableDeadline)
	release()
	noCallArrives(t, channel, 700*time.Millisecond)
}

// TestAQueuedCallWhoseDeadlinePassesIsNeverWritten: a Submit still queued at its deadline is DID_NOT_HAPPEN and never written; the
// connection serves the next call.
func TestAQueuedCallWhoseDeadlinePassesIsNeverWritten(t *testing.T) {
	h := newHarness(t, settings{tune: quietHeartbeats})
	node := h.enroll()
	channel := h.connect(node)
	release := h.center.Hub.StallWrites(node.node.ID)
	call := sessionCall(node, hub.MethodSubmitNodeTask, []byte{1})
	call.Deadline = 300 * time.Millisecond
	didNotHappen(t, await(t, h.callAsync(call)).err, arc.UnreachableDeadline)
	release()
	// The next call is the first the node reads: the abandoned frame was skipped.
	done := h.callAsync(sessionCall(node, hub.MethodGetNodeTask, []byte{2}))
	sent := nextCall(t, channel)
	if !bytes.Equal(sent.GetPayload(), []byte{2}) {
		t.Fatal("the node received the abandoned call")
	}
	ctx, cancel := background()
	defer cancel()
	if err := channel.Answer(ctx, node.node, sent.GetCallId(), node.node.Executed(sent, []byte{3}), []byte{3}); err != nil {
		t.Fatal(err)
	}
	if value := await(t, done); value.err != nil {
		t.Fatal(value.err)
	}
}

// TestAQueuedCallOfAReplacedOrRevokedConnectionIsNeverWritten: a close (4409 replaced, 4401 revoked) fails a queued Submit
// DID_NOT_HAPPEN, and the closed connection never writes it.
func TestAQueuedCallOfAReplacedOrRevokedConnectionIsNeverWritten(t *testing.T) {
	h := newHarness(t, settings{tune: quietHeartbeats})
	ctx, cancel := background()
	defer cancel()
	for _, close := range []struct {
		name string
		code uint32
		act  func(*enrolled)
	}{
		{"replaced", hub.CloseReplaced, func(node *enrolled) { h.connect(node) }},
		{"revoked", hub.CloseCredential, func(node *enrolled) {
			participants := []device.Participant{fleet.NodeParticipant{}, h.center.Hub.Participant()}
			if err := h.db.Runtime.InTx(ctx, "revoke a device", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
				_, err := device.Revoke(ctx, tx, node.user, node.result.DeviceID, device.RevokedByOwner, participants, time.Now())
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		node := h.enroll()
		channel := h.connect(node)
		release := h.center.Hub.StallWrites(node.node.ID)
		sent := h.center.Hub.CallsSent()
		done := h.callAsync(sessionCall(node, hub.MethodSubmitNodeTask, []byte{1}))
		if !eventually(t, 2*time.Second, func() bool { return h.center.Hub.CallsSent() == sent+1 }) {
			t.Fatalf("%s: the call was not queued", close.name)
		}
		close.act(node)
		didNotHappen(t, await(t, done).err, arc.UnreachableChannelClosed)
		release()
		// The closed connection's frames: its RelayClose and nothing of the call.
		for {
			frame, err := channel.Next(ctx)
			if err != nil {
				break
			}
			if frame.GetCall() != nil {
				t.Fatalf("%s: the closed connection wrote the abandoned call", close.name)
			}
			if value := frame.GetClose(); value != nil && value.GetCode() != close.code {
				t.Fatalf("%s: closed %d", close.name, value.GetCode())
			}
		}
	}
}

// TestALateResultIsStillBoundAndCountsAgainstTheNodesBound is review A N-1 and N-3: a delivered call past its deadline counts against
// the node's in-flight bound until its late result (it may still run at the node); a late result is bound like any other, so a
// mismatching one is still a violation.
func TestALateResultIsStillBoundAndCountsAgainstTheNodesBound(t *testing.T) {
	h := newHarness(t, settings{tune: func(s *hub.Settings) { quietHeartbeats(s); s.MaxInFlightCalls = 1 }})
	node := h.enroll()
	channel := h.connect(node)
	ctx, cancel := background()
	defer cancel()
	call := sessionCall(node, hub.MethodSubmitNodeTask, []byte{1})
	call.Deadline = 200 * time.Millisecond
	done := h.callAsync(call)
	sent := nextCall(t, channel)
	if refusal := refused(t, await(t, done).err); refusal.Effect != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN {
		t.Fatalf("a delivered submit past its deadline: %+v", refusal)
	}
	// The late call still holds the node's one slot.
	if refusal := refused(t, await(t, h.callAsync(sessionCall(node, hub.MethodGetNodeTask, []byte{2}))).err); refusal.Key() != "RESOURCE/overloaded" {
		t.Fatalf("a call while a late call may still run: %s", refusal.Key())
	}
	// Its late, honest result frees it.
	if err := channel.Answer(ctx, node.node, sent.GetCallId(), node.node.Executed(sent, []byte{3}), []byte{3}); err != nil {
		t.Fatal(err)
	}
	if !eventually(t, 2*time.Second, func() bool { return h.center.Metrics.ChannelCount("call", "late") == 1 }) {
		t.Fatal("the late result was not taken")
	}
	read := sessionCall(node, hub.MethodGetNodeTask, []byte{4})
	read.Deadline = 200 * time.Millisecond
	done = h.callAsync(read)
	sent = nextCall(t, channel)
	await(t, done)
	// A late result that does not bind (another request digest) is a violation.
	header := node.node.Executed(sent, []byte{5})
	header.RequestSha256 = make([]byte, 32)
	if err := channel.Answer(ctx, node.node, sent.GetCallId(), header, []byte{5}); err != nil {
		t.Fatal(err)
	}
	if closed := channel.AwaitClose(ctx, false); closed.Code != hub.CloseRefused || closed.Reason != "result_mismatch" {
		t.Fatalf("a late result that does not bind: %+v", closed)
	}
}

// TestTwoConcurrentSpendsOfOneNonceAdmitOne is review A N-6: the same assertion verified twice at once spends its nonce once.
func TestTwoConcurrentSpendsOfOneNonceAdmitOne(t *testing.T) {
	h := newHarness(t, settings{})
	node := h.enroll()
	channel := h.connect(node)
	for range 10 {
		_, request := relayed(node, nonceOf(t, channel), []byte{1})
		var wg sync.WaitGroup
		results := make([]error, 2)
		for i := range results {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := background()
				defer cancel()
				_, results[i] = h.center.Hub.VerifyRelayAssertion(ctx, credentialOf(node), request)
			}()
		}
		wg.Wait()
		if (results[0] == nil) == (results[1] == nil) {
			t.Fatalf("two concurrent spends: %v, %v", results[0], results[1])
		}
		for _, err := range results {
			if err != nil && relayRefusal(t, err) != arc.RelayNonceReused {
				t.Fatalf("the losing spend: %v", err)
			}
		}
	}
}

// TestTheKeyLoopRotatesOnItsOwnAndFailsClosedWhenStale is review B B-3 and N-6 and A N-2: the loop re-reads the keys every period
// without help (a successor signs from its not_before); while the store does not answer, the rows last read sign for at most
// KeyStalePeriods periods, then nothing is signed (node_unreachable, DID_NOT_HAPPEN) until a read succeeds again; and Stop returns
// while a key read is blocked.
func TestTheKeyLoopRotatesOnItsOwnAndFailsClosedWhenStale(t *testing.T) {
	const period = 200 * time.Millisecond
	h := newHarness(t, settings{tune: func(s *hub.Settings) { quietHeartbeats(s); s.KeyRefresh = period }})
	node := h.enroll()
	channel := h.connect(node)
	successor, successorKID := h.registerKey(t, "ARCFORGES_CENTER_KEY_NEXT", time.Now().Add(800*time.Millisecond))
	h.center.Hub.UseCommandKeys([]config.CommandKey{h.commandKey, successor})
	// No explicit refresh: the loop reads the rows, and the successor signs from its not_before.
	if !eventually(t, 3*time.Second, func() bool { kid, _ := h.center.Hub.SigningKID(time.Now()); return kid == successorKID }) {
		t.Fatal("the key loop did not take the successor on its own")
	}
	ctx, cancel := background()
	defer cancel()
	// The store stops answering the key reads: a lock on fleet.signing_key that every read waits behind.
	lock, err := h.db.Migration.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Rollback(context.Background()) }()
	if _, err := lock.Exec(ctx, "LOCK TABLE fleet.signing_key IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(hub.KeyStalePeriods*period + 2*period)
	time.Sleep(time.Until(stale))
	if kid, ok := h.center.Hub.SigningKID(time.Now()); ok {
		t.Fatalf("a stale keyring still signs with %s", kid)
	}
	sent := h.center.Hub.CallsSent()
	didNotHappen(t, await(t, h.callAsync(sessionCall(node, hub.MethodSubmitNodeTask, []byte{1}))).err, arc.UnreachableChannelClosed)
	if h.center.Hub.CallsSent() != sent {
		t.Fatal("a stale keyring sent a call")
	}
	if kid := h.health(t); kid != "" {
		t.Fatalf("the health document names %q while the keyring is stale", kid)
	}
	// The store answers again: the next read restores signing.
	if err := lock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if !eventually(t, 7*time.Second, func() bool { _, ok := h.center.Hub.SigningKID(time.Now()); return ok }) {
		t.Fatal("the keyring did not recover")
	}
	done := h.callAsync(sessionCall(node, hub.MethodGetNodeTask, []byte{2}))
	call := nextCall(t, channel)
	if call.GetHeader().GetKid() != successorKID {
		t.Fatalf("the call after the recovery: %s", call.GetHeader().GetKid())
	}
	if err := channel.Answer(ctx, node.node, call.GetCallId(), node.node.Executed(call, []byte{3}), []byte{3}); err != nil {
		t.Fatal(err)
	}
	if value := await(t, done); value.err != nil {
		t.Fatal(value.err)
	}
	// Stop returns while a key read is blocked.
	again, err := h.db.Migration.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = again.Rollback(context.Background()) }()
	if _, err := again.Exec(ctx, "LOCK TABLE fleet.signing_key IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * period)
	stop, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	started := time.Now()
	h.center.Hub.Stop(stop)
	if took := time.Since(started); took > 3*time.Second {
		t.Fatalf("Stop waited %s for a blocked key read", took)
	}
}

// keyForms are the base64, hex and PEM forms of a key's DER (review B N-2).
func keyForms(der []byte, block string) []string {
	return []string{base64.StdEncoding.EncodeToString(der), base64.RawURLEncoding.EncodeToString(der), hex.EncodeToString(der),
		string(pem.EncodeToMemory(&pem.Block{Type: block, Bytes: der}))}
}

// privateForms are the forms of a command key's private half.
func privateForms(t *testing.T, key config.CommandKey) []string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key.Signer())
	if err != nil {
		t.Fatal(err)
	}
	return keyForms(der, "PRIVATE KEY")
}

// TestACallerThatLeftIsNeverSigned is review A N-4: a call whose caller has already gone away is refused DID_NOT_HAPPEN before anything is
// signed or queued.
func TestACallerThatLeftIsNeverSigned(t *testing.T) {
	h := newHarness(t, settings{})
	node := h.enroll()
	h.connect(node)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	inputs, sent := hub.SigningInputs(), h.center.Hub.CallsSent()
	didNotHappen(t, await(t, h.callWith(ctx, sessionCall(node, hub.MethodSubmitNodeTask, []byte{1}))).err, arc.UnreachableDeadline)
	if hub.SigningInputs() != inputs || h.center.Hub.CallsSent() != sent {
		t.Fatal("a call of a caller that left was signed or queued")
	}
}
