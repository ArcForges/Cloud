// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// clock is a settable clock for the lease tests.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(by time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(by)
	c.mu.Unlock()
}

// expireLease ends the live lease by the database's clock, as the time to live passing would (the lease's instants are the
// database's, so a test moves the row, not a clock).
func expireLease(t *testing.T, db *dbtest.Database) {
	t.Helper()
	db.Exec("UPDATE fleet.hub_lease SET expires_at = acquired_at, renewed_at = acquired_at")
}

// TestASecondHubOnTheSameDatabaseRefusesToStart is E1-21 (Plan CTR5-HUB-05 as amended by PB-5 and Q22; EVIDENCE: REAL PostgreSQL, the
// runtime role's privileges): one hub per database. While hub A holds a live lease, hub B's acquisition is refused (it serves no
// channel); a lease that expired (a killed center) is taken over by B with a higher fence, and A's renewal then fails, so A knows it
// lost it; a released lease (a graceful stop) is taken over at once; and a fenced write names the lease's live fence only, so a write of
// an older epoch, even by the same process after it took the lease again, is refused. Every expiry is the database's clock.
func TestASecondHubOnTheSameDatabaseRefusesToStart(t *testing.T) {
	db := dbtest.New(t)
	ctx := context.Background()
	at := &clock{now: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}
	a := NewLease(db.Runtime, platform.NewID(), 30*time.Second, at.Now)
	b := NewLease(db.Runtime, platform.NewID(), 30*time.Second, at.Now)
	first, err := a.Acquire(ctx)
	if err != nil || first != 1 {
		t.Fatalf("A takes the free lease: %d %v", first, err)
	}
	if _, err = b.Acquire(ctx); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("B while A holds a live lease: %v", err)
	}
	if _, held := b.Fence(); held {
		t.Fatal("B holds a fence it was refused")
	}
	// A renews within its time to live; B still cannot take it.
	if renewed, err := a.Renew(ctx); err != nil || !renewed {
		t.Fatalf("A's renewal: %v %v", renewed, err)
	}
	if _, err = b.Acquire(ctx); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("B within A's renewed lease: %v", err)
	}
	// A process whose own clock runs far ahead still cannot take the live lease: the expiry is the database's (review B N-2).
	ahead := NewLease(db.Runtime, platform.NewID(), 30*time.Second, func() time.Time { return time.Now().Add(time.Hour) })
	if _, err = ahead.Acquire(ctx); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("a process whose clock runs ahead: %v", err)
	}
	// A stops renewing (it was killed): after the time to live B takes over with a higher fence, and A's renewal fails.
	expireLease(t, db)
	second, err := b.Acquire(ctx)
	if err != nil || second != first+1 {
		t.Fatalf("B's takeover after the expiry: %d %v", second, err)
	}
	if renewed, err := a.Renew(ctx); err != nil || renewed {
		t.Fatalf("A renewed a lease B took over: %v %v", renewed, err)
	}
	if _, held := a.Fence(); held {
		t.Fatal("A still holds a fence after it lost the lease")
	}
	// B stops gracefully: the lease is released and A takes it over at once, without waiting for the time to live.
	if err = b.Release(ctx); err != nil {
		t.Fatal(err)
	}
	third, err := a.Acquire(ctx)
	if err != nil || third != second+1 {
		t.Fatalf("A's takeover after B released it: %d %v", third, err)
	}
	// The fence of every presence write: only the live fence writes; B's fence, and A's own earlier fence, are refused.
	h := &Hub{db: db.Runtime, lease: a}
	enrollment := seedNode(t, db)
	for fence, want := range map[int64]error{first: ErrFenced, second: ErrFenced, third: nil} {
		if err := h.markOnline(ctx, enrollment, platform.NewID(), fence, at.Now()); !errors.Is(err, want) {
			t.Errorf("a write under fence %d: %v, want %v", fence, err, want)
		}
	}
	// A lease that expired refuses even its own live fence's writes.
	expireLease(t, db)
	if err := h.markOnline(ctx, enrollment, platform.NewID(), third, at.Now()); !errors.Is(err, ErrFenced) {
		t.Errorf("a write under an expired lease: %v", err)
	}
	if n := db.Count("SELECT count(*) FROM fleet.hub_lease"); n != 1 {
		t.Fatalf("the lease is one row: %d", n)
	}
}

// TestTheAcceptWriteTellsAStaleFenceFromAGoneNode (review B B-1): the accept's presence write refuses a fence that is not live with
// ErrFenced and a live fence over a revoked node row with ErrNodeGone, so the hub closes the first 4500 lease_lost and the second 4401.
func TestTheAcceptWriteTellsAStaleFenceFromAGoneNode(t *testing.T) {
	db := dbtest.New(t)
	ctx := context.Background()
	lease := NewLease(db.Runtime, platform.NewID(), 30*time.Second, nil)
	fence, err := lease.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h := &Hub{db: db.Runtime, lease: lease}
	enrollment := seedNode(t, db)
	if err := h.markOnline(ctx, enrollment, platform.NewID(), fence+1, time.Now()); !errors.Is(err, ErrFenced) {
		t.Fatalf("a fence that is not live: %v", err)
	}
	db.Exec("UPDATE fleet.node SET revoked_at = now(), revoke_reason = 1, rev = rev + 1 WHERE enrollment_id = '" + enrollment.String() + "'")
	if err := h.markOnline(ctx, enrollment, platform.NewID(), fence, time.Now()); !errors.Is(err, ErrNodeGone) {
		t.Fatalf("a live fence over a revoked node: %v", err)
	}
	expireLease(t, db)
	if err := h.markOnline(ctx, enrollment, platform.NewID(), fence, time.Now()); !errors.Is(err, ErrFenced) {
		t.Fatalf("an expired lease over a revoked node: %v", err)
	}
}

// TestAClaimWhoseRenewalsFailLapsesLocally (review B B-1): the claim keeps a local expiry, the time to live less a sixth after the start
// of its last successful acquisition or renewal. A renewal that errors leaves it where it was, so once the process's own clock passes
// it the claim holds no fence (Fence false, Lapse true once), even though the database's row still names it.
func TestAClaimWhoseRenewalsFailLapsesLocally(t *testing.T) {
	db := dbtest.New(t)
	at := &clock{now: time.Now()}
	lease := NewLease(db.Runtime, platform.NewID(), 30*time.Second, at.Now)
	if _, err := lease.Acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	at.Advance(20 * time.Second)
	failing, cancel := context.WithCancel(t.Context())
	cancel()
	if renewed, err := lease.Renew(failing); err == nil || renewed {
		t.Fatalf("a renewal over a store that does not answer: %v %v", renewed, err)
	}
	if _, held := lease.Fence(); !held || lease.Lapse() {
		t.Fatal("the claim lapsed before its local expiry")
	}
	at.Advance(5 * time.Second)
	if _, held := lease.Fence(); held {
		t.Fatal("the claim still holds a fence past its local expiry")
	}
	if !lease.Lapse() || lease.Lapse() {
		t.Fatal("the lapse of the claim is not reported exactly once")
	}
	if renewed, err := lease.Renew(t.Context()); err != nil || renewed {
		t.Fatalf("a lapsed claim renewed: %v %v", renewed, err)
	}
	// The row still names this claim's holder and is still live by the database's clock: another process cannot take it, and this
	// claim takes its own row over at once under a higher fence (review B C-N1), so the lapsed epoch's writes stay refused.
	other := NewLease(db.Runtime, platform.NewID(), 30*time.Second, at.Now)
	if _, err := other.Acquire(t.Context()); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("another process over a live lapsed row: %v", err)
	}
	first := db.Count("SELECT fence FROM fleet.hub_lease")
	if again, err := lease.Acquire(t.Context()); err != nil || again != int64(first)+1 {
		t.Fatalf("the claim over its own live lapsed row: %d %v", again, err)
	}
	if n := db.Count("SELECT count(*) FROM fleet.hub_lease WHERE expires_at > clock_timestamp()"); n != 1 {
		t.Fatal("the own takeover left no live lease")
	}
	// A successful renewal moves the local expiry: a fresh claim renewed at 20 s holds until 45 s.
	fresh := NewLease(db.Runtime, platform.NewID(), 30*time.Second, at.Now)
	expireLease(t, db)
	if _, err := fresh.Acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	at.Advance(20 * time.Second)
	if renewed, err := fresh.Renew(t.Context()); err != nil || !renewed {
		t.Fatalf("the fresh claim's renewal: %v %v", renewed, err)
	}
	at.Advance(24 * time.Second)
	if _, held := fresh.Fence(); !held {
		t.Fatal("the renewal did not move the local expiry")
	}
	at.Advance(time.Second)
	if _, held := fresh.Fence(); held {
		t.Fatal("the renewed claim holds past its local expiry")
	}
}

// TestConcurrentAcquisitionsElectOneHolder (PB-5): ten processes that start together over a free lease: exactly one holds it.
func TestConcurrentAcquisitionsElectOneHolder(t *testing.T) {
	db := dbtest.New(t)
	ctx := context.Background()
	now := time.Now()
	var wg sync.WaitGroup
	var mu sync.Mutex
	holders, refused := 0, 0
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lease := NewLease(db.Runtime, platform.NewID(), 30*time.Second, func() time.Time { return now })
			_, err := lease.Acquire(ctx)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				holders++
			case errors.Is(err, ErrLeaseHeld):
				refused++
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if holders != 1 || refused != 9 {
		t.Fatalf("holders %d, refused %d", holders, refused)
	}
}

// seedNode enrolls a node through fleet.Enroll (an account and its approving session first) and returns its enrollment ID.
func seedNode(t *testing.T, db *dbtest.Database) platform.ID {
	t.Helper()
	user := db.Account(1)
	approver := db.Session(user, 1)
	node, err := nodetest.New()
	if err != nil {
		t.Fatal(err)
	}
	info, err := fleet.ParseNodeInfo(node.Info())
	if err != nil {
		t.Fatal(err)
	}
	var result fleet.Enrolled
	if err = db.Runtime.InTx(context.Background(), "enroll", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		result, err = fleet.Enroll(ctx, tx, config.DefaultIdentityPolicy(), fleet.EnrollRequest{UserID: user, Approver: fleet.Approver{SessionID: approver.ID,
			AuthMethod: 1, AuthenticatedAt: time.Now().Add(-time.Minute)}, NodeID: node.ID, Node: info, PublicKey: node.PublicKey, Flow: fleet.FlowDevice}, time.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return result.EnrollmentID
}

// TestTheAcceptLockSpreadsAndIsBounded is review A N-8: a node chooses its own ID, so the accept lock is chosen by a hash of the whole ID
// (nodes whose IDs share every byte but the last spread over the stripes), and the wait for it ends with the hello's context.
func TestTheAcceptLockSpreadsAndIsBounded(t *testing.T) {
	h := New(Options{Settings: Settings{LeaseTTL: 30 * time.Second}})
	stripes := map[int]bool{}
	for index := range 64 {
		id := platform.ID{0x01, 0x92, 0xf7, 0xa0}
		id[15] = byte(index)
		stripes[h.stripeOf(id)] = true
	}
	if len(stripes) < 16 {
		t.Fatalf("64 node IDs that differ in their last byte share %d of %d accept locks", len(stripes), nodeLockStripes)
	}
	node := platform.NewID()
	unlock, err := h.lockNode(context.Background(), node)
	if err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		release, err := h.lockNode(ctx, node)
		if err == nil {
			release()
		}
		waited <- err
	}()
	select {
	case err := <-waited:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("a wait for a held accept lock: %v", err)
		}
	case <-time.After(2 * time.Second):
		unlock()
		t.Fatal("the wait for a held accept lock ignored its context")
	}
	unlock()
	release, err := h.lockNode(context.Background(), node)
	if err != nil {
		t.Fatal(err)
	}
	release()
}
