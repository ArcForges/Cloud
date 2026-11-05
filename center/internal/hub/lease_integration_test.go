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

// TestASecondHubOnTheSameDatabaseRefusesToStart is E1-21 (Plan CTR5-HUB-05 as amended by PB-5 and Q22; EVIDENCE: REAL PostgreSQL, the
// runtime role's privileges): one hub per database. While hub A holds a live lease, hub B's acquisition is refused (it serves no
// channel); a lease that expired (a killed center) is taken over by B with a higher fence, and A's renewal then fails, so A knows it
// lost it; a released lease (a graceful stop) is taken over at once; and a fenced write names the lease's live fence only, so a write of
// an older epoch, even by the same process after it took the lease again, is refused.
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
	at.Advance(20 * time.Second)
	if renewed, err := a.Renew(ctx); err != nil || !renewed {
		t.Fatalf("A's renewal: %v %v", renewed, err)
	}
	at.Advance(20 * time.Second)
	if _, err = b.Acquire(ctx); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("B within A's renewed lease: %v", err)
	}
	// A stops renewing (it was killed): after the time to live B takes over with a higher fence, and A's renewal fails.
	at.Advance(31 * time.Second)
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
	// The fence of every hub write: only the live fence writes; B's fence, and A's own earlier fence, are refused.
	h := &Hub{db: db.Runtime, lease: a}
	enrollment := seedNode(t, db)
	for fence, want := range map[int64]error{first: ErrFenced, second: ErrFenced, third: nil} {
		if err := h.markOnline(ctx, enrollment, platform.NewID(), fence, at.Now()); !errors.Is(err, want) {
			t.Errorf("a write under fence %d: %v, want %v", fence, err, want)
		}
	}
	// A lease that expired refuses even its own live fence's writes.
	at.Advance(31 * time.Second)
	if err := h.markOnline(ctx, enrollment, platform.NewID(), third, at.Now()); !errors.Is(err, ErrFenced) {
		t.Errorf("a write under an expired lease: %v", err)
	}
	if n := db.Count("SELECT count(*) FROM fleet.hub_lease"); n != 1 {
		t.Fatalf("the lease is one row: %d", n)
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
