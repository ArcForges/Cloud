// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The hub lease (Plan PB-5, Q22, CTR5-HUB-05): one hub per database. The node channel's connections live in the memory of one center
// process, so a second process on the same database must not run a hub beside it: it would accept connections the first never sees,
// and routing (AF-CTR-05 E2) would answer node_offline for them. The lease is a fenced singleton row, fleet.hub_lease (migration 0008):
// a holder, a fencing token that rises with every change of holder, and an expiry. It is taken when there is none, when it expired or
// when it was released; it is renewed every LeaseRenew for LeaseTTL; it is released at a graceful stop. Every hub write names the fence
// it was made under and is refused once that fence is no longer the live one, so a paused or partitioned process that lost the lease
// writes nothing. It never uses a session advisory lock, which the transaction-mode pooler of the runtime role does not keep.

// The lease's defaults (PB-5): renewed every 10 s, for 30 s.
const (
	DefaultLeaseTTL   = 30 * time.Second
	DefaultLeaseRenew = 10 * time.Second
)

// ErrLeaseHeld is the answer to an acquisition while another process holds a live lease.
var ErrLeaseHeld = errors.New("another center process holds the hub lease of this database")

// Lease is one process's claim of the hub lease.
type Lease struct {
	db     *store.DB
	holder platform.ID
	ttl    time.Duration
	clock  func() time.Time

	mu    sync.Mutex
	fence int64 // 0 while not held
}

// NewLease is the lease claim of a holder (a random ID per process).
func NewLease(db *store.DB, holder platform.ID, ttl time.Duration, clock func() time.Time) *Lease {
	if clock == nil {
		clock = time.Now
	}
	if ttl <= 0 {
		ttl = DefaultLeaseTTL
	}
	return &Lease{db: db, holder: holder, ttl: ttl, clock: clock}
}

// Holder is the claim's holder ID.
func (l *Lease) Holder() platform.ID { return l.holder }

// Fence is the fence the claim holds, and false while it holds none.
func (l *Lease) Fence() (int64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fence, l.fence != 0
}

func (l *Lease) set(fence int64) {
	l.mu.Lock()
	l.fence = fence
	l.mu.Unlock()
}

// Acquire takes the lease when nobody holds a live one: the row is created with fence 1, or a row that expired (or was released) is
// taken over with its fence raised by one. ErrLeaseHeld while another live lease stands; any other error is the store's.
func (l *Lease) Acquire(ctx context.Context) (int64, error) {
	now := l.clock()
	var fence int64
	held := false
	err := l.db.InTx(ctx, "acquire the hub lease", store.TxOptions{Timeout: 5 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
		held = false
		err := tx.QueryRow(ctx, `INSERT INTO fleet.hub_lease (singleton, holder, fence, acquired_at, renewed_at, expires_at) VALUES (true, $1, 1, $2, $2, $3)
ON CONFLICT (singleton) DO UPDATE SET holder = excluded.holder, fence = fleet.hub_lease.fence + 1, acquired_at = excluded.acquired_at,
    renewed_at = excluded.renewed_at, expires_at = excluded.expires_at
WHERE fleet.hub_lease.expires_at <= excluded.acquired_at
RETURNING fence`, l.holder, now, now.Add(l.ttl)).Scan(&fence)
		if errors.Is(err, pgx.ErrNoRows) {
			held = true
			return nil
		}
		return err
	})
	switch {
	case err != nil:
		return 0, err
	case held:
		return 0, ErrLeaseHeld
	}
	l.set(fence)
	return fence, nil
}

// Renew extends the held lease by its time to live. It reports false, and the claim holds nothing from then on, when the lease is no
// longer this claim's (it expired and another process, or this one under a new fence, took it); an error is the store's, which leaves
// the claim as it was until its expiry.
func (l *Lease) Renew(ctx context.Context) (bool, error) {
	fence, ok := l.Fence()
	if !ok {
		return false, nil
	}
	now := l.clock()
	renewed := false
	err := l.db.InTx(ctx, "renew the hub lease", store.TxOptions{Timeout: 5 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE fleet.hub_lease SET renewed_at = $3, expires_at = $4 WHERE singleton AND holder = $1 AND fence = $2 AND expires_at > $3`,
			l.holder, fence, now, now.Add(l.ttl))
		renewed = err == nil && tag.RowsAffected() == 1
		return err
	})
	if err != nil {
		return true, err
	}
	if !renewed {
		l.set(0)
	}
	return renewed, nil
}

// Release gives the lease up at a graceful stop: its expiry becomes now, so the next process takes it over at once. A lease that is no
// longer this claim's is left alone.
func (l *Lease) Release(ctx context.Context) error {
	fence, ok := l.Fence()
	if !ok {
		return nil
	}
	l.set(0)
	now := l.clock()
	return l.db.InTx(ctx, "release the hub lease", store.TxOptions{Timeout: 5 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE fleet.hub_lease SET renewed_at = greatest(renewed_at, $3), expires_at = greatest(acquired_at, $3)
WHERE singleton AND holder = $1 AND fence = $2 AND expires_at > $3`, l.holder, fence, now)
		return err
	})
}

// fencedCondition is the condition every hub write adds: the fence it names is the live lease's. The fence alone identifies an epoch
// of the lease (it rises with every acquisition, by any holder), so a write of an older epoch of this same process is refused too.
const fencedCondition = `EXISTS (SELECT 1 FROM fleet.hub_lease l WHERE l.singleton AND l.fence = @fence AND l.expires_at > @now)`
