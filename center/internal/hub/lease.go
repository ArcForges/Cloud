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
// when it was released; it is renewed every LeaseRenew for LeaseTTL; it is released at a graceful stop. Every expiry is the database's
// clock (clock_timestamp()), so a replica whose own clock runs ahead never takes a live lease early. Every presence write names the
// fence it was made under and is refused once that fence is no longer the live one, so a paused or partitioned process that lost the
// lease records no presence (the audit appends are not fenced). The claim also keeps a local expiry, LeaseTTL less a sixth after the
// start of its last successful acquisition or renewal, measured on the process's own clock (25 s of PB-5's 30 s): a holder whose
// renewals fail (a store that does not answer, a saturated pool) holds nothing from that instant on. Hub.leaseLoop wakes at it (its
// timer is re-armed to the earlier of the next renewal and the local expiry, and a renewal's own wait ends there too), so admission
// stops and every channel's close starts at the local expiry, 5 s before the database's expiry lets another process take the lease.
// A close takes at most about 3 s (the RelayClose write is bounded by 2 s, the close handshake by 1 s, every connection's in parallel),
// so the channels are closed before then. The database's expiry is the renewal statement's clock_timestamp() plus LeaseTTL, and that
// statement runs after the local start, so the two expiries are offsets of ordered instants on their own clocks: no clock is compared
// with another. It never uses a session advisory lock, which the transaction-mode pooler of the runtime role does not keep.

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

	mu         sync.Mutex
	fence      int64     // 0 while not held
	validUntil time.Time // the local expiry of the claim (the process's clock)
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

// margin is how much earlier than the database the claim gives itself up: a sixth of the time to live (5 s of PB-5's 30 s), so the
// local expiry passes while the database's still stands even when the renewal's statement ran late in its transaction.
func (l *Lease) margin() time.Duration { return l.ttl / 6 }

// Fence is the fence the claim holds, and false while it holds none: never acquired, lost, released, or past its local expiry.
func (l *Lease) Fence() (int64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fence == 0 || !l.clock().Before(l.validUntil) {
		return 0, false
	}
	return l.fence, true
}

// ValidUntil is the claim's local expiry, and false while it holds no fence.
func (l *Lease) ValidUntil() (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.validUntil, l.fence != 0
}

// remaining is the time until the claim's local expiry on the claim's clock (zero or less once it passed), and false without a fence.
func (l *Lease) remaining() (time.Duration, bool) {
	until, held := l.ValidUntil()
	return until.Sub(l.clock()), held
}

// Lapse gives up a claim whose local expiry passed and reports whether it held one: the caller closes its channels.
func (l *Lease) Lapse() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fence == 0 || l.clock().Before(l.validUntil) {
		return false
	}
	l.fence = 0
	return true
}

// hold records a fence granted by a statement that started at start.
func (l *Lease) hold(fence int64, start time.Time) {
	l.mu.Lock()
	l.fence, l.validUntil = fence, start.Add(l.ttl-l.margin())
	l.mu.Unlock()
}

func (l *Lease) set(fence int64) {
	l.mu.Lock()
	l.fence = fence
	l.mu.Unlock()
}

// ttlMicros is the time to live as the statements' interval parameter, in microseconds.
func (l *Lease) ttlMicros() int64 { return l.ttl.Microseconds() }

// Acquire takes the lease when nobody else holds a live one: the row is created with fence 1, or a row that expired (or was released)
// is taken over with its fence raised by one. A row that is still live but names this claim's own holder (the claim lapsed locally
// while the database's expiry still stood, and its channels were closed then) is taken over the same way, under a higher fence, so the
// writes of the lapsed epoch stay refused (review B C-N1). ErrLeaseHeld while another process's live lease stands; any other error is
// the store's.
func (l *Lease) Acquire(ctx context.Context) (int64, error) {
	start := l.clock()
	var fence int64
	held := false
	err := l.db.InTx(ctx, "acquire the hub lease", store.TxOptions{Timeout: 5 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
		held = false
		err := tx.QueryRow(ctx, `INSERT INTO fleet.hub_lease (singleton, holder, fence, acquired_at, renewed_at, expires_at)
VALUES (true, $1, 1, clock_timestamp(), clock_timestamp(), clock_timestamp() + $2::bigint * interval '1 microsecond')
ON CONFLICT (singleton) DO UPDATE SET holder = excluded.holder, fence = fleet.hub_lease.fence + 1, acquired_at = excluded.acquired_at,
    renewed_at = excluded.renewed_at, expires_at = excluded.expires_at
WHERE fleet.hub_lease.expires_at <= excluded.acquired_at OR fleet.hub_lease.holder = excluded.holder
RETURNING fence`, l.holder, l.ttlMicros()).Scan(&fence)
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
	l.hold(fence, start)
	return fence, nil
}

// Renew extends the held lease by its time to live, and the claim's local expiry with it. It reports false, and the claim holds
// nothing from then on, when the lease is no longer this claim's (it expired and another process, or this one under a new fence, took
// it) or the claim is past its local expiry; an error is the store's, which leaves the claim's local expiry where it was.
func (l *Lease) Renew(ctx context.Context) (bool, error) {
	fence, ok := l.Fence()
	if !ok {
		l.set(0)
		return false, nil
	}
	start := l.clock()
	renewed := false
	err := l.db.InTx(ctx, "renew the hub lease", store.TxOptions{Timeout: 5 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE fleet.hub_lease SET renewed_at = clock_timestamp(), expires_at = clock_timestamp() + $3::bigint * interval '1 microsecond'
WHERE singleton AND holder = $1 AND fence = $2 AND expires_at > clock_timestamp()`, l.holder, fence, l.ttlMicros())
		renewed = err == nil && tag.RowsAffected() == 1
		return err
	})
	if err != nil {
		return false, err
	}
	if !renewed {
		l.set(0)
		return false, nil
	}
	l.hold(fence, start)
	return true, nil
}

// Release gives the lease up at a graceful stop: its expiry becomes now, so the next process takes it over at once. A lease that is no
// longer this claim's is left alone.
func (l *Lease) Release(ctx context.Context) error {
	l.mu.Lock()
	fence := l.fence
	l.fence = 0
	l.mu.Unlock()
	if fence == 0 {
		return nil
	}
	return l.db.InTx(ctx, "release the hub lease", store.TxOptions{Timeout: 5 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE fleet.hub_lease SET renewed_at = greatest(renewed_at, clock_timestamp()), expires_at = greatest(acquired_at, clock_timestamp())
WHERE singleton AND holder = $1 AND fence = $2 AND expires_at > clock_timestamp()`, l.holder, fence)
		return err
	})
}

// fencedCondition is the condition every presence write adds: the fence it names is the live lease's, by the database's clock. The
// fence alone identifies an epoch of the lease (it rises with every acquisition, by any holder), so a write of an older epoch of this
// same process is refused too.
const fencedCondition = `EXISTS (SELECT 1 FROM fleet.hub_lease l WHERE l.singleton AND l.fence = @fence AND l.expires_at > clock_timestamp())`
