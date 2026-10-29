// SPDX-License-Identifier: AGPL-3.0-only

// Package ratelimit is the center's rate limits (ArcForges-Design AD-0011 section 7): fixed windows counted in
// platform.rate_limit, one row per bucket, keyed by the SHA-256 of the bucket's kind and key and reset in place when its window
// has passed. A count is taken in its own short transaction before the work it guards, so it commits whether the work is
// admitted or refused. Request buckets (Take) count every request and refuse the ones over the limit; failure buckets (Check
// before the work, Fail after a failed proof) count only failures, and Reserve counts a failure before a proof is checked,
// atomically and only under the limit, so concurrent proofs cannot get past it (Release gives a correct proof's reservation back).
// Keys are client address prefixes (IPv4 /24, IPv6 /56, an IPv4-mapped address as IPv4), accounts and normalised e-mail
// addresses; the store holds only their unsalted digests, which can be reversed by trying values.
package ratelimit

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// Kind names a bucket kind; it is the LimitFailure.limit_name of a refusal and a metric label, so it is a closed value.
type Kind string

// The bucket kinds of the identity surface.
const (
	// SignInPrefix counts sign-in requests (begin, completion, code redemption, enrollment) per client address prefix.
	SignInPrefix Kind = "sign_in_prefix"
	// SignInFailuresAccount counts failed sign-in proofs per account (or per unknown credential).
	SignInFailuresAccount Kind = "sign_in_failures_account"
	// EmailPrefix and EmailAddress count e-mail code requests per client address prefix and per address.
	EmailPrefix  Kind = "email_prefix"
	EmailAddress Kind = "email_address"
	// RedeemFailuresAddress counts wrong e-mail codes per address, across flows.
	RedeemFailuresAddress Kind = "redeem_failures_address"
	// RefreshPrefix counts refreshes per client address prefix.
	RefreshPrefix Kind = "refresh_prefix"
	// StepUpAccount counts step-up ceremonies per account (A1b).
	StepUpAccount Kind = "step_up_account"
	// BootstrapPrefix counts bootstrap token mismatches per client address prefix (there is no global bucket).
	BootstrapPrefix Kind = "bootstrap_prefix"
)

// Kinds is every bucket kind.
func Kinds() []Kind {
	return []Kind{SignInPrefix, SignInFailuresAccount, EmailPrefix, EmailAddress, RedeemFailuresAddress, RefreshPrefix, StepUpAccount, BootstrapPrefix}
}

// Window is the window of a bucket kind in a policy.
func Window(policy config.IdentityPolicy, kind Kind) config.Window {
	switch kind {
	case SignInPrefix:
		return policy.SignInPerPrefix
	case SignInFailuresAccount:
		return policy.SignInFailuresAccount
	case EmailPrefix:
		return policy.EmailPerPrefix
	case EmailAddress:
		return policy.EmailPerAddress
	case RedeemFailuresAddress:
		return policy.RedeemFailuresAddress
	case RefreshPrefix:
		return policy.RefreshPerPrefix
	case StepUpAccount:
		return policy.StepUpPerAccount
	case BootstrapPrefix:
		return policy.BootstrapPerPrefix
	}
	return config.Window{}
}

// Bucket is one counted key of a kind.
type Bucket struct {
	Kind   Kind
	Key    string
	Window config.Window
}

// Hash is the stored key: SHA-256 of the kind, a zero byte and the key.
func (b Bucket) Hash() [32]byte {
	return sha256.Sum256([]byte(string(b.Kind) + "\x00" + b.Key))
}

// Prefix is the bucket key of a client address: its /24 (IPv4) or /56 (IPv6) network, an IPv4-mapped IPv6 address taken as IPv4;
// an unknown address (a self-hosted center without one) is the one key "unknown".
func Prefix(address netip.Addr) string {
	if !address.IsValid() {
		return "unknown"
	}
	address = address.Unmap()
	bits := 56
	if address.Is4() {
		bits = 24
	}
	prefix, err := address.WithZone("").Prefix(bits)
	if err != nil {
		return "unknown"
	}
	return prefix.String()
}

// Decision is the state of a bucket after a count or a check.
type Decision struct {
	// Allowed reports a request within the limit (Take, Check).
	Allowed bool
	// Count is the bucket's count in the current window.
	Count int
	// WindowStart is when the current window began (zero for a bucket without a row).
	WindowStart time.Time
	// RetryAt is when the current window ends.
	RetryAt time.Time
	// First reports the one event of the window the center audits: the first refusal of a request bucket (Take), or the first
	// failure of a failure bucket (Fail).
	First bool
}

// Refusal is RESOURCE/rate_limited for a refused decision: retry after the window, the limit naming the bucket kind.
func (d Decision) Refusal(bucket Bucket) *arc.Refusal {
	return arc.RateLimited(string(bucket.Kind), int64(bucket.Window.Limit), d.RetryAt)
}

// Limiter counts buckets in platform.rate_limit.
type Limiter struct {
	db *store.DB
}

// New is a limiter over the runtime store.
func New(db *store.DB) *Limiter { return &Limiter{db: db} }

// ErrBucket reports a bucket without a key, a positive limit or a window.
var ErrBucket = errors.New("a rate-limit bucket needs a key, a positive limit and a window")

const maxCount = 2147483646

// count adds one to the bucket in its own transaction, resetting a window that has passed.
func (l *Limiter) count(ctx context.Context, bucket Bucket, now time.Time) (time.Time, int, error) {
	if bucket.Key == "" || bucket.Window.Limit < 1 || bucket.Window.Window <= 0 {
		return time.Time{}, 0, ErrBucket
	}
	hash := bucket.Hash()
	var start time.Time
	var count int
	err := l.db.InTx(ctx, "count a rate-limit bucket", store.TxOptions{Timeout: 5 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO platform.rate_limit AS r (bucket_hash, window_start, count) VALUES ($1, $2, 1)
ON CONFLICT (bucket_hash) DO UPDATE SET
    window_start = CASE WHEN r.window_start + $3::interval <= $2 THEN $2 ELSE r.window_start END,
    count = CASE WHEN r.window_start + $3::interval <= $2 THEN 1 ELSE least(r.count, $4) + 1 END
RETURNING window_start, count`, hash[:], now.UTC(), bucket.Window.Window, maxCount).Scan(&start, &count)
	})
	if err != nil {
		return time.Time{}, 0, err
	}
	return start, count, nil
}

// Take counts one request and decides it: allowed while the window's count is at most the limit.
func (l *Limiter) Take(ctx context.Context, bucket Bucket, now time.Time) (Decision, error) {
	start, count, err := l.count(ctx, bucket, now)
	if err != nil {
		return Decision{}, err
	}
	return Decision{Allowed: count <= bucket.Window.Limit, Count: count, WindowStart: start, RetryAt: start.Add(bucket.Window.Window),
		First: count == bucket.Window.Limit+1}, nil
}

// Fail counts one failure of a failure bucket.
func (l *Limiter) Fail(ctx context.Context, bucket Bucket, now time.Time) (Decision, error) {
	start, count, err := l.count(ctx, bucket, now)
	if err != nil {
		return Decision{}, err
	}
	return Decision{Allowed: count < bucket.Window.Limit, Count: count, WindowStart: start, RetryAt: start.Add(bucket.Window.Window),
		First: count == 1}, nil
}

// Reserve counts one failure of a failure bucket before the proof is checked (E6): one statement, in its own transaction, that
// starts a new window or adds one to the current window's count only while the count is under the limit. The conflicting row is
// locked and the condition re-read on its latest version, so concurrent reservations never take more than the limit. A refused
// reservation counts nothing. First reports the window's first failure.
func (l *Limiter) Reserve(ctx context.Context, bucket Bucket, now time.Time) (Decision, error) {
	if bucket.Key == "" || bucket.Window.Limit < 1 || bucket.Window.Window <= 0 {
		return Decision{}, ErrBucket
	}
	hash := bucket.Hash()
	var start time.Time
	var count int
	reserved := true
	err := l.db.InTx(ctx, "reserve a rate-limit failure", store.TxOptions{Timeout: 5 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
		reserved = true
		err := tx.QueryRow(ctx, `INSERT INTO platform.rate_limit AS r (bucket_hash, window_start, count) VALUES ($1, $2, 1)
ON CONFLICT (bucket_hash) DO UPDATE SET
    window_start = CASE WHEN r.window_start + $3::interval <= $2 THEN $2 ELSE r.window_start END,
    count = CASE WHEN r.window_start + $3::interval <= $2 THEN 1 ELSE r.count + 1 END
WHERE r.window_start + $3::interval <= $2 OR r.count < $4
RETURNING window_start, count`, hash[:], now.UTC(), bucket.Window.Window, bucket.Window.Limit).Scan(&start, &count)
		if errors.Is(err, pgx.ErrNoRows) {
			reserved = false
			return tx.QueryRow(ctx, "SELECT window_start, count FROM platform.rate_limit WHERE bucket_hash = $1", hash[:]).Scan(&start, &count)
		}
		return err
	})
	if err != nil {
		return Decision{}, err
	}
	decision := Decision{Allowed: reserved, Count: count, WindowStart: start, RetryAt: start.Add(bucket.Window.Window)}
	decision.First = reserved && count == 1
	return decision, nil
}

// Release gives a reservation back in the caller's transaction (a correct proof is no failure): the count of the reservation's
// window, if that window is still current, loses one.
func Release(ctx context.Context, tx pgx.Tx, bucket Bucket, reservation Decision) error {
	hash := bucket.Hash()
	_, err := tx.Exec(ctx, "UPDATE platform.rate_limit SET count = count - 1 WHERE bucket_hash = $1 AND window_start = $2 AND count > 0",
		hash[:], reservation.WindowStart)
	return err
}

// Check decides a failure bucket without counting: refused once the window holds the limit's number of failures.
func (l *Limiter) Check(ctx context.Context, bucket Bucket, now time.Time) (Decision, error) {
	if bucket.Key == "" || bucket.Window.Limit < 1 || bucket.Window.Window <= 0 {
		return Decision{}, ErrBucket
	}
	hash := bucket.Hash()
	var start time.Time
	var count int
	found := true
	err := l.db.InTx(ctx, "check a rate-limit bucket", store.TxOptions{ReadOnly: true, Timeout: 5 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx, "SELECT window_start, count FROM platform.rate_limit WHERE bucket_hash = $1", hash[:]).Scan(&start, &count)
		if errors.Is(err, pgx.ErrNoRows) {
			found = false
			return nil
		}
		return err
	})
	if err != nil {
		return Decision{}, err
	}
	if !found || !start.Add(bucket.Window.Window).After(now) {
		return Decision{Allowed: true}, nil
	}
	return Decision{Allowed: count < bucket.Window.Limit, Count: count, WindowStart: start, RetryAt: start.Add(bucket.Window.Window)}, nil
}
