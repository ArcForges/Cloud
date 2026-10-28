// SPDX-License-Identifier: AGPL-3.0-only

package platform

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/store"
)

// The stored state of a job.
const (
	jobReady        = 1
	jobLeased       = 2
	jobSucceeded    = 3
	jobDeadLettered = 4
)

// MaxJobPayloadBytes bounds a job's payload.
const MaxJobPayloadBytes = 65536

// DefaultJobAttempts bounds the claims of one job when the caller names no maximum.
const DefaultJobAttempts = 10

// exhaustedReason is the last error of a job that Claim dead-lettered.
const exhaustedReason = "dead-lettered by a claim: the job reached its maximum attempts"

// ErrLeaseLost refuses a renewal, a fenced write or a completion by a holder whose lease ended: another holder claimed the job
// with a higher fence, or the job is no longer leased.
var ErrLeaseLost = errors.New("the job lease was lost")

// Lease is a claimed job.
type Lease struct {
	JobID    ID
	JobType  string
	Holder   string
	Fence    int64
	Attempts int
	Payload  []byte
	Until    time.Time
}

// Schedule adds a ready job in the caller's transaction; it reports false when the job exists already.
func Schedule(ctx context.Context, tx pgx.Tx, jobID ID, jobType string, payload []byte, availableAt time.Time) (bool, error) {
	if !lowerName.MatchString(jobType) || len(payload) > MaxJobPayloadBytes {
		return false, errors.New("a job needs a type name and a payload of at most 64 KiB")
	}
	tag, err := tx.Exec(ctx, `INSERT INTO platform.job_lease (job_id, job_type, attempts, fence, state, payload, available_at, created_at, updated_at)
VALUES ($1, $2, 0, 0, $3, $4, $5, now(), now()) ON CONFLICT (job_id) DO NOTHING`, jobID, jobType, jobReady, nonNil(payload), availableAt)
	if err != nil {
		return false, store.Sanitize("schedule a job", err)
	}
	return tag.RowsAffected() == 1, nil
}

// Claim leases the oldest available job of a type: a ready job whose time has come or a leased job whose lease expired. Every
// claim increments the fence and counts an attempt. A job that is available again after maxAttempts claims (its holders' leases
// kept expiring) is dead-lettered in the same transaction instead of being handed out; maxAttempts <= 0 means
// DefaultJobAttempts. It returns nil when no job is available. Concurrent claimers skip each other's rows.
func Claim(ctx context.Context, db *store.DB, jobType, holder string, duration time.Duration, maxAttempts int) (*Lease, error) {
	if !lowerName.MatchString(jobType) || holder == "" || len(holder) > 128 || duration <= 0 {
		return nil, errors.New("a claim needs a job type, a holder and a positive lease")
	}
	if maxAttempts <= 0 {
		maxAttempts = DefaultJobAttempts
	}
	var lease *Lease
	err := db.InTx(ctx, "claim a job", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		lease = nil
		if _, err := tx.Exec(ctx, `WITH exhausted AS (
    SELECT job_id FROM platform.job_lease
    WHERE job_type = $1 AND attempts >= $4 AND ((state = $2 AND available_at <= now()) OR (state = $3 AND leased_until <= now()))
    FOR UPDATE SKIP LOCKED)
UPDATE platform.job_lease j SET state = $5, holder = NULL, leased_until = NULL, last_error = $6, updated_at = now()
FROM exhausted WHERE j.job_id = exhausted.job_id`, jobType, jobReady, jobLeased, maxAttempts, jobDeadLettered, exhaustedReason); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `WITH candidate AS (
    SELECT job_id FROM platform.job_lease
    WHERE job_type = $1 AND attempts < $6 AND ((state = $2 AND available_at <= now()) OR (state = $3 AND leased_until <= now()))
    ORDER BY available_at, job_id LIMIT 1 FOR UPDATE SKIP LOCKED)
UPDATE platform.job_lease j SET state = $3, holder = $4, leased_until = now() + $5::interval, attempts = j.attempts + 1,
    fence = j.fence + 1, updated_at = now()
FROM candidate WHERE j.job_id = candidate.job_id
RETURNING j.job_id, j.job_type, j.holder, j.fence, j.attempts, j.payload, j.leased_until`, jobType, jobReady, jobLeased, holder, duration, maxAttempts)
		if err != nil {
			return err
		}
		claimed, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Lease, error) {
			var value Lease
			err := row.Scan(&value.JobID, &value.JobType, &value.Holder, &value.Fence, &value.Attempts, &value.Payload, &value.Until)
			return value, err
		})
		if err == nil && len(claimed) == 1 {
			lease = &claimed[0]
		}
		return err
	})
	return lease, err
}

// Renew extends the lease while the holder still holds it.
func (l *Lease) Renew(ctx context.Context, db *store.DB, duration time.Duration) error {
	return db.InTx(ctx, "renew a job lease", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		var until time.Time
		err := tx.QueryRow(ctx, `UPDATE platform.job_lease SET leased_until = now() + $4::interval, updated_at = now()
WHERE job_id = $1 AND fence = $2 AND state = $3 AND leased_until > now() RETURNING leased_until`, l.JobID, l.Fence, jobLeased, duration).Scan(&until)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrLeaseLost
		}
		if err == nil {
			l.Until = until
		}
		return err
	})
}

// Fenced locks the job row in the caller's business transaction and checks that this lease still holds it, so the business
// write commits only under the current fence: a stale holder's transaction fails with ErrLeaseLost, also once the job was
// completed or dead-lettered (no lease).
func (l *Lease) Fenced(ctx context.Context, tx pgx.Tx) error {
	var fence int64
	var state int16
	var live bool
	err := tx.QueryRow(ctx, "SELECT fence, state, coalesce(leased_until > now(), false) FROM platform.job_lease WHERE job_id = $1 FOR UPDATE", l.JobID).Scan(&fence, &state, &live)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (fence != l.Fence || state != jobLeased || !live)) {
		return ErrLeaseLost
	}
	return store.Sanitize("check a job fence", err)
}

// Complete marks the job succeeded in the caller's transaction (with the work's last writes) under the fence.
func (l *Lease) Complete(ctx context.Context, tx pgx.Tx) error {
	if err := l.Fenced(ctx, tx); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "UPDATE platform.job_lease SET state = $2, holder = NULL, leased_until = NULL, updated_at = now(), last_error = NULL WHERE job_id = $1",
		l.JobID, jobSucceeded)
	return store.Sanitize("complete a job", err)
}

// Fail returns the job to ready at retryAt, or dead-letters it after maxAttempts; reason must not quote a credential.
func (l *Lease) Fail(ctx context.Context, db *store.DB, retryAt time.Time, maxAttempts int, reason string) error {
	if len(reason) > 200 {
		reason = reason[:200]
	}
	return db.InTx(ctx, "fail a job", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		if err := l.Fenced(ctx, tx); err != nil {
			return err
		}
		state := jobReady
		if l.Attempts >= maxAttempts {
			state = jobDeadLettered
		}
		_, err := tx.Exec(ctx, "UPDATE platform.job_lease SET state = $2, holder = NULL, leased_until = NULL, available_at = $3, last_error = $4, updated_at = now() WHERE job_id = $1",
			l.JobID, state, retryAt, reason)
		return err
	})
}
