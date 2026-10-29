// SPDX-License-Identifier: AGPL-3.0-only

// Package store is the center's access to its PostgreSQL store with the runtime role (ArcForges-Design data/cloud-store.md
// section 6): transactions with a deadline, cancellation and a bounded retry of serialization failures and deadlocks, a COMMIT
// whose outcome is unknown reported as such and never retried, and errors that keep the operation, the SQLSTATE and the constraint
// name but never the server's message or detail, which can quote row values. The pool keeps no session state (exec query mode), so it works behind the Neon transaction pooler.
package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Defaults of a transaction.
const (
	DefaultTimeout  = 10 * time.Second
	DefaultAttempts = 5
	maxBackoff      = 200 * time.Millisecond
)

// The kinds of a store error.
var (
	// ErrUnavailable: the database cannot be reached or refused the connection; callers answer UNAVAILABLE with retry advice.
	ErrUnavailable = errors.New("the database is unavailable")
	// ErrTimeout: the transaction's deadline passed.
	ErrTimeout = errors.New("the database operation timed out")
	// ErrCanceled: the caller cancelled.
	ErrCanceled = errors.New("the database operation was cancelled")
	// ErrConflict: a unique constraint refused the change.
	ErrConflict = errors.New("a unique constraint refused the change")
	// ErrConstraint: another integrity constraint refused the change.
	ErrConstraint = errors.New("an integrity constraint refused the change")
	// ErrContention: serialization failures or deadlocks outlasted the retries.
	ErrContention = errors.New("the transaction kept conflicting with concurrent transactions")
	// ErrPermission: the runtime role lacks a privilege; this is a deployment defect.
	ErrPermission = errors.New("the runtime role lacks a privilege")
	// ErrInternal: any other database error.
	ErrInternal = errors.New("the database refused the operation")
	// ErrCommitUnknown: a read-write transaction sent its COMMIT and did not learn the outcome (the connection failed, the
	// deadline passed or the call was cancelled while the COMMIT was in flight, or the server answered with an error that does not
	// say it rolled back): the transaction may have committed. It is never retried; callers answer that the effect is unknown.
	ErrCommitUnknown = errors.New("the outcome of the commit is unknown")
)

// Error is a sanitized database error.
type Error struct {
	Operation  string
	SQLState   string
	Constraint string
	Kind       error
}

func (e *Error) Error() string {
	text := fmt.Sprintf("store: %s: %v", e.Operation, e.Kind)
	if e.SQLState != "" {
		text += " (SQLSTATE " + e.SQLState
		if e.Constraint != "" {
			text += ", constraint " + e.Constraint
		}
		text += ")"
	}
	return text
}

// Unwrap lets errors.Is match the kind.
func (e *Error) Unwrap() error { return e.Kind }

// Sanitize turns a database or connection error into an *Error and returns any other error (a caller's domain error) unchanged.
func Sanitize(operation string, err error) error {
	if err == nil {
		return nil
	}
	var sanitized *Error
	if errors.As(err, &sanitized) {
		return err
	}
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		return &Error{Operation: operation, SQLState: pgError.Code, Constraint: pgError.ConstraintName, Kind: kindOf(pgError.Code)}
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return &Error{Operation: operation, Kind: ErrTimeout}
	case errors.Is(err, context.Canceled):
		return &Error{Operation: operation, Kind: ErrCanceled}
	case isConnectionError(err):
		return &Error{Operation: operation, Kind: ErrUnavailable}
	}
	return err
}

func kindOf(code string) error {
	switch {
	case code == "23505":
		return ErrConflict
	case len(code) == 5 && code[:2] == "23":
		return ErrConstraint
	case code == "40001" || code == "40P01":
		return ErrContention
	case code == "42501":
		return ErrPermission
	case code == "57014":
		return ErrTimeout
	case len(code) == 5 && (code[:2] == "08" || code[:2] == "53" || code == "57P01" || code == "57P02" || code == "57P03"):
		return ErrUnavailable
	}
	return ErrInternal
}

func isConnectionError(err error) bool {
	var connect *pgconn.ConnectError
	var network net.Error
	return errors.As(err, &connect) || errors.As(err, &network) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) || pgconn.Timeout(err) || errors.Is(err, pgconn.ErrConnClosed)
}

func retryable(err error) bool {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		return pgError.Code == "40001" || pgError.Code == "40P01"
	}
	// A connection that failed before anything was sent is safe to retry on another one.
	return pgconn.SafeToRetry(err)
}

// DB is the runtime role's pool.
type DB struct {
	pool *pgxpool.Pool
}

// New wraps a pool.
func New(pool *pgxpool.Pool) *DB { return &DB{pool: pool} }

// Pool is the underlying pool (for readiness and metrics).
func (db *DB) Pool() *pgxpool.Pool { return db.pool }

// TxOptions are the options of one transaction.
type TxOptions struct {
	// Isolation is read committed by default; use serializable where an invariant spans rows.
	Isolation pgx.TxIsoLevel
	ReadOnly  bool
	// Timeout bounds the whole transaction including retries (default 10 s); a shorter caller deadline wins.
	Timeout time.Duration
	// Attempts bounds the retries of serialization failures and deadlocks (default 5).
	Attempts int
}

// InTx runs fn in a transaction and commits it. A serialization failure or a deadlock (of fn or of the commit) rolls back and
// runs fn again, up to the attempts and within the deadline, so fn must be safe to repeat: it may touch only the database
// through tx. An error fn returns that is not a database error is returned unchanged after the rollback. A read-write
// transaction whose COMMIT was sent without a definite answer is ErrCommitUnknown and never runs again (see commitRolledBack).
func (db *DB) InTx(ctx context.Context, operation string, options TxOptions, fn func(ctx context.Context, tx pgx.Tx) error) error {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	attempts := options.Attempts
	if attempts <= 0 {
		attempts = DefaultAttempts
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	access := pgx.ReadWrite
	if options.ReadOnly {
		access = pgx.ReadOnly
	}
	for attempt := 1; ; attempt++ {
		err := db.run(ctx, pgx.TxOptions{IsoLevel: options.Isolation, AccessMode: access}, fn)
		if err == nil {
			return nil
		}
		var unknown *commitUnknown
		if errors.As(err, &unknown) {
			sanitized := &Error{Operation: operation, Kind: ErrCommitUnknown}
			var pgError *pgconn.PgError
			if errors.As(unknown.err, &pgError) {
				sanitized.SQLState, sanitized.Constraint = pgError.Code, pgError.ConstraintName
			}
			return sanitized
		}
		if attempt >= attempts || !retryable(err) || ctx.Err() != nil {
			return Sanitize(operation, err)
		}
		backoff := min(maxBackoff, time.Duration(1<<attempt)*5*time.Millisecond)
		backoff = backoff/2 + rand.N(backoff/2+1)
		select {
		case <-ctx.Done():
			return Sanitize(operation, ctx.Err())
		case <-time.After(backoff):
		}
	}
}

// commitUnknown carries the error of a COMMIT whose outcome is unknown.
type commitUnknown struct{ err error }

func (c *commitUnknown) Error() string { return "commit: " + c.err.Error() }

// run is one attempt: begin, fn and commit. An error of the begin or of fn rolls back (the server never commits a transaction
// whose COMMIT it did not receive), so it is retried under the usual rules. An error of a read-write COMMIT is a definite rollback
// only when the server says so; anything else may have committed and is reported as commitUnknown. A read-only transaction has no
// effect, so its COMMIT error is an ordinary error.
func (db *DB) run(ctx context.Context, options pgx.TxOptions, fn func(ctx context.Context, tx pgx.Tx) error) error {
	tx, err := db.pool.BeginTx(ctx, options)
	if err != nil {
		return err
	}
	if err = fn(ctx, tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		if options.AccessMode == pgx.ReadOnly || commitRolledBack(err) {
			return err
		}
		return &commitUnknown{err: err}
	}
	return nil
}

// commitRolledBack reports a COMMIT error that proves the transaction rolled back: the server's own refusal of the commit, a
// transaction rollback (class 40: a serialization failure or a deadlock, which are retried; not 40003, statement completion
// unknown) or an integrity violation of a deferred constraint (class 23), or a transaction that had already failed
// (pgx.ErrTxCommitRollback). Every other error after the COMMIT was sent (a lost connection, a timeout, a cancellation, pgx's
// connection lock error, the pooler's 08P01) leaves the outcome unknown; pgconn.SafeToRetry is not consulted then, because the
// COMMIT may have reached the server.
func commitRolledBack(err error) bool {
	if errors.Is(err, pgx.ErrTxCommitRollback) {
		return true
	}
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		return strings.HasPrefix(pgError.Code, "40") && pgError.Code != "40003" || strings.HasPrefix(pgError.Code, "23")
	}
	return false
}
