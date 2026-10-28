// SPDX-License-Identifier: AGPL-3.0-only

// Package store is the center's access to its PostgreSQL store with the runtime role (ArcForges-Design data/cloud-store.md
// section 6): transactions with a deadline, cancellation and a bounded retry of serialization failures and deadlocks, and
// errors that keep the operation, the SQLSTATE and the constraint name but never the server's message or detail, which can
// quote row values. The pool keeps no session state (exec query mode), so it works behind the Neon transaction pooler.
package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
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
// through tx. An error fn returns that is not a database error is returned unchanged after the rollback.
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
		err := pgx.BeginTxFunc(ctx, db.pool, pgx.TxOptions{IsoLevel: options.Isolation, AccessMode: access}, func(tx pgx.Tx) error {
			return fn(ctx, tx)
		})
		if err == nil {
			return nil
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
