// SPDX-License-Identifier: AGPL-3.0-only

// Package platform holds the center's platform store guarantees on PostgreSQL (ArcForges-Design data/cloud-store.md section 6),
// re-implementing those of the D1 storage plans with native transactions, constraints and row locks: command receipts
// (idempotency per principal and command ID), the inbox, the outbox and its at-least-once publisher, job leases with a fence,
// the append-only audit chain and signing-key metadata.
package platform

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/store"
)

// ID is a uuid.
type ID [16]byte

// NewID returns a random (version 4) uuid.
func NewID() ID {
	var id ID
	if _, err := rand.Read(id[:]); err != nil {
		panic(err)
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return id
}

// String is the canonical lowercase text form.
func (id ID) String() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
}

// Receipt bounds.
const (
	DefaultReceiptRetention = 90 * 24 * time.Hour
	MaxResultBytes          = 262144
	maxTextLength           = 256
)

// The stored status of a command.
const (
	statusInProgress = 1
	statusSucceeded  = 2
	statusFailed     = 3
)

// ErrCommandIDReused refuses a command whose ID was already used by the same principal for another operation or other request
// bytes: the receipt keeps the first request, and a different payload under the same ID is never executed.
var ErrCommandIDReused = errors.New("the command ID was already used with a different request")

// ErrCommandInProgress is answered for a command whose receipt is committed as in progress (a long-running command).
var ErrCommandInProgress = errors.New("the command is still in progress")

// Command is one receipt-guarded command.
type Command struct {
	// Principal is the authenticated caller (account, node or agent grant), never a client-supplied name.
	Principal string
	// CommandID is the client's idempotency key.
	CommandID ID
	// Operation is the method, for example /arcforges.fleet.v1.FleetService/RevokeNode.
	Operation string
	// Request is the request exactly as transmitted. The digest covers these bytes, never a re-encoding (AD-0021 section 10).
	Request []byte
	// Retention is how long the receipt answers replays (default 90 days).
	Retention time.Duration
}

// Refusal is a domain refusal of a command (an ArcError in the reply). Its business changes are rolled back and the refusal is
// stored, so a replay answers the same refusal without running the command again.
type Refusal struct {
	Code   string
	Result []byte
}

func (r *Refusal) Error() string { return "the command was refused: " + r.Code }

// Outcome is the answer to a command: the stored result of its one execution.
type Outcome struct {
	Replayed  bool
	Succeeded bool
	Result    []byte
	ErrorCode string
}

// Execute runs a command at most once per principal and command ID. The receipt row is inserted first in the command's own
// transaction; a concurrent duplicate waits on that row and then answers from the committed receipt, so concurrent duplicates
// execute once. run makes the business changes (and outbox rows) through tx and returns the reply bytes, a *Refusal, or another
// error, which rolls back everything and stores no receipt, so a retry with the same ID runs the command again.
func Execute(ctx context.Context, db *store.DB, command Command, options store.TxOptions, run func(ctx context.Context, tx pgx.Tx) ([]byte, error)) (Outcome, error) {
	if command.Principal == "" || len(command.Principal) > maxTextLength || command.Operation == "" || len(command.Operation) > maxTextLength {
		return Outcome{}, errors.New("a command needs a principal and an operation of at most 256 bytes")
	}
	retention := command.Retention
	if retention <= 0 {
		retention = DefaultReceiptRetention
	}
	digest := sha256.Sum256(command.Request)
	var outcome Outcome
	err := db.InTx(ctx, "execute command", options, func(ctx context.Context, tx pgx.Tx) error {
		outcome = Outcome{}
		tag, err := tx.Exec(ctx, `INSERT INTO platform.command_receipt (principal, command_id, operation, request_sha256, status, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, now(), now() + $6::interval) ON CONFLICT (principal, command_id) DO NOTHING`,
			command.Principal, command.CommandID, command.Operation, digest[:], statusInProgress, retention)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return replay(ctx, tx, command, digest[:], &outcome)
		}
		nested, err := tx.Begin(ctx)
		if err != nil {
			return err
		}
		result, runErr := run(ctx, nested)
		var refusal *Refusal
		switch {
		case errors.As(runErr, &refusal):
			if err = nested.Rollback(ctx); err != nil {
				return err
			}
			if refusal.Code == "" || len(refusal.Code) > 128 || len(refusal.Result) > MaxResultBytes {
				return errors.New("a refusal needs a code of at most 128 bytes and a result of at most 256 KiB")
			}
			outcome = Outcome{Succeeded: false, Result: refusal.Result, ErrorCode: refusal.Code}
			_, err = tx.Exec(ctx, `UPDATE platform.command_receipt SET status = $3, result = $4, error_code = $5, completed_at = now()
WHERE principal = $1 AND command_id = $2`, command.Principal, command.CommandID, statusFailed, refusal.Result, refusal.Code)
			return err
		case runErr != nil:
			return runErr
		}
		if err = nested.Commit(ctx); err != nil {
			return err
		}
		if len(result) > MaxResultBytes {
			return errors.New("a command result is larger than 256 KiB")
		}
		outcome = Outcome{Succeeded: true, Result: result}
		_, err = tx.Exec(ctx, `UPDATE platform.command_receipt SET status = $3, result = $4, completed_at = now()
WHERE principal = $1 AND command_id = $2`, command.Principal, command.CommandID, statusSucceeded, nonNil(result))
		return err
	})
	if err != nil {
		return Outcome{}, err
	}
	return outcome, nil
}

func replay(ctx context.Context, tx pgx.Tx, command Command, digest []byte, outcome *Outcome) error {
	var operation, errorCode *string
	var stored, result []byte
	var status int16
	err := tx.QueryRow(ctx, `SELECT operation, request_sha256, status, result, error_code FROM platform.command_receipt
WHERE principal = $1 AND command_id = $2`, command.Principal, command.CommandID).Scan(&operation, &stored, &status, &result, &errorCode)
	if err != nil {
		return err
	}
	if operation == nil || *operation != command.Operation || !bytes.Equal(stored, digest) {
		return ErrCommandIDReused
	}
	switch status {
	case statusSucceeded:
		*outcome = Outcome{Replayed: true, Succeeded: true, Result: nonNil(result)}
	case statusFailed:
		code := ""
		if errorCode != nil {
			code = *errorCode
		}
		*outcome = Outcome{Replayed: true, Result: result, ErrorCode: code}
	default:
		return ErrCommandInProgress
	}
	return nil
}

func nonNil(value []byte) []byte {
	if value == nil {
		return []byte{}
	}
	return value
}
