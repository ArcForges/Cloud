// SPDX-License-Identifier: AGPL-3.0-only

package platform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/store"
)

// MaxAuditPayloadBytes bounds an audit event's payload (a summary: sizes and SHA-256 digests, never a command line, output or
// file content; AD-0021 section 10).
const MaxAuditPayloadBytes = 65536

var eventType = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,127}$`)

// Event is one audit event.
type Event struct {
	EventID       ID
	OccurredAt    time.Time
	ActorRef      string
	EventType     string
	Reason        string
	CorrelationID *ID
	CommandID     *ID
	TargetKind    string
	TargetID      string
	Payload       []byte
}

// Appended is the position of an appended event in the chain.
type Appended struct {
	Sequence int64
	Hash     [32]byte
}

// ErrChainBroken reports an audit chain whose stored hashes do not match its events.
var ErrChainBroken = errors.New("the audit chain is broken")

// AppendAudit appends an event to the audit chain in the caller's transaction. The chain head row is locked, so appends are
// serialized and every event's hash covers the previous event's hash: a removed, inserted or changed event breaks the chain.
func AppendAudit(ctx context.Context, tx pgx.Tx, event Event) (Appended, error) {
	if event.ActorRef == "" || len(event.ActorRef) > maxTextLength || !eventType.MatchString(event.EventType) || len(event.Reason) > 128 ||
		len(event.TargetKind) > 64 || len(event.TargetID) > maxTextLength || len(event.Payload) > MaxAuditPayloadBytes {
		return Appended{}, errors.New("an audit event needs an actor, an event type and fields within their bounds")
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now()
	}
	event.OccurredAt = event.OccurredAt.UTC().Truncate(time.Microsecond)
	var last int64
	var previous []byte
	if err := tx.QueryRow(ctx, "SELECT last_sequence, last_hash FROM audit.chain_head WHERE singleton FOR UPDATE").Scan(&last, &previous); err != nil {
		return Appended{}, store.Sanitize("lock the audit chain", err)
	}
	var head [32]byte
	copy(head[:], previous)
	appended := Appended{Sequence: last + 1}
	appended.Hash = AuditHash(head, appended.Sequence, event)
	_, err := tx.Exec(ctx, `INSERT INTO audit.audit_event (sequence, event_id, occurred_at, actor_ref, event_type, reason, correlation_id, command_id,
    target_kind, target_id, payload, previous_hash, event_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		appended.Sequence, event.EventID, event.OccurredAt, event.ActorRef, event.EventType, event.Reason, event.CorrelationID, event.CommandID,
		event.TargetKind, event.TargetID, nonNil(event.Payload), head[:], appended.Hash[:])
	if err != nil {
		return Appended{}, store.Sanitize("append an audit event", err)
	}
	if _, err = tx.Exec(ctx, "UPDATE audit.chain_head SET last_sequence = $1, last_hash = $2 WHERE singleton", appended.Sequence, appended.Hash[:]); err != nil {
		return Appended{}, store.Sanitize("advance the audit chain", err)
	}
	return appended, nil
}

// AuditHash is SHA-256 over the previous hash and the event's fields, each length-prefixed (big endian), with the instant in
// UTC microseconds.
func AuditHash(previous [32]byte, sequence int64, event Event) [32]byte {
	var buffer bytes.Buffer
	field := func(value []byte) {
		_ = binary.Write(&buffer, binary.BigEndian, uint32(len(value)))
		buffer.Write(value)
	}
	optional := func(id *ID) {
		if id == nil {
			field(nil)
			return
		}
		field(id[:])
	}
	number := func(value int64) {
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], uint64(value))
		field(encoded[:])
	}
	buffer.WriteString("arcforges.audit.v1")
	field(previous[:])
	number(sequence)
	field(event.EventID[:])
	number(event.OccurredAt.UTC().UnixMicro())
	field([]byte(event.ActorRef))
	field([]byte(event.EventType))
	field([]byte(event.Reason))
	optional(event.CorrelationID)
	optional(event.CommandID)
	field([]byte(event.TargetKind))
	field([]byte(event.TargetID))
	field(event.Payload)
	return sha256.Sum256(buffer.Bytes())
}

// VerifyAudit recomputes the whole chain and compares it with the stored hashes and the chain head; it returns the number of
// events.
func VerifyAudit(ctx context.Context, q interface {
	Query(ctx context.Context, sql string, arguments ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, arguments ...any) pgx.Row
}) (int64, error) {
	rows, err := q.Query(ctx, `SELECT sequence, event_id, occurred_at, actor_ref, event_type, reason, correlation_id, command_id, target_kind,
    target_id, payload, previous_hash, event_hash FROM audit.audit_event ORDER BY sequence`)
	if err != nil {
		return 0, store.Sanitize("read the audit chain", err)
	}
	defer rows.Close()
	var head [32]byte
	var count int64
	for rows.Next() {
		var event Event
		var sequence int64
		var previous, stored []byte
		if err = rows.Scan(&sequence, &event.EventID, &event.OccurredAt, &event.ActorRef, &event.EventType, &event.Reason, &event.CorrelationID,
			&event.CommandID, &event.TargetKind, &event.TargetID, &event.Payload, &previous, &stored); err != nil {
			return count, store.Sanitize("read the audit chain", err)
		}
		count++
		hash := AuditHash(head, sequence, event)
		if sequence != count || !bytes.Equal(previous, head[:]) || !bytes.Equal(stored, hash[:]) {
			return count, fmt.Errorf("%w at sequence %d", ErrChainBroken, sequence)
		}
		head = hash
	}
	if err = rows.Err(); err != nil {
		return count, store.Sanitize("read the audit chain", err)
	}
	var last int64
	var lastHash []byte
	if err = q.QueryRow(ctx, "SELECT last_sequence, last_hash FROM audit.chain_head WHERE singleton").Scan(&last, &lastHash); err != nil {
		return count, store.Sanitize("read the audit chain head", err)
	}
	if last != count || !bytes.Equal(lastHash, head[:]) {
		return count, fmt.Errorf("%w: the chain head does not match the last event", ErrChainBroken)
	}
	return count, nil
}
