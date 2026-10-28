// SPDX-License-Identifier: AGPL-3.0-only

package platform

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/store"
)

// Outbox bounds and defaults.
const (
	MaxPayloadBytes        = 262144
	DefaultPublishBatch    = 32
	DefaultPublishLease    = 30 * time.Second
	DefaultPublishAttempts = 10
	maxBackoffDelay        = 10 * time.Minute
)

// The stored state of an outbox row.
const (
	outboxPending      = 1
	outboxDispatched   = 2
	outboxDeadLettered = 3
)

var (
	lowerName = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
	topicName = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
)

// Message is one event committed with its business change.
type Message struct {
	// DedupKey is unique per event; enqueueing it again is a no-op, and consumers deduplicate redeliveries by it.
	DedupKey      string
	Topic         string
	AggregateKind string
	AggregateID   ID
	AggregateRev  int64
	Payload       []byte
	CorrelationID ID
	CausationID   *ID
}

// Enqueue adds a message in the business transaction, so it commits or rolls back with the change. It reports false when a
// message with the same dedup key exists already.
func Enqueue(ctx context.Context, tx pgx.Tx, message Message) (bool, error) {
	if message.DedupKey == "" || len(message.DedupKey) > maxTextLength || !topicName.MatchString(message.Topic) || !lowerName.MatchString(message.AggregateKind) ||
		message.AggregateRev < 0 || len(message.Payload) > MaxPayloadBytes {
		return false, errors.New("an outbox message needs a dedup key, a topic, an aggregate kind and a payload within their bounds")
	}
	tag, err := tx.Exec(ctx, `INSERT INTO platform.outbox (outbox_id, dedup_key, topic, aggregate_kind, aggregate_id, aggregate_rev, payload,
    correlation_id, causation_id, state, attempts, available_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 0, now(), now()) ON CONFLICT (dedup_key) DO NOTHING`,
		NewID(), message.DedupKey, message.Topic, message.AggregateKind, message.AggregateID, message.AggregateRev, nonNil(message.Payload),
		message.CorrelationID, message.CausationID, outboxPending)
	if err != nil {
		return false, store.Sanitize("enqueue an outbox message", err)
	}
	return tag.RowsAffected() == 1, nil
}

// Delivery is one claimed message handed to the sink.
type Delivery struct {
	OutboxID ID
	Sequence int64
	Message
	// Attempt is 1 for the first delivery; a redelivery after a crash or a failure has a higher attempt and the same dedup key.
	Attempt int
}

// Sink publishes a delivery. It must be idempotent per dedup key or leave deduplication to its consumers, and its errors must
// not quote a credential or the payload (the publisher stores them, truncated, as the row's last error).
type Sink interface {
	Publish(ctx context.Context, delivery Delivery) error
}

// Publisher delivers committed outbox messages at least once. A batch is claimed in a short transaction that extends each row's
// availability by the lease and counts the attempt; each message is then published outside any transaction and marked
// dispatched. A crash between the commit of a message and its publication, or between publication and the mark, leaves the row
// pending, so it is claimed again after the lease and published again: at least once, never lost.
type Publisher struct {
	DB          *store.DB
	Sink        Sink
	Batch       int
	Lease       time.Duration
	MaxAttempts int
	Logger      *slog.Logger
}

// Report counts one publishing pass.
type Report struct {
	Claimed      int
	Dispatched   int
	Failed       int
	DeadLettered int
}

func (p *Publisher) defaults() (batch int, lease time.Duration, attempts int, logger *slog.Logger) {
	batch, lease, attempts, logger = p.Batch, p.Lease, p.MaxAttempts, p.Logger
	if batch <= 0 {
		batch = DefaultPublishBatch
	}
	if lease <= 0 {
		lease = DefaultPublishLease
	}
	if attempts <= 0 {
		attempts = DefaultPublishAttempts
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return
}

// PublishOnce claims and publishes one batch.
func (p *Publisher) PublishOnce(ctx context.Context) (Report, error) {
	batch, lease, maxAttempts, logger := p.defaults()
	var deliveries []Delivery
	err := p.DB.InTx(ctx, "claim outbox messages", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `WITH claimed AS (
    SELECT outbox_id FROM platform.outbox WHERE state = $1 AND available_at <= now() ORDER BY sequence LIMIT $2 FOR UPDATE SKIP LOCKED)
UPDATE platform.outbox o SET attempts = o.attempts + 1, available_at = now() + $3::interval
FROM claimed WHERE o.outbox_id = claimed.outbox_id
RETURNING o.outbox_id, o.sequence, o.dedup_key, o.topic, o.aggregate_kind, o.aggregate_id, o.aggregate_rev, o.payload, o.correlation_id,
    o.causation_id, o.attempts`, outboxPending, batch, lease)
		if err != nil {
			return err
		}
		deliveries, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Delivery, error) {
			var delivery Delivery
			err := row.Scan(&delivery.OutboxID, &delivery.Sequence, &delivery.DedupKey, &delivery.Topic, &delivery.AggregateKind,
				&delivery.AggregateID, &delivery.AggregateRev, &delivery.Payload, &delivery.CorrelationID, &delivery.CausationID, &delivery.Attempt)
			return delivery, err
		})
		return err
	})
	if err != nil {
		return Report{}, err
	}
	slices.SortFunc(deliveries, func(a, b Delivery) int { return int(a.Sequence - b.Sequence) })
	report := Report{Claimed: len(deliveries)}
	for _, delivery := range deliveries {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		publishErr := p.Sink.Publish(ctx, delivery)
		var statement string
		var arguments []any
		switch {
		case publishErr == nil:
			statement = "UPDATE platform.outbox SET state = $2, dispatched_at = now(), last_error = NULL WHERE outbox_id = $1 AND state = $3"
			arguments = []any{delivery.OutboxID, outboxDispatched, outboxPending}
			report.Dispatched++
		case delivery.Attempt >= maxAttempts:
			statement = "UPDATE platform.outbox SET state = $2, last_error = $4 WHERE outbox_id = $1 AND state = $3"
			arguments = []any{delivery.OutboxID, outboxDeadLettered, outboxPending, lastError(publishErr)}
			report.DeadLettered++
			logger.Error("outbox message dead-lettered", "dedupKey", delivery.DedupKey, "topic", delivery.Topic, "attempts", delivery.Attempt)
		default:
			statement = "UPDATE platform.outbox SET available_at = now() + $4::interval, last_error = $5 WHERE outbox_id = $1 AND state = $2 AND attempts = $3"
			arguments = []any{delivery.OutboxID, outboxPending, delivery.Attempt, backoff(delivery.Attempt), lastError(publishErr)}
			report.Failed++
			logger.Warn("outbox publication failed; it will be retried", "dedupKey", delivery.DedupKey, "topic", delivery.Topic, "attempt", delivery.Attempt)
		}
		err := p.DB.InTx(ctx, "mark an outbox message", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, statement, arguments...)
			return err
		})
		if err != nil {
			// The row stays pending and is claimed again after its lease: published again, never lost.
			return report, err
		}
	}
	return report, nil
}

// Run publishes until ctx ends, waiting interval after a pass that claimed nothing.
func (p *Publisher) Run(ctx context.Context, interval time.Duration) error {
	_, _, _, logger := p.defaults()
	for {
		report, err := p.PublishOnce(ctx)
		if err != nil && ctx.Err() == nil {
			logger.Warn("outbox publishing pass failed", "error", err.Error())
		}
		if report.Claimed > 0 && err == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

func backoff(attempt int) time.Duration {
	delay := time.Second << min(attempt, 10)
	return min(delay, maxBackoffDelay)
}

func lastError(err error) string {
	text := fmt.Sprint(err)
	if len(text) > 200 {
		text = text[:200]
	}
	return text
}
