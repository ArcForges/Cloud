// SPDX-License-Identifier: AGPL-3.0-only

package platform

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/store"
)

// DefaultInboxRetention is how long a provider message ID is remembered (the retention sweep is AF-PLAT-01's).
const DefaultInboxRetention = 90 * 24 * time.Hour

// InboxOutcome is how a received message was handled.
type InboxOutcome int16

// The inbox outcomes (platform.inbox_outcome).
const (
	InboxApplied          InboxOutcome = 1
	InboxDuplicateIgnored InboxOutcome = 2
	InboxRejected         InboxOutcome = 3
)

// Receive records a provider message in the transaction that handles it and reports whether this is its first delivery. A
// redelivery (or a concurrent duplicate, which waits for the first transaction) reports false, so its effect is never applied
// twice; when the first transaction rolls back, the message was never received.
func Receive(ctx context.Context, tx pgx.Tx, source, messageID string, retention time.Duration) (bool, error) {
	if !lowerName.MatchString(source) || messageID == "" || len(messageID) > maxTextLength {
		return false, errors.New("an inbox message needs a source name and a message ID of at most 256 bytes")
	}
	if retention <= 0 {
		retention = DefaultInboxRetention
	}
	tag, err := tx.Exec(ctx, `INSERT INTO platform.inbox (source, message_id, received_at, expires_at)
VALUES ($1, $2, now(), now() + $3::interval) ON CONFLICT (source, message_id) DO NOTHING`, source, messageID, retention)
	if err != nil {
		return false, store.Sanitize("receive an inbox message", err)
	}
	return tag.RowsAffected() == 1, nil
}

// Processed records how a received message was handled, in the same transaction.
func Processed(ctx context.Context, tx pgx.Tx, source, messageID string, outcome InboxOutcome) error {
	if outcome < InboxApplied || outcome > InboxRejected {
		return errors.New("unknown inbox outcome")
	}
	tag, err := tx.Exec(ctx, `UPDATE platform.inbox SET processed_at = now(), outcome = $3 WHERE source = $1 AND message_id = $2 AND processed_at IS NULL`,
		source, messageID, outcome)
	if err != nil {
		return store.Sanitize("record an inbox outcome", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("the inbox message was not received in this transaction or is already processed")
	}
	return nil
}
