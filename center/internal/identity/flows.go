// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// Channel is a flow's channel (identity.flow_channel): the API's native clients or a browser on the account pages.
type Channel int16

// The channels.
const (
	ChannelNative  Channel = 1
	ChannelBrowser Channel = 2
)

// FlowKind is a flow's ceremony (identity.flow_kind).
type FlowKind int16

// The ceremonies.
const (
	FlowPasskeySignIn       FlowKind = 1
	FlowPasskeyRegistration FlowKind = 2
	FlowEnrollment          FlowKind = 3
	FlowEmailCode           FlowKind = 4
)

// Purpose is a flow's purpose (the contract's AuthPurpose): authenticate or enroll.
type Purpose int16

// The purposes a flow can have.
const (
	PurposeAuthenticate Purpose = 1
	PurposeEnroll       Purpose = 2
)

// The flow outcomes (identity.flow_outcome).
const (
	outcomeSucceeded = 1
	outcomeExhausted = 2
)

// passkeyAttempts is the attempts of a passkey ceremony: its challenge serves one completion, verified or not.
const passkeyAttempts = 1

// flow is a stored ceremony.
type flow struct {
	ID          platform.ID
	Channel     Channel
	Kind        FlowKind
	Purpose     Purpose
	UserID      *platform.ID
	SessionID   *platform.ID
	Label       *string
	Origin      *string
	Challenge   []byte
	UserHandle  []byte
	EmailHash   []byte
	CodeHash    []byte
	CodeSalt    []byte
	Sends       int16
	Claim       *device.Claim
	Attempts    int16
	MaxAttempts int16
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

func (s *Service) insertFlow(ctx context.Context, tx pgx.Tx, row flow) error {
	var installation *platform.ID
	var product, platformText, version *string
	if row.Claim != nil {
		installation, product, platformText, version = &row.Claim.InstallationID, &row.Claim.Product, &row.Claim.Platform, &row.Claim.AppVersion
	}
	_, err := tx.Exec(ctx, `INSERT INTO identity.auth_flow (flow_id, channel, kind, purpose, user_id, session_id, label, origin, challenge,
    webauthn_user_handle, email_hash, code_hash, code_salt, sends, installation_id, installation_product, installation_platform, installation_version,
    attempts, max_attempts, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, 0, $19, $20, $21)`,
		row.ID, int16(row.Channel), int16(row.Kind), int16(row.Purpose), row.UserID, row.SessionID, row.Label, row.Origin, row.Challenge, row.UserHandle,
		row.EmailHash, row.CodeHash, row.CodeSalt, row.Sends, installation, product, platformText, version, row.MaxAttempts, row.CreatedAt, row.ExpiresAt)
	return err
}

const flowColumns = `flow_id, channel, kind, purpose, user_id, session_id, label, origin, challenge, webauthn_user_handle, email_hash, code_hash,
    code_salt, sends, installation_id, installation_product, installation_platform, installation_version, attempts, max_attempts, created_at,
    expires_at`

func scanFlow(row pgx.Row) (flow, error) {
	var item flow
	var channel, kind, purpose int16
	var installation *platform.ID
	var product, platformText, version *string
	err := row.Scan(&item.ID, &channel, &kind, &purpose, &item.UserID, &item.SessionID, &item.Label, &item.Origin, &item.Challenge, &item.UserHandle,
		&item.EmailHash, &item.CodeHash, &item.CodeSalt, &item.Sends, &installation, &product, &platformText, &version, &item.Attempts,
		&item.MaxAttempts, &item.CreatedAt, &item.ExpiresAt)
	if err != nil {
		return flow{}, err
	}
	item.Channel, item.Kind, item.Purpose = Channel(channel), FlowKind(kind), Purpose(purpose)
	if installation != nil && product != nil && platformText != nil && version != nil {
		item.Claim = &device.Claim{InstallationID: *installation, Product: *product, Platform: *platformText, AppVersion: *version}
	}
	return item, nil
}

// classify explains why a flow could not be used: unknown or of another channel, kind or purpose (not_found), consumed by a
// success (code_reused: the proof was presented again), exhausted or expired (expired), or taken by a completion still in progress
// (code_reused).
func classify(ctx context.Context, q pgx.Tx, id platform.ID, channel Channel, kinds []FlowKind, purpose Purpose, now time.Time) error {
	var storedChannel, storedKind, storedPurpose, attempts, maxAttempts int16
	var outcome *int16
	var expiresAt time.Time
	err := q.QueryRow(ctx, "SELECT channel, kind, purpose, attempts, max_attempts, outcome, expires_at FROM identity.auth_flow WHERE flow_id = $1", id).
		Scan(&storedChannel, &storedKind, &storedPurpose, &attempts, &maxAttempts, &outcome, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return arc.NotFound("auth_flow", id[:])
	}
	if err != nil {
		return err
	}
	matches := false
	for _, kind := range kinds {
		matches = matches || FlowKind(storedKind) == kind
	}
	switch {
	case !matches || Channel(storedChannel) != channel || Purpose(storedPurpose) != purpose:
		return arc.NotFound("auth_flow", id[:])
	case outcome != nil && *outcome == outcomeExhausted:
		return arc.Expired()
	case outcome != nil:
		return arc.CodeReused()
	case !now.Before(expiresAt):
		return arc.Expired()
	}
	return arc.CodeReused()
}

// takeAttempt counts one completion attempt of a flow in its own transaction, before the proof is checked, so the attempt stays
// counted whatever the proof's outcome; it returns the flow, or the refusal of a flow that cannot be used. The count, the flow's end
// (exhaust) and the attempt's give-back (release) are no effect of the call, so their transactions are auxiliary (D10): a COMMIT of
// one without an answer is answered like an unavailable store, and nothing is given back after it.
func (s *Service) takeAttempt(ctx context.Context, id platform.ID, channel Channel, kinds []FlowKind, purpose Purpose) (flow, error) {
	now := s.now()
	stored := make([]int16, len(kinds))
	for index, kind := range kinds {
		stored[index] = int16(kind)
	}
	var item flow
	err := s.db.InTx(ctx, "count a flow attempt", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		item, err = scanFlow(tx.QueryRow(ctx, `UPDATE identity.auth_flow SET attempts = attempts + 1
WHERE flow_id = $1 AND channel = $2 AND kind = ANY($3::smallint[]) AND purpose = $4 AND consumed_at IS NULL AND expires_at > $5 AND attempts < max_attempts
RETURNING `+flowColumns, id, int16(channel), stored, int16(purpose), now))
		if errors.Is(err, pgx.ErrNoRows) {
			return classify(ctx, tx, id, channel, kinds, purpose, now)
		}
		return err
	})
	return item, err
}

// exhaust ends a flow whose last attempt failed, in its own transaction.
func (s *Service) exhaust(ctx context.Context, id platform.ID) error {
	return s.db.InTx(ctx, "end an exhausted flow", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE identity.auth_flow SET consumed_at = $2, outcome = $3
WHERE flow_id = $1 AND consumed_at IS NULL AND attempts >= max_attempts`, id, s.now(), outcomeExhausted)
		return err
	})
}

// release gives back the attempt a completion took when its proof verified but its success transaction failed in the store (a
// lost race for a new installation included, which is a store contention, D4), or when no proof was checked at all, so the advised
// retry of the same request can succeed (F9). It is best effort, in its own short
// transaction: a store that is still down leaves the attempt spent. A flow consumed meanwhile (a success whose reply was lost) is
// never changed, and a wrong proof never reaches it, so it grants no guess.
func (s *Service) release(ctx context.Context, id platform.ID) {
	_ = s.db.InTx(context.WithoutCancel(ctx), "release a flow attempt", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE identity.auth_flow SET attempts = attempts - 1 WHERE flow_id = $1 AND consumed_at IS NULL AND attempts > 0", id)
		return err
	})
}

// consume marks a flow succeeded in the success transaction; a flow consumed meanwhile is a proof presented twice.
func consume(ctx context.Context, tx pgx.Tx, id platform.ID, now time.Time) error {
	tag, err := tx.Exec(ctx, "UPDATE identity.auth_flow SET consumed_at = $2, outcome = $3 WHERE flow_id = $1 AND consumed_at IS NULL", id, now, outcomeSucceeded)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return arc.CodeReused()
	}
	return nil
}
