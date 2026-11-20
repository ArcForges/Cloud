// SPDX-License-Identifier: AGPL-3.0-only

// Package management stores content-free V2 command identities and routing observations.
// It does not execute a Node command or verify a Node response. The typed
// transport authenticates, authorizes and verifies its input before calling it.
package management

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/ArcForges/Cloud/center/internal/page"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrIdentityConflict = errors.New("the command identity is already bound to another intent")
	ErrLegacyCommand    = errors.New("the command is a retained non-executable legacy identity")
	ErrReplayExpired    = errors.New("the retained command is outside its replay boundary")
	ErrLease            = errors.New("the protocol or channel lease is not current")
	ErrTransition       = errors.New("the routing observation does not follow the retained operation")
)

// Store uses only the existing bounded transaction wrapper and runtime role.
type Store struct{ db *store.DB }

// New composes the storage boundary. It registers no route or transport.
func New(db *store.DB) *Store { return &Store{db: db} }

// Identity contains no request, response, argv, environment, output or file body.
type Identity struct {
	Account, Command, Enrollment, Node platform.ID
	Actor, Grant                       platform.ID
	GrantRevision                      int64
	OwnerEpoch                         [16]byte
	IntentSHA256                       [32]byte
	Method                             string
	CreatedAt, ReplayUntil             time.Time
}

// Lease binds a reservation to the actual current hub and Node channel.
type Lease struct {
	Holder, ChannelEpoch, ProtocolEpoch platform.ID
	Fence                               int64
}

// Receipt is a last verified routing observation, never authoritative Run state.
type Receipt struct {
	Account, Command, Enrollment, Node platform.ID
	OwnerEpoch                         [16]byte
	Method                             string
	Namespace, State                   int16
	MayHaveDelivered                   bool
	DeliveryCount                      int
	Effect                             *int16
	ResultSHA256                       []byte
	ResultKind, Reason                 string
	ResultID                           *platform.ID
	CreatedAt, UpdatedAt               time.Time
	FinalAt                            *time.Time
	reservation                        reservationObservation
}

// Reserve joins an existing exact identity, or durably reserves one new operation.
// The boolean is true only for the transaction which inserted that identity.
// No external send occurs inside, or is implied by, this transaction.
func (s *Store) Reserve(ctx context.Context, identity Identity, lease Lease) (receipt Receipt, inserted bool, err error) {
	bound := identity.authority()
	if !bound.empty() && (!bound.valid() || identity.Command == (platform.ID{}) ||
		identity.OwnerEpoch == ([16]byte{}) || identity.IntentSHA256 == ([32]byte{})) {
		return Receipt{}, false, ErrIdentityConflict
	}
	err = s.db.InTx(ctx, "reserve V2 management command", store.TxOptions{Isolation: pgx.Serializable}, func(ctx context.Context, tx pgx.Tx) error {
		inserted = false // A serialization retry must not retain an earlier attempt's decision.
		var tag pgconn.CommandTag
		var e error
		if bound.valid() {
			tag, e = tx.Exec(ctx, `INSERT INTO management.command_identity
 (account_id,command_id,enrollment_id,node_id,namespace,node_owner_epoch,method,intent_sha256,created_at,replay_until,
  actor_id,grant_id,grant_revision)
 VALUES($1,$2,$3,$4,3,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (account_id,command_id) DO NOTHING`,
				identity.Account, identity.Command, identity.Enrollment, identity.Node, identity.OwnerEpoch[:], identity.Method,
				identity.IntentSHA256[:], identity.CreatedAt, identity.ReplayUntil, bound.Actor, bound.Grant, bound.GrantRevision)
		} else {
			// The retained schema-12/13 maintenance fixtures use this
			// historical reservation path. It cannot claim a routed send.
			tag, e = tx.Exec(ctx, `INSERT INTO management.command_identity
 (account_id,command_id,enrollment_id,node_id,namespace,node_owner_epoch,method,intent_sha256,created_at,replay_until)
 VALUES($1,$2,$3,$4,3,$5,$6,$7,$8,$9) ON CONFLICT (account_id,command_id) DO NOTHING`,
				identity.Account, identity.Command, identity.Enrollment, identity.Node, identity.OwnerEpoch[:], identity.Method,
				identity.IntentSHA256[:], identity.CreatedAt, identity.ReplayUntil)
		}
		if e != nil {
			return e
		}
		var namespace int16
		var enrollment, node platform.ID
		var epoch, digest []byte
		var method string
		var replayable bool
		var actor, grant *platform.ID
		var revision *int64
		e = tx.QueryRow(ctx, `SELECT namespace,enrollment_id,node_id,node_owner_epoch,method,intent_sha256,
 replay_until>clock_timestamp(),(to_jsonb(i)->>'actor_id')::uuid,(to_jsonb(i)->>'grant_id')::uuid,
 (to_jsonb(i)->>'grant_revision')::bigint
 FROM management.command_identity i WHERE account_id=$1 AND command_id=$2`, identity.Account, identity.Command).
			Scan(&namespace, &enrollment, &node, &epoch, &method, &digest, &replayable, &actor, &grant, &revision)
		if e != nil {
			return e
		}
		if namespace != 3 {
			return ErrLegacyCommand
		}
		sameAuthority := bound.empty() && actor == nil && grant == nil && revision == nil ||
			actor != nil && grant != nil && revision != nil && *actor == bound.Actor && *grant == bound.Grant && *revision == bound.GrantRevision
		if !sameAuthority || enrollment != identity.Enrollment || node != identity.Node || method != identity.Method ||
			!bytes.Equal(epoch, identity.OwnerEpoch[:]) || !bytes.Equal(digest, identity.IntentSHA256[:]) {
			return ErrIdentityConflict
		}
		if tag.RowsAffected() == 1 {
			if e = requireHubLease(ctx, tx, lease); e != nil {
				return e
			}
			if e = requireChannel(ctx, tx, identity, lease, bound.valid()); e != nil {
				return e
			}
			_, e = tx.Exec(ctx, `INSERT INTO management.remote_operation
 (account_id,command_id,node_owner_epoch,method,state,may_have_delivered,delivery_count,hub_fence,channel_epoch,request_sha256,created_at,updated_at)
 VALUES($1,$2,$3,$4,1,false,0,$5,$6,$7,$8,$8)`, identity.Account, identity.Command, identity.OwnerEpoch[:], identity.Method,
				lease.Fence, lease.ChannelEpoch, identity.IntentSHA256[:], identity.CreatedAt)
			if e != nil {
				return e
			}
			inserted = true
		}
		if !replayable {
			return ErrReplayExpired
		}
		receipt, e = readReceipt(ctx, tx, identity.Account, identity.Command)
		return e
	})
	if err != nil {
		inserted = false
	}
	return
}

const receiptColumns = `i.account_id,i.command_id,i.namespace,coalesce(o.state,a.legacy_state,7)::smallint,
 coalesce(o.may_have_delivered,a.may_have_delivered,true),coalesce(o.delivery_count,a.delivery_count,0),o.effect,coalesce(o.result_sha256,a.response_sha256),
 i.created_at,coalesce(o.updated_at,a.updated_at,i.created_at),coalesce(o.final_at,a.final_at),
 i.enrollment_id,i.node_id,i.node_owner_epoch,i.method,coalesce(o.result_kind,''),o.result_id,coalesce(o.reason,''),
 o.hub_fence,o.channel_epoch`

func readReceipt(ctx context.Context, tx pgx.Tx, account, command platform.ID) (r Receipt, err error) {
	err = scanReceipt(tx.QueryRow(ctx, `SELECT `+receiptColumns+` FROM management.command_identity i
 LEFT JOIN management.remote_operation o USING(account_id,command_id) LEFT JOIN management.legacy_outcome a USING(account_id,command_id) WHERE i.account_id=$1 AND i.command_id=$2`, account, command), &r)
	return
}

func scanReceipt(row interface{ Scan(...any) error }, r *Receipt) error {
	var epoch []byte
	var fence *int64
	var channel *platform.ID
	err := row.Scan(&r.Account, &r.Command, &r.Namespace, &r.State, &r.MayHaveDelivered, &r.DeliveryCount, &r.Effect, &r.ResultSHA256,
		&r.CreatedAt, &r.UpdatedAt, &r.FinalAt, &r.Enrollment, &r.Node, &epoch, &r.Method, &r.ResultKind, &r.ResultID, &r.Reason,
		&fence, &channel)
	if err == nil && r.Namespace == 3 && len(epoch) != len(r.OwnerEpoch) {
		return ErrTransition
	}
	copy(r.OwnerEpoch[:], epoch)
	r.reservation = reservationObservation{}
	if err == nil && r.Namespace == 3 && fence != nil && channel != nil {
		r.reservation = reservationObservation{account: r.Account, command: r.Command, channel: *channel,
			fence: *fence, updatedAt: r.UpdatedAt, state: r.State, deliveryCount: r.DeliveryCount,
			mayHaveDelivered: r.MayHaveDelivered, final: r.FinalAt != nil}
	}
	return err
}

// Inspect reads only the given account's retained identity, including legacy tombstones.
func (s *Store) Inspect(ctx context.Context, account, command platform.ID) (receipt Receipt, err error) {
	err = s.db.InTx(ctx, "inspect V2 management command", store.TxOptions{ReadOnly: true}, func(ctx context.Context, tx pgx.Tx) error {
		var e error
		receipt, e = readReceipt(ctx, tx, account, command)
		return e
	})
	return
}

// List returns bounded account-scoped keyset results. Cursors only position a
// listing; they grant no access and cannot select another account's records.
func (s *Store) List(ctx context.Context, account platform.ID, cursor string, limit int32) (receipts []Receipt, next string, err error) {
	const listing page.Listing = 4 // V2 management operations; historical listings 1..3 are unchanged.
	request, refusal := page.Parse(listing, cursor, limit, true)
	if refusal != nil {
		return nil, "", errors.New("invalid management listing cursor or limit")
	}
	err = s.db.InTx(ctx, "list V2 management commands", store.TxOptions{ReadOnly: true}, func(ctx context.Context, tx pgx.Tx) error {
		var afterAt any
		var afterID any
		if request.After != nil {
			afterAt = request.After.At
			afterID = platform.ID(request.After.ID)
		}
		rows, e := tx.Query(ctx, `SELECT `+receiptColumns+` FROM management.command_identity i
 LEFT JOIN management.remote_operation o USING(account_id,command_id) LEFT JOIN management.legacy_outcome a USING(account_id,command_id)
 WHERE i.account_id=$1 AND ($2::timestamptz IS NULL OR (i.created_at,i.command_id)<($2,$3::uuid))
 ORDER BY i.created_at DESC,i.command_id DESC LIMIT $4`, account, afterAt, afterID, request.Limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		receipts = nil
		for rows.Next() {
			var r Receipt
			if e := scanReceipt(rows, &r); e != nil {
				return e
			}
			receipts = append(receipts, r)
		}
		return rows.Err()
	})
	if err == nil && len(receipts) > request.Limit {
		receipts = receipts[:request.Limit]
		last := receipts[len(receipts)-1]
		next = page.Encode(listing, page.Cursor{At: last.CreatedAt, ID: [16]byte(last.Command)})
	}
	return
}
