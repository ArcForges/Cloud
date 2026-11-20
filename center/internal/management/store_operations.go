// SPDX-License-Identifier: AGPL-3.0-only

package management

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
	"github.com/jackc/pgx/v5"
)

// States are the durable Center routing projection. They are distinct from
// the Node OperationState and RunState wire enums.
const (
	StateAccepted     int16 = 1
	StateSucceeded    int16 = 3
	StateFailed       int16 = 4
	StateRejected     int16 = 5
	StateExpired      int16 = 6
	StateUnknown      int16 = 7
	StateNotDelivered int16 = 8

	EffectDidNotHappen int16 = 1
	EffectHappened     int16 = 2
	EffectUnknown      int16 = 3
)

// Authority is the original authorization association of a routed command.
// A caller supplies it only after authenticating the actor and validating the
// exact account, target and grant association of its read or mutation.
type Authority struct {
	Account, Actor, Enrollment, Node, Grant platform.ID
	GrantRevision                           int64
}

func (i Identity) authority() Authority {
	return Authority{i.Account, i.Actor, i.Enrollment, i.Node, i.Grant, i.GrantRevision}
}

func (a Authority) empty() bool {
	return a.Actor == (platform.ID{}) && a.Grant == (platform.ID{}) && a.GrantRevision == 0
}

func (a Authority) valid() bool {
	return a.Account != (platform.ID{}) && a.Actor != (platform.ID{}) && a.Enrollment != (platform.ID{}) &&
		a.Node != (platform.ID{}) && a.Grant != (platform.ID{}) && a.GrantRevision > 0
}

// Observation is metadata from an authenticated, exact Node response. Reason
// is a typed code only. The Store never receives the request or response body.
type Observation struct {
	State, Effect int16
	ResultSHA256  [32]byte
	ResultKind    string
	ResultID      *platform.ID
	Reason        string
}

var resultReasonCode = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,95}$`)

func (o Observation) valid(method string) bool {
	if (o.ResultKind == "") != (o.ResultID == nil) || o.ResultID != nil && *o.ResultID == (platform.ID{}) ||
		o.ResultSHA256 == ([32]byte{}) || o.Reason != "" && !resultReasonCode.MatchString(o.Reason) {
		return false
	}
	switch o.ResultKind {
	case "", "sandbox", "run", "transfer", "policy", "operation":
	default:
		return false
	}
	switch o.State {
	case StateSucceeded:
		return o.Effect == EffectHappened || o.Effect == EffectDidNotHappen && method == "RunService.Stop"
	case StateFailed:
		return o.Effect == EffectDidNotHappen || o.Effect == EffectHappened
	case StateRejected, StateExpired:
		return o.Effect == EffectDidNotHappen
	default:
		return false
	}
}

// InspectOriginal returns the retained identity of an already-authorized read.
// Legacy or unassociated records, a different actor or a replaced grant do not
// supply the original owner epoch for a routed observation.
func (s *Store) InspectOriginal(ctx context.Context, authority Authority, command platform.ID) (i Identity, r Receipt, err error) {
	if !authority.valid() || command == (platform.ID{}) {
		return i, r, pgx.ErrNoRows
	}
	err = s.db.InTx(ctx, "inspect original V2 management command", store.TxOptions{ReadOnly: true}, func(ctx context.Context, tx pgx.Tx) error {
		i = Identity{Account: authority.Account, Command: command, Enrollment: authority.Enrollment, Node: authority.Node,
			Actor: authority.Actor, Grant: authority.Grant, GrantRevision: authority.GrantRevision}
		var epoch, digest []byte
		e := tx.QueryRow(ctx, `SELECT node_owner_epoch,method,intent_sha256,created_at,replay_until
FROM management.command_identity
WHERE account_id=$1 AND command_id=$2 AND namespace=3 AND enrollment_id=$3 AND node_id=$4
AND actor_id=$5 AND grant_id=$6 AND grant_revision=$7`, i.Account, i.Command, i.Enrollment, i.Node,
			i.Actor, i.Grant, i.GrantRevision).Scan(&epoch, &i.Method, &digest, &i.CreatedAt, &i.ReplayUntil)
		if e != nil {
			return e
		}
		if len(epoch) != len(i.OwnerEpoch) || len(digest) != len(i.IntentSHA256) {
			return ErrTransition
		}
		copy(i.OwnerEpoch[:], epoch)
		copy(i.IntentSHA256[:], digest)
		r, e = readReceipt(ctx, tx, i.Account, i.Command)
		return e
	})
	if err != nil {
		return Identity{}, Receipt{}, err
	}
	return
}

func requireHubLease(ctx context.Context, tx pgx.Tx, lease Lease) error {
	var current bool
	err := tx.QueryRow(ctx, `SELECT true FROM fleet.hub_lease
WHERE singleton AND holder=$1 AND fence=$2 AND expires_at>clock_timestamp() FOR SHARE`,
		lease.Holder, lease.Fence).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLease
	}
	return err
}

func requireChannel(ctx context.Context, tx pgx.Tx, identity Identity, lease Lease, exact bool) error {
	var protocol any
	if lease.ProtocolEpoch == (platform.ID{}) {
		if exact {
			return ErrLease
		}
	} else {
		protocol = lease.ProtocolEpoch
	}
	var current bool
	err := tx.QueryRow(ctx, `SELECT true FROM management.node_protocol p JOIN fleet.node n
ON (n.enrollment_id,n.node_id,n.user_id)=(p.enrollment_id,p.node_id,p.account_id)
WHERE p.enrollment_id=$1 AND p.account_id=$2 AND p.node_id=$3 AND n.connection_id=$4
AND p.revoked_at IS NULL AND n.revoked_at IS NULL
AND ($5::uuid IS NULL OR p.protocol_epoch=$5) FOR SHARE OF p,n`,
		identity.Enrollment, identity.Account, identity.Node, lease.ChannelEpoch, protocol).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLease
	}
	return err
}

type retainedOperation struct {
	state             int16
	mayHaveDelivered  bool
	deliveryCount     int
	final, replayable bool
	fence             int64
	channel           platform.ID
	updatedAt         time.Time
}

// reservationObservation seals the database snapshot that a transport caller
// observed before attempting to claim or disprove delivery.
type reservationObservation struct {
	account, command, channel platform.ID
	fence                     int64
	updatedAt                 time.Time
	state                     int16
	deliveryCount             int
	mayHaveDelivered, final   bool
}

func (o retainedOperation) matches(i Identity, observed reservationObservation) bool {
	return observed.account == i.Account && observed.command == i.Command && observed.channel == o.channel &&
		observed.fence == o.fence && observed.updatedAt.Equal(o.updatedAt) && observed.state == o.state &&
		observed.deliveryCount == o.deliveryCount && observed.mayHaveDelivered == o.mayHaveDelivered && observed.final == o.final
}

func lockOperation(ctx context.Context, tx pgx.Tx, i Identity) (o retainedOperation, err error) {
	err = tx.QueryRow(ctx, `SELECT o.state,o.may_have_delivered,o.delivery_count,o.final_at IS NOT NULL,
       i.replay_until>clock_timestamp(),o.hub_fence,o.channel_epoch,o.updated_at
FROM management.command_identity i JOIN management.remote_operation o USING(account_id,command_id)
WHERE i.account_id=$1 AND i.command_id=$2 AND i.namespace=3 AND i.enrollment_id=$3 AND i.node_id=$4
AND i.node_owner_epoch=$5 AND i.method=$6 AND i.intent_sha256=$7
AND i.actor_id=$8 AND i.grant_id=$9 AND i.grant_revision=$10
FOR UPDATE OF o`, i.Account, i.Command, i.Enrollment, i.Node, i.OwnerEpoch[:], i.Method, i.IntentSHA256[:],
		i.Actor, i.Grant, i.GrantRevision).Scan(&o.state, &o.mayHaveDelivered, &o.deliveryCount,
		&o.final, &o.replayable, &o.fence, &o.channel, &o.updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return o, ErrIdentityConflict
	}
	return
}

func (s *Store) transition(ctx context.Context, label string, i Identity, lease Lease,
	change func(context.Context, pgx.Tx, retainedOperation) (bool, error)) (r Receipt, changed bool, err error) {
	if !i.authority().valid() || i.Command == (platform.ID{}) || i.OwnerEpoch == ([16]byte{}) || i.IntentSHA256 == ([32]byte{}) {
		return Receipt{}, false, ErrIdentityConflict
	}
	err = s.db.InTx(ctx, label, store.TxOptions{Isolation: pgx.Serializable}, func(ctx context.Context, tx pgx.Tx) error {
		changed = false
		if e := requireHubLease(ctx, tx, lease); e != nil {
			return e
		}
		o, e := lockOperation(ctx, tx, i)
		if e != nil {
			return e
		}
		changed, e = change(ctx, tx, o)
		if e != nil {
			return e
		}
		r, e = readReceipt(ctx, tx, i.Account, i.Command)
		return e
	})
	if err != nil {
		return Receipt{}, false, err // No transport permission on an unanswered COMMIT.
	}
	return
}

// MarkPossiblyDelivered commits the first and only send claim. A true result
// after a successful COMMIT authorizes one write to the exact current channel.
// The expected receipt must be the exact observation from admission or from a
// freshly authorized, explicit retry of a retained not-delivered identity.
func (s *Store) MarkPossiblyDelivered(ctx context.Context, i Identity, lease Lease, expected Receipt) (Receipt, bool, error) {
	return s.transition(ctx, "claim first V2 management delivery", i, lease, func(ctx context.Context, tx pgx.Tx, o retainedOperation) (bool, error) {
		if !o.matches(i, expected.reservation) || o.final || o.mayHaveDelivered || o.deliveryCount != 0 ||
			o.state != StateAccepted && o.state != StateNotDelivered {
			return false, nil
		}
		if !o.replayable {
			return false, ErrReplayExpired
		}
		if o.state == StateAccepted && (o.fence != lease.Fence || o.channel != lease.ChannelEpoch) {
			return false, ErrLease
		}
		if err := requireChannel(ctx, tx, i, lease, true); err != nil {
			return false, err
		}
		_, err := tx.Exec(ctx, `UPDATE management.remote_operation
SET state=1,may_have_delivered=true,delivery_count=1,hub_fence=$3,channel_epoch=$4,
    effect=NULL,reason=NULL,updated_at=greatest(updated_at,clock_timestamp())
WHERE account_id=$1 AND command_id=$2`, i.Account, i.Command, lease.Fence, lease.ChannelEpoch)
		return err == nil, err
	})
}

// MarkNotDelivered records a definite no-effect observation only when the
// same observed row proves the pre-send claim was never committed.
func (s *Store) MarkNotDelivered(ctx context.Context, i Identity, lease Lease, expected Receipt) (Receipt, error) {
	r, _, err := s.transition(ctx, "record no V2 management delivery", i, lease, func(ctx context.Context, tx pgx.Tx, o retainedOperation) (bool, error) {
		if !o.matches(i, expected.reservation) {
			return false, ErrTransition
		}
		if o.state == StateNotDelivered {
			return false, nil
		}
		if o.state != StateAccepted || o.final || o.mayHaveDelivered || o.deliveryCount != 0 {
			return false, ErrTransition
		}
		_, e := tx.Exec(ctx, `UPDATE management.remote_operation
SET state=8,effect=1,reason='not_delivered',hub_fence=$3,updated_at=greatest(updated_at,clock_timestamp())
WHERE account_id=$1 AND command_id=$2`, i.Account, i.Command, lease.Fence)
		return e == nil, e
	})
	return r, err
}

// MarkUnknown retains a possible delivery after a timeout, disconnect or
// lost response. A withdrawn lease cannot displace a current hub's outcome.
func (s *Store) MarkUnknown(ctx context.Context, i Identity, lease Lease) (Receipt, error) {
	r, _, err := s.transition(ctx, "retain uncertain V2 management delivery", i, lease, func(ctx context.Context, tx pgx.Tx, o retainedOperation) (bool, error) {
		if o.final || o.state == StateUnknown {
			return false, nil
		}
		if o.state != StateAccepted || !o.mayHaveDelivered || o.deliveryCount == 0 {
			return false, ErrTransition
		}
		return true, setUnknown(ctx, tx, i, lease)
	})
	return r, err
}

func setUnknown(ctx context.Context, tx pgx.Tx, i Identity, lease Lease) error {
	_, err := tx.Exec(ctx, `UPDATE management.remote_operation
SET state=7,effect=3,reason='operation_unknown',hub_fence=$3,updated_at=greatest(updated_at,clock_timestamp())
WHERE account_id=$1 AND command_id=$2`, i.Account, i.Command, lease.Fence)
	return err
}

// RecordResult settles an authenticated definitive response only from the
// exact channel and current hub fence that claimed the original send.
func (s *Store) RecordResult(ctx context.Context, i Identity, lease Lease, observation Observation) (Receipt, error) {
	return s.recordResult(ctx, i, lease, observation, false)
}

// ReconcileResult settles proof from a scoped read of the original epoch and
// command. It keeps the original send channel and cannot set a send claim.
func (s *Store) ReconcileResult(ctx context.Context, i Identity, lease Lease, observation Observation) (Receipt, error) {
	return s.recordResult(ctx, i, lease, observation, true)
}

func (s *Store) recordResult(ctx context.Context, i Identity, lease Lease, observation Observation, reconcile bool) (Receipt, error) {
	if !observation.valid(i.Method) {
		return Receipt{}, ErrTransition
	}
	r, _, err := s.transition(ctx, "settle verified V2 management result", i, lease, func(ctx context.Context, tx pgx.Tx, o retainedOperation) (bool, error) {
		if !reconcile && (o.fence != lease.Fence || o.channel != lease.ChannelEpoch) {
			return false, ErrLease
		}
		if err := requireChannel(ctx, tx, i, lease, true); err != nil {
			return false, err
		}
		if o.final {
			prior, e := readReceipt(ctx, tx, i.Account, i.Command)
			if e == nil && !sameObservation(prior, observation) {
				e = ErrTransition
			}
			return false, e
		}
		if (o.state != StateAccepted && o.state != StateUnknown) || !o.mayHaveDelivered || o.deliveryCount == 0 {
			return false, ErrTransition
		}
		if reconcile && o.state == StateAccepted {
			if err := setUnknown(ctx, tx, i, lease); err != nil {
				return false, err
			}
		}
		_, e := tx.Exec(ctx, `UPDATE management.remote_operation SET state=$3,effect=$4,result_sha256=$5,
 result_kind=NULLIF($6,''),result_id=$7,reason=NULLIF($8,''),hub_fence=$9,
 final_at=greatest(updated_at,clock_timestamp()),updated_at=greatest(updated_at,clock_timestamp())
 WHERE account_id=$1 AND command_id=$2`, i.Account, i.Command, observation.State, observation.Effect,
			observation.ResultSHA256[:], observation.ResultKind, observation.ResultID, observation.Reason, lease.Fence)
		return e == nil, e
	})
	return r, err
}

func sameObservation(r Receipt, o Observation) bool {
	idsMatch := r.ResultID == nil && o.ResultID == nil ||
		r.ResultID != nil && o.ResultID != nil && *r.ResultID == *o.ResultID
	return r.State == o.State && r.Effect != nil && *r.Effect == o.Effect &&
		bytes.Equal(r.ResultSHA256, o.ResultSHA256[:]) && r.ResultKind == o.ResultKind && r.Reason == o.Reason && idsMatch
}
