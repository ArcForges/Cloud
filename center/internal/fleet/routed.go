// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The routing records of the routed mutations (AF-CTR-05 part E2b; Plan CTR5-RTE-03, C.8, PN-6; decisions B-1, B-3, Q-2..Q-5, Q-15;
// migration 0010): one fleet.routed_call row per SubmitNodeTask or CancelNodeTask command of an account, the command's receipt. It
// holds digests, sizes, the task ID, the states and their instants, never a request or response byte: a resend routes its own bytes,
// accepted only when the digest of its RequestDigestInput (with the method, the node and the caller class) equals the record's.
//
// The record is never less conservative than the reply (decisions B-1). An ACCEPTED record with no attempt in flight in this process
// counts as one that may have reached the node; only the hub's DID_NOT_HAPPEN answer, written by the attempt's own settlement, makes a
// record NOT_DELIVERED, and only while no earlier attempt may have reached the node. A settlement that is lost leaves the record
// ACCEPTED, which counts as delivered. The admission (AcceptRouted) is fenced by the hub lease's fencing token: it takes the lease row
// FOR SHARE, so a process that lost the lease commits no record, and a take-over waits for the admissions in flight, whose records its
// boot sweep (SweepRouted) then sees.

// RoutedState is a routing record's state (migration 0010; 2, DELIVERED, is reserved and never written).
type RoutedState int16

// The states of a routing record.
const (
	RoutedAccepted     RoutedState = 1
	RoutedSucceeded    RoutedState = 3
	RoutedFailed       RoutedState = 4
	RoutedRejected     RoutedState = 5
	RoutedExpired      RoutedState = 6
	RoutedUnknown      RoutedState = 7
	RoutedNotDelivered RoutedState = 8
)

// String is the state's audit name.
func (s RoutedState) String() string {
	switch s {
	case RoutedAccepted:
		return "accepted"
	case RoutedSucceeded:
		return "succeeded"
	case RoutedFailed:
		return "failed"
	case RoutedRejected:
		return "rejected_by_node"
	case RoutedExpired:
		return "expired"
	case RoutedUnknown:
		return "unknown"
	case RoutedNotDelivered:
		return "not_delivered"
	}
	return "invalid"
}

// The caller kinds of a routing record.
const (
	RoutedCallerSession int16 = 1
	RoutedCallerRelay   int16 = 2
)

// RoutedCaller is a routed mutation's verified caller as its record keeps it: an account session (its session), or a node relay (the
// relaying node, its local origin and its local session, from the verified relay assertion only).
type RoutedCaller struct {
	Kind           int16
	SessionID      platform.ID
	RelayingNodeID platform.ID
	LocalOrigin    int16
	LocalSessionID platform.ID
	// Actor is the audit actor of the attempt: the account (account:<id>) or the relaying node's installation (node:<id>).
	Actor string
}

// audit adds the caller's identity to an attempt's audit payload (Q-4): an account session's session, or a relay's relaying node, local
// origin and local session, so each attempt and each join names its own caller.
func (c RoutedCaller) audit(payload map[string]any) map[string]any {
	payload["callerKind"] = c.Kind
	if c.Kind == RoutedCallerSession {
		payload["sessionId"] = c.SessionID.String()
	} else {
		payload["relayingNodeId"], payload["localOrigin"], payload["localSessionId"] = c.RelayingNodeID.String(), c.LocalOrigin, c.LocalSessionID.String()
	}
	return payload
}

// RoutedAccept is the admission of one attempt of a routed mutation.
type RoutedAccept struct {
	Request   Request
	AccountID platform.ID
	// Evidence is the account session's step-up evidence to consume (class, bound to the node ID); nil for a relayed caller.
	Evidence  *identity.Caller
	Class     string
	NodeID    platform.ID
	CommandID platform.ID
	Method    int16
	Caller    RoutedCaller
	// Digest is the record digest (SHA-256 over the method, the node, the caller class and RequestDigestInput of the request bytes);
	// RequestSHA256 and Size are the exact bytes' digest and size, audited.
	Digest        []byte
	RequestSHA256 []byte
	Size          int
	Fence         int64
	Window        time.Duration
	// WorkspaceID and TargetAttemptID are checked file-operation metadata, never paths or contents.
	WorkspaceID     *platform.ID
	TargetAttemptID *platform.ID
	TargetPath      *string
	// InFlight reports whether an attempt of this record is in flight in this process; Online whether the node can be routed to now.
	InFlight func() bool
	Online   func() bool
	Now      time.Time
	// Clock is sampled again after transaction/row-lock waits for a live replay fence.
	// Existing callers can omit it when supplying a fixed Now in tests.
	Clock func() time.Time
}

func (a RoutedAccept) now() time.Time {
	if a.Clock != nil {
		return a.Clock()
	}
	return a.Now
}

// RoutedDecision is what an admission decided: route a new attempt (Attempt), or join the attempt in flight (Join).
type RoutedDecision struct {
	Join      bool
	Attempt   int
	Final     bool
	Delivered bool
	State     RoutedState
	// OutcomeSHA256 is a final record's outcome digest, which the answer of a resend is compared with.
	OutcomeSHA256 []byte
	// CreatedAt is the original durable file receipt creation instant. It is carried to the
	// signer so clock rollback cannot make a first file effect predate its receipt.
	CreatedAt time.Time
	// ReplayUntil is set only for an attempt that can repeat a previously delivered command.
	ReplayUntil time.Time
}

// ErrRoutedOffline marks a node_offline refusal of an admission (its error wraps the refusal): the routed API audits it once for a
// mutation (decisions Q-8).
var ErrRoutedOffline = errors.New("the node is offline")

type offline struct{ refusal *arc.Refusal }

func (o offline) Error() string   { return o.refusal.Error() }
func (o offline) Unwrap() []error { return []error{o.refusal, ErrRoutedOffline} }
func offlineRefusal(nodeID platform.ID, now time.Time) error {
	return offline{refusal: arc.NodeOffline(nodeID[:], now)}
}

// mayHaveReached reports whether a record's command may have reached the node: it was delivered, or an attempt was admitted (ACCEPTED,
// in flight here or not). A call for such a record is a resend: its routing failures and non-comparable handler errors, and a not_found
// after the node's revocation, are STATE/node_unreachable, UNKNOWN with SAME_COMMAND (decisions R1, R2).
func (r *routedRow) mayHaveReached() bool {
	return r != nil && (r.delivered || r.state == RoutedAccepted)
}

// unreachableFor is the node_offline refusal of an admission, or, for a record that may have reached the node, node_unreachable
// channel_closed with UNKNOWN (still marked offline for its audit row).
func unreachableFor(record *routedRow, nodeID platform.ID, now time.Time) error {
	if record.mayHaveReached() {
		return offline{refusal: arc.NodeUnreachable(nodeID[:], arc.UnreachableChannelClosed, true)}
	}
	return offlineRefusal(nodeID, now)
}

// routedRow is a routing record as an admission reads it.
type routedRow struct {
	digest    []byte
	state     RoutedState
	delivered bool
	attempts  int
	taskID    *platform.ID
	outcome   []byte
	created   time.Time
	final     bool
}

const routedColumns = `request_digest, state, delivered, attempts, task_id, outcome_sha256, created_at, final_at IS NOT NULL`

// routedStorage selects only migration-owned constant SQL identifiers. No caller-controlled
// table, column or SQL text crosses this boundary. Reads never acquire a mutation receipt.
func routedStorage(method int16) (table, columns string, file bool) {
	switch method {
	case 10, 11, 14, 15, 17, 18:
		return "fleet.routed_file_call", `request_digest, state, delivered, attempts, NULL::uuid, outcome_sha256, created_at, final_at IS NOT NULL`, true
	default:
		return "fleet.routed_call", routedColumns, false
	}
}

func scanRouted(row pgx.Row) (*routedRow, error) {
	var value routedRow
	err := row.Scan(&value.digest, &value.state, &value.delivered, &value.attempts, &value.taskID, &value.outcome, &value.created, &value.final)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &value, nil
}

// refuseResend is the refusal an existing record gives a resend, before anything else: another digest is CONFLICT/command_id_reused; a
// record that may have reached the node (delivered, or ACCEPTED with no attempt in flight in this process) whose replay window passed
// is STATE/invalid_state replay_window_passed, whether the node is online or not, and is never routed (decisions B-1).
func refuseResend(existing *routedRow, accept RoutedAccept, inFlight bool) error {
	if existing == nil {
		return nil
	}
	if !equal(existing.digest, accept.Digest) {
		return arc.CommandIDReused()
	}
	mayHaveReached := existing.delivered || existing.state == RoutedAccepted && !inFlight
	if mayHaveReached && !accept.Now.Before(existing.created.Add(accept.Window)) {
		// The catalogue's pair of invalid_state (decisions R4): DID_NOT_HAPPEN, NEVER. The effect describes this delivery, which is not
		// made; the reason says the window passed and the resource names the recorded task where it is known, so the caller reads it as
		// "may have run, see the task", never as a reason for a new command ID.
		refusal := arc.InvalidState("routed_call", "replay_window_passed")
		refusal.Retry = foundationv1.RetryMode_RETRY_MODE_NEVER
		if existing.taskID != nil && existing.state == RoutedSucceeded {
			refusal.Resource = &arc.Resource{Kind: "task", ID: append([]byte(nil), existing.taskID[:]...)}
		}
		return refusal
	}
	return nil
}

func equal(a, b []byte) bool { return len(a) == len(b) && string(a) == string(b) }

// leaseFence takes the hub lease row FOR SHARE when its fence is the live one: a take-over (Lease.Acquire updates the row) waits until
// the admission commits, so its boot sweep sees the record; a fence that is not live refuses the admission.
const leaseFence = `SELECT EXISTS (SELECT 1 FROM fleet.hub_lease WHERE singleton AND fence = $1 AND expires_at > clock_timestamp() FOR SHARE)`

// AcceptRouted admits one attempt of a routed mutation in one transaction (Tx1), in this order: an existing record's digest and
// replay window (no lock; refuseResend); the node's presence (Online: STATE/node_offline, nothing written); the account session's
// step-up evidence (identity.user and the challenge FOR UPDATE); the account's live node FOR SHARE (STATE/not_found); the record,
// inserted ACCEPTED or locked FOR UPDATE and decided again under the lock (a record with an attempt in flight here is joined;
// any other is routed again with its attempt count raised, ACCEPTED unless it is final, and delivered when it was ACCEPTED); the hub
// fleet.routed.accepted; the hub lease FOR SHARE with the fence (STATE/node_offline when it is not live), last. Lock order:
// identity.user, the challenge, fleet.node, fleet.routed_call, the audit chain head, fleet.hub_lease. A refusal rolls everything back, the evidence
// included.
func AcceptRouted(ctx context.Context, db *store.DB, accept RoutedAccept) (RoutedDecision, error) {
	table, columns, file := routedStorage(accept.Method)
	var decision RoutedDecision
	err := db.InTx(ctx, "admit a routed call", store.TxOptions{Timeout: registryTimeout}, func(ctx context.Context, tx pgx.Tx) error {
		decision = RoutedDecision{}
		// Cross-kind reuse is decided before presence or step-up. The trigger below
		// still arbitrates a concurrent insert that was absent at this read.
		var reserved int16
		reservationErr := tx.QueryRow(ctx, "SELECT receipt_kind FROM fleet.routed_command_id WHERE account_id=$1 AND command_id=$2",
			accept.AccountID, accept.CommandID).Scan(&reserved)
		if reservationErr != nil && !errors.Is(reservationErr, pgx.ErrNoRows) {
			return reservationErr
		}
		expectedKind := int16(1)
		if file {
			expectedKind = 2
		}
		if reservationErr == nil && reserved != expectedKind {
			return arc.CommandIDReused()
		}
		existing, err := scanRouted(tx.QueryRow(ctx, `SELECT `+columns+` FROM `+table+` WHERE account_id = $1 AND command_id = $2`,
			accept.AccountID, accept.CommandID))
		if err != nil {
			return err
		}
		accept.Now = accept.now()
		if err := refuseResend(existing, accept, accept.InFlight()); err != nil {
			return err
		}
		if !accept.Online() {
			return unreachableFor(existing, accept.NodeID, accept.Now)
		}
		if accept.Evidence != nil {
			if err := identity.ConsumeEvidence(ctx, tx, *accept.Evidence, accept.Class, accept.NodeID, accept.Now); err != nil {
				return err
			}
		}
		var enrollment platform.ID
		err = tx.QueryRow(ctx, `SELECT enrollment_id FROM fleet.node WHERE node_id = $1 AND user_id = $2 AND revoked_at IS NULL FOR SHARE`,
			accept.NodeID, accept.AccountID).Scan(&enrollment)
		if errors.Is(err, pgx.ErrNoRows) {
			if existing.mayHaveReached() {
				// The node was revoked after the command may have reached it (decisions R2): node_unreachable, UNKNOWN.
				return arc.NodeUnreachable(accept.NodeID[:], arc.UnreachableChannelClosed, true)
			}
			return arc.NotFound("node", accept.NodeID[:])
		}
		if err != nil {
			return err
		}
		caller := accept.Caller
		var session, relaying, localSession *platform.ID
		var origin *int16
		if caller.Kind == RoutedCallerSession {
			session = &caller.SessionID
		} else {
			relaying, localSession, origin = &caller.RelayingNodeID, &caller.LocalSessionID, &caller.LocalOrigin
		}
		query := `INSERT INTO ` + table + ` (account_id, command_id, node_enrollment_id, node_id, method, caller_kind, session_id,
    relaying_node_id, local_origin, local_session_id, request_digest, request_size, state, delivered, attempts, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 1, false, 1, $13, $13) ON CONFLICT (account_id, command_id) DO NOTHING`
		args := []any{accept.AccountID, accept.CommandID, enrollment, accept.NodeID, accept.Method, caller.Kind, session, relaying, origin, localSession,
			accept.Digest, accept.Size, accept.Now}
		if file {
			query = `INSERT INTO fleet.routed_file_call (account_id, command_id, node_enrollment_id, node_id, method, caller_kind, session_id,
    relaying_node_id, local_origin, local_session_id, request_digest, request_size, state, delivered, attempts, created_at, updated_at, workspace_id, target_attempt_id, request_sha256)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 1, false, 1, $13, $13, $14, $15, $16) ON CONFLICT (account_id, command_id) DO NOTHING`
			args = append(args, accept.WorkspaceID, accept.TargetAttemptID, accept.RequestSHA256)
		}
		tag, err := tx.Exec(ctx, query, args...)
		if err != nil {
			// Preserve the bridge's exact cross-namespace conflict mapping. Other
			// errors retain the existing sanitized rollback semantics.
			if routedNamespaceConflict(err) {
				return arc.CommandIDReused()
			}
			return store.Sanitize("reserve a routed command", err)
		}
		var prior *routedRow
		if tag.RowsAffected() == 1 {
			decision = RoutedDecision{Attempt: 1, State: RoutedAccepted}
			if file {
				// Read the stored value: PostgreSQL timestamps have microsecond precision.
				if err := tx.QueryRow(ctx, `SELECT created_at FROM fleet.routed_file_call WHERE account_id=$1 AND command_id=$2`, accept.AccountID, accept.CommandID).Scan(&decision.CreatedAt); err != nil {
					return err
				}
			}
		} else {
			locked, err := scanRouted(tx.QueryRow(ctx, `SELECT `+columns+` FROM `+table+` WHERE account_id = $1 AND command_id = $2 FOR UPDATE`,
				accept.AccountID, accept.CommandID))
			if err != nil {
				return err
			}
			prior = locked
			inFlight := accept.InFlight()
			accept.Now = accept.now()
			if err := refuseResend(locked, accept, inFlight); err != nil {
				return err
			}
			if inFlight {
				// An attempt of this record is in flight in this process (a first one, or a final record's resend): the duplicate
				// joins it and is not routed again.
				decision = RoutedDecision{Join: true, Attempt: locked.attempts, Final: locked.final, State: locked.state, Delivered: locked.delivered,
					OutcomeSHA256: locked.outcome}
			} else {
				state := RoutedAccepted
				if locked.final {
					state = locked.state
				}
				delivered := locked.delivered || locked.state == RoutedAccepted
				if _, err := tx.Exec(ctx, `UPDATE `+table+` SET attempts = attempts + 1, state = $3, delivered = $4, updated_at = greatest(updated_at, $5)
WHERE account_id = $1 AND command_id = $2`, accept.AccountID, accept.CommandID, state, delivered, accept.Now); err != nil {
					return err
				}
				decision = RoutedDecision{Attempt: locked.attempts + 1, Final: locked.final, State: state, Delivered: delivered, OutcomeSHA256: locked.outcome}
				if file {
					decision.CreatedAt = locked.created
				}
				if delivered {
					decision.ReplayUntil = locked.created.Add(accept.Window)
				}
			}
		}
		if file && !decision.Join && (accept.Method == int16(relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE) ||
			accept.Method == int16(relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE) || accept.Method == int16(relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL)) {
			target := FileTarget{WorkspaceID: accept.WorkspaceID, AttemptID: accept.TargetAttemptID, Path: accept.TargetPath}
			if validTarget(target) {
				if err := SaveFileTarget(ctx, tx, FileTargetBinding{AccountID: accept.AccountID, NodeID: accept.NodeID, EnrollmentID: enrollment,
					LookupID: accept.CommandID, Caller: caller, Kind: FileTargetOperation, Target: target, Now: accept.Now}); err != nil {
					return err
				}
			}
		}
		payload := caller.audit(map[string]any{"method": accept.Method, "nodeId": accept.NodeID.String(), "attempt": decision.Attempt,
			"requestSha256": hex.EncodeToString(accept.RequestSHA256), "requestSize": accept.Size, "joined": decision.Join})
		if file {
			addFileTarget(payload, accept.WorkspaceID, accept.TargetAttemptID, accept.TargetPath)
		}
		if err := auditRouted(ctx, tx, accept.Request, caller.Actor, "fleet.routed.accepted", map[bool]string{true: "joined", false: "accepted"}[decision.Join],
			accept.CommandID, payload, accept.Now); err != nil {
			return err
		}
		// The fence comes last, after the audit append, so a renewal of the lease (an UPDATE of its row) waits for no audit lock, only
		// for this commit (review B N-10).
		live := false
		if err := tx.QueryRow(ctx, leaseFence, accept.Fence).Scan(&live); err != nil {
			return err
		}
		if !live {
			return unreachableFor(prior, accept.NodeID, accept.Now)
		}
		return nil
	})
	if err != nil {
		var refusal *arc.Refusal
		if errors.As(err, &refusal) {
			return RoutedDecision{}, err
		}
		return RoutedDecision{}, store.Sanitize("admit a routed call", err)
	}
	return decision, nil
}

// routedNamespaceConflict recognizes only the future migration's named
// unique-violation constraint; it does not change unrelated constraint errors.
func routedNamespaceConflict(err error) bool {
	var failure *store.Error
	return errors.As(store.Sanitize("reserve a routed command", err), &failure) &&
		failure.SQLState == "23505" && failure.Constraint == "routed_command_id_namespace"
}

// auditRouted appends a routed call's audit event in the caller's transaction: closed codes, digests, sizes and IDs only (PN-6).
func auditRouted(ctx context.Context, tx pgx.Tx, request Request, actor, eventType, reason string, commandID platform.ID, payload map[string]any,
	now time.Time) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: now, ActorRef: actor, EventType: eventType, Reason: reason,
		CorrelationID: request.CorrelationID, CommandID: &commandID, TargetKind: "routed_call", TargetID: commandID.String(), Payload: data})
	return err
}

// AuditRoutedOffline appends one fleet.routed.refused row for a routed mutation refused STATE/node_offline (decisions Q-8: reason
// node_offline, digests and sizes only), in a transaction of its own; the account's routed_calls_per_account bucket already counted the
// call, so the rows are bounded by that quota.
func AuditRoutedOffline(ctx context.Context, db *store.DB, accept RoutedAccept) error {
	return db.InTx(ctx, "audit a routed call to an offline node", store.TxOptions{Timeout: registryTimeout, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		payload := accept.Caller.audit(map[string]any{"method": accept.Method, "nodeId": accept.NodeID.String(), "requestSha256": hex.EncodeToString(accept.RequestSHA256), "requestSize": accept.Size})
		if _, _, file := routedStorage(accept.Method); file {
			addFileTarget(payload, accept.WorkspaceID, accept.TargetAttemptID, accept.TargetPath)
		}
		return auditRouted(ctx, tx, accept.Request, accept.Caller.Actor, "fleet.routed.refused", "node_offline", accept.CommandID, payload, accept.Now)
	})
}

// RoutedAnswer is how one attempt ended, as the hub answered it.
type RoutedAnswer struct {
	// Verified is a verified result; Outcome is its RoutedOutcome (1 EXECUTED, 2 REFUSED_BY_POLICY, 3 REFUSED_VERIFICATION, 4 EXPIRED).
	Verified bool
	Outcome  int32
	// Effect is the effect certainty of the refusal: the hub's (no verified result), the node's signed refusal, or the TaskService
	// handler's own error inside an EXECUTED response.
	Effect foundationv1.EffectCertainty
	// HandlerError is an EXECUTED response whose outcome is the handler's ArcError; Refusal the refusal's CATEGORY/code.
	HandlerError  bool
	Refusal       string
	RefusalReason string // closed non-sensitive reason, when meaningful for a file refusal
	// TaskID is a SubmitNodeTask value's task ID.
	TaskID             *platform.ID
	PlanID             *platform.ID // only a validated, node-signed successful plan
	ResponseSHA256     []byte
	OutcomeSHA256      []byte
	ResponseSize       int
	ExecutedAt         time.Time
	NodeAuditAvailable bool
	Observations       []RoutedObservation
}

// ComparableReplay reports whether this verified answer can represent a replay of a recorded final outcome. An EXECUTED handler
// error whose effect is not HAPPENED may have been decided before the node's deduplication, so its digest is not comparable.
func (answer RoutedAnswer) ComparableReplay() bool {
	return answer.Verified && answer.Outcome == 1 && (!answer.HandlerError || answer.Effect == foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED)
}

// RoutedSettle is the settlement (Tx2) of one attempt.
type RoutedSettle struct {
	Request         Request
	AccountID       platform.ID
	CommandID       platform.ID
	Method          int16
	NodeID          platform.ID
	Attempt         int
	Actor           string
	Caller          RoutedCaller
	Answer          RoutedAnswer
	WorkspaceID     *platform.ID
	TargetAttemptID *platform.ID
	TargetPath      *string
	Now             time.Time
}

// RoutedSettled is what a settlement found: ReplayDiffers when a final record's resend was answered with a comparable executed
// outcome whose digest is not the record's (Q-5).
type RoutedSettled struct {
	State         RoutedState
	ReplayDiffers bool
}

// settled is the state an answer gives a non-final record, its delivered flag and whether it is final (decisions B-1, section 4).
func settled(answer RoutedAnswer, delivered bool) (RoutedState, bool, bool) {
	unknown := answer.Effect == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN
	didNotHappen := answer.Effect == foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN ||
		answer.Effect == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNSPECIFIED
	switch {
	case !answer.Verified && unknown:
		return RoutedUnknown, true, false
	case !answer.Verified && delivered:
		// The hub's DID_NOT_HAPPEN is this attempt's, but an earlier attempt may have reached the node.
		return RoutedUnknown, true, false
	case !answer.Verified:
		return RoutedNotDelivered, false, false
	case answer.Outcome == 1 && !answer.HandlerError:
		return RoutedSucceeded, true, true
	case unknown:
		// The node answered without knowing the effect (a duplicate while the first is still executing; N2 states it so): never final.
		return RoutedUnknown, true, false
	case answer.Outcome != 1 && delivered && didNotHappen:
		// A node's refusal of this attempt that did not happen, while an earlier attempt may have reached the node: the record stays
		// UNKNOWN (with the node's refusal code), never less conservative than before (decisions R1).
		return RoutedUnknown, true, false
	case answer.Outcome == 1 && delivered && didNotHappen:
		// The handler's DID_NOT_HAPPEN error of a resend, while an earlier attempt may have run: UNKNOWN.
		return RoutedUnknown, true, false
	case answer.Outcome == 1:
		// The handler's own error is final only when it says HAPPENED (N2b decisions B-1): the node does not record a transient or
		// pre-deduplication error (node_stopping, overloaded, validation), so a resend may still execute.
		return RoutedFailed, true, !didNotHappen
	case answer.Outcome == 4:
		return RoutedExpired, true, !didNotHappen
	}
	return RoutedRejected, true, !didNotHappen
}

// SettleRouted writes one attempt's answer (Tx2), guarded by the attempt number: a record that a later attempt took over, or that is
// final, keeps its state (a final record's resend compares a comparable executed outcome's digest with the record's; a different
// comparable outcome is replay_digest_differs). fleet.routed.result is appended in the same transaction, and fleet.routed.replay_differs
// for a differing comparable replay. The caller runs it on a context detached from the request, and retries it; a settlement that is never written leaves the
// record ACCEPTED, which counts as one that may have reached the node.
func SettleRouted(ctx context.Context, db *store.DB, settle RoutedSettle) (RoutedSettled, error) {
	table, columns, file := routedStorage(settle.Method)
	var result RoutedSettled
	err := db.InTx(ctx, "settle a routed call", store.TxOptions{Timeout: registryTimeout}, func(ctx context.Context, tx pgx.Tx) error {
		result = RoutedSettled{}
		locked, err := scanRouted(tx.QueryRow(ctx, `SELECT `+columns+` FROM `+table+` WHERE account_id = $1 AND command_id = $2 FOR UPDATE`,
			settle.AccountID, settle.CommandID))
		if err != nil {
			return err
		}
		if locked == nil {
			return errors.New("a settled routing record is missing")
		}
		answer := settle.Answer
		reason := "attempt"
		result.State = locked.state
		switch {
		case locked.final:
			reason = "replay"
			result.ReplayDiffers = answer.ComparableReplay() && !equal(answer.OutcomeSHA256, locked.outcome)
		case locked.attempts != settle.Attempt:
			reason = "superseded"
		default:
			state, delivered, final := settled(answer, locked.delivered)
			var refusal *int16
			if answer.Refusal != "" && state != RoutedSucceeded && answer.Verified {
				value := RefusalCode(answer.Refusal)
				refusal = &value
			}
			var response, outcome []byte
			var size *int
			var executed *time.Time
			if answer.Verified && answer.Outcome == 1 {
				response, outcome, size, executed = answer.ResponseSHA256, answer.OutcomeSHA256, &answer.ResponseSize, &answer.ExecutedAt
			}
			var finalAt *time.Time
			if final {
				finalAt = &settle.Now
			}
			var taskID *platform.ID
			if state == RoutedSucceeded {
				taskID = answer.TaskID
			}
			query := `UPDATE fleet.routed_call SET state = $3, delivered = delivered OR $4, task_id = $5, response_sha256 = $6, outcome_sha256 = $7,
    response_size = $8, executed_at = $9, refusal = $10, final_at = $11, updated_at = greatest(updated_at, $12)
WHERE account_id = $1 AND command_id = $2`
			args := []any{settle.AccountID, settle.CommandID, state, delivered, taskID, response, outcome, size, executed, refusal, finalAt, settle.Now}
			if file {
				query = `UPDATE fleet.routed_file_call SET state = $3, delivered = delivered OR $4, response_sha256 = $5, outcome_sha256 = $6,
    response_size = $7, executed_at = $8, refusal = $9, final_at = $10, updated_at = greatest(updated_at, $11)
WHERE account_id = $1 AND command_id = $2`
				args = []any{settle.AccountID, settle.CommandID, state, delivered, response, outcome, size, executed, refusal, finalAt, settle.Now}
			}
			if _, err := tx.Exec(ctx, query, args...); err != nil {
				return err
			}
			result.State = state
		}
		if file && settle.Method == int16(relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL) && answer.Verified &&
			answer.Outcome == int32(relayv1.RoutedOutcome_ROUTED_OUTCOME_EXECUTED) && !answer.HandlerError && answer.PlanID != nil && result.State == RoutedSucceeded {
			var enrollment platform.ID
			if err := tx.QueryRow(ctx, `SELECT node_enrollment_id FROM fleet.routed_file_call WHERE account_id=$1 AND command_id=$2`, settle.AccountID, settle.CommandID).Scan(&enrollment); err != nil {
				return err
			}
			target := FileTarget{WorkspaceID: settle.WorkspaceID, AttemptID: settle.TargetAttemptID, Path: settle.TargetPath}
			if err := SaveFileTarget(ctx, tx, FileTargetBinding{AccountID: settle.AccountID, NodeID: settle.NodeID, EnrollmentID: enrollment,
				LookupID: *answer.PlanID, Caller: settle.Caller, Kind: FileTargetPlan, Target: target, Now: settle.Now}); err != nil {
				return err
			}
		}
		payload := map[string]any{"method": settle.Method, "nodeId": settle.NodeID.String(), "attempt": settle.Attempt, "state": result.State.String(),
			"verified": answer.Verified, "outcome": answer.Outcome, "effect": answer.Effect.String()}
		if file {
			addFileTarget(payload, settle.WorkspaceID, settle.TargetAttemptID, settle.TargetPath)
			payload["nodeAuditAvailable"] = answer.NodeAuditAvailable
			payload["observations"] = answer.Observations
		}
		if answer.Refusal != "" {
			payload["refusal"] = RefusalCode(answer.Refusal)
		}
		if file && answer.RefusalReason != "" {
			payload["refusalReason"] = answer.RefusalReason
		}
		if answer.ResponseSHA256 != nil {
			payload["responseSha256"], payload["outcomeSha256"], payload["responseSize"] = hex.EncodeToString(answer.ResponseSHA256),
				hex.EncodeToString(answer.OutcomeSHA256), answer.ResponseSize
		}
		if err := auditRouted(ctx, tx, settle.Request, settle.Actor, "fleet.routed.result", reason, settle.CommandID, payload, settle.Now); err != nil {
			return err
		}
		if result.ReplayDiffers {
			return auditRouted(ctx, tx, settle.Request, settle.Actor, "fleet.routed.replay_differs", "replay_digest_differs", settle.CommandID,
				map[string]any{"method": settle.Method, "nodeId": settle.NodeID.String(), "attempt": settle.Attempt,
					"recordedSha256": hex.EncodeToString(locked.outcome), "replayedSha256": hex.EncodeToString(answer.OutcomeSHA256)}, settle.Now)
		}
		return nil
	})
	if err != nil {
		return RoutedSettled{}, store.Sanitize("settle a routed call", err)
	}
	return result, nil
}

// SweepRouted is the hub's boot sweep (C.7; decisions B-1): at each acquisition of the hub lease, before the hub routes anything, every
// ACCEPTED record becomes UNKNOWN and delivered, because no attempt of the new epoch is in flight and an attempt of an earlier one may
// have reached the node. It is fenced: it writes nothing unless the fence is the live one. It reports the records it swept.
func SweepRouted(ctx context.Context, db *store.DB, fence int64, now time.Time) (int64, error) {
	var swept int64
	err := db.InTx(ctx, "sweep the routing records of a previous hub", store.TxOptions{Timeout: registryTimeout}, func(ctx context.Context, tx pgx.Tx) error {
		live := false
		if err := tx.QueryRow(ctx, leaseFence, fence).Scan(&live); err != nil {
			return err
		}
		if !live {
			return ErrSweepFenced
		}
		swept = 0 // reset on a transaction retry
		for _, table := range []string{"fleet.routed_call", "fleet.routed_file_call"} {
			tag, err := tx.Exec(ctx, `UPDATE `+table+` SET state = 7, delivered = true, updated_at = greatest(updated_at, $1) WHERE state = 1`, now)
			if err != nil {
				return err
			}
			swept += tag.RowsAffected()
		}
		return nil
	})
	if errors.Is(err, ErrSweepFenced) {
		return 0, err
	}
	if err != nil {
		return 0, store.Sanitize("sweep the routing records of a previous hub", err)
	}
	return swept, nil
}

// ErrSweepFenced is a sweep whose fence is no longer the live one.
var ErrSweepFenced = errors.New("the hub lease no longer holds the fence of this sweep")

// RoutedRecord is a routing record as tests and the inspection read it.
type RoutedRecord struct {
	NodeID    platform.ID
	State     RoutedState
	Delivered bool
	Attempts  int
	TaskID    *platform.ID
	Final     bool
	Refusal   *int16
}

// MayHaveReached reports whether a record's command may have reached the node (delivered, or ACCEPTED).
func (r *RoutedRecord) MayHaveReached() bool {
	return r != nil && (r.Delivered || r.State == RoutedAccepted)
}

// ReadRouted reads one routing record (nil when there is none).
func ReadRouted(ctx context.Context, db *store.DB, accountID, commandID platform.ID) (*RoutedRecord, error) {
	return ReadRoutedForMethod(ctx, db, accountID, commandID, 1)
}

// ReadRoutedForMethod reads only the authenticated account's receipt kind for this method.
func ReadRoutedForMethod(ctx context.Context, db *store.DB, accountID, commandID platform.ID, method int16) (*RoutedRecord, error) {
	table, _, file := routedStorage(method)
	taskColumn := "task_id"
	if file {
		taskColumn = "NULL::uuid"
	}
	var value *RoutedRecord
	err := db.InTx(ctx, "read a routing record", store.TxOptions{ReadOnly: true, Timeout: registryTimeout}, func(ctx context.Context, tx pgx.Tx) error {
		var record RoutedRecord
		err := tx.QueryRow(ctx, `SELECT node_id, state, delivered, attempts, `+taskColumn+`, final_at IS NOT NULL, refusal FROM `+table+` WHERE account_id = $1 AND
    command_id = $2`, accountID, commandID).Scan(&record.NodeID, &record.State, &record.Delivered, &record.Attempts, &record.TaskID, &record.Final,
			&record.Refusal)
		if errors.Is(err, pgx.ErrNoRows) {
			value = nil
			return nil
		}
		value = &record
		return err
	})
	return value, err
}
