// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/maphash"
	"strings"
	"sync"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

// The routed task methods of FleetService (AF-CTR-05 part E2b; Plan CTR5-RTE-01..07, CTR5-CALL-01..03 as amended by PB-1, PB-2, D0-B1,
// C-N1, C-N6, PN-1, PN-6; decisions B-1..B-3, Q-1..Q-15 and section 4): SubmitNodeTask, GetNodeTask, ListNodeTasks, WaitNodeTask,
// ReadNodeTaskOutput and CancelNodeTask, for an account session and for a node credential as the verified relay of its own node.
//
// The request field carries the exact node.v1 TaskService request bytes. The center decodes a copy only to check its shape (Submit: a
// TaskSpec; Get, Wait and Cancel: the task ID; ReadOutput: the attempt ID; Submit and Cancel: the inner meta.command_id equal to the
// outer one; Wait: wait_ms at most 50,000; ReadOutput: max_bytes at most 262,144 and wait_ms at most 20,000), stores none of it, and
// routes the bytes unchanged (hub.Call). The authorizer decides first (the relay assertion, whose request digest is SHA-256 of the inner
// bytes, ownership of the node, the person's rules, the routed controls, access.authorized, the gate), so the call header's caller is
// the verified session's or the verified relay's, never the request's caller field.
//
// A read is routed with no record. A mutation has a routing record (fleet.routed_call), its receipt: the admission (fleet.AcceptRouted)
// checks a resend's digest and replay window before the node's presence, consumes the account session's step-up evidence, and is
// fenced by the hub lease; the attempt then runs with no transaction open, on a context detached from the request, and its answer is
// settled (fleet.SettleRouted) with retries, also detached. A duplicate of an attempt in flight in this process joins it (Q-15): it
// waits for the same answer within its own deadline, and a caller that goes away ends only its own wait, never the call. The center
// stores no response, so it never answers a resend from its record: a resend is routed again with its own bytes, and the node's command
// deduplication replays the recorded outcome (decisions B-3, N-3).

// RoutedCall is one routed call as the hub takes it (hub.Call): Relay is the relay AuthorizeRelayed verified (hub.VerifiedRelay), nil
// for an account session's call.
type RoutedCall struct {
	AccountID    platform.ID
	TargetNodeID platform.ID
	UserID       platform.ID
	SessionID    platform.ID
	Relay        access.Relay
	CommandID    *platform.ID
	Method       relayv1.RoutedMethod
	Payload      []byte
	Deadline     time.Duration
}

// RoutedResult is a routed call's verified result (hub.Result).
type RoutedResult struct {
	Outcome        relayv1.RoutedOutcome
	Response       []byte
	ResponseSHA256 []byte
	ExecutedAt     time.Time
	Refusal        *arc.Refusal
}

// Router is the hub as the routed API asks it: whether it routes now and under which fence (hub.Hub.Routable), whether a node's
// channel is open here (hub.Hub.Connected), and the routing seam (hub.Hub.Call), whose error is always an *arc.Refusal. The composition
// adapts the hub to it, so this package does not import the hub.
type Router interface {
	Routable() (int64, bool)
	Connected(nodeID platform.ID) bool
	Route(ctx context.Context, call RoutedCall) (RoutedResult, error)
}

// RoutedLimits are the routed API's policy values: the replay window of a mutation (routedReplayWindow) and the routed long polls that
// may wait at once in this process (config.RoutedLongPolls, PN-1).
type RoutedLimits struct {
	ReplayWindow time.Duration
	LongPolls    int
	// Events counts the routed API's events (observe.Metrics; the event family routed).
	Events interface{ ObserveChannel(event, outcome string) }
}

// relayed is a verified relay with the fields the routed API keeps (hub.VerifiedRelay's read-only accessors).
type relayed interface {
	access.Relay
	RelayingNodeID() platform.ID
	LocalOrigin() nodev1.Origin
	LocalSessionID() platform.ID
}

// routedKey is a routed mutation: the account and the command.
type routedKey struct {
	account, command platform.ID
}

// attempt is an attempt of a routed mutation in flight in this process; done is closed once its answer is set.
type attempt struct {
	done     chan struct{}
	response []byte
	err      error
}

// routing is the routed API's in-process state: the slots that serialize the admissions of one command, the attempts in flight, and the
// long-poll bound.
type routing struct {
	router    Router
	limits    RoutedLimits
	seed      maphash.Seed
	slots     [64]sync.Mutex
	mu        sync.Mutex
	attempts  map[routedKey]*attempt
	longPolls chan struct{}
	// settleTries and settleBackoff bound a settlement's retries.
	settleTries   int
	settleBackoff time.Duration
}

// WithRouter gives the registry the hub to route through (the nodes surface's routed methods).
func (r *Registry) WithRouter(router Router, limits RoutedLimits) *Registry {
	// The replay window never passes its bound (config.MaxRoutedReplayWindow), whatever the composition passes.
	limits.ReplayWindow = min(limits.ReplayWindow, config.MaxRoutedReplayWindow)
	r.routing = &routing{router: router, limits: limits, seed: maphash.MakeSeed(), attempts: map[routedKey]*attempt{},
		longPolls: make(chan struct{}, max(limits.LongPolls, 1)), settleTries: 3, settleBackoff: 100 * time.Millisecond}
	return r
}

// slot is the admission lock of one command (striped by a seeded hash of the key).
func (g *routing) slot(key routedKey) *sync.Mutex {
	var raw [32]byte
	copy(raw[:16], key.account[:])
	copy(raw[16:], key.command[:])
	return &g.slots[maphash.Bytes(g.seed, raw[:])%uint64(len(g.slots))]
}

func (g *routing) inFlight(key routedKey) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.attempts[key] != nil
}

// The routed bounds of the inner requests (fleet.proto).
const (
	maxInnerRead     = 3_072
	maxWaitMs        = 50_000
	maxReadOutputMs  = 20_000
	maxReadBytes     = 262_144
	reserveForAnswer = time.Second
)

// routedRequest is what the six routed requests share.
type routedRequest interface {
	proto.Message
	GetMeta() *foundationv1.RequestMeta
	GetNodeId() *foundationv1.Id
	GetCaller() *fleetv1.RoutedCaller
	GetRequest() []byte
	GetRelayAssertion() []byte
}

// inner is a routed request's checked inner request: its method, its deadline and whether it is a long poll.
type inner struct {
	method   relayv1.RoutedMethod
	deadline time.Duration
	longPoll bool
}

// checkInner decodes a copy of the inner request and checks its shape and the routed bounds; it also derives the method's deadline
// (CTR5-RTE-06): 10 s; Wait wait_ms + 5 s; ReadOutput wait_ms + 10 s with wait_ms. Every refusal is VALIDATION/invalid_argument.
func checkInner(method relayv1.RoutedMethod, payload []byte, outer *platform.ID) (inner, error) {
	result := inner{method: method, deadline: routes.RoutedDeadline}
	limit := maxInnerRead
	if method == relayv1.RoutedMethod_ROUTED_METHOD_SUBMIT_NODE_TASK {
		limit = hubMaxCallPayload
	}
	if len(payload) < 1 || len(payload) > limit {
		return inner{}, arc.InvalidArgument("request", "length")
	}
	bad := func(field, rule string) (inner, error) {
		path := "request"
		if field != "" {
			path += "." + field
		}
		return inner{}, arc.InvalidArgument(path, rule)
	}
	var meta *foundationv1.RequestMeta
	switch method {
	case relayv1.RoutedMethod_ROUTED_METHOD_SUBMIT_NODE_TASK:
		var value nodev1.TaskServiceSubmitTaskRequest
		if proto.Unmarshal(payload, &value) != nil {
			return bad("", "malformed")
		}
		if value.GetSpec() == nil {
			return bad("spec", "required")
		}
		meta = value.GetMeta()
	case relayv1.RoutedMethod_ROUTED_METHOD_CANCEL_NODE_TASK:
		var value nodev1.TaskServiceCancelTaskRequest
		if proto.Unmarshal(payload, &value) != nil {
			return bad("", "malformed")
		}
		if _, ok := parseID(value.GetTaskId()); !ok {
			return bad("task_id", "required")
		}
		meta = value.GetMeta()
	case relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_TASK:
		var value nodev1.TaskServiceGetTaskRequest
		if proto.Unmarshal(payload, &value) != nil {
			return bad("", "malformed")
		}
		if _, ok := parseID(value.GetTaskId()); !ok {
			return bad("task_id", "required")
		}
	case relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_TASKS:
		var value nodev1.TaskServiceListTasksRequest
		if proto.Unmarshal(payload, &value) != nil {
			return bad("", "malformed")
		}
	case relayv1.RoutedMethod_ROUTED_METHOD_WAIT_NODE_TASK:
		var value nodev1.TaskServiceWaitTaskRequest
		if proto.Unmarshal(payload, &value) != nil {
			return bad("", "malformed")
		}
		if _, ok := parseID(value.GetTaskId()); !ok {
			return bad("task_id", "required")
		}
		if value.GetWaitMs() > maxWaitMs {
			return bad("wait_ms", "maximum")
		}
		result.deadline = time.Duration(value.GetWaitMs())*time.Millisecond + 5*time.Second
		result.longPoll = value.GetWaitMs() > 0
	case relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_TASK_OUTPUT:
		var value nodev1.TaskServiceReadTaskOutputRequest
		if proto.Unmarshal(payload, &value) != nil {
			return bad("", "malformed")
		}
		if _, ok := parseID(value.GetAttemptId()); !ok {
			return bad("attempt_id", "required")
		}
		if value.GetMaxBytes() > maxReadBytes {
			return bad("max_bytes", "maximum")
		}
		if value.GetWaitMs() > maxReadOutputMs {
			return bad("wait_ms", "maximum")
		}
		if value.GetWaitMs() > 0 {
			result.deadline = time.Duration(value.GetWaitMs())*time.Millisecond + 10*time.Second
			result.longPoll = true
		}
	}
	if outer != nil {
		// A mutation's inner meta.command_id is the outer one (the node deduplicates by it; the call header and the assertion name the
		// outer one).
		if id, ok := parseID(meta.GetCommandId()); !ok || id != *outer {
			return bad("meta.command_id", "mismatch")
		}
	}
	return result, nil
}

// hubMaxCallPayload is the routed call payload's bound (hub.MaxCallPayload; fleet.proto SubmitNodeTask request: 1..253,952 bytes).
const hubMaxCallPayload = 253_952

// hubDeadline is how long the hub waits for a call: the method's deadline less a second for the settlement and the reply (Q-7), so the
// reply never passes the method's deadline.
func hubDeadline(deadline time.Duration) time.Duration {
	return max(deadline-reserveForAnswer, time.Second)
}

// recordDigest is a routed mutation's record digest (Q-4; decisions B-3): SHA-256 over the method, the node, the caller class (an
// account session's user, or a relay's relaying node and local origin) and RequestDigestInput of the inner request bytes (its meta's
// correlation ID left out). The session and the local session are recorded, not digested, so a resend from a refreshed session or a new
// local process of the same origin converges.
func recordDigest(method relayv1.RoutedMethod, nodeID platform.ID, caller fleet.RoutedCaller, userID platform.ID, payload []byte) ([]byte, error) {
	digested, err := platform.RequestDigestInput(payload)
	if err != nil {
		return nil, arc.InvalidArgument("request", "malformed")
	}
	hash := sha256.New()
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(method))
	hash.Write([]byte("ArcForges routed-record v1\n"))
	hash.Write(header[:])
	hash.Write(nodeID[:])
	binary.BigEndian.PutUint16(header[:], uint16(caller.Kind))
	hash.Write(header[:])
	if caller.Kind == fleet.RoutedCallerSession {
		hash.Write(userID[:])
	} else {
		hash.Write(caller.RelayingNodeID[:])
		binary.BigEndian.PutUint16(header[:], uint16(caller.LocalOrigin))
		hash.Write(header[:])
	}
	hash.Write(digested)
	return hash.Sum(nil), nil
}

// OutcomeDigest is the digest a resend's replayed outcome is compared with (decisions Q-5; a binding requirement for N2): SHA-256 of
// the node.v1 response as transmitted, in wire order and byte for byte, with its ResponseMeta (field 1) left out and, inside every
// ArcError of the outcome (field 3), its correlation_id (field 6) and its retry advice's retry_at (field 4, field 2) left out. The node
// replays a recorded outcome byte for byte outside those fields. A malformed response is an error.
func OutcomeDigest(response []byte) ([]byte, error) {
	kept, err := rewrite(response, func(number protowire.Number, value []byte) ([]byte, bool, error) {
		switch number {
		case 1:
			return nil, false, nil
		case 3:
			cleaned, err := rewrite(value, func(number protowire.Number, value []byte) ([]byte, bool, error) {
				switch number {
				case 6:
					return nil, false, nil
				case 4:
					retry, err := rewrite(value, func(number protowire.Number, value []byte) ([]byte, bool, error) { return value, number != 2, nil })
					return retry, true, err
				}
				return value, true, nil
			})
			return cleaned, true, err
		}
		return value, true, nil
	})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(kept)
	return digest[:], nil
}

// rewrite is a message's top-level fields in wire order with each one kept, dropped or (a length-delimited field) replaced by edit;
// edit receives a length-delimited field's contents and any other field's whole value bytes.
func rewrite(message []byte, edit func(protowire.Number, []byte) ([]byte, bool, error)) ([]byte, error) {
	out := make([]byte, 0, len(message))
	for rest := message; len(rest) > 0; {
		number, kind, tagLength := protowire.ConsumeTag(rest)
		if tagLength < 0 {
			return nil, protowire.ParseError(tagLength)
		}
		valueLength := protowire.ConsumeFieldValue(number, kind, rest[tagLength:])
		if valueLength < 0 {
			return nil, protowire.ParseError(valueLength)
		}
		field := rest[:tagLength+valueLength]
		rest = rest[tagLength+valueLength:]
		if kind != protowire.BytesType {
			if _, keep, err := edit(number, field[tagLength:]); err != nil {
				return nil, err
			} else if keep {
				out = append(out, field...)
			}
			continue
		}
		contents, n := protowire.ConsumeBytes(field[tagLength:])
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		replaced, keep, err := edit(number, contents)
		if err != nil {
			return nil, err
		}
		if keep {
			out = protowire.AppendTag(out, number, protowire.BytesType)
			out = protowire.AppendBytes(out, replaced)
		}
	}
	return out, nil
}

// handlerOutcome reads an EXECUTED mutation's response: whether it is the TaskService handler's own ArcError (its CATEGORY/code key and
// effect), and a Submit value's task ID.
func handlerOutcome(method relayv1.RoutedMethod, response []byte) (failed bool, key string, effect foundationv1.EffectCertainty, taskID *platform.ID, err error) {
	var failure *foundationv1.ArcError
	switch method {
	case relayv1.RoutedMethod_ROUTED_METHOD_SUBMIT_NODE_TASK:
		var value nodev1.TaskServiceSubmitTaskResponse
		if err := proto.Unmarshal(response, &value); err != nil {
			return false, "", 0, nil, err
		}
		failure = value.GetError()
		if id, ok := parseID(value.GetValue().GetTaskId()); ok {
			taskID = &id
		}
	default:
		var value nodev1.TaskServiceCancelTaskResponse
		if err := proto.Unmarshal(response, &value); err != nil {
			return false, "", 0, nil, err
		}
		failure = value.GetError()
	}
	if failure == nil {
		return false, "", 0, taskID, nil
	}
	return true, refusalKey(failure.GetCategory(), failure.GetCode()), failure.GetEffect(), nil, nil
}

// refusalKey is a refusal's CATEGORY/code key in lower case, as the refusal code table names it.
func refusalKey(category foundationv1.ErrorCategory, code string) string {
	return strings.ToLower(strings.TrimPrefix(category.String(), "ERROR_CATEGORY_")) + "/" + code
}

// answerOf is an attempt's answer as its settlement takes it.
func answerOf(method relayv1.RoutedMethod, result RoutedResult, err error) fleet.RoutedAnswer {
	var refusal *arc.Refusal
	if err != nil {
		if !errors.As(err, &refusal) {
			refusal = arc.Unavailable()
		}
		return fleet.RoutedAnswer{Effect: refusal.Effect, Refusal: refusalKey(refusal.Category, refusal.Code)}
	}
	answer := fleet.RoutedAnswer{Verified: true, Outcome: int32(result.Outcome)}
	if result.Outcome != relayv1.RoutedOutcome_ROUTED_OUTCOME_EXECUTED {
		if result.Refusal != nil {
			answer.Effect, answer.Refusal = result.Refusal.Effect, refusalKey(result.Refusal.Category, result.Refusal.Code)
		}
		return answer
	}
	answer.ResponseSHA256, answer.ResponseSize, answer.ExecutedAt = result.ResponseSHA256, len(result.Response), result.ExecutedAt
	answer.OutcomeSHA256, _ = OutcomeDigest(result.Response)
	failed, key, effect, taskID, decodeErr := handlerOutcome(method, result.Response)
	if decodeErr != nil {
		// A response the node signed but that is no TaskService response: the effect is unknown.
		answer.HandlerError, answer.Effect, answer.Refusal = true, foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN, "other/other"
		return answer
	}
	if failed && effect == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNSPECIFIED {
		// A handler error without an effect counts as UNKNOWN, never as DID_NOT_HAPPEN (review B N-15).
		effect = foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN
	}
	answer.HandlerError, answer.Refusal, answer.Effect, answer.TaskID = failed, key, effect, taskID
	return answer
}

// routed serves one routed method: it checks the request, authorizes it (the relay assertion included) and routes it; a mutation goes
// through its routing record. It answers the node's response bytes, or the refusal.
func (r *Registry) routed(ctx context.Context, call *ingress.Call, message routedRequest, method relayv1.RoutedMethod) ([]byte, platform.ID, error) {
	if err := checkMeta(message.GetMeta()); err != nil {
		return nil, platform.ID{}, err
	}
	nodeID, err := requiredNode(message.GetNodeId())
	if err != nil {
		return nil, platform.ID{}, err
	}
	var commandID *platform.ID
	mutation := method == relayv1.RoutedMethod_ROUTED_METHOD_SUBMIT_NODE_TASK || method == relayv1.RoutedMethod_ROUTED_METHOD_CANCEL_NODE_TASK
	if mutation {
		id, ok := parseID(message.GetMeta().GetCommandId())
		if !ok {
			return nil, nodeID, arc.InvalidArgument("meta.command_id", "required")
		}
		commandID = &id
	}
	payload := message.GetRequest()
	checked, err := checkInner(method, payload, commandID)
	if err != nil {
		return nil, nodeID, err
	}
	var stated *access.RelayClaim
	if caller, assertion := message.GetCaller(), message.GetRelayAssertion(); caller != nil || assertion != nil {
		if caller != nil && caller.GetKind() != fleetv1.CallerKind_CALLER_KIND_NODE_RELAY {
			return nil, nodeID, arc.InvalidArgument("caller.kind", "not_admitted")
		}
		digest := sha256.Sum256(payload)
		relaying, _ := parseID(caller.GetRelayingNodeId())
		stated = &access.RelayClaim{Assertion: assertion, Method: method, RequestSHA256: digest[:], TargetNodeID: &nodeID, CommandID: commandID,
			CallerRelayingNodeID: relaying, CallerLocalOrigin: caller.GetLocalOrigin()}
	}
	operation, relay, err := r.access.AuthorizeRelayed(ctx, call, r.nodeSubject(call, nodeID, false), stated)
	if err != nil {
		if mutation {
			err = r.resendNotFound(ctx, call, nodeID, *commandID, err)
		}
		return nil, nodeID, err
	}
	if r.routing == nil {
		return nil, nodeID, arc.NodeOffline(nodeID[:], r.clock())
	}
	userID, ok := textID(call.Caller.UserID)
	if !ok {
		return nil, nodeID, arc.Unauthenticated()
	}
	routedCall := RoutedCall{AccountID: userID, TargetNodeID: nodeID, Relay: relay, CommandID: commandID, Method: method, Payload: payload,
		Deadline: hubDeadline(checked.deadline)}
	if relay == nil {
		sessionID, ok := textID(call.Caller.SessionID)
		if !ok {
			return nil, nodeID, arc.Unauthenticated()
		}
		routedCall.UserID, routedCall.SessionID = userID, sessionID
	}
	if !mutation {
		response, err := r.routing.read(ctx, routedCall, checked)
		return response, nodeID, err
	}
	response, err := r.routeMutation(ctx, call, operation, routedCall, checked)
	return response, nodeID, err
}

// resendNotFound is the ownership stage's STATE/not_found for a Submit or Cancel (decisions R2): it consults the caller's own record of
// the command, by the authenticated account and the command ID, so it is no ownership oracle. When that record names this node and may
// have reached it (the node was revoked meanwhile), the reply is node_unreachable, UNKNOWN with SAME_COMMAND; otherwise not_found
// stands. Every other refusal is returned as it is.
func (r *Registry) resendNotFound(ctx context.Context, call *ingress.Call, nodeID, commandID platform.ID, err error) error {
	var refusal *arc.Refusal
	if !errors.As(err, &refusal) || refusal.Category != foundationv1.ErrorCategory_ERROR_CATEGORY_STATE || refusal.Code != "not_found" {
		return err
	}
	userID, ok := textID(call.Caller.UserID)
	if !ok {
		return err
	}
	record, readErr := fleet.ReadRouted(ctx, r.db, userID, commandID)
	if readErr != nil || record == nil || record.NodeID != nodeID || !record.MayHaveReached() {
		return err
	}
	return arc.NodeUnreachable(nodeID[:], arc.UnreachableChannelClosed, true)
}

// read routes a read: no record, no audit of its own (Q-10); a long poll holds one of the process's long-poll slots (PN-1).
func (g *routing) read(ctx context.Context, call RoutedCall, checked inner) ([]byte, error) {
	if checked.longPoll {
		select {
		case g.longPolls <- struct{}{}:
			defer func() { <-g.longPolls }()
		default:
			if g.limits.Events != nil {
				g.limits.Events.ObserveChannel("routed", "long_polls")
			}
			return nil, arc.Unavailable()
		}
	}
	result, err := g.router.Route(ctx, call)
	if err != nil {
		return nil, err
	}
	if result.Outcome != relayv1.RoutedOutcome_ROUTED_OUTCOME_EXECUTED {
		return nil, refusalOf(result)
	}
	return result.Response, nil
}

// refusalOf is a verified result's refusal (the hub sets one for every outcome but EXECUTED).
func refusalOf(result RoutedResult) error {
	if result.Refusal == nil {
		return arc.Internal()
	}
	return result.Refusal
}

// routeMutation admits, routes and settles one attempt of a Submit or Cancel, or joins the attempt in flight (section d, Q-15).
func (r *Registry) routeMutation(ctx context.Context, call *ingress.Call, operation access.Operation, routedCall RoutedCall, checked inner) ([]byte, error) {
	g := r.routing
	now := r.clock()
	key := routedKey{account: routedCall.AccountID, command: *routedCall.CommandID}
	caller := fleet.RoutedCaller{Kind: fleet.RoutedCallerSession, SessionID: routedCall.SessionID, Actor: identity.Actor(routedCall.AccountID)}
	var evidence *identity.Caller
	if verified, ok := routedCall.Relay.(relayed); routedCall.Relay != nil {
		if !ok {
			return nil, arc.Unauthenticated()
		}
		caller = fleet.RoutedCaller{Kind: fleet.RoutedCallerRelay, RelayingNodeID: verified.RelayingNodeID(), LocalOrigin: int16(verified.LocalOrigin()),
			LocalSessionID: verified.LocalSessionID(), Actor: "node:" + verified.RelayingInstallationID().String()}
	} else if operation.NeedsEvidence(false) {
		account, err := accountOf(call)
		if err != nil {
			return nil, err
		}
		evidence = &account.Caller
	}
	digest, err := recordDigest(routedCall.Method, routedCall.TargetNodeID, caller, routedCall.AccountID, routedCall.Payload)
	if err != nil {
		return nil, err
	}
	exact := sha256.Sum256(routedCall.Payload)
	fence, routable := g.router.Routable()
	accept := fleet.RoutedAccept{Request: request(call), AccountID: routedCall.AccountID, Evidence: evidence, Class: operation.ID, NodeID: routedCall.TargetNodeID,
		CommandID: key.command, Method: int16(routedCall.Method), Caller: caller, Digest: digest, RequestSHA256: exact[:], Size: len(routedCall.Payload),
		Fence: fence, Window: g.limits.ReplayWindow, InFlight: func() bool { return g.inFlight(key) },
		Online: func() bool { return routable && g.router.Connected(routedCall.TargetNodeID) }, Now: now}
	slot := g.slot(key)
	slot.Lock()
	decision, err := fleet.AcceptRouted(ctx, r.db, accept)
	if err != nil {
		slot.Unlock()
		if errors.Is(err, fleet.ErrRoutedOffline) {
			r.observe("offline")
			if auditErr := fleet.AuditRoutedOffline(ctx, r.db, accept); auditErr != nil {
				r.logger.WarnContext(ctx, "a routed call to an offline node could not be audited", "correlationId", call.Correlation.CorrelationID,
					"error", auditErr.Error())
			}
		}
		return nil, err
	}
	// The admission ran under the command's slot, and an attempt leaves the attempts in flight only under it too, so a joined attempt
	// is still here.
	g.mu.Lock()
	current := g.attempts[key]
	if !decision.Join {
		current = &attempt{done: make(chan struct{})}
		g.attempts[key] = current
	}
	g.mu.Unlock()
	slot.Unlock()
	if decision.Join {
		r.observe("joined")
	} else {
		r.observe("accepted")
		go r.attempt(key, current, routedCall, decision, request(call), caller.Actor)
	}
	// Each caller waits within its own deadline; one that goes away ends only its own wait.
	timer := time.NewTimer(checked.deadline - reserveForAnswer/2)
	defer timer.Stop()
	select {
	case <-current.done:
		return current.response, current.err
	case <-timer.C:
	case <-ctx.Done():
	}
	return nil, arc.NodeUnreachable(routedCall.TargetNodeID[:], arc.UnreachableDeadline, true)
}

// attempt routes one admitted attempt on a context detached from every request, settles its answer (retried, detached too), sets the
// answer for every waiter, and only then leaves the attempts in flight, so a later admission finds the settled record.
func (r *Registry) attempt(key routedKey, current *attempt, routedCall RoutedCall, decision fleet.RoutedDecision, req fleet.Request, actor string) {
	g := r.routing
	ctx, cancel := context.WithTimeout(context.Background(), routedCall.Deadline+reserveForAnswer)
	result, err := g.router.Route(ctx, routedCall)
	cancel()
	answer := answerOf(routedCall.Method, result, err)
	settle := fleet.RoutedSettle{Request: req, AccountID: key.account, CommandID: key.command, Method: int16(routedCall.Method), NodeID: routedCall.TargetNodeID,
		Attempt: decision.Attempt, Actor: actor, Answer: answer, Now: r.clock()}
	settledOK := false
	for try := 0; try < g.settleTries; try++ {
		if try > 0 {
			time.Sleep(g.settleBackoff << (try - 1))
		}
		settling, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, settleErr := fleet.SettleRouted(settling, r.db, settle)
		cancel()
		if settleErr == nil {
			settledOK = true
			break
		}
		r.logger.Warn("a routed call's answer could not be recorded; retrying", "attempt", try+1, "error", settleErr.Error())
	}
	if settledOK {
		r.observe("settled")
	} else {
		// The record stays as the admission left it (ACCEPTED, or a final record's state): conservative (decisions B-1).
		r.observe("settle_lost")
	}
	switch {
	case (decision.Delivered || decision.Final) && answer.Verified && answer.HandlerError &&
		answer.Effect != foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED:
		// The handler's error of a resend that did not say HAPPENED (a transient or pre-deduplication error, or an unknown effect; review B
		// B-6): node_unreachable, UNKNOWN with SAME_COMMAND (R1); the node's code is kept in the record and the audit row. So the reply
		// never depends on the order in which the node replays.
		current.err = arc.NodeUnreachable(routedCall.TargetNodeID[:], arc.UnreachableChannelClosed, true)
	case decision.Final && answer.Verified && answer.Outcome == int32(relayv1.RoutedOutcome_ROUTED_OUTCOME_EXECUTED) && !equalDigest(answer.OutcomeSHA256, decision.OutcomeSHA256):
		r.observe("replay_differs")
		current.err = arc.ReplayDigestDiffers(routedCall.TargetNodeID[:])
	case err != nil && (decision.Delivered || decision.Final) && answer.Effect != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN:
		// Every routing outcome of a resend (decisions R1) is node_unreachable, UNKNOWN with SAME_COMMAND, whatever this attempt's own
		// refusal said (offline, a full queue, a bound, its deadline before delivery).
		reason := arc.UnreachableChannelClosed
		if refusal, ok := err.(*arc.Refusal); ok && refusal.Code == "node_unreachable" {
			reason = refusal.Reason
		}
		current.err = arc.NodeUnreachable(routedCall.TargetNodeID[:], reason, true)
	case err != nil:
		current.err = err
	case (decision.Delivered || decision.Final) && result.Outcome != relayv1.RoutedOutcome_ROUTED_OUTCOME_EXECUTED:
		// A node-signed refusal of a resend (decisions R1): node_unreachable, UNKNOWN with SAME_COMMAND; the node's own code is kept in
		// the record and the audit row.
		current.err = arc.NodeUnreachable(routedCall.TargetNodeID[:], arc.UnreachableChannelClosed, true)
	case result.Outcome != relayv1.RoutedOutcome_ROUTED_OUTCOME_EXECUTED:
		current.err = refusalOf(result)
	default:
		current.response = result.Response
	}
	close(current.done)
	slot := g.slot(key)
	slot.Lock()
	g.mu.Lock()
	if g.attempts[key] == current {
		delete(g.attempts, key)
	}
	g.mu.Unlock()
	slot.Unlock()
}

func equalDigest(a, b []byte) bool { return len(a) == len(b) && string(a) == string(b) }

// observe counts a routed API event.
func (r *Registry) observe(outcome string) {
	if r.routing != nil && r.routing.limits.Events != nil {
		r.routing.limits.Events.ObserveChannel("routed", outcome)
	}
}

// The six routed methods' handlers: the node's response bytes and the node, or the method's error.

func (r *Registry) submitNodeTask(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceSubmitNodeTaskRequest) (*fleetv1.FleetServiceSubmitNodeTaskResponse, error) {
	value, nodeID, err := r.routed(ctx, call, message, relayv1.RoutedMethod_ROUTED_METHOD_SUBMIT_NODE_TASK)
	response := &fleetv1.FleetServiceSubmitNodeTaskResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceSubmitNodeTaskResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &fleetv1.FleetServiceSubmitNodeTaskResponse_Value{Value: &fleetv1.FleetServiceSubmitNodeTaskValue{Response: value, NodeId: id(nodeID)}}
	return response, nil
}

func (r *Registry) getNodeTask(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceGetNodeTaskRequest) (*fleetv1.FleetServiceGetNodeTaskResponse, error) {
	value, nodeID, err := r.routed(ctx, call, message, relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_TASK)
	response := &fleetv1.FleetServiceGetNodeTaskResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceGetNodeTaskResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &fleetv1.FleetServiceGetNodeTaskResponse_Value{Value: &fleetv1.FleetServiceGetNodeTaskValue{Response: value, NodeId: id(nodeID)}}
	return response, nil
}

func (r *Registry) listNodeTasks(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceListNodeTasksRequest) (*fleetv1.FleetServiceListNodeTasksResponse, error) {
	value, nodeID, err := r.routed(ctx, call, message, relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_TASKS)
	response := &fleetv1.FleetServiceListNodeTasksResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceListNodeTasksResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &fleetv1.FleetServiceListNodeTasksResponse_Value{Value: &fleetv1.FleetServiceListNodeTasksValue{Response: value, NodeId: id(nodeID)}}
	return response, nil
}

func (r *Registry) waitNodeTask(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceWaitNodeTaskRequest) (*fleetv1.FleetServiceWaitNodeTaskResponse, error) {
	value, nodeID, err := r.routed(ctx, call, message, relayv1.RoutedMethod_ROUTED_METHOD_WAIT_NODE_TASK)
	response := &fleetv1.FleetServiceWaitNodeTaskResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceWaitNodeTaskResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &fleetv1.FleetServiceWaitNodeTaskResponse_Value{Value: &fleetv1.FleetServiceWaitNodeTaskValue{Response: value, NodeId: id(nodeID)}}
	return response, nil
}

func (r *Registry) readNodeTaskOutput(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceReadNodeTaskOutputRequest) (*fleetv1.FleetServiceReadNodeTaskOutputResponse, error) {
	value, nodeID, err := r.routed(ctx, call, message, relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_TASK_OUTPUT)
	response := &fleetv1.FleetServiceReadNodeTaskOutputResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceReadNodeTaskOutputResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &fleetv1.FleetServiceReadNodeTaskOutputResponse_Value{Value: &fleetv1.FleetServiceReadNodeTaskOutputValue{Response: value, NodeId: id(nodeID)}}
	return response, nil
}

func (r *Registry) cancelNodeTask(ctx context.Context, call *ingress.Call, message *fleetv1.FleetServiceCancelNodeTaskRequest) (*fleetv1.FleetServiceCancelNodeTaskResponse, error) {
	value, nodeID, err := r.routed(ctx, call, message, relayv1.RoutedMethod_ROUTED_METHOD_CANCEL_NODE_TASK)
	response := &fleetv1.FleetServiceCancelNodeTaskResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := r.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.FleetServiceCancelNodeTaskResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &fleetv1.FleetServiceCancelNodeTaskResponse_Value{Value: &fleetv1.FleetServiceCancelNodeTaskValue{Response: value, NodeId: id(nodeID)}}
	return response, nil
}
