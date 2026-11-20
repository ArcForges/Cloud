// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	v2 "github.com/ArcForges/Contracts/go/arcforges/sandbox/v2"
	"github.com/ArcForges/Contracts/go/arcforges/sandbox/v2/sandboxv2connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/management"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

const (
	watchPollTimeout    = 2 * time.Second
	watchIdleDelay      = 250 * time.Millisecond
	watchWriteBudget    = 2 * time.Second
	watchPerIdentity    = 8
	maxOutputFrameBytes = 64 * 1024
)

type watchDisposition uint8

const (
	watchInvalid watchDisposition = iota
	watchSkip
	watchSend
	watchFinish
)

type watchSlots struct {
	mu       sync.Mutex
	limit    int
	total    int
	accounts map[platform.ID]int
	nodes    map[platform.ID]int
}

func (s *watchSlots) take(scope management.Authority) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.total >= s.limit || s.accounts[scope.Account] >= watchPerIdentity || s.nodes[scope.Node] >= watchPerIdentity {
		return false
	}
	s.total++
	s.accounts[scope.Account]++
	s.nodes[scope.Node]++
	return true
}

func (s *watchSlots) release(scope management.Authority) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total--
	s.accounts[scope.Account]--
	s.nodes[scope.Node]--
	if s.accounts[scope.Account] == 0 {
		delete(s.accounts, scope.Account)
	}
	if s.nodes[scope.Node] == 0 {
		delete(s.nodes, scope.Node)
	}
}

// V2WatchMethods serves the fixed public watches. Each HTTP stream owns one
// exact node channel and makes one pull at a time. The next pull cannot begin
// until the receiver has completed its previous write.
func (s *Server) V2WatchMethods(transport V2ControlTransport, longPolls int) []connect.Method {
	r := &managementRouter{Server: s, transport: transport}
	slots := &watchSlots{
		limit: max(1, longPolls), accounts: make(map[platform.ID]int), nodes: make(map[platform.ID]int),
	}
	methods := routes.ManagementWatchMethods()
	return []connect.Method{
		watchMethod(r, slots, methods[0], v2.ValidateRunServiceWatchOutputRequest, v2.ValidateRunServiceWatchOutputFrame,
			func() func(*v2.RunServiceWatchOutputRequest, *v2.RunServiceWatchOutputFrame) watchDisposition {
				return advanceOutputWatch
			},
			nil,
			func(meta *foundationv1.ResponseMeta, err *foundationv1.ArcError) *v2.RunServiceWatchOutputFrame {
				return &v2.RunServiceWatchOutputFrame{Meta: meta, Frame: &v2.RunServiceWatchOutputFrame_Error{Error: err}}
			}),
		watchMethod(r, slots, methods[1], v2.ValidateNodeServiceWatchEventsRequest, v2.ValidateNodeServiceWatchEventsFrame,
			func() func(*v2.NodeServiceWatchEventsRequest, *v2.NodeServiceWatchEventsFrame) watchDisposition {
				return advanceEventWatch
			},
			nil,
			func(meta *foundationv1.ResponseMeta, err *foundationv1.ArcError) *v2.NodeServiceWatchEventsFrame {
				return &v2.NodeServiceWatchEventsFrame{Meta: meta, Frame: &v2.NodeServiceWatchEventsFrame_Error{Error: err}}
			}),
		watchMethod(r, slots, methods[2], v2.ValidateResourceServiceWatchUsageRequest, v2.ValidateResourceServiceWatchUsageFrame,
			usageWatch, usageInterval,
			func(meta *foundationv1.ResponseMeta, err *foundationv1.ArcError) *v2.ResourceServiceWatchUsageFrame {
				return &v2.ResourceServiceWatchUsageFrame{Meta: meta, Frame: &v2.ResourceServiceWatchUsageFrame_Error{Error: err}}
			}),
	}
}

func watchMethod[Q, F any, Request interface {
	*Q
	controlRequest
}, Frame interface {
	*F
	controlResponse
}](r *managementRouter, slots *watchSlots, method routes.ManagementMethod, validRequest func(Request) bool, validFrame func(Frame) bool,
	start func() func(Request, Frame) watchDisposition, interval func(Request) time.Duration,
	errorFrame func(*foundationv1.ResponseMeta, *foundationv1.ArcError) Frame) connect.Method {
	service, name, _ := strings.Cut(method.ReceiptMethod(), ".")
	return connect.Method{
		Spec: connect.Spec{Procedure: method.Path, StreamType: connect.StreamTypeServer,
			Schema: v2.File_arcforges_sandbox_v2_platform_proto.Services().ByName(protoreflect.Name(service)).Methods().ByName(protoreflect.Name(name))},
		Handler: func(ctx context.Context, _ connect.Spec, stream connect.ServerStream) error {
			request := Request(new(Q))
			if err := stream.Receive(request); err != nil {
				return err
			}
			call, ok := ingress.CallFrom(ctx)
			if !ok {
				return connect.NewError(connect.CodeInternal, "the call was not admitted by the ingress pipeline")
			}
			ctx, cancel := context.WithTimeout(ctx, routes.ManagementDeadline(method))
			defer cancel()
			failure := func(err error) error {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				meta := ingress.ResponseMeta(call.Correlation)
				frame := errorFrame(meta, r.failure(ctx, call, err))
				if !validFrame(frame) {
					frame = errorFrame(meta, arc.Unavailable().Dated(r.clock()).ArcError(call.Correlation))
				}
				return writeWatch(ctx, call, func() error { return stream.Send(frame) })
			}
			if !validRequest(request) || request.GetMeta() == nil || request.GetMeta().GetCommandId() != nil ||
				len(request.ProtoReflect().GetUnknown()) != 0 {
				return failure(arc.InvalidArgument("request", "typed_message_invalid"))
			}
			if err := checkMeta(request.GetMeta()); err != nil {
				return failure(err)
			}
			scope, protocol, err := r.controlTarget(ctx, call)
			if err != nil {
				return failure(err)
			}
			if protocol == nil {
				return failure(controlUpgradeRequired())
			}
			if r.transport == nil {
				return failure(arc.NodeOffline(scope.Node[:], r.clock()))
			}
			authority, err := r.transport.V2ControlAuthority(ctx, scope.Account, scope.Node, scope.Enrollment, *protocol)
			if err != nil {
				return failure(r.transportFailure(err, scope.Node))
			}
			if authority.AccountID != scope.Account || authority.NodeID != scope.Node || authority.EnrollmentID != scope.Enrollment ||
				authority.ProtocolEpoch != *protocol || authority.NodeOwnerEpoch == (platform.ID{}) {
				return failure(arc.NodeOffline(scope.Node[:], r.clock()))
			}
			if !slots.take(scope) {
				return failure(arc.Unavailable())
			}
			defer slots.release(scope)

			correlation, validCorrelation := textID(call.Correlation.CorrelationID)
			if !validCorrelation {
				return failure(arc.InvalidArgument("meta.correlation_id", "malformed"))
			}
			request.GetMeta().CorrelationId = id(correlation)
			advance := start()
			recheck := func() error {
				if err := r.recheckControlCaller(ctx, call); err != nil {
					if errors.Is(err, pgx.ErrNoRows) {
						return arc.Unauthenticated()
					}
					return err
				}
				return r.access.RecheckFeature(ctx, call, method.Path)
			}
			headersSent := false
			for ctx.Err() == nil {
				if err := recheck(); err != nil {
					return failure(err)
				}
				body, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
				if err != nil {
					return failure(arc.InvalidArgument("request", "typed_message_invalid"))
				}
				poll, stop := context.WithTimeout(ctx, watchPollTimeout)
				deadline, _ := poll.Deadline()
				answer, err := r.transport.CallV2(poll, authority, management.V2ControlCall{
					Selector: management.V2ControlSelector(method.Selector), ActorID: scope.Actor, OriginalOwnerEpoch: authority.NodeOwnerEpoch,
					GrantID: scope.Grant, GrantRevision: scope.GrantRevision, Deadline: deadline, Body: body,
				}, nil)
				stop()
				if err != nil {
					return failure(r.transportFailure(err, scope.Node))
				}
				frame := Frame(new(F))
				outcome := watchSkip
				if len(answer) != 1 || answer[0] != 0 {
					if len(answer) < 2 || answer[0] != 1 ||
						(method.Path == sandboxv2connect.RunServiceWatchOutputProcedure && len(answer)-1 > maxOutputFrameBytes) {
						return failure(r.transportFailure(errControlResult, scope.Node))
					}
					frame, err = decodeControlResponse(answer[1:], frame, request.GetMeta().GetCorrelationId(), validFrame)
					if err != nil {
						return failure(r.transportFailure(err, scope.Node))
					}
					if frame.GetError() != nil {
						outcome = watchFinish
					} else {
						outcome = advance(request, frame)
					}
					if outcome == watchInvalid {
						return failure(r.transportFailure(errControlResult, scope.Node))
					}
				}
				if err := recheck(); err != nil {
					return failure(err)
				}
				if !headersSent {
					if err := writeWatch(ctx, call, stream.SendHeaders); err != nil {
						return err
					}
					headersSent = true
				}
				if outcome != watchSkip {
					startedWrite := time.Now()
					if err := writeWatch(ctx, call, func() error { return stream.Send(frame) }); err != nil {
						return err
					}
					if outcome == watchFinish {
						return nil
					}
					if interval != nil && time.Since(startedWrite) >= interval(request) {
						return failure(arc.Unavailable())
					}
				}
				if outcome == watchSkip || interval != nil {
					delay := watchIdleDelay
					if interval != nil {
						delay = interval(request)
					}
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(delay):
					}
				}
			}
			return ctx.Err()
		},
	}
}

func writeWatch(ctx context.Context, call *ingress.Call, write func() error) error {
	deadline, _ := ctx.Deadline()
	if err := call.SetStreamWriteDeadline(minTime(deadline, time.Now().Add(watchWriteBudget))); err != nil {
		return connect.NewError(connect.CodeUnavailable, "watch transport cannot bound the response")
	}
	if err := write(); err != nil {
		if ctx.Err() == nil && errors.Is(err, os.ErrDeadlineExceeded) {
			return connect.NewError(connect.CodeResourceExhausted, "the watch consumer exceeded its write budget")
		}
		return err
	}
	return call.SetStreamWriteDeadline(deadline)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func advanceOutputWatch(request *v2.RunServiceWatchOutputRequest, frame *v2.RunServiceWatchOutputFrame) watchDisposition {
	switch {
	case frame.GetChunk() != nil:
		chunk := frame.GetChunk()
		if (request.Epoch != nil && chunk.GetEpoch() != request.GetEpoch()) ||
			(request.Stream != nil && chunk.GetStream() != request.GetStream()) || chunk.GetOffset() != request.GetOffset() ||
			chunk.GetNextOffset() <= chunk.GetOffset() || chunk.GetNextOffset()-chunk.GetOffset() != uint64(len(chunk.GetData())) {
			return watchInvalid
		}
		request.Epoch = proto.String(chunk.GetEpoch())
		request.Stream = chunk.GetStream().Enum()
		request.Offset = proto.Uint64(chunk.GetNextOffset())
	case frame.GetGap() != nil:
		gap := frame.GetGap()
		if gap.GetRequestedOffset() != request.GetOffset() {
			return watchInvalid
		}
		switch gap.GetReason() {
		case "epoch_changed":
			if request.Epoch == nil || gap.GetEpoch() == request.GetEpoch() {
				return watchInvalid
			}
			return watchFinish
		case "retention":
			if (request.Epoch != nil && gap.GetEpoch() != request.GetEpoch()) || gap.GetEarliestOffset() <= request.GetOffset() {
				return watchInvalid
			}
			request.Epoch = proto.String(gap.GetEpoch())
			request.Offset = proto.Uint64(gap.GetEarliestOffset())
		default:
			return watchInvalid
		}
	case frame.GetRun() != nil:
		run := frame.GetRun()
		if !proto.Equal(run.GetRunId(), request.GetRunId()) || (request.Epoch != nil && run.GetEpoch() != request.GetEpoch()) {
			return watchInvalid
		}
		return watchFinish
	default:
		return watchInvalid
	}
	return watchSend
}

func advanceEventWatch(request *v2.NodeServiceWatchEventsRequest, frame *v2.NodeServiceWatchEventsFrame) watchDisposition {
	if gap := frame.GetGap(); gap != nil {
		if gap.GetRequestedSequence() != request.GetAfterSequence() {
			return watchInvalid
		}
		return watchFinish
	}
	event := frame.GetEvent()
	if event == nil || event.GetSandboxId() == nil || event.GetSequence() <= request.GetAfterSequence() ||
		(request.GetEpoch() != "" && request.GetEpoch() != event.GetEpoch()) {
		return watchInvalid
	}
	request.Epoch, request.AfterSequence = proto.String(event.GetEpoch()), proto.Uint64(event.GetSequence())
	return watchSend
}

func usageInterval(request *v2.ResourceServiceWatchUsageRequest) time.Duration {
	return time.Duration(max(1000, request.GetIntervalMs())) * time.Millisecond
}

func usageWatch() func(*v2.ResourceServiceWatchUsageRequest, *v2.ResourceServiceWatchUsageFrame) watchDisposition {
	var epoch string
	var sequence uint64
	var stale, seen bool
	return func(request *v2.ResourceServiceWatchUsageRequest, frame *v2.ResourceServiceWatchUsageFrame) watchDisposition {
		value := frame.GetSnapshot()
		if value == nil || value.GetScopeKind() != request.GetScopeKind() || !proto.Equal(value.GetScopeId(), request.GetScopeId()) {
			return watchInvalid
		}
		if seen && epoch == value.GetSampleEpoch() {
			if value.GetSampleSequence() < sequence {
				return watchInvalid
			}
			if value.GetSampleSequence() == sequence && value.GetStale() == stale {
				return watchSkip
			}
		}
		epoch, sequence, stale, seen = value.GetSampleEpoch(), value.GetSampleSequence(), value.GetStale(), true
		return watchSend
	}
}
