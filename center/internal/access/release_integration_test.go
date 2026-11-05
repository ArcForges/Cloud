// SPDX-License-Identifier: AGPL-3.0-only

package access

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// slotControl is a resource control that holds a slot for the call's duration, as routed_in_flight_per_account does, and gives it
// back through ingress.Call.AfterCall; its mode decides what happens after the slot was taken.
type slotControl struct {
	mu                    sync.Mutex
	held, taken, released int
	mode                  string
	cancel                context.CancelFunc
}

func (s *slotControl) control() Control {
	return ControlFunc{Key: "slots", Check: func(ctx context.Context, call *ingress.Call, _ Operation) error {
		s.mu.Lock()
		s.held++
		s.taken++
		mode, cancel := s.mode, s.cancel
		s.mu.Unlock()
		call.AfterCall(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.held--
			s.released++
		})
		switch mode {
		case "refuse":
			return arc.RateLimited("slots", 1, time.Now().Add(time.Minute))
		case "panic":
			panic("a control panicked after it took its slot (test)")
		case "cancel":
			cancel()
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}}
}

func (s *slotControl) counts() (int, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.held, s.taken, s.released
}

// TestTheIngressPipelineReleasesASlotWhenTheCallEnds is N-3 of the review of Cloud #143 (the in-flight release): behind the real
// ingress pipeline, a slot a control took is given back once the call ends, whether the handler returned, a later control refused the
// call, a control panicked or the request's context was cancelled. The pipeline's deferred Call.Finish is what gives it back.
func TestTheIngressPipelineReleasesASlotWhenTheCallEnds(t *testing.T) {
	r := newRig(t, feature.Settings{Mode: config.SelfHosted, PushSender: true})
	token, _ := r.credential(r.db.Account(1), session.ScopeAccount)
	slots := &slotControl{}
	*r.controls = []Control{slots.control()}
	for index, mode := range []string{"return", "refuse", "panic", "cancel"} {
		ctx, cancel := context.WithCancel(context.Background())
		slots.mu.Lock()
		slots.mode, slots.cancel = mode, cancel
		slots.mu.Unlock()
		func() {
			defer func() {
				if recovered := recover(); (recovered != nil) != (mode == "panic") {
					t.Errorf("%s: recovered %v", mode, recovered)
				}
			}()
			got, _ := r.callContext(ctx, "RemoteView", token, nil)
			if mode == "return" && !got.reached || mode == "refuse" && got.failure != "RESOURCE/rate_limited" {
				t.Errorf("%s: %+v", mode, got)
			}
		}()
		cancel()
		if held, taken, released := slots.counts(); held != 0 || taken != index+1 || released != index+1 {
			t.Errorf("after the %s call: %d slots held, %d taken, %d released", mode, held, taken, released)
		}
	}
}
