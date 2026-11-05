// SPDX-License-Identifier: AGPL-3.0-only

package pages_test

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

// slots is a resource control that holds a slot for each call's duration (as routed_in_flight_per_account does) and gives it back
// through ingress.Call.AfterCall; its mode decides what happens after the slot was taken.
type slots struct {
	mu                    sync.Mutex
	held, taken, released int
	mode                  string
}

func (s *slots) control() access.Control {
	return access.ControlFunc{Key: "slots", Check: func(ctx context.Context, call *ingress.Call, _ access.Operation) error {
		s.mu.Lock()
		s.held++
		s.taken++
		mode := s.mode
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
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}}
}

func (s *slots) counts() (int, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.held, s.taken, s.released
}

// TestThePagesReleaseASlotWhenTheExchangeEnds is N-3 of the review of Cloud #143 (the in-flight release) for the calls the pages build
// themselves (exchange.call, outside the ingress pipeline): the account page's calls give their slots back when the exchange ends,
// whether it answered, a later control refused, a control panicked or the client went away (the request's context was cancelled).
// The pages' deferred exchange.finish is what gives them back.
func TestThePagesReleaseASlotWhenTheExchangeEnds(t *testing.T) {
	counter := &slots{}
	h := newHarness(t, settings{policy: writePolicy, controls: []access.Control{counter.control()}})
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)
	settle := func(mode string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			held, taken, released := counter.counts()
			if held == 0 && taken == released {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("after the %s exchange: %d slots held, %d taken, %d released", mode, held, taken, released)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	settle("sign-in")
	set := func(mode string) {
		counter.mu.Lock()
		counter.mode = mode
		counter.mu.Unlock()
	}
	_, before, _ := counter.counts()
	if reply := b.get("/account/passkeys"); reply.status != http.StatusOK {
		t.Fatalf("the account page: %d", reply.status)
	}
	if _, taken, _ := counter.counts(); taken < before+2 {
		t.Fatalf("the account page's calls took %d slots", taken-before)
	}
	settle("return")
	set("refuse")
	if reply := b.get("/account/passkeys"); reply.status == http.StatusOK {
		t.Fatalf("a refused call answered %d", reply.status)
	}
	settle("refuse")
	// A panic and a client that goes away: the request is sent by hand, because the connection ends without a reply.
	for _, mode := range []string{"panic", "cancel"} {
		set(mode)
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url+"/account/passkeys", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Cookie", routes.PageCookieName+"="+b.cookie)
		request.Header.Set(config.ClientIPHeader, "203.0.113.10")
		if response, err := (&http.Client{Transport: &http.Transport{}}).Do(request); err == nil {
			_ = response.Body.Close()
			if mode == "cancel" {
				t.Errorf("a cancelled request was answered %d", response.StatusCode)
			}
		}
		cancel()
		settle(mode)
	}
}
