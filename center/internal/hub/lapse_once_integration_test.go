// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// barrierGate answers unavailable, but only once every expected caller is inside it, so the callers pass the gate together.
type barrierGate struct {
	arrived chan struct{}
	release chan struct{}
}

func (g *barrierGate) Availability(context.Context, feature.Key) feature.Decision {
	g.arrived <- struct{}{}
	<-g.release
	return feature.Decision{Reason: feature.ReasonOperatorLimit}
}

// TestALapseCloseIsAuditedOnce is review A N-7 (CTR5-HUB-09: access.gated once per close; EVIDENCE: REAL PostgreSQL, a real
// WebSocket pair): the supervisor and a TokenRefresh can find the lapse at the same instant. Both pass the gate together here, and the
// first to claim the close audits it; the other neither audits nor closes again.
func TestALapseCloseIsAuditedOnce(t *testing.T) {
	db := dbtest.New(t)
	enrollment := seedNode(t, db)
	accepted := make(chan *websocket.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ws, err := websocket.Accept(writer, request, nil)
		if err == nil {
			accepted <- ws
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.CloseNow() }()
	go func() {
		for {
			if _, _, err := client.Read(ctx); err != nil {
				return
			}
		}
	}()
	gate := &barrierGate{arrived: make(chan struct{}, 2), release: make(chan struct{})}
	h := &Hub{db: db.Runtime, gate: gate, codec: RelayCodec{}, clock: time.Now, logger: slog.New(slog.DiscardHandler), metrics: observe.NewMetrics(),
		nodes: map[platform.ID]*conn{}, all: map[*conn]bool{}}
	c := &conn{hub: h, ws: <-accepted, userID: platform.NewID(), installationID: platform.NewID(), enrollmentID: enrollment, connectionID: platform.NewID(),
		stopWrites: make(chan struct{}), writerDone: make(chan struct{}), closeDone: make(chan struct{})}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.writes, c.cancelWrites = context.WithCancel(context.Background())
	defer c.cancel()
	defer c.cancelWrites()
	go c.writer()
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.recheckLapse(ctx)
		}()
	}
	<-gate.arrived
	<-gate.arrived
	close(gate.release)
	wg.Wait()
	if n := db.Count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'access.gated'"); n != 1 {
		t.Fatalf("access.gated %d times for one close", n)
	}
	if !c.closing.Load() || c.closeCode != CloseRefused || c.closeReason != "feature_not_entitled" {
		t.Fatalf("the lapse close: %v %d %s", c.closing.Load(), c.closeCode, c.closeReason)
	}
}
