// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"github.com/coder/websocket"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// Constrain only these test-owned TCP sockets, not the host or global settings.
type smallWriteListener struct{ net.Listener }

func (l smallWriteListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		err = c.(*net.TCPConn).SetWriteBuffer(1024)
	}
	return c, err
}

// The real coder/websocket and a native loopback socket exercise a center write;
// this fixture does not assert anything about a real Node or filesystem.
func testReplaySocket(t *testing.T) (*conn, *pending, *websocket.Conn) {
	t.Helper()
	accepted, handlerDone := make(chan *websocket.Conn, 1), make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		accepted <- ws
		<-handlerDone
	}))
	server.Listener = smallWriteListener{server.Listener}
	server.Start()
	transport := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err == nil {
			err = c.(*net.TCPConn).SetReadBuffer(1024)
		}
		return c, err
	}}
	client, _, err := websocket.Dial(context.Background(), server.URL, &websocket.DialOptions{HTTPClient: &http.Client{Transport: transport}})
	if err != nil {
		t.Fatal(err)
	}
	ws := <-accepted
	writes, cancelWrites := context.WithCancel(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	h := New(Options{Codec: RelayCodec{}, Settings: Settings{WriteTimeout: 3 * time.Second}})
	id, callID := platform.NewID(), platform.NewID()
	p := &pending{callID: callID, method: relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE,
		replayUntil: time.Now().Add(900 * time.Millisecond), expires: time.Now().Add(45 * time.Second), done: make(chan outcome, 1)}
	c := &conn{hub: h, ws: ws, nodeID: id, calls: map[platform.ID]*pending{callID: p}, writes: writes, cancelWrites: cancelWrites,
		ctx: ctx, cancel: cancel, stopWrites: make(chan struct{}), writerDone: make(chan struct{}), closeDone: make(chan struct{})}
	h.nodes[id] = c
	t.Cleanup(func() {
		cancel()
		cancelWrites()
		_ = client.CloseNow()
		_ = ws.CloseNow()
		close(handlerDone)
		server.Close()
		transport.CloseIdleConnections()
	})
	return c, p, ws
}

func requireBlockedReplayIsUnknown(t *testing.T, c *conn, p *pending, data []byte) {
	t.Helper()
	start := time.Now()
	ended := make(chan bool, 1)
	go func() { ended <- c.write(outbound{data: data, call: p}); close(c.writerDone) }()
	select {
	case outcome := <-p.done:
		if outcome.refusal == nil || outcome.refusal.Code != "node_unreachable" ||
			outcome.refusal.Effect != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN ||
			outcome.refusal.Retry != foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND {
			t.Fatalf("a started blocked write must remain UNKNOWN: %+v", outcome.refusal)
		}
		if elapsed := time.Since(start); elapsed < 300*time.Millisecond || elapsed > 3*time.Second {
			t.Fatalf("write wait not bounded by replay fence: %v", elapsed)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("blocked write did not finish")
	}
	select {
	case ok := <-ended:
		if ok {
			t.Fatal("blocked writer did not end")
		}
	case <-time.After(time.Second):
		t.Fatal("writer still blocked")
	}
}

func TestCTR06ReplayDeadlineBoundsWebSocketWriterWait(t *testing.T) {
	c, p, ws := testReplaySocket(t)
	ctx, cancel := context.WithCancel(context.Background())
	writer, err := ws.Writer(ctx, websocket.MessageBinary)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = writer.Close() }()
	requireBlockedReplayIsUnknown(t, c, p, []byte("writer-lock"))
}

func TestCTR06ReplayDeadlineBoundsBlockedNativeSocketWrite(t *testing.T) {
	c, p, _ := testReplaySocket(t)
	// The peer never reads. A bounded 240 KiB frame is larger than both
	// test-owned TCP buffers, forcing a real blocked/possibly partial socket write.
	requireBlockedReplayIsUnknown(t, c, p, bytes.Repeat([]byte{1}, 240*1024))
}
