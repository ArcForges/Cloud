// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"github.com/coder/websocket"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The wrapper only observes the duration of real native TCP writes. It does
// not replace a write or decide its result.
type observedSocket struct {
	net.Conn
	observe atomic.Bool
	started chan (<-chan struct{})
}

func (c *observedSocket) Write(data []byte) (int, error) {
	if !c.observe.Load() {
		return c.Conn.Write(data)
	}
	done := make(chan struct{})
	select {
	case c.started <- done:
	default:
	}
	n, err := c.Conn.Write(data)
	close(done)
	return n, err
}

type acceptedSocket struct {
	raw      *net.TCPConn
	observed *observedSocket
}

// Constrain only these test-owned TCP sockets, not the host or global settings.
type smallWriteListener struct {
	net.Listener
	accepted chan<- acceptedSocket
}

func (l smallWriteListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	raw := c.(*net.TCPConn)
	if err := raw.SetWriteBuffer(1024); err != nil {
		_ = raw.Close()
		return nil, err
	}
	observed := &observedSocket{Conn: raw, started: make(chan (<-chan struct{}), 1024)}
	l.accepted <- acceptedSocket{raw: raw, observed: observed}
	return observed, nil
}

// The real coder/websocket and a native loopback socket exercise a center write;
// this fixture does not assert anything about a real Node or filesystem.
func testReplaySocket(t *testing.T) (*conn, *pending, *websocket.Conn, acceptedSocket) {
	t.Helper()
	accepted, handlerDone := make(chan *websocket.Conn, 1), make(chan struct{})
	sockets := make(chan acceptedSocket, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		accepted <- ws
		<-handlerDone
	}))
	server.Listener = smallWriteListener{Listener: server.Listener, accepted: sockets}
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
	socket := <-sockets
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
	return c, p, ws, socket
}

func requireBlockedReplayIsUnknown(t *testing.T, c *conn, p *pending, data []byte, observed *observedSocket) {
	t.Helper()
	start := time.Now()
	if observed != nil {
		observed.observe.Store(true)
	}
	ended := make(chan bool, 1)
	go func() { ended <- c.write(outbound{data: data, call: p}); close(c.writerDone) }()
	if observed != nil {
		requireNativeWriteBlocked(t, observed, ended)
	}
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
	c, p, ws, _ := testReplaySocket(t)
	ctx, cancel := context.WithCancel(context.Background())
	writer, err := ws.Writer(ctx, websocket.MessageBinary)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = writer.Close() }()
	requireBlockedReplayIsUnknown(t, c, p, []byte("writer-lock"), nil)
}

// Fill the actual socket with valid server WebSocket frames until a real native
// TCP write reports backpressure. The peer never reads; a short deadline stops
// the prefill without closing the socket and is cleared before the tested call.
func fillUnreadSocket(t *testing.T, raw *net.TCPConn) {
	t.Helper()
	const payloadSize = 8192
	const maxPrefill = 32 * 1024 * 1024
	frame := make([]byte, 4+payloadSize)
	frame[0], frame[1] = 0x82, 126 // FIN, binary, unmasked server frame
	binary.BigEndian.PutUint16(frame[2:4], payloadSize)
	total := 0
	for total < maxPrefill {
		if err := raw.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		n, err := raw.Write(frame)
		total += n
		if err != nil {
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatalf("prefill native socket: %v", err)
			}
			if clearErr := raw.SetWriteDeadline(time.Time{}); clearErr != nil {
				t.Fatal(clearErr)
			}
			t.Logf("native socket backpressure after %d bytes", total)
			return
		}
		if n != len(frame) {
			t.Fatalf("short successful native socket write: %d", n)
		}
	}
	t.Fatal("test-owned socket did not reach native backpressure within its bound")
}

// A write observed here invokes the real TCPConn.Write. Require one such call to
// remain inside the OS write for a measurable period before checking the fence.
func requireNativeWriteBlocked(t *testing.T, observed *observedSocket, ended <-chan bool) {
	t.Helper()
	limit := time.NewTimer(600 * time.Millisecond)
	defer limit.Stop()
	for {
		select {
		case done := <-observed.started:
			blocked := time.NewTimer(100 * time.Millisecond)
			select {
			case <-done:
				blocked.Stop()
			case <-blocked.C:
				t.Log("observed a real native socket write blocked for at least 100 ms")
				return
			case <-limit.C:
				blocked.Stop()
				t.Fatal("did not observe a blocked native socket write before the fence")
			}
		case ok := <-ended:
			t.Fatalf("writer returned before native socket backpressure was observed: %v", ok)
		case <-limit.C:
			t.Fatal("no native socket write was observed before the fence")
		}
	}
}

func TestCTR06ReplayDeadlineBoundsBlockedNativeSocketWrite(t *testing.T) {
	c, p, _, socket := testReplaySocket(t)
	fillUnreadSocket(t, socket.raw)
	// Start this test's fixed replay fence after the fixture has filled the socket.
	// The actual call frame remains within the original 240 KiB bound.
	p.replayUntil = time.Now().Add(900 * time.Millisecond)
	requireBlockedReplayIsUnknown(t, c, p, bytes.Repeat([]byte{1}, 240*1024), socket.observed)
}
