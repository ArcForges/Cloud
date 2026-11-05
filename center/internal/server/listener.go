// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// The public listener's connection bounds (Plan PN-1, CTR5-HUB-12). A request connection holds one of MaxConnections slots while it is
// open, as netutil.LimitListener did; a node channel connection, once its upgrade is admitted, gives its slot back and holds one of
// MaxNodeConnections instead, so long-lived channels never starve the requests and the request bound never caps the channels. The
// server's read and write timeouts are set on a connection before its handler runs; the upgrade handler clears both before it hijacks
// the connection (hub.ServeHTTP), so a channel is bounded only by its own heartbeat deadline and write timeout.

// The server's timeouts (unchanged from AF-CTR-02): they bound every request, never an upgraded channel.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 20 * time.Second
	writeTimeout      = 20 * time.Second
	idleTimeout       = 60 * time.Second
	maxHeaderBytes    = 16384
)

// slots are the two bounds of one listener.
type slots struct {
	requests chan struct{}
	nodes    chan struct{}
}

func newSlots(requests, nodes int) *slots {
	return &slots{requests: make(chan struct{}, requests), nodes: make(chan struct{}, nodes)}
}

// slotListener bounds the open connections of a listener by the request slots.
type slotListener struct {
	net.Listener
	slots *slots
	done  chan struct{}
	once  sync.Once
}

func (l *slotListener) Accept() (net.Conn, error) {
	select {
	case l.slots.requests <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	connection, err := l.Listener.Accept()
	if err != nil {
		<-l.slots.requests
		return nil, err
	}
	return &slotConn{Conn: connection, slots: l.slots, holds: l.slots.requests}, nil
}

func (l *slotListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

// slotConn is a connection and the slot it holds.
type slotConn struct {
	net.Conn
	slots *slots
	mu    sync.Mutex
	holds chan struct{} // the slot pool it holds one of; nil once given back
}

// Close closes the connection and gives its slot back, once.
func (c *slotConn) Close() error {
	c.mu.Lock()
	if c.holds != nil {
		<-c.holds
		c.holds = nil
	}
	c.mu.Unlock()
	return c.Conn.Close()
}

// toNode moves the connection from a request slot to a node channel slot; false when every node slot is held (the connection then
// keeps its request slot and is refused).
func (c *slotConn) toNode() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.holds == c.slots.nodes {
		return true
	}
	select {
	case c.slots.nodes <- struct{}{}:
	default:
		return false
	}
	if c.holds != nil {
		<-c.holds
	}
	c.holds = c.slots.nodes
	return true
}

type connKey struct{}

// connContext puts the connection in every request context of it, so the upgrade handler can move it to a node slot.
func connContext(ctx context.Context, connection net.Conn) context.Context {
	return context.WithValue(ctx, connKey{}, connection)
}

// NodeSlot is the hub's Slot of a center: it moves the request's connection to a node channel slot. The connection gives the slot back
// when it closes, so the release it returns does nothing. A request that did not come through a slot listener (an in-process test
// server) is admitted.
func NodeSlot(request *http.Request) (func(), bool) {
	connection, ok := request.Context().Value(connKey{}).(*slotConn)
	if !ok {
		return func() {}, true
	}
	return func() {}, connection.toNode()
}

// newPublicServer is a public listener's server: the center's timeouts and header bound, and the connection context the node slots
// read.
func newPublicServer(handler http.Handler, http1 bool, errorLog *slog.Logger) *http.Server {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(http1)
	protocols.SetUnencryptedHTTP2(true)
	return &http.Server{
		Handler: handler, Protocols: protocols, ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: readTimeout, WriteTimeout: writeTimeout,
		IdleTimeout: idleTimeout, MaxHeaderBytes: maxHeaderBytes, ErrorLog: slog.NewLogLogger(errorLog.Handler(), slog.LevelWarn), ConnContext: connContext,
	}
}

// listen bounds a listener by the request and node slots.
func listen(listener net.Listener, requests, nodes int) net.Listener {
	return &slotListener{Listener: listener, slots: newSlots(requests, nodes), done: make(chan struct{})}
}
