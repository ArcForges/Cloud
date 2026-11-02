// SPDX-License-Identifier: AGPL-3.0-only

package mailtest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// PostmarkReply scripts one answer of the Postmark stand-in.
type PostmarkReply struct {
	// Status is the HTTP status; 200 when zero.
	Status int
	// Body is the JSON answer; a success answer when empty and the status is 200.
	Body string
	// Location is sent as a Location header (for redirect statuses).
	Location string
	// Stall holds the request open without answering until the client goes away.
	Stall bool
	// StallBody sends the status line and headers, a partial body, and then holds the request open.
	StallBody bool
	// StallAfterBody sends the status line, headers and the complete success body, and then holds the request open (the body
	// never ends, as when the connection hangs before the final chunk).
	StallAfterBody bool
	// Flood answers with an endless body of the status, counted by BytesWritten.
	Flood bool
}

// PostmarkRequest is what the stand-in received.
type PostmarkRequest struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

// PostmarkServer is a running stand-in for the Postmark single-message endpoint, speaking plain HTTP on 127.0.0.1. It also checks the
// token the way Postmark does: a request without the configured token gets 401 and ErrorCode 10.
type PostmarkServer struct {
	server   *httptest.Server
	token    string
	mu       sync.Mutex
	reply    PostmarkReply
	requests []PostmarkRequest
	written  atomic.Int64
}

// successBody is the shape of Postmark's success answer.
const successBody = `{"ErrorCode":0,"Message":"OK","MessageID":"message-id-test-0001","SubmittedAt":"2026-01-01T00:00:00Z","To":"x"}`

// StartPostmark starts the stand-in; token is the Server token it accepts. It stops with the test.
func StartPostmark(t testing.TB, token string, reply PostmarkReply) *PostmarkServer {
	t.Helper()
	p := &PostmarkServer{token: token, reply: reply}
	p.server = httptest.NewServer(http.HandlerFunc(p.handle))
	t.Cleanup(p.server.Close)
	return p
}

// URL is the endpoint, "http://127.0.0.1:port/email".
func (p *PostmarkServer) URL() string { return p.server.URL + "/email" }

// Set replaces the scripted answer.
func (p *PostmarkServer) Set(reply PostmarkReply) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reply = reply
}

// Requests returns the requests received so far.
func (p *PostmarkServer) Requests() []PostmarkRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]PostmarkRequest(nil), p.requests...)
}

// BytesWritten is how many body bytes the stand-in wrote for the Flood reply.
func (p *PostmarkServer) BytesWritten() int64 { return p.written.Load() }

func (p *PostmarkServer) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body) // drain first: the server notices an aborted client only after it
	p.mu.Lock()
	p.requests = append(p.requests, PostmarkRequest{Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: body})
	reply := p.reply
	p.mu.Unlock()
	if r.Header.Get("X-Postmark-Server-Token") != p.token {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"ErrorCode":10,"Message":"Request does not contain a valid Server token."}`)
		return
	}
	if reply.Stall {
		<-r.Context().Done()
		return
	}
	status := reply.Status
	if status == 0 {
		status = http.StatusOK
	}
	if reply.Location != "" {
		w.Header().Set("Location", reply.Location)
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case reply.Flood:
		w.WriteHeader(status)
		chunk := []byte(strings.Repeat(" ", 64<<10))
		for r.Context().Err() == nil {
			n, err := w.Write(chunk)
			p.written.Add(int64(n))
			if err != nil {
				return
			}
		}
	case reply.StallBody, reply.StallAfterBody:
		w.WriteHeader(status)
		if reply.StallAfterBody {
			_, _ = io.WriteString(w, successBody)
		} else {
			_, _ = io.WriteString(w, `{"ErrorCode":0,"Mess`)
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-r.Context().Done()
	default:
		text := reply.Body
		if text == "" && status == http.StatusOK {
			text = successBody
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, text)
	}
}
