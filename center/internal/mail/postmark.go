// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
)

// postmarkURL is the single-message endpoint. It is a constant of the adapter, not configuration: a configurable URL would let one
// mistake send the server token to another host. Tests inject a local URL through PostmarkOptions.BaseURL.
const postmarkURL = "https://api.postmarkapp.com/email"

// maxPostmarkResponse bounds what one send reads from the answer body, and maxPostmarkHeader the response header block the
// transport accepts. Postmark's answer is a few hundred bytes.
const (
	maxPostmarkResponse = 16 << 10
	maxPostmarkHeader   = 16 << 10
)

// PostmarkOptions configure the Postmark sender. BaseURL and Client are for tests only: production leaves them empty (the
// constant https endpoint and the transport built below).
type PostmarkOptions struct {
	// Token is the Postmark Server API token.
	Token config.Secret
	// From is the sender address and FromName its optional display name; both are validated again at every send.
	From     string
	FromName string
	// Stream is the Postmark message stream; "outbound" when empty.
	Stream string
	// Timeout bounds the whole send (connect, request, answer); DefaultTimeout when not positive.
	Timeout time.Duration
	// BaseURL replaces the endpoint (tests only).
	BaseURL string
	// Client replaces the HTTP client (tests only). Its redirect policy is replaced either way.
	Client *http.Client
	// Dial replaces the dialer of the default transport (tests only; ignored when Client is set). The transport keeps every other
	// setting, so a test can map a made-up host name to a local listener without a packet leaving the machine.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// postmarkTLSConfig is the TLS configuration of the Postmark channel, which carries the server token: TLS 1.2 or later and the
// default verification against the system roots, nothing else. A test pins the value of each field and offers the transport an
// old-TLS server.
func postmarkTLSConfig() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS12} }

// postmarkTransport is the transport of the default client: no proxy (the token goes only where the URL says, never through an
// environment proxy), the TLS configuration above, bounded dial, handshake and response header, one connection per send.
func postmarkTransport(dial func(ctx context.Context, network, address string) (net.Conn, error)) *http.Transport {
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	return &http.Transport{
		Proxy:                  nil,
		TLSClientConfig:        postmarkTLSConfig(),
		DialContext:            dial,
		TLSHandshakeTimeout:    5 * time.Second,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: maxPostmarkHeader,
	}
}

// Postmark sends through the Postmark single-message HTTP API. The token travels in a header on a TLS 1.2+ connection that
// verifies the server certificate against the system roots; a redirect is never followed (Go forwards a custom header such as
// X-Postmark-Server-Token to another host) and the environment's proxy is never used.
type Postmark struct {
	o      PostmarkOptions
	client *http.Client
}

// NewPostmark is the sender of the options; it never connects.
func NewPostmark(o PostmarkOptions) *Postmark {
	if o.BaseURL == "" {
		o.BaseURL = postmarkURL
	}
	if o.Stream == "" {
		o.Stream = "outbound"
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	client := o.Client
	if client == nil {
		client = &http.Client{Transport: postmarkTransport(o.Dial)}
	}
	checked := *client
	checked.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Postmark{o: o, client: &checked}
}

// Enabled is true.
func (*Postmark) Enabled() bool { return true }

type postmarkRequest struct {
	From          string `json:"From"`
	To            string `json:"To"`
	Subject       string `json:"Subject"`
	TextBody      string `json:"TextBody"`
	MessageStream string `json:"MessageStream"`
	TrackOpens    bool   `json:"TrackOpens"`
	TrackLinks    string `json:"TrackLinks"`
}

type postmarkResponse struct {
	ErrorCode *int   `json:"ErrorCode"`
	MessageID string `json:"MessageID"`
}

func (p *Postmark) fail(class error, stage string, code int, timeout bool) error {
	return &Error{Class: class, Provider: "postmark", Stage: stage, Code: code, Timeout: timeout}
}

// Send delivers one message. No retry.
func (p *Postmark) Send(ctx context.Context, m Message) (result error) {
	defer func() {
		if recover() != nil {
			result = p.fail(ErrUnavailable, "panic", 0, false)
		}
	}()
	if err := validate("postmark", m); err != nil {
		return err
	}
	if err := validateSender("postmark", p.o.From, p.o.FromName); err != nil {
		return err
	}
	from := p.o.From
	if p.o.FromName != "" {
		from = p.o.FromName + " <" + p.o.From + ">"
	}
	body, err := json.Marshal(postmarkRequest{From: from, To: m.To, Subject: m.Subject, TextBody: m.Text, MessageStream: p.o.Stream, TrackLinks: "None"})
	if err != nil {
		return p.fail(ErrRejected, "message", 0, false)
	}
	ctx, cancel := context.WithTimeout(ctx, p.o.Timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.o.BaseURL, bytes.NewReader(body))
	if err != nil {
		return p.fail(ErrUnavailable, "http", 0, false)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Postmark-Server-Token", p.o.Token.Reveal())
	response, err := p.client.Do(request)
	if err != nil {
		// The text of a net/http error names the URL; it is dropped.
		var netErr net.Error
		timeout := errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout()
		return p.fail(ErrUnavailable, "http", 0, timeout)
	}
	defer response.Body.Close()
	var reply postmarkResponse
	text, readErr := io.ReadAll(io.LimitReader(response.Body, maxPostmarkResponse+1))
	parsed := readErr == nil && len(text) <= maxPostmarkResponse && json.Unmarshal(text, &reply) == nil && reply.ErrorCode != nil
	stage, code, class := postmarkOutcome(response.StatusCode, reply, parsed)
	if class == nil {
		return nil
	}
	// The one Timeout rule of both adapters: never together with a code (a status or an ErrorCode that arrived is not a timeout).
	return p.fail(class, stage, code, code == 0 && readErr != nil && errors.Is(ctx.Err(), context.DeadlineExceeded))
}

// postmarkOutcome classifies an answer by HTTP status and Postmark ErrorCode, never by a bare number alone (HTTP 413 is a payload
// over the limit, ErrorCode 413 an account that is not approved). A nil class is success. Order matters:
//
//   - 200 with ErrorCode 0 and a MessageID is the only success; a 200 that is not Postmark's answer (not JSON, empty, no MessageID:
//     a captive portal, a proxy) and any other 2xx is unavailable, because the outcome is unknown;
//   - 401 and 403 are unauthorized; 429, 3xx and 1xx are unavailable (by status, whatever the body says);
//   - a parsed non-zero ErrorCode decides the class (postmarkClassOfCode) on a 200 and on every 4xx, and on a 5xx only when it is
//     a code of the published table (a 500 with ErrorCode 501 is "no DKIM info" and an operator must act; a 500 with a code nobody
//     knows stays a transient server error);
//   - every other status is by status: a 4xx without a parsable ErrorCode (400, 404, 413, 415, a 422 without a body) is rejected, a
//     5xx is unavailable.
func postmarkOutcome(status int, reply postmarkResponse, parsed bool) (stage string, code int, class error) {
	coded := parsed && *reply.ErrorCode != 0
	switch {
	case status == http.StatusOK:
		switch {
		case parsed && *reply.ErrorCode == 0 && strings.TrimSpace(reply.MessageID) != "":
			return "", 0, nil
		case coded:
			return "response", *reply.ErrorCode, postmarkClassOfCode(*reply.ErrorCode)
		}
		return "response", 0, ErrUnavailable
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		return "http", status, ErrUnauthorized
	case status == http.StatusTooManyRequests, status >= 300 && status < 400, status < 200, status > 200 && status < 300:
		return "http", status, ErrUnavailable
	case coded && status >= 400 && status < 500, coded && status >= 500 && postmarkKnownCode(*reply.ErrorCode):
		return "response", *reply.ErrorCode, postmarkClassOfCode(*reply.ErrorCode)
	case status >= 500:
		return "http", status, ErrUnavailable
	}
	return "http", status, ErrRejected
}

// postmarkKnownCode reports whether code is in the published table of ErrorCodes that the Email API can return.
func postmarkKnownCode(code int) bool {
	switch code {
	case 10, 100, 101, 300, 402, 403, 406, 410, 411, 412, 413, 422, 501, 1235, 1236, 1480:
		return true
	}
	return false
}

// postmarkClassOfCode maps a Postmark ErrorCode. 100 (maintenance) and 101 (internal error) are transient; the codes a single
// message can cause (300 validation, 402 invalid JSON, 403 invalid field, 406 inactive recipient, 410, 411) are rejected; every
// other code is unauthorized: the token (10), the account (412 pending approval, 413 not approved, 422 invalid server), the sender
// signature or domain, the stream (1235, 1236) or the source address (1480) is wrong, and an operator must act. An undocumented
// code lands there too, by design: the center sends one fixed template to a validated address, so a new code is systemic in
// practice. The published table keeps changing; the test token accepts an unconfirmed sender and any stream, so the first live
// send is the first real test of these codes (NOT PROVEN until then).
func postmarkClassOfCode(code int) error {
	switch code {
	case 100, 101:
		return ErrUnavailable
	case 300, 402, 403, 406, 410, 411:
		return ErrRejected
	default:
		return ErrUnauthorized
	}
}
