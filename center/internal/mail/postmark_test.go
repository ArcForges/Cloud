// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/mail/mailtest"
)

// All Postmark tests are MOCKED: the stand-in of package mailtest or httptest on 127.0.0.1, an injected RoundTripper, or a child
// process (the proxy test) whose adapter dials only through a test hook that maps a made-up host name to a loopback listener. No
// test here resolves a name or sends a packet beyond the loopback interface.

type postmarkRig struct {
	server *mailtest.PostmarkServer
	sender *Postmark
	token  string
}

func newPostmarkRig(t *testing.T, reply mailtest.PostmarkReply, modify func(*PostmarkOptions)) *postmarkRig {
	t.Helper()
	token := sentinel("postmark-token")
	server := mailtest.StartPostmark(t, token, reply)
	options := PostmarkOptions{Token: config.NewSecret(token), From: testFrom, FromName: "ArcForges", BaseURL: server.URL(), Timeout: 5 * time.Second}
	if modify != nil {
		modify(&options)
	}
	return &postmarkRig{server: server, sender: NewPostmark(options), token: token}
}

func TestPostmarkSendsTheDocumentedRequest(t *testing.T) {
	for _, stream := range []string{"", "custom-stream"} {
		rig := newPostmarkRig(t, mailtest.PostmarkReply{}, func(o *PostmarkOptions) { o.Stream = stream })
		message := testMessage()
		if err := rig.sender.Send(context.Background(), message); err != nil {
			t.Fatal(err)
		}
		requests := rig.server.Requests()
		if len(requests) != 1 {
			t.Fatalf("%d requests", len(requests))
		}
		request := requests[0]
		if request.Method != http.MethodPost || request.Path != "/email" || request.Header.Get("Accept") != "application/json" ||
			request.Header.Get("Content-Type") != "application/json" || request.Header.Get("X-Postmark-Server-Token") != rig.token {
			t.Errorf("request line or headers: %s %s %v", request.Method, request.Path, request.Header)
		}
		var fields map[string]any
		if err := json.Unmarshal(request.Body, &fields); err != nil {
			t.Fatal(err)
		}
		keys := make([]string, 0, len(fields))
		for key := range fields {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		if want := []string{"From", "MessageStream", "Subject", "TextBody", "To", "TrackLinks", "TrackOpens"}; !slices.Equal(keys, want) {
			t.Errorf("JSON keys %v, want %v", keys, want)
		}
		wantStream := stream
		if wantStream == "" {
			wantStream = "outbound"
		}
		if fields["From"] != "ArcForges <"+testFrom+">" || fields["To"] != testTo || fields["Subject"] != message.Subject || fields["TextBody"] != message.Text ||
			fields["MessageStream"] != wantStream || fields["TrackOpens"] != false || fields["TrackLinks"] != "None" {
			t.Errorf("JSON values %v", fields)
		}
		if strings.Contains(string(request.Body), rig.token) {
			t.Error("the token is in the request body")
		}
	}
	nameless := newPostmarkRig(t, mailtest.PostmarkReply{}, func(o *PostmarkOptions) { o.FromName = "" })
	if err := nameless.sender.Send(context.Background(), testMessage()); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	_ = json.Unmarshal(nameless.server.Requests()[0].Body, &fields)
	if fields["From"] != testFrom {
		t.Errorf("a nameless From is %v", fields["From"])
	}
}

type outcomeCase struct {
	name   string
	status int
	body   string
	class  error // nil: success
	stage  string
	code   int
}

// postmarkCases is the classification of every answer the adapter distinguishes; keyed by HTTP status and ErrorCode, never by a bare
// number (HTTP 413 is a payload over the limit, ErrorCode 413 an account that is not approved).
func postmarkCases(recipient string) []outcomeCase {
	leaky := func(code int) string {
		return fmt.Sprintf(`{"ErrorCode":%d,"Message":"Illegal email address '%s' for the stream"}`, code, recipient)
	}
	cases := []outcomeCase{
		{"accepted", 200, "", nil, "", 0},
		{"200 without a MessageID", 200, `{"ErrorCode":0,"Message":"OK"}`, ErrUnavailable, "response", 0},
		{"200 with an empty MessageID", 200, `{"ErrorCode":0,"MessageID":"  "}`, ErrUnavailable, "response", 0},
		{"200 not JSON", 200, `<html>sign in to the network</html>`, ErrUnavailable, "response", 0},
		{"200 blank body", 200, "\n", ErrUnavailable, "response", 0},
		{"200 with a null ErrorCode", 200, `{"ErrorCode":null,"MessageID":"x"}`, ErrUnavailable, "response", 0},
		{"200 with a text ErrorCode", 200, `{"ErrorCode":"0","MessageID":"x"}`, ErrUnavailable, "response", 0},
		{"200 with ErrorCode 100", 200, leaky(100), ErrUnavailable, "response", 100},
		{"200 with ErrorCode 101", 200, leaky(101), ErrUnavailable, "response", 101},
		{"200 with ErrorCode 300", 200, leaky(300), ErrRejected, "response", 300},
		{"200 with ErrorCode 10", 200, leaky(10), ErrUnauthorized, "response", 10},
		{"200 with ErrorCode 412", 200, leaky(412), ErrUnauthorized, "response", 412},
		{"401 with ErrorCode 10", 401, leaky(10), ErrUnauthorized, "http", 401},
		{"401 without a body", 401, "\n", ErrUnauthorized, "http", 401},
		{"403", 403, "\n", ErrUnauthorized, "http", 403},
		{"422 without a parsable ErrorCode", 422, `<html>`, ErrRejected, "http", 422},
		{"422 with ErrorCode 0", 422, `{"ErrorCode":0}`, ErrRejected, "http", 422},
		{"422 with an unknown code", 422, leaky(9999), ErrUnauthorized, "response", 9999},
		// The ErrorCode decides on every 4xx that carries a parseable Postmark body (a 404 with ErrorCode 501 is an unknown sender
		// signature); the status decides when there is none.
		{"404 with ErrorCode 501", 404, leaky(501), ErrUnauthorized, "response", 501},
		{"404 with an unknown code", 404, leaky(9999), ErrUnauthorized, "response", 9999},
		{"400 with ErrorCode 300", 400, leaky(300), ErrRejected, "response", 300},
		{"HTTP 413 with ErrorCode 413 (not approved)", 413, leaky(413), ErrUnauthorized, "response", 413},
		{"HTTP 413 payload without a body", 413, "\n", ErrRejected, "http", 413},
		{"HTTP 413 with ErrorCode 0", 413, `{"ErrorCode":0}`, ErrRejected, "http", 413},
		{"429 with an unknown code", 429, leaky(9999), ErrUnavailable, "http", 429},
		{"401 with ErrorCode 300", 401, leaky(300), ErrUnauthorized, "http", 401},
		{"403 with ErrorCode 300", 403, leaky(300), ErrUnauthorized, "http", 403},
		{"302 with an unknown code", 302, leaky(9999), ErrUnavailable, "http", 302},
		{"500 with an unknown code", 500, leaky(9999), ErrUnavailable, "http", 500},
		{"400", 400, "\n", ErrRejected, "http", 400},
		{"404", 404, "\n", ErrRejected, "http", 404},
		{"415", 415, `<html>unsupported</html>`, ErrRejected, "http", 415},
		{"429", 429, "\n", ErrUnavailable, "http", 429},
		{"500 with ErrorCode 101", 500, leaky(101), ErrUnavailable, "response", 101},
		{"500 with ErrorCode 501", 500, leaky(501), ErrUnauthorized, "response", 501},
		{"502", 502, "\n", ErrUnavailable, "http", 502},
		{"503 with ErrorCode 100", 503, leaky(100), ErrUnavailable, "response", 100},
		{"504", 504, "\n", ErrUnavailable, "http", 504},
		{"201 with a success body", 201, `{"ErrorCode":0,"MessageID":"x"}`, ErrUnavailable, "http", 201},
		{"202 with a success body", 202, `{"ErrorCode":0,"MessageID":"x"}`, ErrUnavailable, "http", 202},
		{"204", 204, "", ErrUnavailable, "http", 204},
	}
	for _, code := range []int{300, 402, 403, 406, 410, 411} {
		cases = append(cases, outcomeCase{fmt.Sprintf("422 with ErrorCode %d", code), 422, leaky(code), ErrRejected, "response", code})
	}
	for _, code := range []int{10, 412, 413, 422, 501, 1235, 1236, 1480, 400, 405, 409} {
		cases = append(cases, outcomeCase{fmt.Sprintf("422 with ErrorCode %d", code), 422, leaky(code), ErrUnauthorized, "response", code})
	}
	for _, code := range []int{100, 101} {
		cases = append(cases, outcomeCase{fmt.Sprintf("422 with ErrorCode %d", code), 422, leaky(code), ErrUnavailable, "response", code})
	}
	return cases
}

// TestPostmarkClassifiesEveryAnswer runs the whole table through the stand-in and checks each failure's text against the leak
// markers: the recipient the provider echoes, the token and the sender.
func TestPostmarkClassifiesEveryAnswer(t *testing.T) {
	for _, c := range postmarkCases(testTo) {
		rig := newPostmarkRig(t, mailtest.PostmarkReply{Status: c.status, Body: c.body}, nil)
		err := rig.sender.Send(context.Background(), testMessage())
		if c.class == nil {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		failure, ok := err.(*Error)
		if !ok || failure.Class != c.class || failure.Stage != c.stage || failure.Code != c.code || failure.Provider != "postmark" || failure.Timeout {
			t.Errorf("%s: got %+v, want class %q stage %q code %d", c.name, err, c.class, c.stage, c.code)
			continue
		}
		noLeak(t, err, testTo, rig.token, "Illegal", testFrom)
	}
}

// TestEachCodeOfTheAdaptersTableKeepsItsClassOnA4xxAndA5xx: the adapter's table of 16 ErrorCodes (postmarkKnownCode) decides the
// class on a 5xx too (a code outside the table on a 5xx stays transient), so a code missing from the table would turn an
// operator-must-act refusal into an outage. One row per code of the table, on both statuses; a code outside the table is the
// control and takes the catch-all (how the real service classes the account, sender, stream and source-address codes is NOT
// PROVEN until the first live send).
func TestEachCodeOfTheAdaptersTableKeepsItsClassOnA4xxAndA5xx(t *testing.T) {
	published := map[int]error{10: ErrUnauthorized, 100: ErrUnavailable, 101: ErrUnavailable, 300: ErrRejected, 402: ErrRejected, 403: ErrRejected,
		406: ErrRejected, 410: ErrRejected, 411: ErrRejected, 412: ErrUnauthorized, 413: ErrUnauthorized, 422: ErrUnauthorized, 501: ErrUnauthorized,
		1235: ErrUnauthorized, 1236: ErrUnauthorized, 1480: ErrUnauthorized}
	for code, want := range published {
		reply := postmarkResponse{ErrorCode: &code, MessageID: "x"}
		for _, status := range []int{422, 500} {
			if _, got, class := postmarkOutcome(status, reply, true); class != want || got != code {
				t.Errorf("code %d on %d: class %v code %d, want %v", code, status, class, got, want)
			}
		}
	}
	unpublished := 99999
	reply := postmarkResponse{ErrorCode: &unpublished, MessageID: "x"}
	if _, _, class := postmarkOutcome(500, reply, true); class != ErrUnavailable {
		t.Errorf("an unpublished code on a 500: %v", class)
	}
	if _, _, class := postmarkOutcome(422, reply, true); class != ErrUnauthorized {
		t.Errorf("an unpublished code on a 422: %v", class)
	}
}

// TestPostmarkOutcomeIsAPureFunctionOfStatusAndBody pins the decision table without a server, including statuses a server cannot
// easily produce.
func TestPostmarkOutcomeIsAPureFunctionOfStatusAndBody(t *testing.T) {
	code := func(n int) postmarkResponse { return postmarkResponse{ErrorCode: &n, MessageID: "x"} }
	zero := func(id string) postmarkResponse { n := 0; return postmarkResponse{ErrorCode: &n, MessageID: id} }
	for _, c := range []struct {
		name   string
		status int
		reply  postmarkResponse
		parsed bool
		class  error
		stage  string
		code   int
	}{
		{"success", 200, zero("id"), true, nil, "", 0},
		{"success without parse", 200, postmarkResponse{}, false, ErrUnavailable, "response", 0},
		{"1xx", 100, postmarkResponse{}, false, ErrUnavailable, "http", 100},
		{"199", 199, postmarkResponse{}, false, ErrUnavailable, "http", 199},
		{"299", 299, zero("id"), true, ErrUnavailable, "http", 299},
		{"300", 300, postmarkResponse{}, false, ErrUnavailable, "http", 300},
		{"399", 399, postmarkResponse{}, false, ErrUnavailable, "http", 399},
		{"422 with 1235", 422, code(1235), true, ErrUnauthorized, "response", 1235},
		{"422 unparsed", 422, code(1235), false, ErrRejected, "http", 422},
		{"418 with ErrorCode 300", 418, code(300), true, ErrRejected, "response", 300},
		{"418 unparsed", 418, postmarkResponse{}, false, ErrRejected, "http", 418},
		{"599 with the published code 501", 599, code(501), true, ErrUnauthorized, "response", 501},
		{"599 with an unknown code", 599, code(9999), true, ErrUnavailable, "http", 599},
		{"599", 599, postmarkResponse{}, false, ErrUnavailable, "http", 599},
		{"429 with a code", 429, code(300), true, ErrUnavailable, "http", 429},
		{"401 with a code", 401, code(300), true, ErrUnauthorized, "http", 401},
	} {
		stage, got, class := postmarkOutcome(c.status, c.reply, c.parsed)
		if class != c.class || stage != c.stage || got != c.code {
			t.Errorf("%s: %v %q %d, want %v %q %d", c.name, class, stage, got, c.class, c.stage, c.code)
		}
	}
}

// TestPostmarkDoesNotFollowARedirectAndTheTargetSeesNothing: the token header would follow the redirect to another host, so five
// redirect statuses are failures and zero requests reach the target.
func TestPostmarkDoesNotFollowARedirectAndTheTargetSeesNothing(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		target := mailtest.StartPostmark(t, sentinel("postmark-token"), mailtest.PostmarkReply{})
		rig := newPostmarkRig(t, mailtest.PostmarkReply{Status: status, Location: target.URL()}, nil)
		expectFailure(t, rig.sender.Send(context.Background(), testMessage()), ErrUnavailable, "http", status)
		if got := len(target.Requests()); got != 0 || len(rig.server.Requests()) != 1 {
			t.Errorf("status %d: the target saw %d requests, the first server %d", status, got, len(rig.server.Requests()))
		}
	}
	// The redirect policy also holds for an injected client, whatever its own policy says.
	target := mailtest.StartPostmark(t, sentinel("postmark-token"), mailtest.PostmarkReply{})
	rig := newPostmarkRig(t, mailtest.PostmarkReply{Status: 307, Location: target.URL()}, func(o *PostmarkOptions) { o.Client = &http.Client{} })
	expectFailure(t, rig.sender.Send(context.Background(), testMessage()), ErrUnavailable, "http", 307)
	if len(target.Requests()) != 0 {
		t.Error("an injected client followed the redirect")
	}
}

func TestPostmarkDeadlineEndsAStalledRequestAndAStalledBody(t *testing.T) {
	for name, reply := range map[string]struct {
		reply mailtest.PostmarkReply
		stage string
	}{
		"no answer":    {mailtest.PostmarkReply{Stall: true}, "http"},
		"stalled body": {mailtest.PostmarkReply{StallBody: true}, "response"},
		// A complete success answer whose body never ends is not trusted: the read failed, so the outcome is reported as unknown.
		"complete body that never ends": {mailtest.PostmarkReply{StallAfterBody: true}, "response"},
	} {
		rig := newPostmarkRig(t, reply.reply, func(o *PostmarkOptions) { o.Timeout = 300 * time.Millisecond })
		begun := time.Now()
		failure := expectFailure(t, rig.sender.Send(context.Background(), testMessage()), ErrUnavailable, reply.stage, 0)
		if elapsed := time.Since(begun); elapsed > 8*time.Second {
			t.Errorf("%s: the send took %v with a 300 ms deadline", name, elapsed)
		}
		if !failure.Timeout {
			t.Errorf("%s: Timeout is false although the deadline ended the send", name)
		}
	}
}

// TestPostmarkReadsAtMostTheCapOfAnAnswer measures both layers of the response bound separately: the reader cap (an endless body is
// abandoned, measured by the bytes the server managed to write) and the length check (a valid success answer followed by padding
// beyond the cap is not an acceptance, which the reader cap alone would let through because the padding is whitespace).
func TestPostmarkReadsAtMostTheCapOfAnAnswer(t *testing.T) {
	t.Run("reader cap", func(t *testing.T) {
		rig := newPostmarkRig(t, mailtest.PostmarkReply{Flood: true}, func(o *PostmarkOptions) { o.Timeout = 2 * time.Second })
		begun := time.Now()
		expectFailure(t, rig.sender.Send(context.Background(), testMessage()), ErrUnavailable, "response", 0)
		if elapsed := time.Since(begun); elapsed > time.Second {
			t.Errorf("an endless body held the send for %v: it was read to the deadline", elapsed)
		}
		time.Sleep(100 * time.Millisecond) // let the stand-in notice the closed connection
		if written := rig.server.BytesWritten(); written >= mailtest.FloodLimit/2 {
			t.Errorf("the server could write %d of %d bytes of an endless answer: the reader cap is gone", written, mailtest.FloodLimit)
		}
	})
	t.Run("length check", func(t *testing.T) {
		padded := `{"ErrorCode":0,"Message":"OK","MessageID":"message-id-test-0001"}` + strings.Repeat(" ", maxPostmarkResponse)
		rig := newPostmarkRig(t, mailtest.PostmarkReply{Body: padded}, nil)
		expectFailure(t, rig.sender.Send(context.Background(), testMessage()), ErrUnavailable, "response", 0)
		prefix := `{"ErrorCode":0,"Message":"OK","MessageID":"message-id-test-0001"}`
		fits := prefix + strings.Repeat(" ", maxPostmarkResponse-len(prefix))
		over := newPostmarkRig(t, mailtest.PostmarkReply{Body: fits + " "}, nil)
		expectFailure(t, over.sender.Send(context.Background(), testMessage()), ErrUnavailable, "response", 0) // exactly the cap plus one byte
		fitting := newPostmarkRig(t, mailtest.PostmarkReply{Body: fits}, nil)
		if err := fitting.sender.Send(context.Background(), testMessage()); err != nil {
			t.Errorf("an answer of exactly the cap is refused: %v", err)
		}
	})
}

func TestPostmarkRefusesInjectionFormsBeforeAnyRequest(t *testing.T) {
	rig := newPostmarkRig(t, mailtest.PostmarkReply{}, nil)
	for name, message := range map[string]Message{
		"recipient list":         {To: "a@example.test,b@example.test", Subject: "s", Text: "t"},
		"recipient with name":    {To: "Ada <a@example.test>", Subject: "s", Text: "t"},
		"recipient with CRLF":    {To: "a@example.test\r\nBcc: b@example.test", Subject: "s", Text: "t"},
		"recipient IP literal":   {To: "a@127.0.0.1", Subject: "s", Text: "t"},
		"subject with CRLF":      {To: testTo, Subject: "s\r\nBcc: b@example.test", Text: "t"},
		"subject encoded word":   {To: testTo, Subject: "=?utf-8?q?x?=", Text: "t"},
		"text with a NUL":        {To: testTo, Subject: "s", Text: "a\x00b"},
		"empty text":             {To: testTo, Subject: "s"},
		"oversized text":         {To: testTo, Subject: "s", Text: strings.Repeat("t", MaxTextBytes+1)},
		"invalid UTF-8 in text":  {To: testTo, Subject: "s", Text: "a\xff"},
		"subject over the bound": {To: testTo, Subject: strings.Repeat("s", MaxSubjectBytes+1), Text: "t"},
	} {
		if failure, ok := rig.sender.Send(context.Background(), message).(*Error); !ok || failure.Class != ErrRejected || failure.Stage != "message" {
			t.Errorf("%s: %v", name, failure)
		}
	}
	for _, sender := range []struct{ from, name string }{{"", ""}, {"a@127.0.0.1", ""}, {testFrom, "Ada\r\nBcc: x@example.test"}, {testFrom, "=?utf-8?q?x?="}} {
		bad := newPostmarkRig(t, mailtest.PostmarkReply{}, func(o *PostmarkOptions) { o.From, o.FromName = sender.from, sender.name })
		expectFailure(t, bad.sender.Send(context.Background(), testMessage()), ErrRejected, "message", 0)
		if len(bad.server.Requests()) != 0 {
			t.Errorf("a request went out for the sender %+v", sender)
		}
	}
	if got := len(rig.server.Requests()); got != 0 {
		t.Errorf("%d requests for refused messages", got)
	}
}

func TestPostmarkWithAWrongTokenIsUnauthorizedAndTheTokenIsNeverPrinted(t *testing.T) {
	rig := newPostmarkRig(t, mailtest.PostmarkReply{}, func(o *PostmarkOptions) { o.Token = config.NewSecret(sentinel("another-token")) })
	err := rig.sender.Send(context.Background(), testMessage())
	expectFailure(t, err, ErrUnauthorized, "http", 401)
	noLeak(t, err, rig.token, sentinel("another-token"), testTo)
}

// TestPostmarkDefaultEndpointIsTheDocumentedHTTPSURL: with no BaseURL the request goes to the constant https endpoint (recorded
// through an injected RoundTripper, so nothing leaves the machine). Together with the source pin that no non-test file sets
// BaseURL, this is why the adapter needs no scheme check of its own.
func TestPostmarkDefaultEndpointIsTheDocumentedHTTPSURL(t *testing.T) {
	var seen []string
	transport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		seen = append(seen, r.Method+" "+r.URL.String())
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ErrorCode":0,"MessageID":"x"}`)), Header: http.Header{}, Request: r}, nil
	})
	sender := NewPostmark(PostmarkOptions{Token: config.NewSecret(sentinel("postmark-token")), From: testFrom, Client: &http.Client{Transport: transport}})
	if err := sender.Send(context.Background(), testMessage()); err != nil {
		t.Fatal(err)
	}
	if want := "POST https://api.postmarkapp.com/email"; len(seen) != 1 || seen[0] != want || postmarkURL != "https://api.postmarkapp.com/email" {
		t.Errorf("requests %v, constant %q", seen, postmarkURL)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPostmarkRecoversAPanicOfItsTransportAndDefaultsItsTimeout(t *testing.T) {
	panicking := roundTripperFunc(func(*http.Request) (*http.Response, error) { panic("a panic in the transport") })
	sender := NewPostmark(PostmarkOptions{Token: config.NewSecret(sentinel("postmark-token")), From: testFrom, Client: &http.Client{Transport: panicking}})
	expectFailure(t, sender.Send(context.Background(), testMessage()), ErrUnavailable, "panic", 0)
	if sender.o.Timeout != DefaultTimeout || NewPostmark(PostmarkOptions{Timeout: -1}).o.Timeout != DefaultTimeout || NewPostmark(PostmarkOptions{Timeout: time.Second}).o.Timeout != time.Second {
		t.Error("the timeout default or an explicit timeout is wrong")
	}
	if !sender.Enabled() {
		t.Error("the sender is disabled")
	}
}

func TestPostmarkConnectionFailureIsUnavailableWithoutAnAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	url := "http://" + ln.Addr().String() + "/email"
	_ = ln.Close() // nothing listens any more
	sender := NewPostmark(PostmarkOptions{Token: config.NewSecret(sentinel("postmark-token")), From: testFrom, BaseURL: url, Timeout: 5 * time.Second})
	err = sender.Send(context.Background(), testMessage())
	failure := expectFailure(t, err, ErrUnavailable, "http", 0)
	noLeak(t, err, url, ln.Addr().String(), testTo)
	if failure.Timeout {
		t.Error("a refused connection is marked as a timeout")
	}
}

// TestPostmarkVerifiesTheServerCertificate: the token header rides on this channel. Through the constructor's own default transport
// (Client nil) a TLS server whose certificate the system roots do not trust is a failure, and the handler is never entered. The
// mutants "InsecureSkipVerify", "VerifyConnection returns nil" and "a plain DialTLSContext" are killed by this test only.
func TestPostmarkVerifiesTheServerCertificate(t *testing.T) {
	var entered atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered.Add(1)
		_, _ = io.WriteString(w, `{"ErrorCode":0,"MessageID":"x"}`)
	}))
	t.Cleanup(server.Close)
	options := PostmarkOptions{Token: config.NewSecret(sentinel("postmark-token")), From: testFrom, BaseURL: server.URL, Timeout: 5 * time.Second}
	err := NewPostmark(options).Send(context.Background(), testMessage())
	expectFailure(t, err, ErrUnavailable, "http", 0)
	noLeak(t, err, server.URL, "certificate", "x509")
	if entered.Load() != 0 {
		t.Fatalf("the handler was entered %d times: the certificate was not verified", entered.Load())
	}
	// The harness is sound: with the server's own client (which trusts its certificate) the same request is accepted.
	options.Client = server.Client()
	if err = NewPostmark(options).Send(context.Background(), testMessage()); err != nil || entered.Load() != 1 {
		t.Fatalf("a trusted certificate is refused: %v (handler entered %d times)", err, entered.Load())
	}
}

// The environment variables that hand the re-executed child of the proxy test its fake proxy and its local stand-in.
const (
	proxyChildEnvironment   = "ARCFORGES_TEST_MAIL_PROXY_CHILD"
	proxyStandInEnvironment = "ARCFORGES_TEST_MAIL_PROXY_STANDIN"
)

// TestPostmarkNeverUsesTheEnvironmentProxy has two layers, each with its own test. The structural layer is deterministic: the
// default transport has no proxy function. The behavioural layer re-executes this test binary with a fake proxy in the environment
// (net/http reads the environment once per process, so an in-process test cannot do it reliably) and is HERMETIC: the adapter is
// built with the test-only Dial hook, the target is the made-up non-loopback name postmark.test.invalid (Go exempts loopback
// destinations from proxying, which is why the name must not be loopback), the hook maps that name to a local listener and FAILS
// the child if it is ever asked to dial the proxy address or anything else. No name is resolved and no packet leaves the host.
func TestPostmarkNeverUsesTheEnvironmentProxy(t *testing.T) {
	if os.Getenv(proxyChildEnvironment) == "1" {
		proxyChild(t)
		return
	}
	t.Run("structural", func(t *testing.T) {
		transport, ok := NewPostmark(PostmarkOptions{}).client.Transport.(*http.Transport)
		if !ok || transport.Proxy != nil {
			t.Fatalf("the default transport is %T with a proxy function", NewPostmark(PostmarkOptions{}).client.Transport)
		}
	})
	t.Run("behavioural", func(t *testing.T) {
		proxy := localListener(t)
		standIn := localListener(t)
		child := exec.Command(os.Args[0], "-test.run=^TestPostmarkNeverUsesTheEnvironmentProxy$", "-test.count=1", "-test.timeout=60s")
		proxyURL := "http://" + proxy.addr
		child.Env = append(slices.DeleteFunc(os.Environ(), func(entry string) bool {
			upper := strings.ToUpper(entry)
			return strings.HasPrefix(upper, "HTTP_PROXY=") || strings.HasPrefix(upper, "HTTPS_PROXY=") || strings.HasPrefix(upper, "NO_PROXY=") || strings.HasPrefix(upper, "ALL_PROXY=")
		}), proxyChildEnvironment+"=1", proxyStandInEnvironment+"="+standIn.addr, "HTTP_PROXY="+proxyURL, "http_proxy="+proxyURL,
			"HTTPS_PROXY="+proxyURL, "https_proxy="+proxyURL, "NO_PROXY=", "no_proxy=")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("the child failed: %v\n%s", err, output)
		}
		if got := proxy.accepted.Load(); got != 0 {
			t.Fatalf("the fake proxy accepted %d connections: the adapter used the environment proxy", got)
		}
	})
}

// counted is a loopback listener that accepts and closes every connection and counts them.
type counted struct {
	addr     string
	accepted atomic.Int64
}

func localListener(t *testing.T) *counted {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	l := &counted{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			l.accepted.Add(1)
			_ = conn.Close()
		}
	}()
	return l
}

// proxyChild runs inside the child process: it proves the environment is seen (a control), then sends through the default
// transport to a made-up host name over http and https, and requires that the adapter asked its dialer for exactly that name and
// port and never for the proxy.
func proxyChild(t *testing.T) {
	standIn := os.Getenv(proxyStandInEnvironment)
	proxy := strings.TrimPrefix(os.Getenv("HTTP_PROXY"), "http://")
	var mu sync.Mutex
	var asked []string
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		asked = append(asked, address)
		mu.Unlock()
		if address != "postmark.test.invalid:80" && address != "postmark.test.invalid:443" {
			return nil, errors.New("the adapter dialled an address it must not dial")
		}
		return (&net.Dialer{}).DialContext(ctx, network, standIn)
	}
	for _, target := range []string{"http://postmark.test.invalid/email", "https://postmark.test.invalid/email"} {
		probe, _ := http.NewRequest(http.MethodPost, target, nil)
		if seen, err := http.ProxyFromEnvironment(probe); err != nil || seen == nil || seen.Host != proxy {
			t.Fatalf("control: the environment proxy is not seen for %s (%v)", target, err)
		}
		sender := NewPostmark(PostmarkOptions{Token: config.NewSecret(sentinel("postmark-token")), From: testFrom, BaseURL: target, Dial: dial, Timeout: 2 * time.Second})
		if err := sender.Send(context.Background(), testMessage()); err == nil {
			t.Fatalf("a send to %s succeeded against a stand-in that answers nothing", target)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"postmark.test.invalid:80", "postmark.test.invalid:443"}; !slices.Equal(asked, want) {
		t.Fatalf("the dialer was asked for %v, want exactly %v (an address of the proxy would be the environment proxy; none would be a hook that is not used)", asked, want)
	}
}

// timeoutError is a net.Error that reports a timeout while the context of the send is still live (a dial or handshake limit of the
// transport that fires before the send deadline).
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// TestPostmarkTimeoutNeverTravelsWithACode applies the one Timeout rule of both adapters (no code, and the deadline): a status or an
// ErrorCode that arrived is not a timeout even when the body behind it stalls or ends early; a transport-level timeout that fires
// before the send deadline is one; a body cut short without any deadline is not.
func TestPostmarkTimeoutNeverTravelsWithACode(t *testing.T) {
	for _, status := range []int{401, 422, 500, 503} {
		rig := newPostmarkRig(t, mailtest.PostmarkReply{Status: status, StallBody: true}, func(o *PostmarkOptions) { o.Timeout = 300 * time.Millisecond })
		err := rig.sender.Send(context.Background(), testMessage())
		failure := typed(t, err)
		if failure.Code != status || failure.Timeout {
			t.Errorf("status %d with a body that stalls: %v (code %d, timeout %v)", status, err, failure.Code, failure.Timeout)
		}
	}
	truncated := newPostmarkRig(t, mailtest.PostmarkReply{Truncate: true}, nil)
	failure := expectFailure(t, truncated.sender.Send(context.Background(), testMessage()), ErrUnavailable, "response", 0)
	if failure.Timeout {
		t.Error("a body that ends early without any deadline is reported as a timeout")
	}
	slow := roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, timeoutError{} })
	sender := NewPostmark(PostmarkOptions{Token: config.NewSecret(sentinel("postmark-token")), From: testFrom, Client: &http.Client{Transport: slow}, Timeout: 30 * time.Second})
	failure = expectFailure(t, sender.Send(context.Background(), testMessage()), ErrUnavailable, "http", 0)
	if !failure.Timeout {
		t.Error("a timeout of the transport that fires before the send deadline is not reported as a timeout")
	}
}

// TestPostmarkTLSConfigurationIsPinnedByValue is the structural layer of the TLS floor: the value of every field of the default
// transport that matters for the channel carrying the token.
func TestPostmarkTLSConfigurationIsPinnedByValue(t *testing.T) {
	transport, ok := NewPostmark(PostmarkOptions{}).client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("the default transport is not an *http.Transport")
	}
	c := transport.TLSClientConfig
	if c == nil || c.MinVersion != tls.VersionTLS12 || c.MaxVersion != 0 || c.InsecureSkipVerify || c.CipherSuites != nil || c.Renegotiation != tls.RenegotiateNever ||
		c.KeyLogWriter != nil || c.VerifyConnection != nil || c.VerifyPeerCertificate != nil || c.RootCAs != nil || c.ServerName != "" || c.Certificates != nil {
		t.Fatalf("the TLS configuration of the Postmark channel is not the pinned one: %+v", c)
	}
	if transport.Proxy != nil || transport.DialTLSContext != nil || !transport.DisableKeepAlives || transport.MaxResponseHeaderBytes != 16<<10 {
		t.Errorf("the transport differs from the pinned one: %+v", transport)
	}
}

// TestPostmarkRefusesAServerThatOffersOnlyOldTLS is the behavioural layer, through the production transport settings (only the
// roots differ, so that the test server can be trusted): a server limited to TLS 1.1 is refused and its handler never entered, while
// the same server at TLS 1.2 is accepted (the control). Lowering the floor makes the first half fail.
func TestPostmarkRefusesAServerThatOffersOnlyOldTLS(t *testing.T) {
	for _, c := range []struct {
		name string
		max  uint16
		ok   bool
	}{{"TLS 1.1 only", tls.VersionTLS11, false}, {"TLS 1.2", tls.VersionTLS12, true}} {
		var entered atomic.Int64
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			entered.Add(1)
			_, _ = io.WriteString(w, `{"ErrorCode":0,"MessageID":"x"}`)
		}))
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: c.max}
		server.StartTLS()
		pool := x509.NewCertPool()
		pool.AddCert(server.Certificate())
		transport := postmarkTransport(nil)
		transport.TLSClientConfig.RootCAs = pool // the only difference from production: trust the test server
		sender := NewPostmark(PostmarkOptions{Token: config.NewSecret(sentinel("postmark-token")), From: testFrom, BaseURL: server.URL,
			Client: &http.Client{Transport: transport}, Timeout: 5 * time.Second})
		err := sender.Send(context.Background(), testMessage())
		if c.ok && (err != nil || entered.Load() != 1) {
			t.Errorf("%s: %v (handler entered %d times)", c.name, err, entered.Load())
		}
		if !c.ok {
			expectFailure(t, err, ErrUnavailable, "http", 0)
			if entered.Load() != 0 {
				t.Errorf("%s: the handler was entered: the floor is below TLS 1.2", c.name)
			}
		}
		server.Close()
	}
}

// TestPostmarkBoundsAreTheDesignedOnes pins the values of the transport's bounds and measures the response header limit: an answer
// with a 64 KiB header (above the 16 KiB limit, below Go's default of 1 MiB) is refused.
func TestPostmarkBoundsAreTheDesignedOnes(t *testing.T) {
	if maxPostmarkResponse != 16<<10 || maxPostmarkHeader != 16<<10 {
		t.Fatalf("response bounds %d and %d", maxPostmarkResponse, maxPostmarkHeader)
	}
	rig := newPostmarkRig(t, mailtest.PostmarkReply{FloodHeader: true}, nil)
	expectFailure(t, rig.sender.Send(context.Background(), testMessage()), ErrUnavailable, "http", 0)
}
