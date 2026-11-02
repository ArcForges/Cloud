// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/mail/mailtest"
)

// All Postmark tests are MOCKED: the stand-in of package mailtest or httptest on 127.0.0.1, an injected RoundTripper, or a child
// process whose only network traffic is a connection attempt to a reserved documentation address (see the proxy test).

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
		{"404 with ErrorCode 501", 404, leaky(501), ErrRejected, "http", 404},
		{"HTTP 413 payload", 413, leaky(413), ErrRejected, "http", 413},
		{"400", 400, "\n", ErrRejected, "http", 400},
		{"404", 404, "\n", ErrRejected, "http", 404},
		{"415", 415, `<html>unsupported</html>`, ErrRejected, "http", 415},
		{"429", 429, "\n", ErrUnavailable, "http", 429},
		{"500 with ErrorCode 101", 500, leaky(101), ErrUnavailable, "http", 500},
		{"500 with ErrorCode 501", 500, leaky(501), ErrUnavailable, "http", 500},
		{"502", 502, "\n", ErrUnavailable, "http", 502},
		{"503 with ErrorCode 100", 503, leaky(100), ErrUnavailable, "http", 503},
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
		{"418", 418, code(300), true, ErrRejected, "http", 418},
		{"599", 599, postmarkResponse{}, false, ErrUnavailable, "http", 599},
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
		if written := rig.server.BytesWritten(); written > maxPostmarkResponse+16<<20 {
			t.Errorf("the server could write %d bytes of an endless answer", written)
		}
	})
	t.Run("length check", func(t *testing.T) {
		padded := `{"ErrorCode":0,"Message":"OK","MessageID":"message-id-test-0001"}` + strings.Repeat(" ", maxPostmarkResponse)
		rig := newPostmarkRig(t, mailtest.PostmarkReply{Body: padded}, nil)
		expectFailure(t, rig.sender.Send(context.Background(), testMessage()), ErrUnavailable, "response", 0)
		prefix := `{"ErrorCode":0,"Message":"OK","MessageID":"message-id-test-0001"}`
		fits := prefix + strings.Repeat(" ", maxPostmarkResponse-len(prefix))
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

// proxyChildEnvironment marks the child process of TestPostmarkNeverUsesTheEnvironmentProxy.
const proxyChildEnvironment = "ARCFORGES_TEST_MAIL_PROXY_CHILD"

// TestPostmarkNeverUsesTheEnvironmentProxy has two layers, each with its own test. The structural layer is deterministic: the
// default transport has no proxy function. The behavioural layer re-executes this test binary with a fake proxy in the environment
// (net/http reads the environment once per process, so an in-process test cannot do it reliably) and a target on a reserved
// documentation address (a loopback target is exempt from the proxy and would prove nothing); the parent counts the connections its
// fake proxy accepts. The child's only traffic is a connection attempt to 192.0.2.1, an address reserved for documentation.
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
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		var accepted atomic.Int64
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				accepted.Add(1)
				_ = conn.Close()
			}
		}()
		proxy := "http://" + ln.Addr().String()
		child := exec.Command(os.Args[0], "-test.run=^TestPostmarkNeverUsesTheEnvironmentProxy$", "-test.count=1", "-test.timeout=60s")
		child.Env = append(slices.DeleteFunc(os.Environ(), func(entry string) bool {
			upper := strings.ToUpper(entry)
			return strings.HasPrefix(upper, "HTTP_PROXY=") || strings.HasPrefix(upper, "HTTPS_PROXY=") || strings.HasPrefix(upper, "NO_PROXY=") || strings.HasPrefix(upper, "ALL_PROXY=")
		}), proxyChildEnvironment+"=1", "HTTP_PROXY="+proxy, "http_proxy="+proxy, "HTTPS_PROXY="+proxy, "https_proxy="+proxy, "NO_PROXY=", "no_proxy=")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("the child failed: %v\n%s", err, output)
		}
		if got := accepted.Load(); got != 0 {
			t.Fatalf("the fake proxy accepted %d connections: the adapter used the environment proxy", got)
		}
	})
}

// proxyChild runs inside the child process: it proves the environment is seen (a control), then sends through the default transport
// to a non-loopback address over http and https.
func proxyChild(t *testing.T) {
	for _, target := range []string{"http://192.0.2.1:9/email", "https://192.0.2.1:9/email"} {
		probe, _ := http.NewRequest(http.MethodPost, target, nil)
		if seen, err := http.ProxyFromEnvironment(probe); err != nil || seen == nil {
			t.Fatalf("control: the environment proxy is not seen for %s (%v)", target, err)
		}
		sender := NewPostmark(PostmarkOptions{Token: config.NewSecret(sentinel("postmark-token")), From: testFrom, BaseURL: target, Timeout: 400 * time.Millisecond})
		if err := sender.Send(context.Background(), testMessage()); err == nil {
			t.Fatalf("a send to %s succeeded", target)
		}
	}
}
