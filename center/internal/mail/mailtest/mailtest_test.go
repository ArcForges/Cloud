// SPDX-License-Identifier: AGPL-3.0-only

package mailtest

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"testing"
	"time"
)

// Everything here is MOCKED: the test doubles are driven by raw clients and the standard library's own SMTP client on 127.0.0.1.

const hostName = "smtp.example.test"

// wire is a raw line-oriented client for the protocol-level behaviours.
type wire struct {
	t      *testing.T
	conn   net.Conn
	reader *bufio.Reader
}

func dialWire(t *testing.T, address string) *wire {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return &wire{t: t, conn: conn, reader: bufio.NewReader(conn)}
}

func (w *wire) send(text string) {
	w.t.Helper()
	if _, err := io.WriteString(w.conn, text); err != nil {
		w.t.Fatal(err)
	}
}

// reply reads one reply (all lines of a multi-line reply) and returns it without line ends.
func (w *wire) reply() string {
	w.t.Helper()
	var lines []string
	for {
		text, err := w.reader.ReadString('\n')
		if err != nil {
			w.t.Fatalf("reading a reply after %q: %v", lines, err)
		}
		text = strings.TrimRight(text, "\r\n")
		lines = append(lines, text)
		if len(text) < 4 || text[3] != '-' {
			return strings.Join(lines, "\n")
		}
	}
}

func (w *wire) expect(prefix string) string {
	w.t.Helper()
	got := w.reply()
	if !strings.HasPrefix(got, prefix) {
		w.t.Fatalf("got %q, want a reply starting %q", got, prefix)
	}
	return got
}

// silent reports that nothing arrives within the window.
func (w *wire) silent(window time.Duration) bool {
	w.t.Helper()
	_ = w.conn.SetReadDeadline(time.Now().Add(window))
	defer func() { _ = w.conn.SetReadDeadline(time.Now().Add(10 * time.Second)) }()
	_, err := w.reader.Peek(1)
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}

func newServer(t *testing.T, modify func(*SMTPOptions)) (*SMTPServer, *CA) {
	t.Helper()
	ca := NewCA(t, "mailtest test CA")
	opts := SMTPOptions{Certificate: ca.Leaf(t, hostName)}
	if modify != nil {
		modify(&opts)
	}
	return StartSMTP(t, opts), ca
}

// upgrade runs the TLS handshake of a wire client against the CA.
func (w *wire) upgrade(ca *CA) {
	w.t.Helper()
	secured := tls.Client(w.conn, &tls.Config{ServerName: hostName, RootCAs: ca.Pool(), MinVersion: tls.VersionTLS12})
	if err := secured.Handshake(); err != nil {
		w.t.Fatal(err)
	}
	w.conn, w.reader = secured, bufio.NewReader(secured)
}

func TestACAIssuesCertificatesThatOnlyItsPoolTrusts(t *testing.T) {
	first, second := NewCA(t, "first"), NewCA(t, "second")
	leaf := first.Leaf(t, hostName, "other.example.test")
	for _, check := range []struct {
		name string
		pool *CA
		host string
		ok   bool
	}{
		{"its own pool, first name", first, hostName, true},
		{"its own pool, second name", first, "other.example.test", true},
		{"its own pool, another name", first, "elsewhere.example.test", false},
		{"another authority", second, hostName, false},
	} {
		ln, err := net.Listen("tcp", "127.0.0.1:0") // a real socket: a synchronous net.Pipe deadlocks when both sides write
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			if conn, err := ln.Accept(); err == nil {
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				_ = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{leaf}}).Handshake()
				_ = conn.Close()
			}
		}()
		client, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = client.SetDeadline(time.Now().Add(5 * time.Second))
		err = tls.Client(client, &tls.Config{ServerName: check.host, RootCAs: check.pool.Pool(), MinVersion: tls.VersionTLS12}).Handshake()
		if (err == nil) != check.ok {
			t.Errorf("%s: handshake error %v", check.name, err)
		}
		_ = client.Close()
		_ = ln.Close()
	}
}

func TestSMTPServerAcceptsAMessageOverSTARTTLS(t *testing.T) {
	server, ca := newServer(t, nil)
	host, port, _ := net.SplitHostPort(server.Addr())
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client, err := smtp.NewClient(conn, hostName)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Hello("client.example.test"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := client.Extension("STARTTLS"); !ok {
		t.Fatal("STARTTLS is not offered")
	}
	if err = client.StartTLS(&tls.Config{ServerName: hostName, RootCAs: ca.Pool(), MinVersion: tls.VersionTLS12}); err != nil {
		t.Fatal(err)
	}
	if err = client.Auth(smtp.PlainAuth("", "user-word", "password-word", hostName)); err != nil {
		t.Fatal(err)
	}
	if err = client.Mail("from@example.test"); err != nil {
		t.Fatal(err)
	}
	if err = client.Rcpt("to@example.test"); err != nil {
		t.Fatal(err)
	}
	writer, err := client.Data()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write([]byte("Subject: x\r\n\r\n.leading dot\r\n.\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err = client.Quit(); err != nil {
		t.Fatal(err)
	}
	sessions := server.Captures()
	if len(sessions) != 1 || server.Connections() != 1 {
		t.Fatalf("%d sessions, %d connections", len(sessions), server.Connections())
	}
	c := sessions[0]
	if !c.TLS || c.AuthSeenBeforeTLS || c.User != "user-word" || c.Password != "password-word" || !c.Quit {
		t.Errorf("session: tls=%v authBefore=%v user=%q password=%q quit=%v", c.TLS, c.AuthSeenBeforeTLS, c.User, c.Password, c.Quit)
	}
	if want := "Subject: x\r\n\r\n.leading dot\r\n.\r\nbody\r\n"; string(c.Data) != want {
		t.Errorf("data %q, want %q (one leading dot removed per line)", c.Data, want)
	}
	if !strings.HasPrefix(c.From, "MAIL FROM:<from@example.test>") || len(c.Rcpt) != 1 || !strings.HasPrefix(c.Rcpt[0], "RCPT TO:<to@example.test>") {
		t.Errorf("envelope %q %q", c.From, c.Rcpt)
	}
	if plain := c.Plain.String(); !strings.HasPrefix(plain, "EHLO client.example.test\r\nSTARTTLS\r\n") || strings.Contains(plain, "AUTH") ||
		strings.Contains(plain, "MAIL") || strings.Contains(plain, "password-word") {
		t.Errorf("clear-text transcript %q holds more than EHLO and STARTTLS", plain)
	}
	if len(c.Hello) < 2 {
		t.Errorf("EHLO lines %q (one before and one after STARTTLS)", c.Hello)
	}
}

func TestSMTPServerImplicitTLSAndOptionsOfTheEnvelope(t *testing.T) {
	server, ca := newServer(t, func(o *SMTPOptions) { o.Implicit = true })
	w := dialWire(t, server.Addr())
	w.upgrade(ca)
	w.expect("220 " + hostName)
	w.send("EHLO c.example.test\r\n")
	if got := w.expect("250-" + hostName); strings.Contains(got, "STARTTLS") {
		t.Errorf("STARTTLS is advertised inside an implicit TLS session: %q", got)
	}
	w.send("STARTTLS\r\n")
	w.expect("502")
	w.send("QUIT\r\n")
	w.expect("221")
	if sessions := server.Captures(); len(sessions) != 1 || !sessions[0].TLS || sessions[0].Plain.Len() != 0 {
		t.Errorf("implicit TLS: %+v", sessions)
	}
}

func TestSMTPServerDowngradeAndClearTextAuthAreRefusedAndRecorded(t *testing.T) {
	server, _ := newServer(t, func(o *SMTPOptions) { o.NoStartTLS = true })
	w := dialWire(t, server.Addr())
	w.expect("220")
	w.send("EHLO c.example.test\r\n")
	if got := w.expect("250-"); strings.Contains(got, "STARTTLS") {
		t.Errorf("STARTTLS is advertised although NoStartTLS is set: %q", got)
	}
	w.send("STARTTLS\r\n")
	w.expect("502")
	w.send("AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00user-word\x00password-word")) + "\r\n")
	w.expect("530")
	w.send("QUIT\r\n")
	w.expect("221")
	c := server.Captures()[0]
	if !c.AuthSeenBeforeTLS || c.User != "" || c.TLS {
		t.Errorf("clear-text AUTH: seen=%v user=%q tls=%v", c.AuthSeenBeforeTLS, c.User, c.TLS)
	}
	if !strings.Contains(c.Plain.String(), "AUTH PLAIN") {
		t.Errorf("the transcript %q lacks the clear-text AUTH", c.Plain.String())
	}
}

func TestSMTPServerRepliesCanBeReplaced(t *testing.T) {
	server, ca := newServer(t, func(o *SMTPOptions) {
		o.AuthReply, o.MailReply, o.RcptReply = "535 5.7.8 auth word", "553 mail word", "550 rcpt word"
		o.EHLOReply = "250-" + hostName + "\r\n250-STARTTLS\r\n250 AUTH PLAIN"
	})
	w := dialWire(t, server.Addr())
	w.expect("220")
	w.send("EHLO c.example.test\r\n")
	if got := w.expect("250-"); strings.Contains(got, "8BITMIME") {
		t.Errorf("the EHLO reply was not replaced: %q", got)
	}
	w.send("STARTTLS\r\n")
	w.expect("220")
	w.upgrade(ca)
	w.send("AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00u\x00p")) + "\r\n")
	w.expect("535 5.7.8 auth word")
	w.send("MAIL FROM:<a@example.test>\r\n")
	w.expect("553 mail word")
	w.send("RCPT TO:<a@example.test>\r\n")
	w.expect("550 rcpt word")
	w.send("NOOP\r\n")
	w.expect("250")
	w.send("BOGUS\r\n")
	w.expect("500")
	w.send("QUIT\r\n")
	w.expect("221")
	server.Captures()

	refused, _ := newServer(t, func(o *SMTPOptions) { o.GreetingReply = "554 5.7.1 blocked" })
	w = dialWire(t, refused.Addr())
	w.expect("554 5.7.1 blocked")
	if _, err := w.reader.ReadByte(); err == nil {
		t.Error("the connection stays open after a refusing greeting")
	}
}

// TestSMTPServerRefusesALineThatIsNotPlainCRLF pins the strictness of the DATA loop with a raw-wire client (MOCKED: this models a
// rule; it is not a statement about a real provider): a bare LF, a bare CR and a CR inside a line are each counted and the message
// is refused with 501, while a clean message is accepted.
func TestSMTPServerRefusesALineThatIsNotPlainCRLF(t *testing.T) {
	for _, form := range []struct {
		name, data string
		bad        int
	}{
		{"clean", "Subject: x\r\n\r\nbody\r\n", 0},
		{"bare LF", "Subject: x\r\n\r\nbody\n", 1},
		{"bare CR", "Subject: x\r\n\r\nbo\rdy\r\n", 1},
		{"CR then LF inside two lines", "Subject: x\r\nA: b\r\r\n\r\nbody\r\n", 1},
		{"all bare LF", "Subject: x\n\nbody\n", 3},
	} {
		server, ca := newServer(t, nil)
		w := dialWire(t, server.Addr())
		w.expect("220")
		w.send("EHLO c.example.test\r\nSTARTTLS\r\n")
		w.expect("250-")
		w.expect("220")
		w.upgrade(ca)
		w.send("EHLO c.example.test\r\nMAIL FROM:<a@example.test>\r\n")
		w.expect("250-")
		w.expect("250 2.1.0")
		w.send("RCPT TO:<b@example.test>\r\nDATA\r\n")
		w.expect("250 2.1.5")
		w.expect("354")
		w.send(form.data + ".\r\n")
		got := w.reply()
		w.send("QUIT\r\n")
		w.expect("221")
		c := server.Captures()[0]
		if c.DataViolations != form.bad {
			t.Errorf("%s: %d violations, want %d", form.name, c.DataViolations, form.bad)
		}
		if (form.bad == 0) != strings.HasPrefix(got, "250") || (form.bad > 0) != strings.HasPrefix(got, "501") {
			t.Errorf("%s: reply %q", form.name, got)
		}
	}
}

func TestSMTPServerMisbehavioursDoWhatTheyNameAndEndWithTheClient(t *testing.T) {
	type behaviour struct {
		name   string
		modify func(*SMTPOptions)
		drive  func(t *testing.T, w *wire, ca *CA, server *SMTPServer)
	}
	greet := func(w *wire) {
		w.expect("220")
		w.send("EHLO c.example.test\r\n")
		w.expect("250-")
	}
	for _, b := range []behaviour{
		{"StallGreeting", func(o *SMTPOptions) { o.StallGreeting = true }, func(t *testing.T, w *wire, _ *CA, _ *SMTPServer) {
			if !w.silent(150 * time.Millisecond) {
				t.Error("the server spoke")
			}
		}},
		{"StallAfterGreeting", func(o *SMTPOptions) { o.StallAfterGreeting = true }, func(t *testing.T, w *wire, _ *CA, _ *SMTPServer) {
			w.expect("220")
			w.send("EHLO c.example.test\r\n")
			if !w.silent(150 * time.Millisecond) {
				t.Error("the server answered EHLO")
			}
		}},
		{"SilentAfterHandshake", func(o *SMTPOptions) { o.Implicit, o.SilentAfterHandshake = true, true }, func(t *testing.T, w *wire, ca *CA, _ *SMTPServer) {
			w.upgrade(ca) // the handshake completes
			if !w.silent(150 * time.Millisecond) {
				t.Error("the server sent a greeting")
			}
		}},
		{"SilentAfterAuth", func(o *SMTPOptions) { o.SilentAfterAuth, o.AuthReply = true, "535 5.7.8 no" }, func(t *testing.T, w *wire, ca *CA, _ *SMTPServer) {
			w.expect("220")
			w.send("EHLO c.example.test\r\nSTARTTLS\r\n")
			w.expect("250-")
			w.expect("220")
			w.upgrade(ca)
			w.send("AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00u\x00p")) + "\r\n")
			w.expect("535")
			w.send("*\r\n")
			if !w.silent(150 * time.Millisecond) {
				t.Error("the server answered after the AUTH reply")
			}
		}},
		{"SilentQuit", func(o *SMTPOptions) { o.SilentQuit = true }, func(t *testing.T, w *wire, _ *CA, _ *SMTPServer) {
			greet(w)
			w.send("QUIT\r\n")
			if !w.silent(150 * time.Millisecond) {
				t.Error("the server answered QUIT")
			}
		}},
		{"DropAfterData", func(o *SMTPOptions) { o.DropAfterData = true }, func(t *testing.T, w *wire, ca *CA, _ *SMTPServer) {
			w.expect("220")
			w.send("EHLO c.example.test\r\nSTARTTLS\r\n")
			w.expect("250-")
			w.expect("220")
			w.upgrade(ca)
			w.send("EHLO c.example.test\r\nMAIL FROM:<a@example.test>\r\n")
			w.expect("250-")
			w.expect("250 2.1.0")
			w.send("RCPT TO:<b@example.test>\r\nDATA\r\n")
			w.expect("250 2.1.5")
			w.expect("354")
			w.send("Subject: x\r\n\r\nbody\r\n.\r\n")
			if _, err := w.reader.ReadByte(); err == nil {
				t.Error("the server answered the message")
			}
		}},
		{"PipelineAfterStartTLS", func(o *SMTPOptions) { o.PipelineAfterStartTLS = true }, func(t *testing.T, w *wire, _ *CA, _ *SMTPServer) {
			w.expect("220")
			w.send("EHLO c.example.test\r\nSTARTTLS\r\n")
			w.expect("250-")
			w.expect("220 2.0.0")
			w.expect("250 injected in clear text")
		}},
		{"FloodGreeting", func(o *SMTPOptions) { o.FloodGreeting = true }, func(t *testing.T, w *wire, _ *CA, server *SMTPServer) {
			buffer := make([]byte, 1<<20)
			if _, err := io.ReadFull(w.reader, buffer); err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(buffer, []byte("220-xxxx")) {
				t.Errorf("the flood starts %q", buffer[:12])
			}
			_ = w.conn.Close()
			deadline := time.Now().Add(5 * time.Second)
			var before int64
			for time.Now().Before(deadline) {
				before = server.BytesWritten()
				time.Sleep(50 * time.Millisecond)
				if server.BytesWritten() == before {
					break
				}
			}
			if before < 1<<20 || before >= FloodLimit/2 {
				t.Errorf("the server wrote %d bytes after a client that read 1 MiB and left", before)
			}
			if server.BytesWritten() != before {
				t.Error("the flood does not stop when the client goes away")
			}
		}},
	} {
		t.Run(b.name, func(t *testing.T) {
			server, ca := newServer(t, b.modify)
			w := dialWire(t, server.Addr())
			b.drive(t, w, ca, server)
			_ = w.conn.Close()
			if sessions := server.Captures(); len(sessions) != 1 {
				t.Fatalf("%d sessions", len(sessions))
			}
		})
	}
}

func TestPostmarkStandInChecksTheTokenAndRecordsRequests(t *testing.T) {
	token := strings.Join([]string{"synthetic", "word", "built", "postmark", "sentinel"}, "-")
	server := StartPostmark(t, token, PostmarkReply{})
	post := func(header string) (int, string) {
		request, _ := http.NewRequest(http.MethodPost, server.URL(), strings.NewReader(`{"To":"a@example.test"}`))
		request.Header.Set("X-Postmark-Server-Token", header)
		request.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body)
	}
	if status, body := post(token); status != 200 || !strings.Contains(body, `"ErrorCode":0`) || !strings.Contains(body, "MessageID") {
		t.Errorf("accepted token: %d %s", status, body)
	}
	if status, body := post("wrong"); status != 401 || !strings.Contains(body, `"ErrorCode":10`) {
		t.Errorf("wrong token: %d %s", status, body)
	}
	server.Set(PostmarkReply{Status: 422, Body: `{"ErrorCode":300,"Message":"x"}`})
	if status, body := post(token); status != 422 || !strings.Contains(body, "300") {
		t.Errorf("scripted: %d %s", status, body)
	}
	server.Set(PostmarkReply{Status: 301, Location: "http://127.0.0.1:1/elsewhere"})
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, _ := http.NewRequest(http.MethodPost, server.URL(), strings.NewReader("{}"))
	request.Header.Set("X-Postmark-Server-Token", token)
	if response, err := noFollow.Do(request); err != nil || response.StatusCode != 301 || response.Header.Get("Location") == "" {
		t.Errorf("redirect: %v %v", response, err)
	}
	requests := server.Requests()
	if len(requests) != 4 || requests[0].Method != "POST" || requests[0].Path != "/email" || string(requests[0].Body) != `{"To":"a@example.test"}` ||
		requests[0].Header.Get("Content-Type") != "application/json" {
		t.Errorf("recorded %+v", requests)
	}
}

func TestPostmarkStandInMisbehaviours(t *testing.T) {
	token := strings.Join([]string{"synthetic", "word", "built", "postmark", "sentinel"}, "-")
	get := func(server *PostmarkServer, client *http.Client) (*http.Response, error) {
		request, _ := http.NewRequest(http.MethodPost, server.URL(), strings.NewReader("{}"))
		request.Header.Set("X-Postmark-Server-Token", token)
		return client.Do(request)
	}
	t.Run("Stall holds the request until the client gives up", func(t *testing.T) {
		server := StartPostmark(t, token, PostmarkReply{Stall: true})
		_, err := get(server, &http.Client{Timeout: 200 * time.Millisecond})
		if err == nil {
			t.Fatal("a stalled request answered")
		}
	})
	t.Run("StallBody sends headers and part of the body", func(t *testing.T) {
		server := StartPostmark(t, token, PostmarkReply{StallBody: true})
		response, err := get(server, &http.Client{Timeout: 300 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err == nil || !strings.HasPrefix(string(body), `{"ErrorCode":0,"Mess`) {
			t.Errorf("read %q, %v", body, err)
		}
	})
	t.Run("StallAfterBody sends the whole answer and then never ends it", func(t *testing.T) {
		server := StartPostmark(t, token, PostmarkReply{StallAfterBody: true})
		response, err := get(server, &http.Client{Timeout: 300 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err == nil || !strings.Contains(string(body), `"MessageID":"message-id-test-0001"`) {
			t.Errorf("read %q, %v", body, err)
		}
	})
	t.Run("Flood writes until the client goes away", func(t *testing.T) {
		server := StartPostmark(t, token, PostmarkReply{Flood: true})
		response, err := get(server, &http.Client{Timeout: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.ReadFull(response.Body, make([]byte, 256<<10)); err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		deadline, last := time.Now().Add(5*time.Second), int64(-1)
		for time.Now().Before(deadline) && server.BytesWritten() != last {
			last = server.BytesWritten()
			time.Sleep(100 * time.Millisecond)
		}
		if last < 256<<10 || last >= FloodLimit/2 || server.BytesWritten() != last {
			t.Errorf("flood wrote %d then %d", last, server.BytesWritten())
		}
	})
}

func TestTheServersListenOnLoopbackOnly(t *testing.T) {
	server, _ := newServer(t, nil)
	if host, _, err := net.SplitHostPort(server.Addr()); err != nil || host != "127.0.0.1" {
		t.Errorf("SMTP listens on %q: %v", server.Addr(), err)
	}
	post := StartPostmark(t, "x", PostmarkReply{})
	if !strings.HasPrefix(post.URL(), "http://127.0.0.1:") || !strings.HasSuffix(post.URL(), "/email") {
		t.Errorf("Postmark stand-in at %q", post.URL())
	}
}
