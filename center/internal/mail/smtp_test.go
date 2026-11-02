// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"context"
	"errors"
	"net"
	"net/smtp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/mail/mailtest"
)

// All SMTP tests are MOCKED: the in-process server of package mailtest on 127.0.0.1 with a throwaway CA and an injected dialer. No
// name is resolved and nothing leaves the machine. The tests that need the race detector say so; the Windows leg runs every other test.

type smtpRig struct {
	server *mailtest.SMTPServer
	ca     *mailtest.CA
	sender *SMTP
	user   string
	pass   string
	dials  *atomic.Int64
}

func newSMTPRig(t *testing.T, serverChange func(*mailtest.SMTPOptions), senderChange func(*SMTPOptions)) *smtpRig {
	t.Helper()
	var change func(*mailtest.SMTPOptions, *mailtest.CA)
	if serverChange != nil {
		change = func(o *mailtest.SMTPOptions, _ *mailtest.CA) { serverChange(o) }
	}
	return newSMTPRigWithCA(t, change, senderChange)
}

// newSMTPRigWithCA is newSMTPRig for a server change that needs the rig's authority (a certificate for another name).
func newSMTPRigWithCA(t *testing.T, serverChange func(*mailtest.SMTPOptions, *mailtest.CA), senderChange func(*SMTPOptions)) *smtpRig {
	t.Helper()
	ca := mailtest.NewCA(t, "mail test CA")
	serverOptions := mailtest.SMTPOptions{Certificate: ca.Leaf(t, testHost)}
	if serverChange != nil {
		serverChange(&serverOptions, ca)
	}
	server := mailtest.StartSMTP(t, serverOptions)
	dials := new(atomic.Int64)
	options := SMTPOptions{
		Host: testHost, Port: 2587, Username: config.NewSecret(sentinel("smtp-user")), Password: config.NewSecret(sentinel("smtp-password")),
		From: testFrom, FromName: "ArcForges", Timeout: 5 * time.Second, RootCAs: ca.Pool(), Now: func() time.Time { return buildTime },
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, "tcp", server.Addr())
		},
	}
	if serverOptions.Implicit {
		options.Mode, options.Port = ImplicitTLS, 2465
	}
	if senderChange != nil {
		senderChange(&options)
	}
	return &smtpRig{server: server, ca: ca, sender: NewSMTP(options), user: sentinel("smtp-user"), pass: sentinel("smtp-password"), dials: dials}
}

// capture returns the only session of the rig.
func (r *smtpRig) capture(t *testing.T) *mailtest.Capture {
	t.Helper()
	sessions := r.server.Captures()
	if len(sessions) != 1 {
		t.Fatalf("%d sessions, want 1", len(sessions))
	}
	return sessions[0]
}

// noCredentialOnTheWire fails when the server saw the credential in clear text or at all.
func (r *smtpRig) noCredentialOnTheWire(t *testing.T) {
	t.Helper()
	for _, c := range r.server.Captures() {
		if c.User != "" || c.Password != "" || c.AuthSeenBeforeTLS || strings.Contains(c.Plain.String(), "AUTH") || strings.Contains(c.Plain.String(), r.pass) {
			t.Fatalf("a credential reached the server: user %q, auth before TLS %v, clear text %q", c.User, c.AuthSeenBeforeTLS, c.Plain.String())
		}
	}
}

func TestSMTPDeliversOverStartTLSAndImplicitTLS(t *testing.T) {
	for _, mode := range []string{"starttls", "implicit"} {
		rig := newSMTPRig(t, func(o *mailtest.SMTPOptions) { o.Implicit = mode == "implicit" }, nil)
		message := testMessage()
		if err := rig.sender.Send(context.Background(), message); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		c := rig.capture(t)
		if !c.TLS || c.AuthSeenBeforeTLS || c.User != rig.user || c.Password != rig.pass || !c.Quit {
			t.Errorf("%s: tls=%v authBefore=%v user=%q quit=%v", mode, c.TLS, c.AuthSeenBeforeTLS, c.User, c.Quit)
		}
		if !strings.HasPrefix(c.From, "MAIL FROM:<"+testFrom+">") || len(c.Rcpt) != 1 || !strings.HasPrefix(c.Rcpt[0], "RCPT TO:<"+testTo+">") {
			t.Errorf("%s: envelope %q %q", mode, c.From, c.Rcpt)
		}
		for _, hello := range c.Hello {
			if hello != "EHLO example.test" {
				t.Errorf("%s: the EHLO name is %q: it must be the From domain", mode, hello)
			}
		}
		plain := c.Plain.String()
		if mode == "implicit" && plain != "" {
			t.Errorf("implicit TLS: clear text %q", plain)
		}
		if mode == "starttls" && plain != "EHLO example.test\r\nSTARTTLS\r\n" {
			t.Errorf("starttls: the clear-text part is %q, want only EHLO and STARTTLS (no AUTH, no MAIL, no password)", plain)
		}
		if c.DataViolations != 0 {
			t.Errorf("%s: the message has %d lines that are not plain CRLF", mode, c.DataViolations)
		}
		p := parseBuilt(t, c.Data)
		checkWire(t, c.Data)
		if p.header.Get("To") != testTo || p.header.Get("From") != "ArcForges <"+testFrom+">" || p.subject != message.Subject ||
			p.body != strings.ReplaceAll(message.Text, "\n", "\r\n") || p.header.Get("Date") != "Mon, 02 Nov 2026 13:04:05 +0000" ||
			!strings.HasSuffix(p.header.Get("Message-ID"), "@example.test>") {
			t.Errorf("%s: the captured message reads %v %q %q", mode, p.header, p.subject, p.body)
		}
		if got := rig.dials.Load(); got != 1 {
			t.Errorf("%s: %d dials", mode, got)
		}
	}
}

func TestSMTPBodyWithLeadingDotsSurvivesDotStuffing(t *testing.T) {
	text := ".leading dot\n.\n..\nan accent é and =3D\n" + strings.Repeat("long ", 60) + "\ntrailing   \n"
	rig := newSMTPRig(t, nil, nil)
	message := Message{To: testTo, Subject: "Dots", Text: text}
	if err := rig.sender.Send(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	c := rig.capture(t)
	checkWire(t, c.Data)
	if got := parseBuilt(t, c.Data).body; got != strings.ReplaceAll(text, "\n", "\r\n") {
		t.Errorf("the body came back as %q", got)
	}
}

func TestSMTPHelloNameDefaultsToTheFromDomainAndCanBeSet(t *testing.T) {
	rig := newSMTPRig(t, nil, func(o *SMTPOptions) { o.HelloName = "relay.example.test" })
	if err := rig.sender.Send(context.Background(), testMessage()); err != nil {
		t.Fatal(err)
	}
	for _, hello := range rig.capture(t).Hello {
		if hello != "EHLO relay.example.test" {
			t.Errorf("the EHLO name is %q", hello)
		}
	}
}

func TestSMTPConnectNeverSendsACredential(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		rig := newSMTPRig(t, func(o *mailtest.SMTPOptions) { o.Implicit = implicit }, nil)
		session, err := rig.sender.connect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := session.client.TLSConnectionState(); !ok {
			t.Error("connect returns a session that is not encrypted")
		}
		if ok, mechanisms := session.client.Extension("AUTH"); !ok || !strings.Contains(mechanisms, "PLAIN") {
			t.Errorf("AUTH is not seen after TLS: %v %q", ok, mechanisms)
		}
		session.close()
		rig.noCredentialOnTheWire(t)
	}
}

func TestSMTPDowngradeSendsNothingMoreThanEHLO(t *testing.T) {
	rig := newSMTPRig(t, func(o *mailtest.SMTPOptions) { o.NoStartTLS = true }, nil)
	err := rig.sender.Send(context.Background(), testMessage())
	expectFailure(t, err, ErrUnavailable, "tls", 0)
	noLeak(t, err, rig.user, rig.pass, testTo)
	rig.noCredentialOnTheWire(t)
	if plain := rig.capture(t).Plain.String(); plain != "EHLO example.test\r\n" {
		t.Errorf("a server without STARTTLS received %q", plain)
	}
	if rig.server.Connections() != 1 {
		t.Errorf("%d connections: a failed send must not be retried", rig.server.Connections())
	}
}

// TestSMTPLoopbackHostNamesDoNotWaiveTLS: net/smtp.PlainAuth waives its TLS check for localhost, 127.0.0.1 and ::1; the adapter's
// own checks do not.
func TestSMTPLoopbackHostNamesDoNotWaiveTLS(t *testing.T) {
	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		rig := newSMTPRig(t, func(o *mailtest.SMTPOptions) { o.NoStartTLS = true }, func(o *SMTPOptions) { o.Host = host })
		expectFailure(t, rig.sender.Send(context.Background(), testMessage()), ErrUnavailable, "tls", 0)
		rig.noCredentialOnTheWire(t)
	}
}

func TestSMTPRefusesACertificateOfAnotherAuthorityOrAnotherNameInBothModes(t *testing.T) {
	other := mailtest.NewCA(t, "another CA")
	for _, implicit := range []bool{false, true} {
		for _, c := range []struct {
			name   string
			server func(*mailtest.SMTPOptions, *mailtest.CA)
			sender func(*SMTPOptions)
		}{
			{"another CA", func(o *mailtest.SMTPOptions, _ *mailtest.CA) { o.Certificate = other.Leaf(t, testHost) }, nil},
			{"another name", func(o *mailtest.SMTPOptions, ca *mailtest.CA) { o.Certificate = ca.Leaf(t, "elsewhere.example.test") }, nil},
			{"system roots", nil, func(o *SMTPOptions) { o.RootCAs = nil }},
		} {
			rig := newSMTPRigWithCA(t, func(o *mailtest.SMTPOptions, ca *mailtest.CA) {
				o.Implicit = implicit
				if c.server != nil {
					c.server(o, ca)
				}
			}, c.sender)
			err := rig.sender.Send(context.Background(), testMessage())
			expectFailure(t, err, ErrUnavailable, "tls", 0)
			noLeak(t, err, rig.user, rig.pass, testTo, "x509", "certificate")
			rig.noCredentialOnTheWire(t)
			for _, session := range rig.server.Captures() {
				if len(session.Data) != 0 || session.From != "" {
					t.Errorf("%s (implicit %v): a message was sent after a failed handshake", c.name, implicit)
				}
			}
		}
	}
}

// TestSMTPClearTextLineInjectedAfterSTARTTLSIsNeverTakenAsAReply: the server answers STARTTLS with the 220 and an extra clear-text
// line in the same write. net/smtp replaces its reader at the upgrade and drops what it had buffered, so the line cannot become the
// answer to a later command; the send completes over TLS only (a line that arrived later would fail the handshake instead, which
// the test also accepts), and no credential or message goes out in clear text.
func TestSMTPClearTextLineInjectedAfterSTARTTLSIsNeverTakenAsAReply(t *testing.T) {
	rig := newSMTPRig(t, func(o *mailtest.SMTPOptions) { o.PipelineAfterStartTLS = true }, nil)
	err := rig.sender.Send(context.Background(), testMessage())
	if err != nil {
		expectFailure(t, err, ErrUnavailable, "tls", 0)
	}
	for _, c := range rig.server.Captures() {
		if c.AuthSeenBeforeTLS || strings.Contains(c.Plain.String(), "AUTH") || strings.Contains(c.Plain.String(), "MAIL") {
			t.Errorf("clear text after the injection: %q", c.Plain.String())
		}
	}
}

func TestSMTPClassifiesEveryReply(t *testing.T) {
	denied := "554 Access denied: User arn:aws:iam::000000000000:user/" + sentinel("resource") + " is not authorized to perform ses:SendRawEmail on resource arn:aws:ses:eu-west-1:000000000000:identity/example.test"
	notVerified := "554 Message rejected: Email address is not verified. The following identities failed the check in region EU-WEST-1: " + testTo
	type row struct {
		name   string
		server func(*mailtest.SMTPOptions)
		class  error
		stage  string
		code   int
	}
	rows := []row{
		{"greeting 554", func(o *mailtest.SMTPOptions) { o.GreetingReply = "554 5.7.1 Service unavailable; client host blocked" }, ErrUnavailable, "dial", 554},
		{"greeting 554 multi-line", func(o *mailtest.SMTPOptions) { o.GreetingReply = "554-first line\r\n554 second line" }, ErrUnavailable, "dial", 554},
		{"greeting 521", func(o *mailtest.SMTPOptions) { o.GreetingReply = "521 no mail here" }, ErrUnavailable, "dial", 521},
		{"greeting 421", func(o *mailtest.SMTPOptions) { o.GreetingReply = "421 busy" }, ErrUnavailable, "dial", 421},
		{"EHLO and HELO 554", func(o *mailtest.SMTPOptions) { o.EHLOReply = "554 5.5.1 no service" }, ErrUnavailable, "dial", 554},
		{"EHLO and HELO 502", func(o *mailtest.SMTPOptions) { o.EHLOReply = "502 not implemented" }, ErrUnavailable, "dial", 502},
		{"AUTH 535", func(o *mailtest.SMTPOptions) { o.AuthReply = "535 5.7.8 Authentication Credentials Invalid" }, ErrUnauthorized, "auth", 535},
		{"AUTH 530", func(o *mailtest.SMTPOptions) { o.AuthReply = "530 Authentication required" }, ErrUnauthorized, "auth", 530},
		{"AUTH 534", func(o *mailtest.SMTPOptions) { o.AuthReply = "534 mechanism too weak" }, ErrUnauthorized, "auth", 534},
		{"AUTH 538", func(o *mailtest.SMTPOptions) { o.AuthReply = "538 encryption required" }, ErrUnauthorized, "auth", 538},
		{"AUTH 535 account not subscribed", func(o *mailtest.SMTPOptions) { o.AuthReply = "535 Account not subscribed" }, ErrUnauthorized, "auth", 535},
		{"AUTH another 5xx", func(o *mailtest.SMTPOptions) { o.AuthReply = "501 5.5.2 syntax" }, ErrUnauthorized, "auth", 501},
		{"AUTH 454", func(o *mailtest.SMTPOptions) { o.AuthReply = "454 4.7.0 Temporary authentication failure" }, ErrUnavailable, "auth", 454},
		{"AUTH 421", func(o *mailtest.SMTPOptions) { o.AuthReply = "421 Too many concurrent SMTP connections" }, ErrUnavailable, "auth", 421},
		{"MAIL 530", func(o *mailtest.SMTPOptions) { o.MailReply = "530 5.7.0 Authentication required" }, ErrUnauthorized, "envelope", 530},
		{"MAIL 554 Access denied", func(o *mailtest.SMTPOptions) { o.MailReply = denied }, ErrUnauthorized, "envelope", 554},
		{"RCPT 554 Access denied", func(o *mailtest.SMTPOptions) { o.RcptReply = denied }, ErrUnauthorized, "envelope", 554},
		{"DATA 554 Access denied", func(o *mailtest.SMTPOptions) { o.DataReply = denied }, ErrUnauthorized, "data", 554},
		{"MAIL 554 not verified", func(o *mailtest.SMTPOptions) { o.MailReply = notVerified }, ErrRejected, "envelope", 554},
		{"DATA 554 not verified", func(o *mailtest.SMTPOptions) { o.DataReply = notVerified }, ErrRejected, "data", 554},
		{"RCPT relay access denied", func(o *mailtest.SMTPOptions) { o.RcptReply = "554 5.7.1 Relay access denied" }, ErrRejected, "envelope", 554},
		{"RCPT Access denied in the middle", func(o *mailtest.SMTPOptions) { o.RcptReply = "554 Message rejected: reason Access denied somewhere" }, ErrRejected, "envelope", 554},
		{"MAIL 553", func(o *mailtest.SMTPOptions) { o.MailReply = "553 5.1.3 Syntax error in the address " + testFrom }, ErrRejected, "envelope", 553},
		{"RCPT 550", func(o *mailtest.SMTPOptions) { o.RcptReply = "550 5.1.1 Mailbox " + testTo + " unknown" }, ErrRejected, "envelope", 550},
		{"DATA 552", func(o *mailtest.SMTPOptions) { o.DataReply = "552 Message is too long" }, ErrRejected, "data", 552},
		{"MAIL 451", func(o *mailtest.SMTPOptions) { o.MailReply = "451 4.3.0 Temporary local problem" }, ErrUnavailable, "envelope", 451},
		{"RCPT 421", func(o *mailtest.SMTPOptions) { o.RcptReply = "421 Too many concurrent SMTP connections" }, ErrUnavailable, "envelope", 421},
		{"DATA 454", func(o *mailtest.SMTPOptions) { o.DataReply = "454 Throttling failure: Maximum sending rate exceeded." }, ErrUnavailable, "data", 454},
		{"no AUTH offered", func(o *mailtest.SMTPOptions) { o.EHLOReply = "250-" + testHost + "\r\n250 STARTTLS" }, ErrUnauthorized, "auth", 0},
		{"only AUTH LOGIN", func(o *mailtest.SMTPOptions) { o.EHLOReply = "250-" + testHost + "\r\n250-STARTTLS\r\n250 AUTH LOGIN" }, ErrUnauthorized, "auth", 0},
	}
	for _, r := range rows {
		rig := newSMTPRig(t, r.server, nil)
		err := rig.sender.Send(context.Background(), testMessage())
		failure := expectFailure(t, err, r.class, r.stage, r.code)
		if failure.Provider != "smtp" || failure.Timeout {
			t.Errorf("%s: provider %q, timeout %v", r.name, failure.Provider, failure.Timeout)
		}
		noLeak(t, err, rig.user, rig.pass, testTo, testFrom, sentinel("resource"), "arn:aws", "Mailbox", "verified")
		if rig.dials.Load() != 1 {
			t.Errorf("%s: %d dials (no retry)", r.name, rig.dials.Load())
		}
	}
}

// TestSMTPRefusesAnInvalidMessageBeforeAnyConnection: every injection form of the message and of the sender is refused with zero
// dials.
func TestSMTPRefusesAnInvalidMessageBeforeAnyConnection(t *testing.T) {
	messages := map[string]Message{
		"recipient list":     {To: "a@example.test,b@example.test", Subject: "s", Text: "t"},
		"recipient name":     {To: "Ada <a@example.test>", Subject: "s", Text: "t"},
		"recipient CRLF":     {To: "a@example.test\r\nRCPT TO:<b@example.test>", Subject: "s", Text: "t"},
		"recipient LF":       {To: "a@example.test\nBcc: b@example.test", Subject: "s", Text: "t"},
		"recipient IP":       {To: "a@127.0.0.1", Subject: "s", Text: "t"},
		"recipient NUL":      {To: "a\x00@example.test", Subject: "s", Text: "t"},
		"subject CR":         {To: testTo, Subject: "s\rBcc: b@example.test", Text: "t"},
		"subject LF":         {To: testTo, Subject: "s\nBcc: b@example.test", Text: "t"},
		"subject CRLF":       {To: testTo, Subject: "s\r\nBcc: b@example.test", Text: "t"},
		"subject NUL":        {To: testTo, Subject: "s\x00", Text: "t"},
		"subject empty":      {To: testTo, Subject: "", Text: "t"},
		"subject blank":      {To: testTo, Subject: " ", Text: "t"},
		"subject word":       {To: testTo, Subject: "=?utf-8?q?x?=", Text: "t"},
		"subject too long":   {To: testTo, Subject: strings.Repeat("s", MaxSubjectBytes+1), Text: "t"},
		"text NUL":           {To: testTo, Subject: "s", Text: "t\x00"},
		"text CR":            {To: testTo, Subject: "s", Text: "a\rb"},
		"text empty":         {To: testTo, Subject: "s", Text: ""},
		"text too long":      {To: testTo, Subject: "s", Text: strings.Repeat("t", MaxTextBytes+1)},
		"text invalid UTF-8": {To: testTo, Subject: "s", Text: "\xff"},
	}
	rig := newSMTPRig(t, nil, nil)
	for name, message := range messages {
		if failure, ok := rig.sender.Send(context.Background(), message).(*Error); !ok || failure.Class != ErrRejected || failure.Stage != "message" || failure.Code != 0 {
			t.Errorf("%s: %v", name, failure)
		}
	}
	for _, sender := range []struct{ from, name string }{{"", ""}, {"a@127.0.0.1", ""}, {"a@example.test,b@example.test", ""}, {testFrom, "Ada\r\nBcc: x@example.test"}, {testFrom, "=?utf-8?q?x?="}} {
		bad := newSMTPRig(t, nil, func(o *SMTPOptions) { o.From, o.FromName = sender.from, sender.name })
		expectFailure(t, bad.sender.Send(context.Background(), testMessage()), ErrRejected, "message", 0)
		if bad.dials.Load() != 0 || bad.server.Connections() != 0 {
			t.Errorf("sender %+v: %d dials", sender, bad.dials.Load())
		}
	}
	if rig.dials.Load() != 0 || rig.server.Connections() != 0 {
		t.Errorf("%d dials, %d connections for refused messages", rig.dials.Load(), rig.server.Connections())
	}
}

// TestSMTPModeIsAClosedSetRefusedBeforeAnyDial is the FIRST layer of the TLS defence: a mode outside the two constants is refused
// before anything is dialled, whatever the host name and whatever the server offers. Counting connections (not only AUTH bytes) is
// what separates this layer from the gate of TestSMTPSendsTheCredentialOnlyThroughTheTLSGate.
func TestSMTPModeIsAClosedSetRefusedBeforeAnyDial(t *testing.T) {
	for _, mode := range []SMTPMode{7, -1, 2, ImplicitTLS + 1} {
		for _, host := range []string{"localhost", "127.0.0.1", "::1", testHost} {
			for _, noStartTLS := range []bool{true, false} {
				rig := newSMTPRig(t, func(o *mailtest.SMTPOptions) { o.NoStartTLS = noStartTLS }, func(o *SMTPOptions) { o.Mode, o.Host = mode, host })
				err := rig.sender.Send(context.Background(), testMessage())
				expectFailure(t, err, ErrUnavailable, "config", 0)
				noLeak(t, err, rig.user, rig.pass)
				if rig.dials.Load() != 0 || rig.server.Connections() != 0 {
					t.Fatalf("mode %d host %s: %d dials, %d connections", mode, host, rig.dials.Load(), rig.server.Connections())
				}
				if _, err = rig.sender.connect(context.Background()); err == nil {
					t.Fatalf("mode %d: connect succeeded", mode)
				}
			}
		}
	}
	if StartTLS != 0 {
		t.Error("the zero SMTPMode is not the safe one")
	}
}

// TestSMTPSendsTheCredentialOnlyThroughTheTLSGate is the SECOND layer: authenticate refuses a client that is not talking TLS, in
// every mode value and for the host names that net/smtp.PlainAuth would wave through. The client here is plain text on purpose.
func TestSMTPSendsTheCredentialOnlyThroughTheTLSGate(t *testing.T) {
	for _, mode := range []SMTPMode{StartTLS, ImplicitTLS, 7} {
		for _, host := range []string{"localhost", "127.0.0.1"} {
			rig := newSMTPRig(t, func(o *mailtest.SMTPOptions) { o.NoStartTLS = true }, func(o *SMTPOptions) { o.Mode, o.Host = mode, host })
			conn, err := net.DialTimeout("tcp", rig.server.Addr(), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			client, err := smtp.NewClient(conn, host)
			if err != nil {
				t.Fatal(err)
			}
			if err = client.Hello("example.test"); err != nil {
				t.Fatal(err)
			}
			err = rig.sender.authenticate(client)
			expectFailure(t, err, ErrUnavailable, "tls", 0)
			_ = client.Close()
			rig.noCredentialOnTheWire(t)
		}
	}
}

func TestSMTPDeadlineEndsEverySilentServer(t *testing.T) {
	for name, change := range map[string]func(*mailtest.SMTPOptions){
		"silent greeting":       func(o *mailtest.SMTPOptions) { o.StallGreeting = true },
		"silent after greeting": func(o *mailtest.SMTPOptions) { o.StallAfterGreeting = true },
	} {
		rig := newSMTPRig(t, change, func(o *SMTPOptions) { o.Timeout = 300 * time.Millisecond })
		begun := time.Now()
		failure := expectFailure(t, rig.sender.Send(context.Background(), testMessage()), ErrUnavailable, "dial", 0)
		if !failure.Timeout {
			t.Errorf("%s: Timeout is false", name)
		}
		if elapsed := time.Since(begun); elapsed > 8*time.Second {
			t.Errorf("%s: %v with a 300 ms deadline", name, elapsed)
		}
	}
}

// TestSMTPImplicitTLSDeadlineAndCancelAfterTheHandshake needs the race detector to say anything: the context hook that closes the
// connection must not read a variable the send reassigns for the encrypted connection (a data race under -race, invisible without
// it, so the Windows leg cannot see this class). The server completes the TLS handshake and then stays silent; the loop gives the
// detector several interleavings.
func TestSMTPImplicitTLSDeadlineAndCancelAfterTheHandshake(t *testing.T) {
	for range 5 {
		for name, change := range map[string]func(*mailtest.SMTPOptions){
			"silent after the handshake": func(o *mailtest.SMTPOptions) { o.Implicit, o.SilentAfterHandshake = true, true },
			"silent after the greeting":  func(o *mailtest.SMTPOptions) { o.Implicit, o.StallAfterGreeting = true, true },
		} {
			rig := newSMTPRig(t, change, func(o *SMTPOptions) { o.Timeout = 150 * time.Millisecond })
			failure := typed(t, rig.sender.Send(context.Background(), testMessage()))
			if failure.Class != ErrUnavailable || !failure.Timeout || failure.Code != 0 {
				t.Errorf("%s (deadline): %+v", name, failure)
			}
			canceled := newSMTPRig(t, change, func(o *SMTPOptions) { o.Timeout = 30 * time.Second })
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(120*time.Millisecond, cancel)
			begun := time.Now()
			failure = typed(t, canceled.sender.Send(ctx, testMessage()))
			cancel()
			if failure.Class != ErrUnavailable || failure.Timeout || time.Since(begun) > 10*time.Second {
				t.Errorf("%s (cancel): %+v after %v", name, failure, time.Since(begun))
			}
		}
	}
}

func TestSMTPCallerCancelEndsASendAndIsNotATimeout(t *testing.T) {
	rig := newSMTPRig(t, func(o *mailtest.SMTPOptions) { o.StallGreeting = true }, func(o *SMTPOptions) { o.Timeout = 30 * time.Second })
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	begun := time.Now()
	failure := expectFailure(t, rig.sender.Send(ctx, testMessage()), ErrUnavailable, "dial", 0)
	if failure.Timeout || time.Since(begun) > 10*time.Second {
		t.Errorf("timeout %v after %v", failure.Timeout, time.Since(begun))
	}
}

func TestSMTPConnectionFailureIsUnavailableWithoutAnAddress(t *testing.T) {
	refused := errors.New("dial tcp " + sentinel("host") + ": connection refused")
	sender := NewSMTP(SMTPOptions{Host: testHost, Port: 2587, From: testFrom, Timeout: 2 * time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) { return nil, refused }})
	err := sender.Send(context.Background(), testMessage())
	expectFailure(t, err, ErrUnavailable, "dial", 0)
	noLeak(t, err, sentinel("host"), testHost, testTo)
}

// TestSMTPReadsAtMostTheCapFromAServer measures the byte bound: an endless reply line ends the send at the cap, long before the
// deadline, and the server can write only about the cap plus what the sockets buffer. Without the cap net/textproto reads the line
// until the deadline (8.6 s against 2 ms in the plan's prototype).
func TestSMTPReadsAtMostTheCapFromAServer(t *testing.T) {
	rig := newSMTPRig(t, func(o *mailtest.SMTPOptions) { o.FloodGreeting = true }, func(o *SMTPOptions) { o.Timeout = 3 * time.Second })
	begun := time.Now()
	failure := expectFailure(t, rig.sender.Send(context.Background(), testMessage()), ErrUnavailable, "dial", 0)
	elapsed := time.Since(begun)
	if failure.Timeout || elapsed > 1500*time.Millisecond {
		t.Errorf("an endless reply line held the send for %v (timeout %v): it was read to the deadline", elapsed, failure.Timeout)
	}
	time.Sleep(100 * time.Millisecond)
	if written := rig.server.BytesWritten(); written > maxServerBytes+16<<20 {
		t.Errorf("the server could write %d bytes of an endless line", written)
	}
}

// TestSMTPAServerThatGoesSilentAfterRefusingTheCredentialHoldsTheSendToTheDeadline documents the accepted bound (the standard
// library's Auth sends "*" and QUIT and waits for both): the failure is the refusal, not a timeout, and the hold is at most the
// adapter timeout.
func TestSMTPAServerThatGoesSilentAfterRefusingTheCredentialHoldsTheSendToTheDeadline(t *testing.T) {
	rig := newSMTPRig(t, func(o *mailtest.SMTPOptions) {
		o.AuthReply, o.SilentAfterAuth = "535 5.7.8 Authentication Credentials Invalid", true
	}, func(o *SMTPOptions) { o.Timeout = 600 * time.Millisecond })
	begun := time.Now()
	failure := expectFailure(t, rig.sender.Send(context.Background(), testMessage()), ErrUnauthorized, "auth", 535)
	if failure.Timeout {
		t.Error("a refusal that arrived is reported as a timeout")
	}
	if elapsed := time.Since(begun); elapsed > 8*time.Second {
		t.Errorf("the hold lasted %v with a 600 ms deadline", elapsed)
	}
}

// TestSMTPAcceptedMessageIsASuccessEvenIfQuitIsNeverAnswered: the result is known once the data is accepted; a silent QUIT is
// bounded by its own sub-deadline, not by the full timeout.
func TestSMTPAcceptedMessageIsASuccessEvenIfQuitIsNeverAnswered(t *testing.T) {
	rig := newSMTPRig(t, func(o *mailtest.SMTPOptions) { o.SilentQuit = true }, func(o *SMTPOptions) { o.Timeout = 8 * time.Second })
	begun := time.Now()
	if err := rig.sender.Send(context.Background(), testMessage()); err != nil {
		t.Fatalf("an accepted message is reported as a failure: %v", err)
	}
	if elapsed := time.Since(begun); elapsed > 4*time.Second {
		t.Errorf("a silent QUIT held the send for %v of an 8 s deadline", elapsed)
	}
	if c := rig.capture(t); !c.Quit || len(c.Data) == 0 {
		t.Errorf("quit %v, %d data bytes", c.Quit, len(c.Data))
	}
}

func TestSMTPConnectionLostAfterTheDataIsUnavailableAndNeverRepeated(t *testing.T) {
	rig := newSMTPRig(t, func(o *mailtest.SMTPOptions) { o.DropAfterData = true }, nil)
	failure := expectFailure(t, rig.sender.Send(context.Background(), testMessage()), ErrUnavailable, "data", 0)
	if failure.Timeout || rig.server.Connections() != 1 || rig.dials.Load() != 1 {
		t.Errorf("timeout %v, %d connections", failure.Timeout, rig.server.Connections())
	}
	if len(rig.capture(t).Data) == 0 {
		t.Error("the server never received the message")
	}
}

func TestSMTPRecoversAPanicOfItsDialerAndDefaultsItsTimeout(t *testing.T) {
	sender := NewSMTP(SMTPOptions{Host: testHost, Port: 2587, From: testFrom, Dial: func(context.Context, string, string) (net.Conn, error) { panic("a panic in the dialer") }})
	expectFailure(t, sender.Send(context.Background(), testMessage()), ErrUnavailable, "panic", 0)
	if sender.o.Timeout != DefaultTimeout || NewSMTP(SMTPOptions{Timeout: -1}).o.Timeout != DefaultTimeout || NewSMTP(SMTPOptions{Timeout: time.Second}).o.Timeout != time.Second {
		t.Error("the timeout default or an explicit timeout is wrong")
	}
	if !sender.Enabled() || sender.o.HelloName != "example.test" || sender.o.Now == nil {
		t.Error("the constructor defaults are wrong")
	}
}

// TestSMTPDialsTheConfiguredHostAndPort checks what the adapter asks its dialer for.
func TestSMTPDialsTheConfiguredHostAndPort(t *testing.T) {
	var asked atomic.Value
	sender := NewSMTP(SMTPOptions{Host: testHost, Port: 2465, From: testFrom, Timeout: time.Second, Dial: func(_ context.Context, network, address string) (net.Conn, error) {
		asked.Store(network + " " + address)
		return nil, errors.New("not dialled")
	}})
	_ = sender.Send(context.Background(), testMessage())
	if asked.Load() != "tcp smtp.example.test:2465" {
		t.Errorf("the adapter dialled %v", asked.Load())
	}
}
