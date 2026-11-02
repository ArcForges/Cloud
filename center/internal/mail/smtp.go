// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
)

// SMTPMode is how the connection is encrypted. The set is closed: there is no plain-text mode, not even for a loopback relay, and a
// value outside the two constants is refused before anything is dialled. The zero value is StartTLS.
type SMTPMode int

const (
	// StartTLS connects in clear text, requires the STARTTLS extension and upgrades before anything else is sent (ports 587, 2587, 25).
	StartTLS SMTPMode = iota
	// ImplicitTLS wraps the whole connection in TLS (ports 465, 2465).
	ImplicitTLS
)

// SMTPOptions configure the SMTP sender. RootCAs and Dial are for tests only: production leaves them nil (the system roots, a
// plain net.Dialer).
type SMTPOptions struct {
	// Host is the DNS name of the submission service; the certificate is checked against it.
	Host string
	Port int
	Mode SMTPMode
	// Username and Password are the credential of AUTH PLAIN, sent over TLS only.
	Username config.Secret
	Password config.Secret
	// From is the envelope and header sender and FromName its optional display name; both are validated again at every send.
	From     string
	FromName string
	// HelloName is the EHLO name; the domain of From when empty (never "localhost" and never the container's host name).
	HelloName string
	// Timeout bounds the whole conversation; DefaultTimeout when not positive.
	Timeout time.Duration
	// RootCAs replaces the system roots (tests only).
	RootCAs *x509.CertPool
	// Dial replaces the dialer (tests only).
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// Now replaces the clock of the Date header (tests only).
	Now func() time.Time
}

// SMTP sends through an authenticated, encrypted SMTP submission service (Amazon SES SMTP is the first target), using the standard
// library's net/smtp as the protocol engine inside this package's own dial, TLS, deadline and byte-cap code and a hand-built message.
type SMTP struct{ o SMTPOptions }

// maxServerBytes bounds everything one send reads from the server (replies, certificates): net/textproto reads a reply line without
// a limit, so a server that never ends a line could grow memory until the deadline.
const maxServerBytes = 256 << 10

// quitGrace bounds the wait for the answer to QUIT once the message is accepted: the result is already known, so a silent server
// must not hold the send (and its delivery slot) until the full deadline.
const quitGrace = time.Second

// NewSMTP is the sender of the options; it never connects.
func NewSMTP(o SMTPOptions) *SMTP {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.HelloName == "" {
		_, o.HelloName, _ = strings.Cut(o.From, "@")
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	return &SMTP{o: o}
}

// Enabled is true.
func (*SMTP) Enabled() bool { return true }

// fail builds a typed failure. The SMTP reply code is kept; the reply text, which can name the recipient or a resource, and the text
// of a lower-level error, which can name hosts, never are.
func (s *SMTP) fail(class error, stage string, err error) error {
	result := &Error{Class: class, Provider: "smtp", Stage: stage}
	var protocol *textproto.Error
	var netErr net.Error
	switch {
	case errors.As(err, &protocol):
		result.Code = protocol.Code
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()):
		result.Timeout = true
	}
	return result
}

// classify maps the error of an SMTP command to a class. Order matters:
//
//   - no reply at all (a network fault, a timeout, EOF) is unavailable: the outcome may be unknown;
//   - any reply at the greeting, EHLO/HELO or STARTTLS (stages dial and tls) is unavailable, whatever its code: a refused connection
//     says nothing about the message and no credential has been presented yet;
//   - 530, 534, 535, 538, any 5xx at AUTH, and "554 Access denied ..." (SES: the IAM or sending-authorization policy of the SMTP
//     credential lacks ses:SendRawEmail) are unauthorized: an operator must act. The text prefix is matched on the reply and then
//     discarded; if SES changes its wording the class degrades to rejected;
//   - other 5xx (550, 552, 553, "554 Message rejected: ...") are rejected;
//   - 4xx (421, 451, 454) are unavailable.
func (s *SMTP) classify(stage string, err error) error {
	var protocol *textproto.Error
	if !errors.As(err, &protocol) {
		return s.fail(ErrUnavailable, stage, err)
	}
	switch {
	case stage == "dial" || stage == "tls":
		return s.fail(ErrUnavailable, stage, err)
	case protocol.Code == 530, protocol.Code == 534, protocol.Code == 535, protocol.Code == 538, protocol.Code >= 500 && stage == "auth",
		protocol.Code == 554 && strings.HasPrefix(protocol.Msg, "Access denied"):
		return s.fail(ErrUnauthorized, stage, err)
	case protocol.Code >= 500:
		return s.fail(ErrRejected, stage, err)
	default:
		return s.fail(ErrUnavailable, stage, err)
	}
}

// smtpSession is a connected, greeted and encrypted conversation that has not authenticated yet.
type smtpSession struct {
	client *smtp.Client
	// raw is the byte-capped connection below TLS. It is captured once, before the context hook is registered, and never
	// reassigned, so the hook cannot race with the switch to the encrypted connection.
	raw  net.Conn
	stop func() bool
}

// close ends the conversation: the hook is removed and the connection closed (the server sees no QUIT; the caller sends it).
func (c *smtpSession) close() {
	c.stop()
	_ = c.raw.Close()
}

// connect dials, wraps the connection (implicit TLS), reads the greeting, says EHLO and, in StartTLS mode, requires and runs the
// upgrade. It never authenticates and sends no credential, so the opt-in probe of a real endpoint and the tests of downgrade and
// certificates call it without one. The mode is a closed set: any other value is refused before anything is dialled.
func (s *SMTP) connect(ctx context.Context) (*smtpSession, error) {
	switch s.o.Mode {
	case StartTLS, ImplicitTLS:
	default:
		return nil, s.fail(ErrUnavailable, "config", nil)
	}
	dial := s.o.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	conn, err := dial(ctx, "tcp", net.JoinHostPort(s.o.Host, strconv.Itoa(s.o.Port)))
	if err != nil {
		return nil, s.fail(ErrUnavailable, "dial", err)
	}
	// One deadline for the whole conversation, and the context closes the connection, so no read or write outlives the send.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	raw := net.Conn(&cappedConn{Conn: conn, remaining: maxServerBytes})
	session := &smtpSession{raw: raw, stop: context.AfterFunc(ctx, func() { _ = raw.Close() })}
	refuse := func(class error, stage string, err error) (*smtpSession, error) {
		session.close()
		return nil, s.fail(class, stage, err)
	}
	secured := raw
	tlsConfig := &tls.Config{ServerName: s.o.Host, MinVersion: tls.VersionTLS12, RootCAs: s.o.RootCAs}
	if s.o.Mode == ImplicitTLS {
		wrapped := tls.Client(raw, tlsConfig)
		if err = wrapped.HandshakeContext(ctx); err != nil {
			return refuse(ErrUnavailable, "tls", err)
		}
		secured = wrapped
	}
	client, err := smtp.NewClient(secured, s.o.Host)
	if err != nil {
		session.close()
		return nil, s.classify("dial", err)
	}
	session.client = client
	if err = client.Hello(s.o.HelloName); err != nil {
		session.close()
		return nil, s.classify("dial", err)
	}
	if s.o.Mode == StartTLS {
		// net/smtp sends STARTTLS whatever EHLO advertised, and a downgraded server must never be talked to further.
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return refuse(ErrUnavailable, "tls", nil)
		}
		if err = client.StartTLS(tlsConfig); err != nil {
			return refuse(ErrUnavailable, "tls", err)
		}
	}
	return session, nil
}

// authenticate sends the credential. It is the only function that does, and its first statement is a gate that does not depend on
// the mode, the host name or the standard library: the client must be talking TLS. smtp.PlainAuth has the same check, but waives
// it for the host names localhost, 127.0.0.1 and ::1, so it is not a layer of this defence; the gate is, and it has its own test.
// AUTH PLAIN is used only when the server advertises it (SES offers PLAIN and LOGIN; the standard library has no LOGIN and none
// is needed).
func (s *SMTP) authenticate(client *smtp.Client) error {
	if _, ok := client.TLSConnectionState(); !ok {
		return s.fail(ErrUnavailable, "tls", nil)
	}
	if ok, mechanisms := client.Extension("AUTH"); !ok || !strings.Contains(" "+strings.ToUpper(mechanisms)+" ", " PLAIN ") {
		return s.fail(ErrUnauthorized, "auth", nil)
	}
	if err := client.Auth(smtp.PlainAuth("", s.o.Username.Reveal(), s.o.Password.Reveal(), s.o.Host)); err != nil {
		return s.classify("auth", err)
	}
	return nil
}

// Send delivers one message: refuse an invalid message (validate) or sender (buildMessage checks the From address and name and the
// recipient again, and runs before any connection), connect (bounded), authenticate over TLS, submit, quit. No retry:
// an ambiguous end (a connection lost after the data) is unavailable and never repeated. The Timeout flag follows the context, but
// only for a failure that carries no reply code: a refusal that arrived is not a timeout. Once the message is accepted the result is
// success even when the server does not answer QUIT. A failed AUTH makes net/smtp send "*" and QUIT and wait for their answers, so
// a server that goes silent after refusing the credential holds the delivery slot until the deadline (at most the adapter timeout;
// the standard library offers no hook to bound that exchange).
func (s *SMTP) Send(ctx context.Context, m Message) (result error) {
	defer func() {
		if recover() != nil {
			result = &Error{Class: ErrUnavailable, Provider: "smtp", Stage: "panic"}
		}
	}()
	if err := validate("smtp", m); err != nil {
		return err
	}
	data, err := buildMessage(s.o.FromName, s.o.From, m.To, m.Subject, m.Text, s.o.Now())
	if err != nil {
		return invalid("smtp")
	}
	ctx, cancel := context.WithTimeout(ctx, s.o.Timeout)
	defer cancel()
	defer func() { // the connection closed by the deadline reads as "use of closed connection", not as a timeout
		var failure *Error
		if errors.As(result, &failure) && failure.Code == 0 && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			failure.Timeout = true
		}
	}()
	session, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer session.close()
	client := session.client
	if err = s.authenticate(client); err != nil {
		return err
	}
	if err = client.Mail(s.o.From); err != nil {
		return s.classify("envelope", err)
	}
	if err = client.Rcpt(m.To); err != nil {
		return s.classify("envelope", err)
	}
	writer, err := client.Data()
	if err != nil {
		return s.classify("data", err)
	}
	if _, err = writer.Write(data); err != nil {
		return s.classify("data", err)
	}
	if err = writer.Close(); err != nil {
		return s.classify("data", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = session.raw.SetDeadline(minTime(deadline, time.Now().Add(quitGrace)))
	}
	_ = client.Quit()
	return nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// cappedConn limits the bytes read from the server.
type cappedConn struct {
	net.Conn
	remaining int64
}

func (c *cappedConn) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, errors.New("mail: the server sent too much")
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= int64(n)
	return n, err
}
