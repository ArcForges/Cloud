// SPDX-License-Identifier: AGPL-3.0-only

package mailtest

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// FloodLimit is how many bytes the endless-answer misbehaviours (SMTPOptions.FloodGreeting, PostmarkReply.Flood) write before they
// stop and wait for the client. A test asserts that the bytes written stay below half of it with the client's cap in place; a client
// without a cap reads all of it. The amount a server manages to write before it notices a closed client depends on the host's
// socket buffers (about 0.4 MiB on Windows, 0.3 to 12 MiB on Linux), so the assertion is relative to this fixed total, never to the
// cap and never an absolute number tuned on one host.
const FloodLimit = 64 << 20

// SMTPOptions choose how an SMTP test server behaves. The zero value (apart from the certificate) is a well-behaved submission
// server: STARTTLS offered, AUTH PLAIN and LOGIN advertised in every EHLO reply (AUTH before TLS is refused with 530 and recorded,
// so the double is more adversarial than a server that hides AUTH until TLS), every command accepted.
type SMTPOptions struct {
	// Certificate is the server certificate (CA.Leaf).
	Certificate tls.Certificate
	// Hostname is the name in the greeting; smtp.example.test when empty.
	Hostname string
	// Implicit wraps the connection in TLS from the first byte.
	Implicit bool
	// NoStartTLS does not advertise STARTTLS (a downgrade) and answers STARTTLS with 502.
	NoStartTLS bool
	// MaxTLSVersion, when not zero, makes the server speak TLS 1.0 up to that version only (tls.VersionTLS11 for an old-TLS
	// server); zero means TLS 1.2 and later.
	MaxTLSVersion uint16

	// Replacements of single replies. The text is a complete reply line, for example "535 5.7.8 nope".
	GreetingReply string // the greeting (the connection is then closed after it when the code is 4xx or 5xx)
	EHLOReply     string // the whole reply of EHLO and HELO
	AuthReply     string
	MailReply     string
	RcptReply     string
	DataReply     string // the reply after the message ends
	// DataCommandReply replaces the 354 that answers the DATA command itself, for example "554 5.5.1 no valid recipients"; the
	// session then waits for the next command.
	DataCommandReply string

	// Misbehaviours.
	StallGreeting         bool // accept the connection and never speak
	SilentAfterHandshake  bool // implicit TLS: complete the handshake, then read and never speak
	StallAfterGreeting    bool // send the greeting, then read and never answer anything
	SilentAfterAuth       bool // send the AUTH reply, then read and never answer anything
	SilentQuit            bool // never answer QUIT
	DropAfterData         bool // read the message, then close without a reply
	FloodGreeting         bool // answer the connection with an endless reply line
	PipelineAfterStartTLS bool // send an extra clear-text line after the 220 of STARTTLS (a response-injection attempt)
}

// Capture is what one SMTP session did. Read it only from the result of SMTPServer.Captures, which waits for the session to end.
type Capture struct {
	done chan struct{}
	// Plain is everything the client sent before TLS.
	Plain bytes.Buffer
	// TLS reports that the session ended encrypted.
	TLS bool
	// AuthSeenBeforeTLS reports that the client sent AUTH in clear text.
	AuthSeenBeforeTLS bool
	// User and Password are the decoded AUTH PLAIN credential.
	User, Password string
	// From is the MAIL command line and Rcpt the RCPT command lines.
	From string
	Rcpt []string
	// Data is the message as received: the leading dot of dot-stuffed lines removed, CRLF kept.
	Data []byte
	// Hello holds the EHLO/HELO lines.
	Hello []string
	// DataViolations counts lines of the message that were not a plain CRLF-terminated line: a bare LF, a bare CR, or a CR inside
	// a line. The server then refuses the message with 501 (a MOCKED model of strictness; nothing here is known about a real
	// provider's behaviour inside DATA).
	DataViolations int
	// Quit reports that the client sent QUIT.
	Quit bool
}

// SMTPServer is a running test server.
type SMTPServer struct {
	t        testing.TB
	ln       net.Listener
	opts     SMTPOptions
	mu       sync.Mutex
	captures []*Capture
	conns    int
	written  atomic.Int64
}

// StartSMTP starts a server on 127.0.0.1 with an ephemeral port; it stops with the test.
func StartSMTP(t testing.TB, opts SMTPOptions) *SMTPServer {
	t.Helper()
	if opts.Hostname == "" {
		opts.Hostname = "smtp.example.test"
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &SMTPServer{t: t, ln: ln, opts: opts}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns++
			s.mu.Unlock()
			go s.serve(conn)
		}
	}()
	return s
}

// Addr is the listening address, "127.0.0.1:port".
func (s *SMTPServer) Addr() string { return s.ln.Addr().String() }

// Captures returns the sessions so far, each after its end (the client closed or the server finished): reading a session while it
// runs would race with the server goroutine. It fails the test when a session does not end within five seconds.
func (s *SMTPServer) Captures() []*Capture {
	s.mu.Lock()
	all := append([]*Capture(nil), s.captures...)
	s.mu.Unlock()
	for _, c := range all {
		select {
		case <-c.done:
		case <-time.After(5 * time.Second):
			s.t.Fatal("a server session did not end")
		}
	}
	return all
}

// Connections is the number of connections accepted so far.
func (s *SMTPServer) Connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

// BytesWritten is how many bytes the server wrote to its clients, counted for the endless greeting only (at most FloodLimit).
func (s *SMTPServer) BytesWritten() int64 { return s.written.Load() }

func (s *SMTPServer) serve(raw net.Conn) {
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(20 * time.Second))
	c := &Capture{done: make(chan struct{})}
	defer close(c.done)
	s.mu.Lock()
	s.captures = append(s.captures, c)
	s.mu.Unlock()
	opts := s.opts
	if opts.StallGreeting {
		_, _ = io.Copy(io.Discard, raw) // never speak; end when the client closes
		return
	}
	if opts.FloodGreeting {
		chunk := []byte(strings.Repeat("x", 64<<10))
		if n, err := raw.Write([]byte("220-")); err == nil {
			s.written.Add(int64(n))
		}
		for s.written.Load() < FloodLimit {
			n, err := raw.Write(chunk)
			s.written.Add(int64(n))
			if err != nil {
				return
			}
		}
		_, _ = io.Copy(io.Discard, raw) // the limit is reached: wait for the client (or the session deadline)
		return
	}
	conn := raw
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{opts.Certificate}, MinVersion: tls.VersionTLS12}
	if opts.MaxTLSVersion != 0 {
		tlsConfig.MinVersion, tlsConfig.MaxVersion = tls.VersionTLS10, opts.MaxTLSVersion
	}
	if opts.Implicit {
		secured := tls.Server(raw, tlsConfig)
		if err := secured.Handshake(); err != nil {
			return
		}
		conn = secured
		c.TLS = true
		if opts.SilentAfterHandshake {
			_, _ = io.Copy(io.Discard, conn)
			return
		}
	}
	reader := bufio.NewReader(conn)
	say := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
	line := func() (string, bool) {
		text, err := reader.ReadString('\n')
		if !c.TLS {
			c.Plain.WriteString(text)
		}
		return strings.TrimRight(text, "\r\n"), err == nil
	}
	greeting := opts.GreetingReply
	if greeting == "" {
		greeting = "220 " + opts.Hostname + " ESMTP ready"
	}
	say(greeting)
	if len(greeting) > 0 && (greeting[0] == '4' || greeting[0] == '5') {
		return
	}
	if opts.StallAfterGreeting {
		_, _ = io.Copy(io.Discard, reader)
		return
	}
	for {
		text, ok := line()
		if !ok {
			return
		}
		switch strings.ToUpper(strings.Fields(text + " x")[0]) {
		case "EHLO", "HELO":
			c.Hello = append(c.Hello, text)
			if opts.EHLOReply != "" {
				say(opts.EHLOReply)
				continue
			}
			extensions := []string{"250-" + opts.Hostname, "250-8BITMIME", "250-SIZE 10485760"}
			if !opts.NoStartTLS && !c.TLS {
				extensions = append(extensions, "250-STARTTLS")
			}
			extensions = append(extensions, "250 AUTH PLAIN LOGIN")
			say(strings.Join(extensions, "\r\n"))
		case "STARTTLS":
			if opts.NoStartTLS || c.TLS {
				say("502 5.5.1 not offered")
				continue
			}
			if opts.PipelineAfterStartTLS {
				// One write, so the extra clear-text line reaches the client together with the 220 and the outcome does not depend on
				// segment timing; it must never be taken as the reply to the client's next command.
				say("220 2.0.0 ready to start TLS\r\n250 injected in clear text")
			} else {
				say("220 2.0.0 ready to start TLS")
			}
			secured := tls.Server(raw, tlsConfig)
			if err := secured.Handshake(); err != nil {
				return
			}
			conn, c.TLS = secured, true
			reader = bufio.NewReader(conn)
		case "AUTH":
			if !c.TLS {
				c.AuthSeenBeforeTLS = true
				say("530 5.7.0 Must issue a STARTTLS command first")
				continue
			}
			if fields := strings.Fields(text); len(fields) == 3 && strings.EqualFold(fields[1], "PLAIN") {
				decoded, _ := base64.StdEncoding.DecodeString(fields[2])
				if parts := strings.Split(string(decoded), "\x00"); len(parts) == 3 {
					c.User, c.Password = parts[1], parts[2]
				}
			}
			if opts.AuthReply != "" {
				say(opts.AuthReply)
			} else {
				say("235 2.7.0 Authentication successful")
			}
			if opts.SilentAfterAuth {
				_, _ = io.Copy(io.Discard, reader)
				return
			}
		case "MAIL":
			if opts.MailReply != "" {
				say(opts.MailReply)
				continue
			}
			c.From = text
			say("250 2.1.0 ok")
		case "RCPT":
			if opts.RcptReply != "" {
				say(opts.RcptReply)
				continue
			}
			c.Rcpt = append(c.Rcpt, text)
			say("250 2.1.5 ok")
		case "DATA":
			if opts.DataCommandReply != "" {
				say(opts.DataCommandReply)
				continue
			}
			say("354 end data with <CR><LF>.<CR><LF>")
			var data bytes.Buffer
			for {
				l, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				if !strings.HasSuffix(l, "\r\n") || strings.Count(l, "\r") != 1 || strings.Count(l, "\n") != 1 {
					c.DataViolations++
				}
				data.WriteString(strings.TrimPrefix(l, ".")) // un-dot-stuff one leading dot
			}
			c.Data = data.Bytes()
			switch {
			case opts.DropAfterData:
				return
			case c.DataViolations > 0:
				say("501 5.5.2 Syntax error. CR and LF must be CRLF paired.")
			case opts.DataReply != "":
				say(opts.DataReply)
			default:
				say("250 2.0.0 queued as TESTID")
			}
		case "QUIT":
			c.Quit = true
			if opts.SilentQuit {
				_, _ = io.Copy(io.Discard, reader)
				return
			}
			say("221 2.0.0 bye")
			return
		case "RSET", "NOOP":
			say("250 ok")
		default:
			say("500 5.5.2 unknown")
		}
	}
}
