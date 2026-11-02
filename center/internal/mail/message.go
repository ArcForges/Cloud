// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"mime"
	"mime/quotedprintable"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ArcForges/Cloud/center/internal/config"
)

// Bounds of a message: a sign-in code mail is a few hundred bytes.
const (
	// MaxSubjectBytes bounds the subject. With the 3.7-fold growth of RFC 2047 encoding the longest header line is 740 bytes
	// ("Subject: " and the line end included), under the 998-byte limit of RFC 5322 section 2.1.1; raising the bound much above
	// 260 would break that limit (a test measures the worst case).
	MaxSubjectBytes = 200
	// MaxTextBytes bounds the body.
	MaxTextBytes = 16 << 10
)

// ValidAddress reports whether text is one plain RFC 5322 dot-atom addr-spec of printable ASCII that is safe in an SMTP command,
// in a To header and in a comma-separated provider field. The rule lives in config.ValidMailAddress (the single source shared with
// the e-mail normalization of the identity service); a property test pins that every address it accepts is exactly what
// net/mail parses as one bare address.
func ValidAddress(text string) bool { return config.ValidMailAddress(text) }

// invalid is the refusal of a message that is not sent at all (stage "message").
func invalid(provider string) error {
	return &Error{Class: ErrRejected, Provider: provider, Stage: "message"}
}

// validate refuses a message that could carry an injection or exceed the bounds. It runs before any connection, in both
// adapters. The subject must not contain "=?": an RFC 2047 encoded-word opener in a printable-ASCII subject would be sent as it is
// and decoded by the receiver into something else than the sender wrote (the stdlib cannot force Q-encoding of printable ASCII).
func validate(provider string, m Message) error {
	switch {
	case !ValidAddress(m.To):
		return invalid(provider)
	case len(m.Subject) == 0 || len(m.Subject) > MaxSubjectBytes || !utf8.ValidString(m.Subject) ||
		m.Subject != strings.TrimSpace(m.Subject) || strings.IndexFunc(m.Subject, unicode.IsControl) >= 0 ||
		strings.Contains(m.Subject, "=?"):
		return invalid(provider)
	case len(m.Text) == 0 || len(m.Text) > MaxTextBytes || !utf8.ValidString(m.Text) ||
		strings.IndexFunc(m.Text, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }) >= 0:
		return invalid(provider)
	}
	return nil
}

// validateSender refuses a sender identity that could not be written into a header or a command: the From address and the
// display name come from operator configuration (which validates them at start), and the adapters check them again because a
// hand-built option set bypasses the configuration.
func validateSender(provider, from, fromName string) error {
	if !ValidAddress(from) || !config.ValidMailDisplayName(fromName) {
		return invalid(provider)
	}
	return nil
}

// buildMessage renders one RFC 5322 message with CRLF line ends: headers, a blank line and a quoted-printable UTF-8 text body.
// from and to are ValidAddress values and fromName satisfies config.ValidMailDisplayName; buildMessage checks them again (the
// second layer after validate and validateSender, each with its own test), so that no input can add a header line.
func buildMessage(fromName, from, to, subject, text string, now time.Time) ([]byte, error) {
	if !ValidAddress(from) || !ValidAddress(to) || !config.ValidMailDisplayName(fromName) ||
		strings.ContainsAny(subject, "\r\n\x00") || strings.Contains(subject, "=?") {
		return nil, errors.New("mail: invalid header value")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	_, domain, _ := strings.Cut(from, "@")
	var out bytes.Buffer
	header := func(name, value string) { out.WriteString(name + ": " + value + "\r\n") }
	if fromName != "" {
		header("From", fromName+" <"+from+">")
	} else {
		header("From", from)
	}
	header("To", to)
	header("Subject", mime.QEncoding.Encode("utf-8", subject)) // unchanged when it is printable ASCII
	header("Date", now.UTC().Format(time.RFC1123Z))
	header("Message-ID", "<"+hex.EncodeToString(id[:])+"@"+domain+">")
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "quoted-printable")
	header("Auto-Submitted", "auto-generated")
	out.WriteString("\r\n")
	body := quotedprintable.NewWriter(&out)
	if _, err := body.Write([]byte(strings.ReplaceAll(text, "\n", "\r\n"))); err != nil {
		return nil, err
	}
	if err := body.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
