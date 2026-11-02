// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"bytes"
	"io"
	"mime"
	"mime/quotedprintable"
	netmail "net/mail"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

var buildTime = time.Date(2026, 11, 2, 13, 4, 5, 0, time.UTC)

// addressOfLength builds a valid address of exactly total bytes (a 64-byte local part, labels of at most 63 bytes).
func addressOfLength(t testing.TB, total int) string {
	t.Helper()
	local := strings.Repeat("a", 64)
	rest := total - len(local) - 1
	var labels []string
	for rest > 0 {
		size := min(rest, 63)
		if rest-size > 0 && rest-size < 3 {
			size = rest - 3
		}
		labels = append(labels, strings.Repeat("b", size))
		rest -= size + 1
	}
	address := local + "@" + strings.Join(labels, ".")
	if len(address) != total {
		t.Fatalf("built %d bytes, want %d", len(address), total)
	}
	return address
}

// parsed is a built message read back with net/mail.
type parsed struct {
	header  netmail.Header
	subject string
	body    string
	raw     []byte
}

func parseBuilt(t testing.TB, raw []byte) parsed {
	t.Helper()
	message, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("net/mail cannot read the message: %v\n%q", err, raw)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(message.Header.Get("Subject"))
	if err != nil {
		t.Fatalf("the subject does not decode: %v", err)
	}
	body, err := io.ReadAll(quotedprintable.NewReader(message.Body))
	if err != nil {
		t.Fatalf("the body does not decode: %v", err)
	}
	return parsed{header: message.Header, subject: subject, body: string(body), raw: raw}
}

// checkWire fails on a bare CR or LF, a header line over the RFC 5322 limit, and on a header block that holds anything but the
// nine headers buildMessage writes, each once.
func checkWire(t testing.TB, raw []byte) {
	t.Helper()
	for i, c := range raw {
		if c == '\r' && (i+1 >= len(raw) || raw[i+1] != '\n') {
			t.Fatalf("a bare CR at %d", i)
		}
		if c == '\n' && (i == 0 || raw[i-1] != '\r') {
			t.Fatalf("a bare LF at %d", i)
		}
	}
	head, _, found := strings.Cut(string(raw), "\r\n\r\n")
	if !found {
		t.Fatal("no blank line after the headers")
	}
	seen := map[string]int{}
	for _, line := range strings.Split(head, "\r\n") {
		if len(line)+2 > 998 {
			t.Fatalf("a header line of %d bytes", len(line)+2)
		}
		if strings.Contains(line, "=?") && len(line) > 76 {
			t.Fatalf("a line with an encoded-word of %d characters (RFC 2047 section 2 allows 76)", len(line))
		}
		if line[0] == ' ' || line[0] == '\t' { // a continuation of the field before it
			continue
		}
		name, _, _ := strings.Cut(line, ":")
		seen[name]++
	}
	for _, name := range []string{"From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type", "Content-Transfer-Encoding", "Auto-Submitted"} {
		if seen[name] != 1 {
			t.Fatalf("header %s appears %d times", name, seen[name])
		}
		delete(seen, name)
	}
	if len(seen) != 0 {
		t.Fatalf("unexpected headers %v", seen)
	}
}

func TestMessageBoundsAreTheDesignedOnes(t *testing.T) {
	// The other tests size their forms from the constants; this one pins the numbers, so that raising a bound is a visible change
	// (200 bytes keep the worst-case subject line under 998 bytes; 16 KiB is far above a sign-in mail).
	if MaxSubjectBytes != 200 || MaxTextBytes != 16384 {
		t.Fatalf("bounds %d and %d", MaxSubjectBytes, MaxTextBytes)
	}
	text := func(size int) Message { return Message{To: testTo, Subject: "s", Text: strings.Repeat("t", size)} }
	if validate("smtp", text(16384)) != nil || validate("smtp", text(16385)) == nil {
		t.Error("the text bound is not 16384 bytes")
	}
	subject := func(size int) Message { return Message{To: testTo, Subject: strings.Repeat("s", size), Text: "t"} }
	if validate("smtp", subject(200)) != nil || validate("smtp", subject(201)) == nil {
		t.Error("the subject bound is not 200 bytes")
	}
}

func TestValidateRefusesEveryInjectionFormAndAcceptsTheOrdinaryMessage(t *testing.T) {
	good := testMessage()
	if err := validate("smtp", good); err != nil {
		t.Fatalf("the ordinary message is refused: %v", err)
	}
	with := func(change func(*Message)) Message {
		m := good
		change(&m)
		return m
	}
	bad := map[string]Message{
		"To a list":              with(func(m *Message) { m.To = "a@example.test,b@example.test" }),
		"To a list with space":   with(func(m *Message) { m.To = "a@example.test, b@example.test" }),
		"To CRLF header":         with(func(m *Message) { m.To = "a@example.test\r\nBcc: b@example.test" }),
		"To LF":                  with(func(m *Message) { m.To = "a@example.test\nBcc: b@example.test" }),
		"To angle brackets":      with(func(m *Message) { m.To = "<a@example.test>" }),
		"To display name":        with(func(m *Message) { m.To = "Ada <a@example.test>" }),
		"To quoted":              with(func(m *Message) { m.To = `"a b"@example.test` }),
		"To empty":               with(func(m *Message) { m.To = "" }),
		"To IP literal":          with(func(m *Message) { m.To = "a@127.0.0.1" }),
		"To numeric last label":  with(func(m *Message) { m.To = "a@1.1" }),
		"To NUL":                 with(func(m *Message) { m.To = "a\x00@example.test" }),
		"To over 254 bytes":      with(func(m *Message) { m.To = addressOfLength(t, 255) }),
		"Subject empty":          with(func(m *Message) { m.Subject = "" }),
		"Subject CR":             with(func(m *Message) { m.Subject = "x\rBcc: a@example.test" }),
		"Subject LF":             with(func(m *Message) { m.Subject = "x\nBcc: a@example.test" }),
		"Subject CRLF":           with(func(m *Message) { m.Subject = "x\r\nBcc: a@example.test" }),
		"Subject NUL":            with(func(m *Message) { m.Subject = "x\x00y" }),
		"Subject tab":            with(func(m *Message) { m.Subject = "x\ty" }),
		"Subject SOH first":      with(func(m *Message) { m.Subject = "\x01abc" }),
		"Subject DEL first":      with(func(m *Message) { m.Subject = "\x7fabc" }),
		"Subject ESC first":      with(func(m *Message) { m.Subject = "\x1babc" }),
		"Subject NEL first":      with(func(m *Message) { m.Subject = "\u0085abc" }),
		"Text SOH first":         with(func(m *Message) { m.Text = "\x01abc" }),
		"Text DEL first":         with(func(m *Message) { m.Text = "\x7fabc" }),
		"Text ESC first":         with(func(m *Message) { m.Text = "\x1babc" }),
		"Text NEL first":         with(func(m *Message) { m.Text = "\u0085abc" }),
		"Subject DEL":            with(func(m *Message) { m.Subject = "x\x7fy" }),
		"Subject NEL":            with(func(m *Message) { m.Subject = "x\u0085y" }),
		"Subject only a space":   with(func(m *Message) { m.Subject = " " }),
		"Subject leading space":  with(func(m *Message) { m.Subject = " x" }),
		"Subject trailing space": with(func(m *Message) { m.Subject = "x " }),
		"Subject no-break space": with(func(m *Message) { m.Subject = "x " }),
		"Subject encoded word":   with(func(m *Message) { m.Subject = "=?utf-8?q?x?=" }),
		"Subject word inside":    with(func(m *Message) { m.Subject = "Code =?utf-8?B?eA==?= now" }),
		"Subject opener at end":  with(func(m *Message) { m.Subject = "x=?" }),
		"Subject invalid UTF-8":  with(func(m *Message) { m.Subject = "x\xff" }),
		"Subject over 200 bytes": with(func(m *Message) { m.Subject = strings.Repeat("s", MaxSubjectBytes+1) }),
		"Text empty":             with(func(m *Message) { m.Text = "" }),
		"Text NUL":               with(func(m *Message) { m.Text = "a\x00b" }),
		"Text CR":                with(func(m *Message) { m.Text = "a\rb" }),
		"Text CRLF":              with(func(m *Message) { m.Text = "a\r\nb" }),
		"Text form feed":         with(func(m *Message) { m.Text = "a\fb" }),
		"Text escape":            with(func(m *Message) { m.Text = "a\x1bb" }),
		"Text DEL":               with(func(m *Message) { m.Text = "a\x7fb" }),
		"Text invalid UTF-8":     with(func(m *Message) { m.Text = "a\xc3" }),
		"Text over 16 KiB":       with(func(m *Message) { m.Text = strings.Repeat("t", MaxTextBytes+1) }),
	}
	for name, message := range bad {
		for _, provider := range []string{"smtp", "postmark"} {
			if failure, ok := validate(provider, message).(*Error); !ok || failure.Class != ErrRejected || failure.Stage != "message" {
				t.Errorf("%s (%s) was not refused as a rejected message: %v", name, provider, failure)
			}
		}
	}
	for name, message := range map[string]Message{
		"subject of the maximum length": with(func(m *Message) { m.Subject = strings.Repeat("s", MaxSubjectBytes) }),
		"text of the maximum length":    with(func(m *Message) { m.Text = strings.Repeat("t", MaxTextBytes) }),
		"tab and newlines in the text":  with(func(m *Message) { m.Text = "a\tb\n\nc\n" }),
		"non-ASCII subject and text":    with(func(m *Message) { m.Subject, m.Text = "Ihr Code äöü ✓", "Code: 漢字 \U0001F600\n" }),
		"an equals sign in the subject": with(func(m *Message) { m.Subject = "a=b ?x" }),
		"address of the maximum length": with(func(m *Message) { m.To = addressOfLength(t, 254) }),
	} {
		if err := validate("smtp", message); err != nil {
			t.Errorf("%s is refused: %v", name, err)
		}
	}
}

// TestEachLayerRefusesInjection tests the two layers of the header defence separately (a defence with two layers hides the removal
// of one behind the other unless each has its own test): validate, which runs before any connection, and buildMessage, which
// renders the headers and refuses on its own.
func TestEachLayerRefusesInjection(t *testing.T) {
	t.Run("validate alone", func(t *testing.T) {
		for _, subject := range []string{"x\r\nBcc: a@example.test", "x\ny", "x\ry", "x\x00y", "=?utf-8?q?x?="} {
			m := testMessage()
			m.Subject = subject
			expectFailure(t, validate("smtp", m), ErrRejected, "message", 0)
		}
		for _, to := range []string{"a@example.test,b@example.test", "a@example.test\r\nBcc: b@example.test", "<a@example.test>"} {
			m := testMessage()
			m.To = to
			expectFailure(t, validate("postmark", m), ErrRejected, "message", 0)
		}
	})
	t.Run("buildMessage alone", func(t *testing.T) {
		build := func(name, from, to, subject string) error {
			_, err := buildMessage(name, from, to, subject, "body", buildTime)
			return err
		}
		if err := build("", testFrom, testTo, "A subject"); err != nil {
			t.Fatalf("an ordinary message is refused: %v", err)
		}
		refused := map[string][4]string{
			"subject CR":          {"", testFrom, testTo, "x\rBcc: a@example.test"},
			"subject LF":          {"", testFrom, testTo, "x\nBcc: a@example.test"},
			"subject CRLF":        {"", testFrom, testTo, "x\r\nBcc: a@example.test"},
			"subject NUL":         {"", testFrom, testTo, "x\x00y"},
			"subject encoded":     {"", testFrom, testTo, "=?utf-8?q?x?="},
			"to list":             {"", testFrom, "a@example.test,b@example.test", "s"},
			"to CRLF":             {"", testFrom, "a@example.test\r\nBcc: b@example.test", "s"},
			"to display name":     {"", testFrom, "Ada <a@example.test>", "s"},
			"from list":           {"", "a@example.test,b@example.test", testTo, "s"},
			"from CRLF":           {"", "a@example.test\r\nBcc: b@example.test", testTo, "s"},
			"from IP literal":     {"", "a@127.0.0.1", testTo, "s"},
			"name CRLF":           {"Ada\r\nBcc: a@example.test", testFrom, testTo, "s"},
			"name LF":             {"Ada\nBcc: a@example.test", testFrom, testTo, "s"},
			"name angle":          {"Ada <x@example.test>", testFrom, testTo, "s"},
			"name encoded word":   {"=?utf-8?q?x?=", testFrom, testTo, "s"},
			"name quote":          {`Ada "x"`, testFrom, testTo, "s"},
			"name non-ASCII":      {"Adé", testFrom, testTo, "s"},
			"name over 64 bytes":  {strings.Repeat("n", 65), testFrom, testTo, "s"},
			"name leading space":  {" Ada", testFrom, testTo, "s"},
			"name trailing space": {"Ada ", testFrom, testTo, "s"},
		}
		for name, form := range refused {
			if err := build(form[0], form[1], form[2], form[3]); err == nil {
				t.Errorf("%s: buildMessage accepted it", name)
			}
		}
	})
	t.Run("validateSender alone", func(t *testing.T) {
		for _, name := range []string{"", "ArcForges", "Arc Forges Sign-in"} {
			if err := validateSender("smtp", testFrom, name); err != nil {
				t.Errorf("sender %q is refused: %v", name, err)
			}
		}
		for _, form := range [][2]string{{addressOfLength(t, 188), strings.Repeat("n", 64)}, {addressOfLength(t, 251), "n"}, {addressOfLength(t, 254), ""}} {
			if err := validateSender("postmark", form[0], form[1]); err != nil { // 255, 255 and a bare 254
				t.Errorf("the sender of %d+%d bytes is refused: %v", len(form[0]), len(form[1]), err)
			}
		}
		for _, form := range [][2]string{
			{"", ""}, {"a@127.0.0.1", ""}, {"a@example.test,b@example.test", ""}, {"Ada <a@example.test>", ""}, {testFrom, "Ada\r\nBcc: x@example.test"},
			{testFrom, "=?utf-8?q?x?="}, {testFrom, "Ada <x@example.test>"}, {testFrom, strings.Repeat("n", 65)}, {testFrom, "Inc."},
			// The composed "Name <address>" is bounded by Postmark's 255 characters: 64 + 3 + 189 = 256, 1 + 3 + 254 = 258.
			{addressOfLength(t, 189), strings.Repeat("n", 64)}, {addressOfLength(t, 254), "n"}, {addressOfLength(t, 252), "n"},
		} {
			expectFailure(t, validateSender("postmark", form[0], form[1]), ErrRejected, "message", 0)
		}
	})
}

func TestBuildMessageWritesTheDocumentedHeadersAndABodyThatRoundTrips(t *testing.T) {
	text := "Your code: word-word-word\n.leading dot\n.\n=3D equals\nan accent é and a long line " + strings.Repeat("long ", 40) + "\nspaces at the end   \n"
	raw, err := buildMessage("ArcForges Sign-in", testFrom, testTo, "Your sign-in code ✓", text, buildTime)
	if err != nil {
		t.Fatal(err)
	}
	checkWire(t, raw)
	p := parseBuilt(t, raw)
	h := p.header
	if h.Get("From") != "ArcForges Sign-in <"+testFrom+">" || h.Get("To") != testTo || len(h["To"]) != 1 || len(h["Subject"]) != 1 {
		t.Errorf("From %q To %q", h.Get("From"), h["To"])
	}
	if h.Get("Bcc") != "" || h.Get("Cc") != "" {
		t.Error("Bcc or Cc present")
	}
	if p.subject != "Your sign-in code ✓" {
		t.Errorf("subject %q", p.subject)
	}
	if date, err := h.Date(); err != nil || !date.Equal(buildTime) || h.Get("Date") != "Mon, 02 Nov 2026 13:04:05 +0000" {
		t.Errorf("date %q: %v", h.Get("Date"), err)
	}
	id := h.Get("Message-ID")
	if !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, "@example.test>") || len(id) != 1+32+len("@example.test")+1 {
		t.Errorf("Message-ID %q", id)
	}
	if h.Get("MIME-Version") != "1.0" || h.Get("Content-Type") != "text/plain; charset=utf-8" || h.Get("Content-Transfer-Encoding") != "quoted-printable" ||
		h.Get("Auto-Submitted") != "auto-generated" {
		t.Errorf("MIME headers %v", h)
	}
	if want := strings.ReplaceAll(text, "\n", "\r\n"); p.body != want {
		t.Errorf("body %q, want %q", p.body, want)
	}
	other, _ := buildMessage("", testFrom, testTo, "s", "b", buildTime)
	if parseBuilt(t, other).header.Get("Message-ID") == id {
		t.Error("two messages share a Message-ID")
	}
	if parseBuilt(t, other).header.Get("From") != testFrom {
		t.Error("a nameless From carries a name")
	}
}

// subjectLines returns the physical lines of the Subject field (the line and its continuations) of a built message.
func subjectLines(raw []byte) []string {
	var lines []string
	collecting := false
	for _, line := range strings.Split(string(raw), "\r\n") {
		switch {
		case line == "":
			return lines
		case strings.HasPrefix(line, "Subject:"):
			collecting = true
			lines = append(lines, line)
		case collecting && (line[0] == ' ' || line[0] == '\t'):
			lines = append(lines, line)
		default:
			collecting = false
		}
	}
	return lines
}

// TestSubjectsRoundTripThroughRFC2047AndAFoldedSubjectKeepsEveryLineWithinTheLimit measures the bound. A subject that needs encoding
// is written as "Subject:" alone and one encoded-word of at most 75 characters per continuation line (CRLF and a space between them,
// RFC 2047 section 2), so no physical line of the field passes 76 characters, whatever the subject size; the worst case is the
// longest subject of 200 bytes, all of it encoded (about 740 characters of encoded text). A printable-ASCII subject stays on the
// Subject line as it is, and every subject reads back unchanged.
func TestSubjectsRoundTripThroughRFC2047AndAFoldedSubjectKeepsEveryLineWithinTheLimit(t *testing.T) {
	for _, subject := range []string{
		"Plain ASCII subject", "a=b and c?d", "=", "?=", "=x", "x?=", "tab-free  two  spaces", "Ihr Code \u00e4\u00f6\u00fc", "\u2713",
		"\u00e9 =x", strings.Repeat("\u00e9", 100), strings.Repeat("\U0001F600", 50), strings.Repeat("\u6f22", 66) + "ab",
		"\u00e9" + strings.Repeat("=", 199), "\u00e9" + strings.Repeat("?", 198), strings.Repeat("s", MaxSubjectBytes),
	} {
		raw, err := buildMessage("", testFrom, testTo, subject, "body", buildTime)
		if err != nil {
			t.Fatalf("%q: %v", subject, err)
		}
		checkWire(t, raw)
		if got := parseBuilt(t, raw).subject; got != subject {
			t.Errorf("%q came back as %q", subject, got)
		}
	}
	ascii, _ := buildMessage("", testFrom, testTo, "Plain ASCII subject", "b", buildTime)
	if lines := subjectLines(ascii); len(lines) != 1 || lines[0] != "Subject: Plain ASCII subject" {
		t.Errorf("an ASCII subject is %q", lines)
	}
	short, _ := buildMessage("", testFrom, testTo, "\u2713", "b", buildTime)
	if lines := subjectLines(short); len(lines) != 2 || lines[0] != "Subject:" || lines[1] != " =?utf-8?q?=E2=9C=93?=" {
		t.Errorf("a short encoded subject is %q", lines)
	}
	worst := strings.Repeat("\u00e9", 100) // 200 bytes, the longest subject, every byte of it encoded
	raw, err := buildMessage("", testFrom, testTo, worst, "b", buildTime)
	if err != nil {
		t.Fatal(err)
	}
	lines := subjectLines(raw)
	if len(lines) < 10 || lines[0] != "Subject:" {
		t.Fatalf("the worst-case subject is %d lines: %q", len(lines), lines)
	}
	total := 0
	for _, line := range lines[1:] {
		word := line[1:]
		total += len(word)
		if line[0] != ' ' || len(line) > 76 || len(word) > 75 || !strings.HasPrefix(word, "=?utf-8?q?") || !strings.HasSuffix(word, "?=") {
			t.Errorf("continuation line %q (%d characters)", line, len(line))
		}
	}
	if total < 700 {
		t.Errorf("the worst case encodes to %d characters: this test's idea of the worst case changed", total)
	}
}

func TestValidAddressIsTheSharedRuleAndNetMailAgreesOnEveryAddressItAccepts(t *testing.T) {
	for _, text := range []string{"ada@example.org", "A.b+c@Sub.Example.ORG", "a@x.9a", "!#$%&'*+-/?=^_`{|}~@example.org", "a?=b@example.org", addressOfLength(t, 254)} {
		if !ValidAddress(text) {
			t.Errorf("%q should be valid", text)
		}
	}
	for _, text := range []string{"", "a@127.0.0.1", "a@1.1", "a@0.0.0.0", "a@example.1", addressOfLength(t, 255), "a@b,c@d.ef", "a b@example.org", "<a@example.org>"} {
		if ValidAddress(text) {
			t.Errorf("%q should be invalid", text)
		}
	}
}

func checkAddress(t testing.TB, text string) {
	t.Helper()
	if !ValidAddress(text) {
		return
	}
	address, err := netmail.ParseAddress(text)
	if err != nil || address.Name != "" || address.Address != text {
		t.Fatalf("%q passes ValidAddress but net/mail reads %+v, %v", text, address, err)
	}
	if list, err := netmail.ParseAddressList(text); err != nil || len(list) != 1 {
		t.Fatalf("%q passes ValidAddress but is a list of %d: %v", text, len(list), err)
	}
	if strings.ContainsAny(text, " \t\r\n,;<>\"()[]\\:") || len(text) > 254 || !utf8.ValidString(text) || strings.Count(text, "@") != 1 {
		t.Fatalf("%q passes ValidAddress with a special", text)
	}
	last := text[strings.LastIndexByte(text, '.')+1:]
	if strings.Trim(last, "0123456789") == "" {
		t.Fatalf("%q has an all-numeric last label", text)
	}
	if lower := strings.ToLower(last); strings.HasPrefix(lower, "0x") && strings.Trim(lower[2:], "0123456789abcdef") == "" {
		t.Fatalf("%q has a hexadecimal IP-like last label", text)
	}
	if local, _, _ := strings.Cut(text, "@"); strings.Contains(local, "=?") {
		t.Fatalf("%q has an encoded-word opener in the local part", text)
	}
}

// FuzzValidAddress checks that an address the validator accepts is exactly what net/mail reads as one bare address, with no
// specials and a letter in the last label. The seeds cover the numeric-last-label forms and the byte bounds.
func FuzzValidAddress(f *testing.F) {
	long := addressOfLength(f, 254)
	for _, seed := range []string{
		"ada@example.org", "a@127.0.0.1", "a@1.1", "a@x.9a", "a@example.1", "a@127.0.0.0x1", "a@1.2.3.0x7f", "=?utf-8?q?x?=@example.org",
		"=?utf-8?q?a=0D=0ABcc=3A_evil=40x.test?=@example.org", "a?=b@example.org", "a@b", "a@b@c.de", "a b@c.de", "a@b.de,c@d.ef",
		"\"a\"@b.cd", "<a@b.cd>", "a@b.cd\r\nBcc: x@y.zz", "A@B.CD", long, long + "x", strings.Repeat("a", 65) + "@b.cd",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) { checkAddress(t, text) })
}

// FuzzBuildMessage checks that a message the validator admits builds into a message that net/mail reads back with exactly one
// Subject and one To, no other header, only CRLF line ends, a subject and a body that round-trip. The seeds include the
// encoded-word forms a random mutation does not find (a well-formed "=?utf-8?q?x?=" is the one that broke the first property).
func FuzzBuildMessage(f *testing.F) {
	for _, seed := range []struct{ to, subject, text string }{
		{testTo, "Your code", "Code: 123\n"}, {testTo, " ", "x"}, {testTo, "=?utf-8?q?x?=", "x"}, {testTo, "=??B??=", "x"},
		{testTo, "a=b", ".\n.."}, {testTo, "éé", "é\n=3D\n"}, {"a@127.0.0.1", "s", "x"}, {testTo, "s\r\nBcc: x@y.zz", "x"},
		{testTo, "s", "line one\r\nline two"}, {testTo + ",b@example.test", "s", "x"}, {testTo, "s", "a  \n\t\n"},
	} {
		f.Add(seed.to, seed.subject, seed.text)
	}
	f.Fuzz(func(t *testing.T, to, subject, text string) {
		message := Message{To: to, Subject: subject, Text: text}
		if validate("smtp", message) != nil {
			return
		}
		raw, err := buildMessage("", testFrom, to, subject, text, buildTime)
		if err != nil {
			t.Fatalf("a validated message does not build: %v", err)
		}
		checkWire(t, raw)
		p := parseBuilt(t, raw)
		if p.header.Get("To") != to || len(p.header["To"]) != 1 || len(p.header["Subject"]) != 1 {
			t.Fatalf("To %q Subject %q", p.header["To"], p.header["Subject"])
		}
		if p.subject != subject {
			t.Fatalf("subject %q came back as %q", subject, p.subject)
		}
		if want := strings.ReplaceAll(text, "\n", "\r\n"); p.body != want {
			t.Fatalf("body %q came back as %q", text, p.body)
		}
	})
}
