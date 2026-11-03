// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"
)

// All tests here are MOCKED: they read a made-up environment; no provider is contacted.

func mailSentinel(role string) string { return secretSentinel("mail-" + role) }

// postmarkEnvironment is a valid Postmark configuration whose credential is a sentinel.
func postmarkEnvironment() map[string]string {
	return map[string]string{EnvMailProvider: MailPostmark, EnvMailFrom: "sender@example.test", EnvMailPostmarkToken: mailSentinel("token")}
}

// smtpEnvironment is a valid SMTP configuration whose credentials are sentinels.
func smtpEnvironment() map[string]string {
	return map[string]string{EnvMailProvider: MailSMTP, EnvMailFrom: "sender@example.test", EnvMailSMTPHost: "smtp.example.test",
		EnvMailSMTPUsername: mailSentinel("user"), EnvMailSMTPPassword: mailSentinel("password")}
}

func loadWith(mode Mode, extra map[string]string) (Config, error) {
	values := minimal(mode)
	for name, value := range extra {
		values[name] = value
	}
	return Load(environment(values))
}

func TestTheMailVariablesAreTheElevenOfTheDesign(t *testing.T) {
	names := MailVariables()
	if len(names) != 11 || names[0] != EnvMailProvider {
		t.Fatalf("%d variables, first %q", len(names), names[0])
	}
	seen := map[string]bool{}
	for _, name := range names {
		if !strings.HasPrefix(name, "ARCFORGES_CENTER_MAIL_") || seen[name] {
			t.Errorf("%q is not a unique mail variable", name)
		}
		seen[name] = true
	}
	for _, name := range []string{"ARCFORGES_CENTER_MAIL_PROVIDER", "ARCFORGES_CENTER_MAIL_FROM", "ARCFORGES_CENTER_MAIL_FROM_NAME", "ARCFORGES_CENTER_MAIL_TIMEOUT",
		"ARCFORGES_CENTER_MAIL_POSTMARK_TOKEN", "ARCFORGES_CENTER_MAIL_POSTMARK_STREAM", "ARCFORGES_CENTER_MAIL_SMTP_HOST", "ARCFORGES_CENTER_MAIL_SMTP_PORT",
		"ARCFORGES_CENTER_MAIL_SMTP_MODE", "ARCFORGES_CENTER_MAIL_SMTP_USERNAME", "ARCFORGES_CENTER_MAIL_SMTP_PASSWORD"} {
		if !seen[name] {
			t.Errorf("%s is missing", name)
		}
	}
}

func TestMailIsDisabledByDefaultAndWhenTheProviderIsDisabledOrEmpty(t *testing.T) {
	for name, extra := range map[string]map[string]string{
		"nothing set":               nil,
		"disabled":                  {EnvMailProvider: "disabled"},
		"empty provider":            {EnvMailProvider: ""},
		"empty values are unset":    {EnvMailProvider: "disabled", EnvMailFrom: "", EnvMailPostmarkToken: "", EnvMailSMTPPassword: ""},
		"empty values, no provider": {EnvMailFrom: "", EnvMailTimeout: ""},
	} {
		for _, mode := range []Mode{SelfHosted, OfficialHosted} {
			config, err := loadWith(mode, extra)
			if err != nil || config.Mail.Provider != MailDisabled || config.Mail != (Mail{Provider: MailDisabled}) {
				t.Errorf("%s (%s): %+v, %v", name, mode, config.Mail, err)
			}
		}
	}
}

func TestAValidPostmarkConfigurationLoadsWithItsDefaults(t *testing.T) {
	for _, mode := range []Mode{SelfHosted, OfficialHosted} {
		config, err := loadWith(mode, postmarkEnvironment())
		if err != nil {
			t.Fatal(err)
		}
		m := config.Mail
		if m.Provider != MailPostmark || m.From != "sender@example.test" || m.FromName != "" || m.Timeout != DefaultMailTimeout || m.PostmarkStream != "outbound" ||
			m.PostmarkToken.Reveal() != mailSentinel("token") || m.SMTPHost != "" || m.SMTPPort != 0 || !m.SMTPUsername.Empty() {
			t.Errorf("%s: %+v", mode, m)
		}
	}
	custom := postmarkEnvironment()
	custom[EnvMailFromName], custom[EnvMailTimeout], custom[EnvMailPostmarkStream] = "ArcForges Sign-in", "2s", "sign-in-1"
	config, err := loadWith(SelfHosted, custom)
	if err != nil || config.Mail.FromName != "ArcForges Sign-in" || config.Mail.Timeout != 2*time.Second || config.Mail.PostmarkStream != "sign-in-1" {
		t.Errorf("%+v, %v", config.Mail, err)
	}
}

func TestAValidSMTPConfigurationLoadsWithItsDefaultsAndBothModes(t *testing.T) {
	config, err := loadWith(SelfHosted, smtpEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	m := config.Mail
	if m.Provider != MailSMTP || m.SMTPHost != "smtp.example.test" || m.SMTPPort != 587 || m.SMTPMode != MailStartTLS || m.Timeout != DefaultMailTimeout ||
		m.SMTPUsername.Reveal() != mailSentinel("user") || m.SMTPPassword.Reveal() != mailSentinel("password") || !m.PostmarkToken.Empty() || m.PostmarkStream != "" {
		t.Errorf("%+v", m)
	}
	implicit := smtpEnvironment()
	implicit[EnvMailSMTPMode] = MailTLS
	if config, err = loadWith(SelfHosted, implicit); err != nil || config.Mail.SMTPPort != 465 || config.Mail.SMTPMode != MailTLS {
		t.Errorf("implicit TLS defaults: %+v, %v", config.Mail, err)
	}
	for _, port := range []string{"1", "25", "587", "2587", "2465", "65535"} {
		custom := smtpEnvironment()
		custom[EnvMailSMTPPort] = port
		if config, err = loadWith(SelfHosted, custom); err != nil || fmt.Sprint(config.Mail.SMTPPort) != port {
			t.Errorf("port %s: %+v, %v", port, config.Mail, err)
		}
	}
}

// refusal is one row of the start-up refusal table: the environment, the variable the message must name.
type refusal struct {
	row      string
	provider map[string]string
	set      map[string]string
	names    string
}

// ruleReasons and rowReasons are the fixed text each refusal must carry besides the variable's name: the name alone cannot tell
// two rules apart (a missing sender is also refused by the pair rule, and a value with white space by the rule of its variable).
var (
	ruleReasons = map[string]string{"R1": "must be disabled, postmark or smtp", "R2": "is set although the mail provider is disabled",
		"R6": "does not apply to the", "R9": "must be a duration from", "R10": "has leading or trailing white space"}
	rowReasons = map[string]string{"R3 from missing": "must be one plain e-mail address", "R4 the pair over 255 bytes": "together are over",
		"R5 the public test token": "public test token", "R8 mode plain": "plain-text SMTP does not exist"}
)

func TestEveryRefusalRowIsRefusedNamingTheVariable(t *testing.T) {
	long := func(n int) string { return strings.Repeat("a", n) }
	rows := []refusal{
		// R1: the provider.
		{"R1 unknown provider", nil, map[string]string{EnvMailProvider: "ses"}, EnvMailProvider},
		{"R1 upper case", nil, map[string]string{EnvMailProvider: "Postmark"}, EnvMailProvider},
		{"R1 none", nil, map[string]string{EnvMailProvider: "none"}, EnvMailProvider},
		{"R1 plain", nil, map[string]string{EnvMailProvider: "plain"}, EnvMailProvider},
		// R2: a disabled provider with anything else set.
		{"R2 token with no provider", nil, map[string]string{EnvMailPostmarkToken: mailSentinel("token")}, EnvMailPostmarkToken},
		{"R2 password with disabled", nil, map[string]string{EnvMailProvider: "disabled", EnvMailSMTPPassword: mailSentinel("password")}, EnvMailSMTPPassword},
		{"R2 from with no provider", nil, map[string]string{EnvMailFrom: "sender@example.test"}, EnvMailFrom},
		{"R2 timeout with disabled", nil, map[string]string{EnvMailProvider: "disabled", EnvMailTimeout: "5s"}, EnvMailTimeout},
		{"R2 names the first variable", nil, map[string]string{EnvMailSMTPPassword: "x", EnvMailFrom: "sender@example.test"}, EnvMailFrom},
		// R3: the sender address.
		{"R3 from missing", postmarkEnvironment(), map[string]string{EnvMailFrom: ""}, EnvMailFrom},
		{"R3 from not an address", postmarkEnvironment(), map[string]string{EnvMailFrom: "sender"}, EnvMailFrom},
		{"R3 from with a display name", postmarkEnvironment(), map[string]string{EnvMailFrom: "Ada <sender@example.test>"}, EnvMailFrom},
		{"R3 from an IP literal", postmarkEnvironment(), map[string]string{EnvMailFrom: "sender@127.0.0.1"}, EnvMailFrom},
		{"R3 from a list", postmarkEnvironment(), map[string]string{EnvMailFrom: "a@example.test,b@example.test"}, EnvMailFrom},
		{"R3 from over 254 bytes", postmarkEnvironment(), map[string]string{EnvMailFrom: long(64) + "@" + long(63) + "." + long(63) + "." + long(63) + ".org"}, EnvMailFrom},
		// R4: the display name and the composed sender.
		{"R4 name with a dot", postmarkEnvironment(), map[string]string{EnvMailFromName: "ArcForges Inc."}, EnvMailFromName},
		{"R4 name with an angle bracket", postmarkEnvironment(), map[string]string{EnvMailFromName: "a<b"}, EnvMailFromName},
		{"R4 name with an encoded word", postmarkEnvironment(), map[string]string{EnvMailFromName: "=?utf-8?q?x?="}, EnvMailFromName},
		{"R4 name over 64 bytes", postmarkEnvironment(), map[string]string{EnvMailFromName: long(65)}, EnvMailFromName},
		{"R4 name non-ASCII", postmarkEnvironment(), map[string]string{EnvMailFromName: "Adé"}, EnvMailFromName},
		{"R4 the pair over 255 bytes", postmarkEnvironment(), map[string]string{EnvMailFrom: long(64) + "@" + long(63) + "." + long(60) + ".org", EnvMailFromName: long(64)}, EnvMailFrom},
		// R5: Postmark.
		{"R5 token missing", postmarkEnvironment(), map[string]string{EnvMailPostmarkToken: ""}, EnvMailPostmarkToken},
		{"R5 the public test token", postmarkEnvironment(), map[string]string{EnvMailPostmarkToken: postmarkTestToken()}, EnvMailPostmarkToken},
		{"R5 token over 128 bytes", postmarkEnvironment(), map[string]string{EnvMailPostmarkToken: long(129)}, EnvMailPostmarkToken},
		{"R5 token with a space", postmarkEnvironment(), map[string]string{EnvMailPostmarkToken: "a b"}, EnvMailPostmarkToken},
		{"R5 token with a control character", postmarkEnvironment(), map[string]string{EnvMailPostmarkToken: "a\x01b"}, EnvMailPostmarkToken},
		{"R5 token with DEL", postmarkEnvironment(), map[string]string{EnvMailPostmarkToken: "a\x7fb"}, EnvMailPostmarkToken},
		{"R5 token non-ASCII", postmarkEnvironment(), map[string]string{EnvMailPostmarkToken: "aéb"}, EnvMailPostmarkToken},
		{"R5 stream upper case", postmarkEnvironment(), map[string]string{EnvMailPostmarkStream: "Outbound"}, EnvMailPostmarkStream},
		{"R5 stream with an underscore", postmarkEnvironment(), map[string]string{EnvMailPostmarkStream: "a_b"}, EnvMailPostmarkStream},
		{"R5 stream over 40 bytes", postmarkEnvironment(), map[string]string{EnvMailPostmarkStream: long(41)}, EnvMailPostmarkStream},
		// R6: the other provider's variables.
		{"R6 postmark with an SMTP host", postmarkEnvironment(), map[string]string{EnvMailSMTPHost: "smtp.example.test"}, EnvMailSMTPHost},
		{"R6 postmark with an SMTP password", postmarkEnvironment(), map[string]string{EnvMailSMTPPassword: mailSentinel("password")}, EnvMailSMTPPassword},
		{"R6 postmark with an SMTP mode", postmarkEnvironment(), map[string]string{EnvMailSMTPMode: "tls"}, EnvMailSMTPMode},
		{"R6 postmark with an SMTP port", postmarkEnvironment(), map[string]string{EnvMailSMTPPort: "587"}, EnvMailSMTPPort},
		{"R6 postmark with an SMTP user", postmarkEnvironment(), map[string]string{EnvMailSMTPUsername: mailSentinel("user")}, EnvMailSMTPUsername},
		{"R6 smtp with a token", smtpEnvironment(), map[string]string{EnvMailPostmarkToken: mailSentinel("token")}, EnvMailPostmarkToken},
		{"R6 smtp with a stream", smtpEnvironment(), map[string]string{EnvMailPostmarkStream: "outbound"}, EnvMailPostmarkStream},
		// R7: the SMTP host and port.
		{"R7 host missing", smtpEnvironment(), map[string]string{EnvMailSMTPHost: ""}, EnvMailSMTPHost},
		{"R7 host localhost", smtpEnvironment(), map[string]string{EnvMailSMTPHost: "localhost"}, EnvMailSMTPHost},
		{"R7 host an IPv4 literal", smtpEnvironment(), map[string]string{EnvMailSMTPHost: "127.0.0.1"}, EnvMailSMTPHost},
		{"R7 host a hexadecimal IP", smtpEnvironment(), map[string]string{EnvMailSMTPHost: "127.0.0.0x1"}, EnvMailSMTPHost},
		{"R7 host an IPv6 literal", smtpEnvironment(), map[string]string{EnvMailSMTPHost: "[::1]"}, EnvMailSMTPHost},
		{"R7 host with a space", smtpEnvironment(), map[string]string{EnvMailSMTPHost: "smtp .example.test"}, EnvMailSMTPHost},
		{"R7 host with an underscore", smtpEnvironment(), map[string]string{EnvMailSMTPHost: "smtp_1.example.test"}, EnvMailSMTPHost},
		{"R7 host over 253 bytes", smtpEnvironment(), map[string]string{EnvMailSMTPHost: long(63) + "." + long(63) + "." + long(63) + "." + long(63) + ".org"}, EnvMailSMTPHost},
		{"R7 port zero", smtpEnvironment(), map[string]string{EnvMailSMTPPort: "0"}, EnvMailSMTPPort},
		{"R7 port 65536", smtpEnvironment(), map[string]string{EnvMailSMTPPort: "65536"}, EnvMailSMTPPort},
		{"R7 port not a number", smtpEnvironment(), map[string]string{EnvMailSMTPPort: "smtp"}, EnvMailSMTPPort},
		{"R7 port with a sign", smtpEnvironment(), map[string]string{EnvMailSMTPPort: "+587"}, EnvMailSMTPPort},
		{"R7 port with a fraction", smtpEnvironment(), map[string]string{EnvMailSMTPPort: "587.0"}, EnvMailSMTPPort},
		// R8: the mode and the credentials.
		{"R8 mode plain", smtpEnvironment(), map[string]string{EnvMailSMTPMode: "plain"}, EnvMailSMTPMode},
		{"R8 mode none", smtpEnvironment(), map[string]string{EnvMailSMTPMode: "none"}, EnvMailSMTPMode},
		{"R8 mode upper case", smtpEnvironment(), map[string]string{EnvMailSMTPMode: "STARTTLS"}, EnvMailSMTPMode},
		{"R8 mode ssl", smtpEnvironment(), map[string]string{EnvMailSMTPMode: "ssl"}, EnvMailSMTPMode},
		{"R8 user missing", smtpEnvironment(), map[string]string{EnvMailSMTPUsername: ""}, EnvMailSMTPUsername},
		{"R8 password missing", smtpEnvironment(), map[string]string{EnvMailSMTPPassword: ""}, EnvMailSMTPPassword},
		{"R8 user over 256 bytes", smtpEnvironment(), map[string]string{EnvMailSMTPUsername: long(257)}, EnvMailSMTPUsername},
		{"R8 password with a control character", smtpEnvironment(), map[string]string{EnvMailSMTPPassword: "a\x7fb"}, EnvMailSMTPPassword},
		{"R8 password with a unit separator", smtpEnvironment(), map[string]string{EnvMailSMTPPassword: "a\x1fb"}, EnvMailSMTPPassword},
		{"R8 user with a tab inside", smtpEnvironment(), map[string]string{EnvMailSMTPUsername: "a\tb"}, EnvMailSMTPUsername},
		{"R8 password with a newline inside", smtpEnvironment(), map[string]string{EnvMailSMTPPassword: "a\nb"}, EnvMailSMTPPassword},
		// R9: the timeout.
		{"R9 not a duration", postmarkEnvironment(), map[string]string{EnvMailTimeout: "soon"}, EnvMailTimeout},
		{"R9 no unit", postmarkEnvironment(), map[string]string{EnvMailTimeout: "10"}, EnvMailTimeout},
		{"R9 under 2s", postmarkEnvironment(), map[string]string{EnvMailTimeout: "1999ms"}, EnvMailTimeout},
		{"R9 over 25s", postmarkEnvironment(), map[string]string{EnvMailTimeout: "26s"}, EnvMailTimeout},
		{"R9 negative", postmarkEnvironment(), map[string]string{EnvMailTimeout: "-5s"}, EnvMailTimeout},
		{"R9 zero", postmarkEnvironment(), map[string]string{EnvMailTimeout: "0"}, EnvMailTimeout},
		{"R9 an hour", smtpEnvironment(), map[string]string{EnvMailTimeout: "1h"}, EnvMailTimeout},
		// R10: leading or trailing white space, whatever the variable and the provider.
		{"R10 provider with a newline", nil, map[string]string{EnvMailProvider: "postmark\n"}, EnvMailProvider},
		{"R10 from with a trailing space", postmarkEnvironment(), map[string]string{EnvMailFrom: "sender@example.test "}, EnvMailFrom},
		{"R10 token with a newline", postmarkEnvironment(), map[string]string{EnvMailPostmarkToken: mailSentinel("token") + "\n"}, EnvMailPostmarkToken},
		{"R10 password with a leading tab", smtpEnvironment(), map[string]string{EnvMailSMTPPassword: "\t" + mailSentinel("password")}, EnvMailSMTPPassword},
		{"R10 a blank value", nil, map[string]string{EnvMailTimeout: " "}, EnvMailTimeout},
		{"R10 host with a newline", smtpEnvironment(), map[string]string{EnvMailSMTPHost: "smtp.example.test\n"}, EnvMailSMTPHost},
		{"R10 user with a trailing space", smtpEnvironment(), map[string]string{EnvMailSMTPUsername: mailSentinel("user") + " "}, EnvMailSMTPUsername},
		{"R10 password with a leading space", smtpEnvironment(), map[string]string{EnvMailSMTPPassword: " " + mailSentinel("password")}, EnvMailSMTPPassword},
		{"R10 provider with a trailing space", postmarkEnvironment(), map[string]string{EnvMailProvider: "postmark "}, EnvMailProvider},
	}
	secrets := []string{mailSentinel("token"), mailSentinel("user"), mailSentinel("password")}
	for _, r := range rows {
		values := map[string]string{}
		for name, value := range r.provider {
			values[name] = value
		}
		for name, value := range r.set {
			values[name] = value
		}
		config, err := loadWith(SelfHosted, values)
		if err == nil || !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (%+v) or not an ErrInvalid: %v", r.row, config.Mail, err)
			continue
		}
		if !strings.Contains(err.Error(), ": "+r.names+" ") && !strings.Contains(err.Error(), ": "+r.names+":") {
			t.Errorf("%s: the refusal %q does not name %s", r.row, err, r.names)
		}
		want, ok := rowReasons[r.row]
		if !ok {
			want, ok = ruleReasons[strings.Fields(r.row)[0]]
		}
		if ok && !strings.Contains(err.Error(), want) {
			t.Errorf("%s: the refusal %q does not carry %q", r.row, err, want)
		}
		// Errors name the variable and never repeat a value: no credential, no offending text.
		for _, secret := range secrets {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: the refusal repeats a credential: %q", r.row, err)
			}
		}
		for name, value := range r.set {
			if value != "" && len(value) > 5 && name != EnvMailProvider && strings.Contains(err.Error(), value) { // "plain" is in the fixed text of R8
				t.Errorf("%s: the refusal repeats the offending value of %s: %q", r.row, name, err)
			}
		}
		if config.Mail.Provider != "" {
			t.Errorf("%s: a refused configuration returned %+v", r.row, config.Mail)
		}
	}
}

// TestNoRefusalRepeatsAnOffendingValueInAnyVariable puts a sentinel (which is invalid in every slot that has a rule) into each of
// the eleven variables in turn, under both providers, and requires that no refusal contains it.
func TestNoRefusalRepeatsAnOffendingValueInAnyVariable(t *testing.T) {
	for _, base := range []map[string]string{postmarkEnvironment(), smtpEnvironment(), nil} {
		for _, name := range MailVariables() {
			values := map[string]string{}
			for k, v := range base {
				values[k] = v
			}
			offending := mailSentinel("offending") + " " + mailSentinel("tail") // a space inside: invalid for a token, host, name, stream and mode
			values[name] = offending
			_, err := loadWith(SelfHosted, values)
			if err != nil && (strings.Contains(err.Error(), mailSentinel("offending")) || strings.Contains(err.Error(), mailSentinel("tail"))) {
				t.Errorf("%s: the refusal repeats the offending value: %q", name, err)
			}
		}
	}
}

func TestAMailConfigurationNeverPrintsItsCredentials(t *testing.T) {
	for _, extra := range []map[string]string{postmarkEnvironment(), smtpEnvironment()} {
		config, err := loadWith(SelfHosted, extra)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		slog.New(slog.NewTextHandler(&out, nil)).Info("probe", "mail", config.Mail, "config", config)
		text := fmt.Sprintf("%v|%+v|%#v|%v|%+v|%v", config, config, config, config.Mail, config.Mail, &config) + out.String()
		for _, secret := range []string{mailSentinel("token"), mailSentinel("user"), mailSentinel("password")} {
			if strings.Contains(text, secret) {
				t.Errorf("a printed configuration holds %q", secret)
			}
		}
	}
}

func TestTheMailVariablesDoNotChangeTheRestOfTheConfiguration(t *testing.T) {
	plain, err := loadWith(SelfHosted, nil)
	if err != nil {
		t.Fatal(err)
	}
	withMail, err := loadWith(SelfHosted, postmarkEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	if plain.PublicBaseURL != withMail.PublicBaseURL || plain.HTTPAddress != withMail.HTTPAddress || !slices.Equal(plain.DisabledFeatures, withMail.DisabledFeatures) ||
		plain.Identity.Enabled(SurfaceIdentity) != withMail.Identity.Enabled(SurfaceIdentity) || plain.Database != nil || withMail.Database != nil {
		t.Errorf("mail changed the configuration: %+v vs %+v", plain, withMail)
	}
}

func TestTheMailVariablesAreNotCompiledIntoTheDefaults(t *testing.T) {
	// No default sender, host or token exists: with a provider and nothing else, the start is refused.
	for _, provider := range []string{MailPostmark, MailSMTP} {
		if _, err := loadWith(SelfHosted, map[string]string{EnvMailProvider: provider}); err == nil {
			t.Errorf("%s with no further variable was accepted", provider)
		}
	}
}

// TestTheBoundsOfTheRulesAreInclusive loads each bound exactly (a rule one too strict would refuse a value the design allows).
func TestTheBoundsOfTheRulesAreInclusive(t *testing.T) {
	long := func(n int) string { return strings.Repeat("a", n) }
	for _, timeout := range []string{"2s", "25s", "2000ms", "25000ms"} {
		custom := postmarkEnvironment()
		custom[EnvMailTimeout] = timeout
		if config, err := loadWith(SelfHosted, custom); err != nil || config.Mail.Timeout.String() == "" {
			t.Errorf("timeout %s: %v", timeout, err)
		}
	}
	custom := postmarkEnvironment()
	custom[EnvMailPostmarkToken], custom[EnvMailPostmarkStream] = long(MaxPostmarkTokenBytes), long(MaxPostmarkStreamBytes)
	if config, err := loadWith(SelfHosted, custom); err != nil || len(config.Mail.PostmarkToken.Reveal()) != 128 || len(config.Mail.PostmarkStream) != 40 {
		t.Errorf("the longest token and stream: %v", err)
	}
	custom = postmarkEnvironment()
	custom[EnvMailPostmarkToken], custom[EnvMailPostmarkStream] = "a", "a"
	if _, err := loadWith(SelfHosted, custom); err != nil {
		t.Errorf("the shortest token and stream: %v", err)
	}
	custom = smtpEnvironment()
	custom[EnvMailSMTPUsername], custom[EnvMailSMTPPassword] = long(MaxMailCredentialBytes), long(MaxMailCredentialBytes)
	if config, err := loadWith(SelfHosted, custom); err != nil || len(config.Mail.SMTPUsername.Reveal()) != 256 || len(config.Mail.SMTPPassword.Reveal()) != 256 {
		t.Errorf("the longest credentials: %v", err)
	}
	// The composed sender: 64 bytes of name, " <", an address of 188 bytes and ">" make 255; one more byte of address makes 256.
	domain := func(n int) string { return long(60) + "." + long(n-60-1-4) + ".org" } // n bytes in all
	exact := long(64) + "@" + domain(123)
	if len(exact) != 188 || len(long(64)+" <"+exact+">") != 255 {
		t.Fatalf("the fixture is %d bytes", len(exact))
	}
	custom = postmarkEnvironment()
	custom[EnvMailFrom], custom[EnvMailFromName] = exact, long(64)
	if config, err := loadWith(SelfHosted, custom); err != nil || config.Mail.From != exact {
		t.Errorf("a sender of exactly 255 bytes: %v", err)
	}
	custom[EnvMailFrom] = long(64) + "@" + domain(124)
	if _, err := loadWith(SelfHosted, custom); err == nil {
		t.Error("a sender of 256 bytes was accepted")
	}
}

// TestTheCharacterClassesOfTheRulesAreExact loads the characters at the edges of each class: a rule one character too strict refuses a
// value the design allows (the center would not start for a valid token), and one too loose accepts a byte the provider refuses.
func TestTheCharacterClassesOfTheRulesAreExact(t *testing.T) {
	long := func(n int) string { return strings.Repeat("a", n) }
	for _, token := range []string{"!", "~", "a~b!", "A.b-c_d", "0", "z", long(MaxPostmarkTokenBytes)} {
		custom := postmarkEnvironment()
		custom[EnvMailPostmarkToken] = token
		if config, err := loadWith(SelfHosted, custom); err != nil || config.Mail.PostmarkToken.Reveal() != token {
			t.Errorf("token %q: %v", token, err)
		}
	}
	for _, stream := range []string{"z", "a", "0", "9", "z9", "a0", "0a", "z0-9", "a-b", long(MaxPostmarkStreamBytes)} {
		custom := postmarkEnvironment()
		custom[EnvMailPostmarkStream] = stream
		if config, err := loadWith(SelfHosted, custom); err != nil || config.Mail.PostmarkStream != stream {
			t.Errorf("stream %q: %v", stream, err)
		}
	}
	for _, credential := range []string{"pass word", "a b", "~!@#$%^&*()", "a\u00e9", long(MaxMailCredentialBytes)} {
		custom := smtpEnvironment()
		custom[EnvMailSMTPUsername], custom[EnvMailSMTPPassword] = credential, credential
		if config, err := loadWith(SelfHosted, custom); err != nil || config.Mail.SMTPUsername.Reveal() != credential || config.Mail.SMTPPassword.Reveal() != credential {
			t.Errorf("credential %q: %v", credential, err)
		}
	}
	// The documented defaults, by value and not by the name of the constant.
	if DefaultMailTimeout != 10*time.Second || MinMailTimeout != 2*time.Second || MaxMailTimeout != 25*time.Second || DefaultStartTLSPort != 587 || DefaultTLSPort != 465 {
		t.Error("a documented default or bound changed")
	}
	if config, err := loadWith(SelfHosted, postmarkEnvironment()); err != nil || config.Mail.Timeout != 10*time.Second {
		t.Errorf("the default timeout is %v (%v)", config.Mail.Timeout, err)
	}
}

// TestTheHostRulesApplyInBothModes: the SMTP host is checked by name in the implicit TLS mode as much as in STARTTLS (a skipped check
// would start a center that cannot verify its certificate), and the longest host is 252 bytes: the address rule's 254 less "a@".
func TestTheHostRulesApplyInBothModes(t *testing.T) {
	long := func(n int) string { return strings.Repeat("a", n) }
	host := func(total int) string { // a name of exactly total bytes: labels of at most 63 bytes and a last label of letters
		labels := []string{}
		for total > 63+1+3 {
			labels = append(labels, long(63))
			total -= 64
		}
		return strings.Join(append(labels, long(total)), ".")
	}
	for _, mode := range []string{MailStartTLS, MailTLS} {
		for _, bad := range []string{"127.0.0.1", "10.0.0.5", "relay", "localhost", "127.0.0.0x1", "[::1]", "smtp .example.test", "smtp_1.example.test", host(253), host(254)} {
			custom := smtpEnvironment()
			custom[EnvMailSMTPMode], custom[EnvMailSMTPHost] = mode, bad
			_, err := loadWith(SelfHosted, custom)
			if err == nil {
				t.Errorf("mode %s: the host %.40q (%d bytes) was accepted", mode, bad, len(bad))
			} else if len(bad) > 252 && (!strings.Contains(err.Error(), "at most 252 bytes") || !strings.Contains(err.Error(), EnvMailSMTPHost)) {
				// The operator is told the limit the center applies: 252 bytes, and the variable.
				t.Errorf("mode %s: the refusal of a host of %d bytes does not state the limit of 252 bytes: %v", mode, len(bad), err)
			}
		}
		for _, good := range []string{"smtp.example.test", host(250), host(252)} {
			custom := smtpEnvironment()
			custom[EnvMailSMTPMode], custom[EnvMailSMTPHost] = mode, good
			if config, err := loadWith(SelfHosted, custom); err != nil || config.Mail.SMTPHost != good {
				t.Errorf("mode %s: the host of %d bytes was refused: %v", mode, len(good), err)
			}
		}
	}
	if len(host(252)) != 252 || len(host(253)) != 253 {
		t.Fatalf("the fixtures are %d and %d bytes", len(host(252)), len(host(253)))
	}
}
