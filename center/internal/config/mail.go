// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"strings"
	"time"
)

// The environment variables of the mail configuration (AF-CTR-03). Mail is disabled unless the provider names one; the Worker passes
// these variables to the Container only while it is configured, and the hosted environments configure none today.
const (
	EnvMailProvider       = "ARCFORGES_CENTER_MAIL_PROVIDER"
	EnvMailFrom           = "ARCFORGES_CENTER_MAIL_FROM"
	EnvMailFromName       = "ARCFORGES_CENTER_MAIL_FROM_NAME"
	EnvMailTimeout        = "ARCFORGES_CENTER_MAIL_TIMEOUT"
	EnvMailPostmarkToken  = "ARCFORGES_CENTER_MAIL_POSTMARK_TOKEN"
	EnvMailPostmarkStream = "ARCFORGES_CENTER_MAIL_POSTMARK_STREAM"
	EnvMailSMTPHost       = "ARCFORGES_CENTER_MAIL_SMTP_HOST"
	EnvMailSMTPPort       = "ARCFORGES_CENTER_MAIL_SMTP_PORT"
	EnvMailSMTPMode       = "ARCFORGES_CENTER_MAIL_SMTP_MODE"
	EnvMailSMTPUsername   = "ARCFORGES_CENTER_MAIL_SMTP_USERNAME"
	EnvMailSMTPPassword   = "ARCFORGES_CENTER_MAIL_SMTP_PASSWORD"
)

// The providers, the defaults and the bounds of the mail configuration.
const (
	MailDisabled = "disabled"
	MailPostmark = "postmark"
	MailSMTP     = "smtp"
	// MailStartTLS and MailTLS are the two SMTP modes. There is no plain-text mode, not even for a loopback relay.
	MailStartTLS = "starttls"
	MailTLS      = "tls"

	DefaultMailTimeout     = 10 * time.Second
	MinMailTimeout         = 2 * time.Second
	MaxMailTimeout         = 25 * time.Second
	DefaultPostmarkStream  = "outbound"
	MaxPostmarkStreamBytes = 40
	MaxPostmarkTokenBytes  = 128
	MaxMailCredentialBytes = 256
	DefaultStartTLSPort    = 587
	DefaultTLSPort         = 465
)

// MailVariables are the eleven variables, the provider first. The Worker's closed lists repeat them, and a Worker test compares
// them with this list.
func MailVariables() []string {
	return []string{EnvMailProvider, EnvMailFrom, EnvMailFromName, EnvMailTimeout, EnvMailPostmarkToken, EnvMailPostmarkStream,
		EnvMailSMTPHost, EnvMailSMTPPort, EnvMailSMTPMode, EnvMailSMTPUsername, EnvMailSMTPPassword}
}

// Mail is the validated mail configuration. Provider is always one of disabled, postmark and smtp; a disabled configuration holds
// nothing else. The credentials are Secrets and no error of the configuration repeats a value.
type Mail struct {
	Provider string
	// From and FromName are the sender address and its optional display name (config.ValidMailSender).
	From     string
	FromName string
	Timeout  time.Duration
	// Postmark.
	PostmarkToken  Secret
	PostmarkStream string
	// SMTP.
	SMTPHost     string
	SMTPPort     int
	SMTPMode     string
	SMTPUsername Secret
	SMTPPassword Secret
}

// postmarkTestToken is Postmark's public test token, built from its words: it delivers nothing, so a center configured with it
// would lose every code silently.
func postmarkTestToken() string { return strings.Join([]string{"POSTMARK", "API", "TEST"}, "_") }

// loadMail reads and validates the mail variables (R1 to R10 of the plan). Every refusal names the variable and a closed reason, never
// the value: the parse errors of strconv and time quote their input, so none of them is wrapped.
func loadMail(lookup func(string) (string, bool)) (Mail, error) {
	values := map[string]string{}
	for _, name := range MailVariables() {
		value, _ := lookup(name)
		// R10: a copied newline or space is refused, whatever the variable and whatever the provider.
		if value != strings.TrimSpace(value) {
			return Mail{}, invalid("%s has leading or trailing white space", name)
		}
		values[name] = value
	}
	switch values[EnvMailProvider] {
	case "", MailDisabled:
		// R2: a disabled provider with any other mail variable set is a mistake (the hosted Worker passes nothing when disabled).
		for _, name := range MailVariables()[1:] {
			if values[name] != "" {
				return Mail{}, invalid("%s is set although the mail provider is disabled", name)
			}
		}
		return Mail{Provider: MailDisabled}, nil
	case MailPostmark, MailSMTP:
	default: // R1
		return Mail{}, invalid("%s must be %s, %s or %s", EnvMailProvider, MailDisabled, MailPostmark, MailSMTP)
	}
	mail := Mail{Provider: values[EnvMailProvider]}
	// R3 and R4: the sender.
	mail.From, mail.FromName = values[EnvMailFrom], values[EnvMailFromName]
	if !ValidMailAddress(mail.From) {
		return Mail{}, invalid("%s must be one plain e-mail address (required)", EnvMailFrom)
	}
	if !ValidMailDisplayName(mail.FromName) {
		return Mail{}, invalid("%s must be at most %d bytes of printable ASCII without quotes, brackets, commas, colons, semicolons, dots or an encoded-word opener",
			EnvMailFromName, MaxMailDisplayNameBytes)
	}
	if !ValidMailSender(mail.From, mail.FromName) {
		return Mail{}, invalid("%s and %s together are over %d bytes", EnvMailFrom, EnvMailFromName, MaxMailSenderBytes)
	}
	// R9: the timeout.
	mail.Timeout = DefaultMailTimeout
	if value := values[EnvMailTimeout]; value != "" {
		timeout, err := time.ParseDuration(value)
		if err != nil || timeout < MinMailTimeout || timeout > MaxMailTimeout {
			return Mail{}, invalid("%s must be a duration from %s to %s", EnvMailTimeout, MinMailTimeout, MaxMailTimeout)
		}
		mail.Timeout = timeout
	}
	// R6: the other provider's variables.
	foreign := []string{EnvMailSMTPHost, EnvMailSMTPPort, EnvMailSMTPMode, EnvMailSMTPUsername, EnvMailSMTPPassword}
	if mail.Provider == MailSMTP {
		foreign = []string{EnvMailPostmarkToken, EnvMailPostmarkStream}
	}
	for _, name := range foreign {
		if values[name] != "" {
			return Mail{}, invalid("%s does not apply to the %s provider", name, mail.Provider)
		}
	}
	if mail.Provider == MailPostmark {
		return loadPostmark(mail, values)
	}
	return loadSMTP(mail, values)
}

// loadPostmark validates the Postmark variables (R5).
func loadPostmark(mail Mail, values map[string]string) (Mail, error) {
	token := values[EnvMailPostmarkToken]
	if token == "" || len(token) > MaxPostmarkTokenBytes || strings.IndexFunc(token, func(r rune) bool { return r <= ' ' || r >= 0x7f }) >= 0 {
		return Mail{}, invalid("%s is required: 1 to %d bytes of visible ASCII", EnvMailPostmarkToken, MaxPostmarkTokenBytes)
	}
	if token == postmarkTestToken() {
		return Mail{}, invalid("%s is Postmark's public test token, which delivers nothing", EnvMailPostmarkToken)
	}
	mail.PostmarkToken = NewSecret(token)
	mail.PostmarkStream = DefaultPostmarkStream
	if stream := values[EnvMailPostmarkStream]; stream != "" {
		if len(stream) > MaxPostmarkStreamBytes || strings.IndexFunc(stream, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') }) >= 0 {
			return Mail{}, invalid("%s must be 1 to %d characters of a-z, 0-9 and hyphen", EnvMailPostmarkStream, MaxPostmarkStreamBytes)
		}
		mail.PostmarkStream = stream
	}
	return mail, nil
}

// loadSMTP validates the SMTP variables (R7 and R8).
func loadSMTP(mail Mail, values map[string]string) (Mail, error) {
	mail.SMTPMode = MailStartTLS
	switch mode := values[EnvMailSMTPMode]; mode {
	case "":
	case MailStartTLS, MailTLS:
		mail.SMTPMode = mode
	default:
		return Mail{}, invalid("%s must be %s or %s; plain-text SMTP does not exist", EnvMailSMTPMode, MailStartTLS, MailTLS)
	}
	mail.SMTPHost = values[EnvMailSMTPHost]
	// A DNS name of at least two labels with a letter in the last one: an IP literal is refused (the certificate is checked by name).
	if !ValidMailAddress("a@" + mail.SMTPHost) {
		return Mail{}, invalid("%s must be a DNS name of at least two labels (an IP address is refused), at most 252 bytes", EnvMailSMTPHost)
	}
	port := DefaultStartTLSPort
	if mail.SMTPMode == MailTLS {
		port = DefaultTLSPort
	}
	number, err := bounded(values[EnvMailSMTPPort], port, 1, 65535)
	if err != nil {
		return Mail{}, invalid("%s: %v", EnvMailSMTPPort, err)
	}
	mail.SMTPPort = number
	for _, credential := range []struct {
		name  string
		value *Secret
	}{{EnvMailSMTPUsername, &mail.SMTPUsername}, {EnvMailSMTPPassword, &mail.SMTPPassword}} {
		value := values[credential.name]
		if value == "" || len(value) > MaxMailCredentialBytes || strings.IndexFunc(value, func(r rune) bool { return r < ' ' || r == 0x7f }) >= 0 {
			return Mail{}, invalid("%s is required: 1 to %d bytes without control characters", credential.name, MaxMailCredentialBytes)
		}
		*credential.value = NewSecret(value)
	}
	return mail, nil
}
