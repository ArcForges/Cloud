// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"errors"

	"github.com/ArcForges/Cloud/center/internal/config"
)

// New builds the sender of a validated configuration: Disabled for a disabled one, otherwise the adapter of the provider behind a
// Guard (four sends in flight, sixty-four waiting). It sets none of the test-only options of the adapters (RootCAs, Dial, BaseURL,
// Client): a production sender uses the system roots, a plain dialer, the constant endpoint and its own transport, and a pin parses
// this function to keep it so. It reads no environment: the configuration is the only input.
func New(m config.Mail) (Sender, error) {
	switch m.Provider {
	case "", config.MailDisabled:
		return Disabled{}, nil
	case config.MailPostmark:
		return NewGuard(NewPostmark(PostmarkOptions{Token: m.PostmarkToken, From: m.From, FromName: m.FromName, Stream: m.PostmarkStream, Timeout: m.Timeout})), nil
	case config.MailSMTP:
		var mode SMTPMode
		switch m.SMTPMode {
		case config.MailStartTLS:
			mode = StartTLS
		case config.MailTLS:
			mode = ImplicitTLS
		default:
			return nil, errors.New("mail: the SMTP mode is neither starttls nor tls")
		}
		return NewGuard(NewSMTP(SMTPOptions{Host: m.SMTPHost, Port: m.SMTPPort, Mode: mode, Username: m.SMTPUsername, Password: m.SMTPPassword,
			From: m.From, FromName: m.FromName, Timeout: m.Timeout})), nil
	}
	return nil, errors.New("mail: the provider is neither disabled, postmark nor smtp")
}
