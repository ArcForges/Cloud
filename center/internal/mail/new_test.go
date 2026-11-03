// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
)

// MOCKED: New builds the senders from a configuration value; it connects to nothing.

func TestNewBuildsDisabledForADisabledConfiguration(t *testing.T) {
	for _, provider := range []string{"", config.MailDisabled} {
		sender, err := New(config.Mail{Provider: provider})
		if _, ok := sender.(Disabled); !ok || err != nil || sender.Enabled() {
			t.Errorf("provider %q: %T %v", provider, sender, err)
		}
	}
}

func TestNewBuildsAGuardedPostmarkAdapterFromTheConfiguration(t *testing.T) {
	sender, err := New(config.Mail{Provider: config.MailPostmark, From: testFrom, FromName: "ArcForges", Timeout: 7 * time.Second,
		PostmarkToken: config.NewSecret(sentinel("postmark-token")), PostmarkStream: "sign-in"})
	if err != nil {
		t.Fatal(err)
	}
	guard, ok := sender.(*Guard)
	if !ok || !sender.Enabled() {
		t.Fatalf("%T (enabled %v)", sender, sender.Enabled())
	}
	postmark, ok := guard.inner.(*Postmark)
	if !ok {
		t.Fatalf("the guard holds %T", guard.inner)
	}
	transport, isTransport := postmark.client.Transport.(*http.Transport)
	o := postmark.o
	if o.Token.Reveal() != sentinel("postmark-token") || o.From != testFrom || o.FromName != "ArcForges" || o.Stream != "sign-in" || o.Timeout != 7*time.Second ||
		o.BaseURL != postmarkURL || o.Client != nil || o.Dial != nil || !isTransport || transport.Proxy != nil ||
		!reflect.DeepEqual(transport.TLSClientConfig, postmarkTLSConfig()) {
		t.Errorf("the Postmark adapter differs from the configuration or carries a test-only option: %+v", o)
	}
}

func TestNewBuildsAGuardedSMTPAdapterFromTheConfigurationInBothModes(t *testing.T) {
	for mode, want := range map[string]SMTPMode{config.MailStartTLS: StartTLS, config.MailTLS: ImplicitTLS} {
		sender, err := New(config.Mail{Provider: config.MailSMTP, From: testFrom, FromName: "ArcForges", Timeout: 9 * time.Second, SMTPHost: testHost, SMTPPort: 2587, SMTPMode: mode,
			SMTPUsername: config.NewSecret(sentinel("smtp-user")), SMTPPassword: config.NewSecret(sentinel("smtp-password"))})
		if err != nil {
			t.Fatal(err)
		}
		guard, ok := sender.(*Guard)
		if !ok {
			t.Fatalf("%T", sender)
		}
		smtp, ok := guard.inner.(*SMTP)
		if !ok {
			t.Fatalf("the guard holds %T", guard.inner)
		}
		o := smtp.o
		if o.Host != testHost || o.Port != 2587 || o.Mode != want || o.Username.Reveal() != sentinel("smtp-user") || o.Password.Reveal() != sentinel("smtp-password") ||
			o.From != testFrom || o.FromName != "ArcForges" || o.Timeout != 9*time.Second || o.RootCAs != nil || o.Dial != nil || reflect.ValueOf(o.Now).Pointer() != reflect.ValueOf(time.Now).Pointer() {
			t.Errorf("mode %s: the SMTP adapter differs from the configuration or carries a test-only option: %+v", mode, o)
		}
	}
}

func TestNewRefusesAnUnknownProviderOrModeWithoutRepeatingAnything(t *testing.T) {
	secret := config.NewSecret(sentinel("smtp-password"))
	for name, m := range map[string]config.Mail{
		"provider": {Provider: "ses", SMTPPassword: secret},
		"mode":     {Provider: config.MailSMTP, SMTPMode: "plain", SMTPHost: testHost, SMTPPassword: secret},
		"no mode":  {Provider: config.MailSMTP, SMTPHost: testHost, SMTPPassword: secret},
	} {
		sender, err := New(m)
		if err == nil || sender != nil {
			t.Errorf("%s: %T %v", name, sender, err)
			continue
		}
		if strings.Contains(err.Error(), sentinel("smtp-password")) || strings.Contains(err.Error(), testHost) {
			t.Errorf("%s: the refusal repeats a value: %v", name, err)
		}
	}
}
