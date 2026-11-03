// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/mail"
)

// TestAServiceHoldingAnAdapterNeverPrintsItsCredentials is the identity half of the credential-printing tests (the mail and config
// packages have the others): the service keeps its sender in an unexported field, which is the shape a plain-string Secret leaks
// through under %s and %q and slog's text handler. MOCKED: nothing is sent.
func TestAServiceHoldingAnAdapterNeverPrintsItsCredentials(t *testing.T) {
	user, pass, token := "synthetic-word-built-smtp-user-sentinel", "synthetic-word-built-smtp-password-sentinel", "synthetic-word-built-postmark-token-sentinel"
	smtp := mail.NewSMTP(mail.SMTPOptions{Host: "smtp.example.test", Port: 2587, Username: config.NewSecret(user), Password: config.NewSecret(pass), From: "sender@example.test"})
	postmark := mail.NewPostmark(mail.PostmarkOptions{Token: config.NewSecret(token), From: "sender@example.test"})
	forms := map[string]string{}
	for _, secret := range []string{user, pass, token} {
		forms[secret] = secret
		forms[secret+" (hex)"] = hex.EncodeToString([]byte(secret))
		forms[secret+" (base64)"] = base64.StdEncoding.EncodeToString([]byte(secret))
	}
	for name, sender := range map[string]mail.Sender{"smtp": smtp, "postmark": postmark, "guarded smtp": mail.NewGuard(smtp), "guarded postmark": mail.NewGuard(postmark)} {
		service := New(Options{Mail: sender})
		for shapeName, shape := range map[string]any{"pointer": service, "value copy of the sender holder": struct{ s *Service }{service}, "slice": []any{service}, "map": map[string]any{"k": service}} {
			var texts []string
			for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
				texts = append(texts, fmt.Sprintf(verb, shape))
			}
			for handler, build := range map[string]func(*bytes.Buffer) slog.Handler{
				"slog text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
				"slog json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
			} {
				var out bytes.Buffer
				slog.New(build(&out)).Info("probe", "service", shape)
				texts = append(texts, handler+": "+out.String())
			}
			if data, err := json.Marshal(shape); err == nil {
				texts = append(texts, string(data))
			}
			for _, text := range texts {
				for what, form := range forms {
					if strings.Contains(text, form) {
						t.Errorf("%s in a %s leaks %s: %.120s", name, shapeName, what, text)
					}
				}
			}
		}
	}
}
