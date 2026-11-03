// SPDX-License-Identifier: AGPL-3.0-only

package mail

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
)

type senderHolder struct{ sender Sender }

type exportedSenderHolder struct{ Sender Sender }

type optionsHolder struct{ options SMTPOptions }

// secretForms are the encodings of a credential that must not appear in any output: as written, in hex (%x) and in base64 (an AUTH
// PLAIN line is base64 of the credential).
func secretForms(secrets ...string) map[string]string {
	forms := map[string]string{}
	for _, secret := range secrets {
		forms[secret] = secret
		forms[secret+" (hex)"] = hex.EncodeToString([]byte(secret))
		forms[secret+" (base64)"] = base64.StdEncoding.EncodeToString([]byte(secret))
	}
	return forms
}

// TestAdaptersNeverPrintTheirCredentials is the test the first plan lacked: the adapters hold their credentials in unexported
// fields, where fmt cannot call the Secret's methods, so a Secret that wraps a plain string leaks through %v, %+v, %#v, %s, %q, %x
// and %d of the adapter, of a holder of it, of a slice or a map of it, and through slog's text handler. The pointer form keeps every
// one of them out. (MOCKED: nothing is sent.) Package identity pins the same for the identity service that holds a sender.
func TestAdaptersNeverPrintTheirCredentials(t *testing.T) {
	user, pass, token := sentinel("smtp-user"), sentinel("smtp-password"), sentinel("postmark-token")
	smtpSender := NewSMTP(SMTPOptions{Host: testHost, Port: 2587, Username: config.NewSecret(user), Password: config.NewSecret(pass), From: testFrom})
	postmarkSender := NewPostmark(PostmarkOptions{Token: config.NewSecret(token), From: testFrom})
	shapes := map[string]any{}
	for name, sender := range map[string]Sender{"smtp": smtpSender, "postmark": postmarkSender, "guarded smtp": NewGuard(smtpSender), "guarded postmark": NewGuard(postmarkSender)} {
		shapes[name] = sender
		shapes[name+" in an unexported field"] = senderHolder{sender: sender}
		shapes[name+" behind a pointer holder"] = &senderHolder{sender: sender}
		shapes[name+" in an exported field"] = exportedSenderHolder{Sender: sender}
		shapes[name+" in a slice"] = []any{sender}
		shapes[name+" in a map"] = map[string]any{"k": sender}
		shapes[name+" in an interface"] = struct{ Any any }{Any: sender}
	}
	copied := *smtpSender
	shapes["smtp copied by value"] = copied
	shapes["smtp options"] = SMTPOptions{Username: config.NewSecret(user), Password: config.NewSecret(pass)}
	shapes["smtp options in an unexported field"] = optionsHolder{options: SMTPOptions{Username: config.NewSecret(user), Password: config.NewSecret(pass)}}
	shapes["postmark options"] = PostmarkOptions{Token: config.NewSecret(token)}
	copiedPostmark := *postmarkSender
	shapes["postmark copied by value"] = copiedPostmark

	forms := secretForms(user, pass, token)
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"}
	check := func(what, text string) {
		t.Helper()
		for name, form := range forms {
			if strings.Contains(text, form) {
				t.Errorf("%s leaks %s", what, name)
			}
		}
	}
	for name, shape := range shapes {
		for _, verb := range verbs {
			check(name+" with "+verb, fmt.Sprintf(verb, shape))
		}
		for handler, build := range map[string]func(*bytes.Buffer) slog.Handler{
			"slog text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
			"slog json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
		} {
			var out bytes.Buffer
			slog.New(build(&out)).Info("probe", "value", shape, slog.Any("again", shape))
			check(name+" with "+handler, out.String())
		}
		if data, err := json.Marshal(shape); err == nil {
			check(name+" with encoding/json", string(data))
		}
	}
}
