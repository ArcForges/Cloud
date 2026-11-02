// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// secretSentinel is built from words, never a literal that looks like a credential (the secret scan reads test data too).
func secretSentinel(role string) string {
	return strings.Join([]string{"synthetic", "word", "built", role, "sentinel"}, "-")
}

type unexportedHolder struct{ secret Secret }

type exportedHolder struct{ Secret Secret }

type nestedHolder struct{ inner *unexportedHolder }

// leaks reports every encoding of the sentinel found in text: as written, in hex (%x) and in base64.
func leaks(text, sentinel string) []string {
	var found []string
	for name, form := range map[string]string{
		"text":   sentinel,
		"hex":    hex.EncodeToString([]byte(sentinel)),
		"base64": base64.StdEncoding.EncodeToString([]byte(sentinel)),
	} {
		if strings.Contains(text, form) {
			found = append(found, name)
		}
	}
	return found
}

// TestSecretNeverPrintsItsValue runs the shapes a credential can be reached through (a bare value, an exported field, an
// unexported field, a slice, a map, a pointer) through every formatting path (MOCKED: no provider is involved). The shapes with
// an unexported field are the ones a plain-string Secret fails: fmt cannot call methods on a value reached through an unexported
// field, so only the pointer keeps the string out of reach.
func TestSecretNeverPrintsItsValue(t *testing.T) {
	sentinel := secretSentinel("config")
	secret := NewSecret(sentinel)
	shapes := map[string]any{
		"bare value":              secret,
		"pointer to the value":    &secret,
		"exported field":          exportedHolder{Secret: secret},
		"pointer to exported":     &exportedHolder{Secret: secret},
		"unexported field":        unexportedHolder{secret: secret},
		"pointer to unexported":   &unexportedHolder{secret: secret},
		"nested unexported":       nestedHolder{inner: &unexportedHolder{secret: secret}},
		"slice":                   []any{secret, unexportedHolder{secret: secret}},
		"map":                     map[string]any{"k": secret, "u": &unexportedHolder{secret: secret}},
		"struct inside interface": struct{ Any any }{Any: unexportedHolder{secret: secret}},
	}
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%p", "%T", "%10.3s", "%-20v"}
	for name, shape := range shapes {
		for _, verb := range verbs {
			if found := leaks(fmt.Sprintf(verb, shape), sentinel); len(found) > 0 {
				t.Errorf("%s with %s leaks the value (%v)", name, verb, found)
			}
		}
		if found := leaks(fmt.Sprint(shape)+fmt.Sprintln(shape), sentinel); len(found) > 0 {
			t.Errorf("%s with Sprint leaks the value (%v)", name, found)
		}
		for handler, build := range map[string]func(*bytes.Buffer) slog.Handler{
			"slog text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
			"slog json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
		} {
			var out bytes.Buffer
			slog.New(build(&out)).Info("probe", "value", shape, slog.Any("again", shape))
			if found := leaks(out.String(), sentinel); len(found) > 0 {
				t.Errorf("%s with %s leaks the value (%v)", name, handler, found)
			}
		}
		if data, err := json.Marshal(shape); err == nil {
			if found := leaks(string(data), sentinel); len(found) > 0 {
				t.Errorf("%s with encoding/json leaks the value (%v)", name, found)
			}
		}
	}
}

// TestSecretPrintsTheMarkerWhereGoCanCallItsMethods pins what the secret prints in the shapes that do reach its methods, so a
// refactor cannot silently turn the marker into something else.
func TestSecretPrintsTheMarkerWhereGoCanCallItsMethods(t *testing.T) {
	secret := NewSecret(secretSentinel("marker"))
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		if got := fmt.Sprintf(verb, secret); got != redacted {
			t.Errorf("%s printed %q", verb, got)
		}
	}
	if got := fmt.Sprintf("%+v", exportedHolder{Secret: secret}); got != "{Secret:"+redacted+"}" {
		t.Errorf("an exported field printed %q", got)
	}
	var out bytes.Buffer
	slog.New(slog.NewJSONHandler(&out, nil)).Info("probe", "secret", secret)
	if !strings.Contains(out.String(), `"secret":"`+redacted+`"`) {
		t.Errorf("slog printed %s", out.String())
	}
	data, err := json.Marshal(exportedHolder{Secret: secret})
	if err != nil || string(data) != `{"Secret":"`+redacted+`"}` {
		t.Errorf("json printed %s, %v", data, err)
	}
	text, err := secret.MarshalText()
	if err != nil || string(text) != redacted {
		t.Errorf("text printed %q, %v", text, err)
	}
}

// TestSecretZeroValueIsEmptyAndSafe pins that the zero Secret (an unset configuration field) is usable everywhere.
func TestSecretZeroValueIsEmptyAndSafe(t *testing.T) {
	var zero Secret
	if !zero.Empty() || zero.Reveal() != "" || !NewSecret("").Empty() || NewSecret("x").Empty() {
		t.Fatal("Empty or Reveal of an unset secret")
	}
	if got := fmt.Sprintf("%v %#v %s", zero, zero, &zero); got != strings.Repeat(redacted+" ", 2)+redacted {
		t.Fatalf("the zero secret printed %q", got)
	}
	if NewSecret("value").Reveal() != "value" {
		t.Fatal("Reveal does not return the value")
	}
}

// TestSecretIsNotComparableByValue documents the cost of the pointer form: two secrets of equal content are not ==. A caller must
// compare Reveal results (tests) or use Empty.
func TestSecretIsNotComparableByValue(t *testing.T) {
	if a, b := NewSecret("same"), NewSecret("same"); a == b || a.Reveal() != b.Reveal() {
		t.Fatal("Secret compares by value: the pointer form is gone")
	}
}
