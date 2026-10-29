// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/arc/arctest"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

// everyRefusal is every refusal a page can show: each constructor of package arc the identity surface uses.
func everyRefusal(at time.Time) []*arc.Refusal {
	id := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	return []*arc.Refusal{
		arc.InvalidArgument("name", "length"), arc.InvalidArgument("name", "pattern"), arc.InvalidArgument("display_name", "length"), arc.InvalidArgument("display_name", "pattern"),
		arc.InvalidArgument("credential", "not_verified"), arc.InvalidArgument("query", "not_admitted"), arc.InvalidArgument("body", "malformed"), arc.InvalidCursor(),
		arc.Unauthenticated(), arc.TokenExpired(), arc.CredentialRevoked(), arc.StepUpRequired(), arc.PermissionDenied("device.list"),
		arc.NotFound("session", id), arc.InvalidState("credential", "last_credential"), arc.InvalidState("account", "credentials_locked"), arc.InvalidState("account", "other"),
		arc.Expired(), arc.NotActivated("pages"), arc.CodeReused(), arc.AlreadyExists("credential", id), arc.CommandIDReused(), arc.RevisionConflict(1, 2),
		arc.RateLimited("sign_in_prefix", 30, at.Add(90*time.Second)), arc.RateLimited("sign_in_prefix", 30, at.Add(10*time.Minute)), arc.Unavailable(), arc.Internal(), arc.CommitUnknown(),
	}
}

// TestEveryRefusalHasATextAStatusAndAnErrorBody (accessibility: error text for every refusal): the text is fixed per code, never
// echoes anything the request said, and states the wait of a limit; the status is one the Worker lets through or the 503 it answers
// itself; the JSON body carries the ArcError.
func TestEveryRefusalHasATextAStatusAndAnErrorBody(t *testing.T) {
	at := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	allowed := map[int]bool{400: true, 403: true, 404: true, 413: true, 415: true, 429: true, 503: true}
	call := correlation.New()
	for _, refusal := range everyRefusal(at) {
		value := refusal.Dated(at).ArcError(call)
		text := messageFor(value, at)
		if text == "" || text == "The request could not be completed." {
			t.Errorf("%s has no text of its own: %q", refusal.Key(), text)
		}
		for _, echoed := range []string{refusal.Reason, "credential_id", "session_id", "device_id", "sign_in_prefix"} {
			if echoed != "" && strings.Contains(text, echoed) {
				t.Errorf("%s: the text repeats %q", refusal.Key(), echoed)
			}
		}
		if status := statusOf(value); !allowed[status] {
			t.Errorf("%s has the status %d", refusal.Key(), status)
		}
		if violations := arctest.Violations(value); len(violations) != 0 {
			t.Errorf("%s: %v", refusal.Key(), violations)
		}
		var body struct {
			Error struct {
				Category, Code, MessageKey, Effect, CorrelationID string
				Retry                                             struct{ Mode, RetryAt string }
			}
		}
		encoded, err := json.Marshal(errorOf(value))
		if err != nil || json.Unmarshal(encoded, &body) != nil || body.Error.Code != refusal.Code || body.Error.MessageKey != refusal.MessageKey() ||
			body.Error.CorrelationID != call.CorrelationID || body.Error.Effect == "" || body.Error.Retry.Mode == "" {
			t.Errorf("%s: %s", refusal.Key(), encoded)
		}
		if (body.Error.Retry.Mode == "afterTime") != (body.Error.Retry.RetryAt != "") {
			t.Errorf("%s: the retry advice %+v", refusal.Key(), body.Error.Retry)
		}
	}
	if got := messageFor(arc.RateLimited("x", 1, at.Add(90*time.Second)).ArcError(call), at); !strings.Contains(got, "90 seconds") {
		t.Errorf("the wait of a limit: %q", got)
	}
	if got := messageFor(arc.RateLimited("x", 1, at.Add(10*time.Minute)).ArcError(call), at); !strings.Contains(got, "10 minutes") {
		t.Errorf("the wait of a limit: %q", got)
	}
	// The statuses are the categories': a malformed request 400, a refused credential or authorization 403, a missing object and a
	// disabled surface 404, a limit 429, a store that is down or an internal failure 503.
	for key, want := range map[string]int{
		"VALIDATION/invalid_argument": 400, "AUTHENTICATION/unauthenticated": 403, "AUTHENTICATION/step_up_required": 403, "AUTHORIZATION/permission_denied": 403,
		"STATE/not_found": 404, "STATE/not_activated": 404, "STATE/expired": 400, "STATE/invalid_state": 400, "CONFLICT/code_reused": 400, "CONFLICT/command_id_reused": 400,
		"RESOURCE/rate_limited": 429, "RESOURCE/overloaded": 503, "INTERNAL/internal": 503,
	} {
		found := false
		for _, refusal := range everyRefusal(at) {
			if refusal.Key() == key {
				found = true
				if got := statusOf(refusal.ArcError(call)); got != want {
					t.Errorf("%s is %d, not %d", key, got, want)
				}
			}
		}
		if !found {
			t.Errorf("%s is not among the refusals", key)
		}
	}
}

// TestTheStrictReaderRefusesWhatJSONAllowsButTheDocumentDoesNot: a repeated key at any depth, a document that is deep or large, data
// after the value and a null member.
func TestTheStrictReaderRefusesWhatJSONAllowsButTheDocumentDoesNot(t *testing.T) {
	deep := strings.Repeat(`{"a":`, maxJSONDepth+2) + `1` + strings.Repeat(`}`, maxJSONDepth+2)
	wide := `{"a":[` + strings.Repeat(`1,`, maxJSONElements) + `1]}`
	for name, text := range map[string]string{
		"a repeated key": `{"a":1,"a":2}`, "a nested repeated key": `{"a":{"b":1,"b":2}}`, "a repeated key in an array": `{"a":[{"b":1,"b":2}]}`, "data after the value": `{"a":1} x`,
		"two values": `{"a":1}{"a":1}`, "too deep": deep, "too many values": wide, "an array": `[1]`, "text": `"x"`, "empty": ``, "a truncated value": `{"a":`,
	} {
		if _, refusal := parseObject([]byte(text), "", "a"); refusal == nil {
			t.Errorf("%s was admitted", name)
		}
	}
	root, refusal := parseObject([]byte(` {"a": "x", "n": null} `), "", "a", "n")
	if refusal != nil || root.has("n") || !root.has("a") {
		t.Fatalf("a null member is absent: %v", refusal)
	}
	if _, refusal = parseObject([]byte(`{"z":1}`), "p", "a"); refusal == nil || refusal.Reason != "p.z: unknown" {
		t.Fatalf("an unknown member: %v", refusal)
	}
	if id, ok := parseUUID("00000000-0000-0000-0000-000000000000"); ok || id != [16]byte{} {
		t.Fatal("the nil UUID is admitted")
	}
	if _, ok := parseUUID("6C1D7F0E-3A52-4B9C-8E47-90A1B2C3D4E5"); ok {
		t.Fatal("an upper-case UUID is admitted")
	}
	if id, ok := parseUUID("6c1d7f0e-3a52-4b9c-8e47-90a1b2c3d4e5"); !ok || id[0] != 0x6c || id[15] != 0xe5 {
		t.Fatal("a canonical UUID is refused")
	}
}

// TestTheSessionCookieIsWrittenByteForByte (SEC-03): the Set-Cookie value is the __Host- cookie with Path=/, Secure, HttpOnly and
// SameSite=Strict and no Domain; the removal is the same with Max-Age=0. The Worker's page handler checks exactly these forms.
func TestTheSessionCookieIsWrittenByteForByte(t *testing.T) {
	handle := strings.Repeat("A", 43)
	if got := sessionCookie(handle, 43200); got != "__Host-af_session="+handle+"; Path=/; Max-Age=43200; Secure; HttpOnly; SameSite=Strict" {
		t.Fatalf("the cookie %q", got)
	}
	if got := clearCookie(); got != "__Host-af_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict" {
		t.Fatalf("the removal %q", got)
	}
	if routes.PageCookieName != "__Host-af_session" {
		t.Fatal("the cookie name")
	}
}
