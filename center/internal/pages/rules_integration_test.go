// SPDX-License-Identifier: AGPL-3.0-only

package pages_test

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// TestTheRateLimitsAreTheAPIs (F2, DC-15): the pages' sign-in steps count in the buckets the API counts, so a client's address
// prefix and an account's failed proofs are limited across both: calls made through the API use up what the pages may make, and
// the other way round, while another network is unaffected.
func TestTheRateLimitsAreTheAPIs(t *testing.T) {
	h := newHarness(t, settings{policy: `{"signInPerPrefixLimit": 4, "signInFailuresAccountLimit": 2}`})
	same, elsewhere := h.newBrowser(), h.newBrowser()
	same.ip, elsewhere.ip = "203.0.113.10", "198.51.100.77"
	begin := func(b *browser) response {
		return b.postJSON("/session/v1/web/authentication/begin", map[string]any{"method": "passkey", "purpose": "authenticate", "installation": b.claim()})
	}
	same.bootstrapState()
	elsewhere.bootstrapState()
	for range 2 {
		if _, refusal := h.apiBegin("203.0.113.10"); refusal != "" {
			t.Fatalf("the API begin: %s", refusal)
		}
	}
	for range 2 {
		if reply := begin(same); reply.status != 200 {
			t.Fatalf("a page begin within the limit: %d %s", reply.status, reply.text())
		}
	}
	limited := begin(same)
	if limited.status != 429 || limited.refusal(t) != "resource/rate_limited" || !strings.Contains(limited.text(), `"limitName":"sign_in_prefix"`) ||
		!strings.Contains(limited.text(), `"retryAt"`) {
		t.Fatalf("the fifth call of the prefix: %d %s", limited.status, limited.text())
	}
	if _, refusal := h.apiBegin("203.0.113.10"); refusal != "RESOURCE/rate_limited" {
		t.Fatalf("the API after the pages used the bucket: %q", refusal)
	}
	if reply := begin(elsewhere); reply.status != 200 {
		t.Fatalf("another network: %d %s", reply.status, reply.text())
	}
	// A page that is limited says so in words, with the wait.
	h.do(request{method: http.MethodGet, path: "/account/sign-in"})
	form := same.postForm("/account/sessions/revoke-all", url.Values{"command_id": {uuid(platform.NewID())}})
	if form.status != 403 {
		t.Fatalf("a form without a session: %d", form.status)
	}

	// Failed proofs per account: two wrong assertions of one account's credential refuse the third, even a right one, on the pages
	// and on the API alike.
	h2 := newHarness(t, settings{policy: `{"signInPerPrefixLimit": 1000, "signInFailuresAccountLimit": 2}`})
	who := h2.seedAccount(1)
	b := h2.newBrowser()
	for range 2 {
		challenge := b.beginSignIn()
		if wrong := b.completeSignIn(challenge.FlowID, who, randomBytes(t, 32)); wrong.status != 403 {
			t.Fatalf("a wrong proof: %d %s", wrong.status, wrong.text())
		}
	}
	challenge := b.beginSignIn()
	if refused := b.completeSignIn(challenge.FlowID, who, unb64(t, challenge.Challenge)); refused.status != 429 || refused.refusal(t) != "resource/rate_limited" {
		t.Fatalf("a right proof after two wrong ones: %d %s", refused.status, refused.text())
	}
	native, refusal := h2.apiBegin("")
	if refusal != "" {
		t.Fatal(refusal)
	}
	flow := platformIDOf(native.GetFlowId())
	reply := h2.api("/arcforges.publicapi.v1.IdentityService/CompleteAuthentication", &publicapiv1.IdentityServiceCompleteAuthenticationRequest{
		Meta: &foundationv1.RequestMeta{}, FlowId: &foundationv1.Id{Value: flow[:]}, Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_Passkey{Passkey: assertionProto(who.authenticator.Assert(who.key, native.GetChallenge()))}}}, "")
	var completed publicapiv1.IdentityServiceCompleteAuthenticationResponse
	if reply.status != "0" || proto.Unmarshal(reply.body, &completed) != nil || completed.GetError().GetCode() != "rate_limited" {
		t.Fatalf("the API after the pages' failures: %q %v", reply.status, completed.GetError())
	}
}

func assertionProto(value passkey.Assertion) *publicapiv1.WebAuthnAssertion {
	return &publicapiv1.WebAuthnAssertion{CredentialId: value.CredentialID, ClientDataJson: value.ClientDataJSON, AuthenticatorData: value.AuthenticatorData,
		Signature: value.Signature, UserHandle: value.UserHandle}
}

// grpcCall is a cookie-authenticated RPC of the API (binary gRPC-Web), as the Web client makes it.
func (b *browser) grpcCall(path string, message proto.Message) response {
	b.h.t.Helper()
	data, err := proto.Marshal(message)
	if err != nil {
		b.h.t.Fatal(err)
	}
	return b.h.do(request{method: http.MethodPost, path: path, contentType: "application/grpc-web+proto", body: ingress.Frame(data), cookie: b.cookie, csrf: b.csrf, ip: b.ip})
}

// idle is the idle expiry of the browser's session.
func (b *browser) idle() time.Time {
	b.h.t.Helper()
	var at time.Time
	id := idOf(b.h.t, b.bootstrapPeek())
	if err := b.h.migration.QueryRow(context.Background(), "SELECT idle_expires_at FROM identity.session WHERE session_id = $1", id).Scan(&at); err != nil {
		b.h.t.Fatal(err)
	}
	return at
}

// bootstrapPeek is the browser's session ID read from the store without any request.
func (b *browser) bootstrapPeek() string {
	b.h.t.Helper()
	handle := mustHandle(b.h.t, b.cookie).Digest()
	var id platform.ID
	if err := b.h.migration.QueryRow(context.Background(), "SELECT session_id FROM identity.session WHERE browser_handle_hash = $1", handle[:]).Scan(&id); err != nil {
		b.h.t.Fatal(err)
	}
	return uuid(id)
}

// TestASessionIsRenewedOnlyByAPageLoadOrTheBootstrapRead (SEC-12): the idle expiry of a cookie session moves forward when a page
// loads or the bootstrap route is read, never on an RPC or a POST, and never beyond the absolute 12 hours; an idle session is gone.
func TestASessionIsRenewedOnlyByAPageLoadOrTheBootstrapRead(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)
	start := h.clock.Now()
	first := b.idle()
	if d := first.Sub(start); d > 30*time.Minute || d < 30*time.Minute-2*time.Second {
		t.Fatalf("the idle expiry at sign-in is %s ahead", d)
	}
	h.clock.Advance(20 * time.Minute)
	// An RPC with the cookie, a JSON POST and a form POST do not renew.
	if reply := b.grpcCall("/arcforges.publicapi.v1.IdentityService/ListSessions", &publicapiv1.IdentityServiceListSessionsRequest{Meta: &foundationv1.RequestMeta{},
		Page: &foundationv1.PageRequest{}}); reply.status != 200 {
		t.Fatalf("the RPC: %d", reply.status)
	}
	if reply := b.stepUp(who, identity.ClassRevokeAllSessions, who.id); reply.status != 200 {
		t.Fatalf("the step-up: %d", reply.status)
	}
	b.postForm("/account/sessions/revoke-all", url.Values{"command_id": {uuid(platform.NewID())}})
	if got := b.idle(); !got.Equal(first) {
		t.Fatalf("an RPC or a POST moved the idle expiry from %s to %s", first, got)
	}
	// The bootstrap read renews: 30 minutes from now.
	state := b.bootstrapState()
	renewed := b.idle()
	if d := renewed.Sub(h.clock.Now()); d > 30*time.Minute || d < 30*time.Minute-2*time.Second {
		t.Fatalf("after the bootstrap read the idle expiry is %s ahead", d)
	}
	if shown, err := time.Parse(time.RFC3339Nano, state.Session.IdleExpiresAt); err != nil || !shown.Equal(renewed.UTC().Truncate(time.Microsecond)) {
		t.Fatalf("the bootstrap reply shows %s, the store holds %s", state.Session.IdleExpiresAt, renewed)
	}
	// A page load renews as well; a page for a session that is not renewed (idle past its limit) is the sign-in redirect.
	h.clock.Advance(25 * time.Minute)
	b.page("/account/devices")
	if d := b.idle().Sub(h.clock.Now()); d > 30*time.Minute || d < 30*time.Minute-2*time.Second {
		t.Fatalf("after a page load the idle expiry is %s ahead", d)
	}
	h.clock.Advance(31 * time.Minute)
	if state = b.bootstrapState(); state.Authenticated {
		t.Fatal("a session idle for 31 minutes is still signed in")
	}
	if page := b.get("/account/passkeys"); page.status != 303 {
		t.Fatalf("a page for an idle session: %d", page.status)
	}
	// The absolute lifetime caps every renewal: the idle expiry never passes the session's 12 hours.
	long := h.newBrowser()
	long.mustSignIn(who)
	id := idOf(t, long.bootstrapPeek())
	var expires time.Time
	if err := h.migration.QueryRow(context.Background(), "SELECT expires_at FROM identity.session WHERE session_id = $1", id).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	for range 40 {
		h.clock.Advance(20 * time.Minute)
		if h.clock.Now().Before(expires) {
			long.bootstrapState()
			if long.idle().After(expires) {
				t.Fatalf("the idle expiry %s passed the absolute expiry %s", long.idle(), expires)
			}
		}
	}
	if state = long.bootstrapState(); state.Authenticated {
		t.Fatal("a session older than 12 hours is signed in")
	}
	// A revoked session is never renewed.
	revoked := h.newBrowser()
	revoked.mustSignIn(who)
	revoked.postEmpty("/session/v1/web/logout")
	before := h.count("SELECT sum(rev) FROM identity.session WHERE user_id = $1", who.id)
	revoked.get("/session/v1/web/bootstrap")
	if h.count("SELECT sum(rev) FROM identity.session WHERE user_id = $1", who.id) != before {
		t.Fatal("a revoked session was renewed")
	}
}

// TestAnotherAccountsObjectsAreNotFoundThroughThePages (F2, cross-account isolation): an account's forms cannot reach another
// account's session, device or passkey; each is STATE/not_found as an unknown object is, nothing changes, and the pages list only
// the caller's own.
func TestAnotherAccountsObjectsAreNotFoundThroughThePages(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	alice, bob := h.seedAccount(1), h.seedAccount(1)
	a, b := h.newBrowser(), h.newBrowser()
	a.mustSignIn(alice)
	b.mustSignIn(bob)
	stateA := a.bootstrapState()
	sessionA, deviceA := idOf(t, stateA.Session.SessionID), idOf(t, stateA.Session.DeviceID)
	credentialA := laptopCredential(t, h, alice.id)
	if _, err := h.migration.Exec(context.Background(), "UPDATE device.device SET display_name = 'Alice laptop' WHERE device_id = $1", deviceA); err != nil {
		t.Fatal(err)
	}
	bobSessions, bobDevices := b.page("/account/sessions"), b.page("/account/devices")
	for _, page := range []response{bobSessions, bobDevices, b.page("/account/passkeys")} {
		if strings.Contains(page.text(), "Alice") || strings.Contains(page.text(), uuid(sessionA)) || strings.Contains(page.text(), uuid(deviceA)) || strings.Contains(page.text(), uuid(credentialA)) {
			t.Fatal("a page lists another account's object")
		}
	}
	// Bob proves a step-up for each of Alice's objects (the target hash is a hash of identifiers he names) and posts the form.
	post := func(path string, fields url.Values) response {
		fields.Set("command_id", uuid(platform.NewID()))
		return b.postForm(path, fields)
	}
	b.mustStepUp(bob, identity.ClassRevokeSession, sessionA)
	b.mustStepUp(bob, identity.ClassRevokeDevice, deviceA)
	b.mustStepUp(bob, identity.ClassRemoveCredential, credentialA)
	for name, reply := range map[string]response{
		"revoking Alice's session": post("/account/sessions/revoke", url.Values{"session_id": {uuid(sessionA)}}),
		"revoking Alice's device":  post("/account/devices/revoke", url.Values{"device_id": {uuid(deviceA)}}),
		"renaming Alice's device":  post("/account/devices/rename", url.Values{"device_id": {uuid(deviceA)}, "name": {"Bob was here"}}),
		"renaming Alice's passkey": post("/account/passkeys/rename", url.Values{"credential_id": {uuid(credentialA)}, "name": {"Bob was here"}}),
		"removing Alice's passkey": post("/account/passkeys/remove", url.Values{"credential_id": {uuid(credentialA)}}),
	} {
		if reply.status != 404 || !strings.Contains(reply.text(), "no longer exists") {
			t.Errorf("%s: %d %.200s", name, reply.status, reply.text())
		}
	}
	if !h.live(sessionA) || h.count("SELECT count(*) FROM device.device WHERE device_id = $1 AND revoked_at IS NULL AND display_name = 'Alice laptop'", deviceA) != 1 ||
		h.count("SELECT count(*) FROM identity.auth_identity WHERE auth_identity_id = $1 AND revoked_at IS NULL AND label = 'Seeded key'", credentialA) != 1 {
		t.Fatal("Bob changed Alice's objects")
	}
	if !a.bootstrapState().Authenticated {
		t.Fatal("Alice was signed out")
	}
	// An unknown ID is refused alike, so the answer does not tell Alice's objects from nothing.
	nobody := platform.NewID()
	b.mustStepUp(bob, identity.ClassRevokeSession, nobody)
	unknown := post("/account/sessions/revoke", url.Values{"session_id": {uuid(nobody)}})
	if unknown.status != 404 {
		t.Fatalf("an unknown session: %d", unknown.status)
	}
	// Bob's revoke-all spares Alice's sessions.
	b.mustStepUp(bob, identity.ClassRevokeAllSessions, bob.id)
	if reply := post("/account/sessions/revoke-all", url.Values{}); reply.status != 303 || !h.live(sessionA) {
		t.Fatalf("revoke-all: %d", reply.status)
	}
	h.verifyAudit()
}

// TestEveryPageIsAccessibleHTMLWithNothingExternal (accessibility, SEC-16): lang, a title, a heading that takes focus, an
// aria-live error summary, labelled inputs, named buttons, tables with captions and header cells, and no inline script, inline
// style, event handler attribute or reference to another origin; the assets have their media types.
func TestEveryPageIsAccessibleHTMLWithNothingExternal(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)
	pages := map[string]response{}
	for _, route := range routes.PageRoutes() {
		if route.Method == http.MethodGet && route.Kind == routes.PageHTMLKind {
			pages[route.Path] = b.page(route.Path)
		}
	}
	b.mustStepUp(who, identity.ClassBeginRegistration, who.id)
	pages["the creation page"] = b.submit(formsTo(t, pages["/account/passkeys"], "/account/passkeys/add")[0], url.Values{"display_name": {"Key"}})
	pages["an error page"] = b.submit(formsTo(t, pages["/account/passkeys"], "/account/passkeys/rename")[0], url.Values{"name": {strings.Repeat("x", 65)}})
	inputPattern := regexp.MustCompile(`<input([^>]*)>`)
	labelPattern := regexp.MustCompile(`<label for="([^"]*)"`)
	buttonPattern := regexp.MustCompile(`(?s)<button([^>]*)>(.*?)</button>`)
	for name, page := range pages {
		text := page.text()
		if page.header.Get("Content-Type") != routes.TypeHTML {
			t.Errorf("%s: %q", name, page.header.Get("Content-Type"))
		}
		for _, want := range []string{`<html lang="en">`, `<meta charset="utf-8">`, `<meta name="viewport"`, `<title>`, `<main id="main" tabindex="-1">`, `<h1 id="heading" tabindex="-1">`,
			`id="error-summary"`, `role="alert"`, `aria-live="assertive"`, `<a class="skip" href="#main">`} {
			if !strings.Contains(text, want) {
				t.Errorf("%s lacks %s", name, want)
			}
		}
		if strings.Count(text, "<h1") != 1 {
			t.Errorf("%s has %d h1", name, strings.Count(text, "<h1"))
		}
		labelled := map[string]bool{}
		for _, match := range labelPattern.FindAllStringSubmatch(text, -1) {
			labelled[match[1]] = true
		}
		for _, match := range inputPattern.FindAllStringSubmatch(text, -1) {
			if strings.Contains(match[1], `type="hidden"`) {
				continue
			}
			id := regexp.MustCompile(`id="([^"]*)"`).FindStringSubmatch(match[1])
			if id == nil || !labelled[id[1]] {
				t.Errorf("%s: an input without a label: %s", name, match[1])
			}
		}
		for _, match := range buttonPattern.FindAllStringSubmatch(text, -1) {
			if strings.TrimSpace(match[2]) == "" && !strings.Contains(match[1], "aria-label") {
				t.Errorf("%s: a button without a name: %s", name, match[1])
			}
		}
		if strings.Contains(text, "<table") && (!strings.Contains(text, "<caption>") || !strings.Contains(text, `<th scope="col">`) || !strings.Contains(text, `<th scope="row">`)) {
			t.Errorf("%s: a table without a caption or header cells", name)
		}
		for _, bad := range []*regexp.Regexp{regexp.MustCompile(`\sstyle=`), regexp.MustCompile(`\son[a-z]+=`), regexp.MustCompile(`https?://`),
			regexp.MustCompile(`<(iframe|object|embed|img|base|meta http-equiv)`), regexp.MustCompile(`javascript:`)} {
			if bad.MatchString(text) {
				t.Errorf("%s matches %s", name, bad)
			}
		}
		for _, tag := range regexp.MustCompile(`<script[^>]*>`).FindAllString(text, -1) {
			if !strings.Contains(tag, ` src="/api/account/account.js"`) || !strings.Contains(tag, `type="module"`) {
				t.Errorf("%s has the script tag %s", name, tag)
			}
		}
		for _, match := range regexp.MustCompile(`(?:href|src|action)="([^"]*)"`).FindAllStringSubmatch(text, -1) {
			if !strings.HasPrefix(match[1], "/api/") && !strings.HasPrefix(match[1], "#") {
				t.Errorf("%s links to %s", name, match[1])
			}
		}
	}
	// The assets, and the script's discipline under Trusted Types.
	for path, mediaType := range map[string]string{"/account/account.js": routes.TypeJS, "/account/account.css": routes.TypeCSS} {
		reply := h.do(request{method: http.MethodGet, path: path})
		if reply.status != 200 || reply.header.Get("Content-Type") != mediaType || len(reply.body) < 100 {
			t.Errorf("%s: %d %q", path, reply.status, reply.header.Get("Content-Type"))
		}
	}
	script, err := os.ReadFile("static/account.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, sink := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setAttribute(\"style\"", "srcdoc", "createContextualFragment", "DOMParser", "importScripts", "setTimeout(\""} {
		if strings.Contains(string(script), sink) {
			t.Errorf("the script uses %s", sink)
		}
	}
	css, err := os.ReadFile("static/account.css")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(css), "url(") || strings.Contains(string(css), "@import") || strings.Contains(string(css), "http") {
		t.Error("the style sheet loads something")
	}
	h.verifyAudit()
}

// TestNoSecretReachesTheStoreTheLogsOrAHeaderButItsOwn (F12, SEC-03): every cookie handle, CSRF token and the bootstrap token the
// pages saw is nowhere in the database (as text or as the hex of its bytes), the statement statistics, the center's log, the
// server's log, a reply body or a header but the Set-Cookie that issues the handle (and the CSRF token only where the bootstrap
// reply and the forms carry it).
func TestNoSecretReachesTheStoreTheLogsOrAHeaderButItsOwn(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	ctx := context.Background()
	admin := pgtest.Connect(t, pgtest.WithDatabase(t, pgtest.ServerURL(t), h.database))
	if _, err := admin.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS pg_stat_statements"); err != nil {
		t.Fatal(err)
	}
	owner := h.newBrowser()
	if reply, _, _ := owner.enrollOwner(h.bootstrap, "Owner"); reply.status != 200 {
		t.Fatalf("enrollment: %d %s", reply.status, reply.text())
	}
	who := h.seedAccount(1)
	second := h.newBrowser()
	second.mustSignIn(who)
	second.page("/account/passkeys")
	second.page("/account/sessions")
	second.page("/account/devices")
	second.mustStepUp(who, identity.ClassRevokeAllSessions, who.id)
	second.postForm("/account/sessions/revoke-all", url.Values{"command_id": {uuid(platform.NewID())}})
	second.postEmpty("/session/v1/web/logout")
	owner.get("/session/v1/web/bootstrap")
	handles := map[string]bool{}
	for _, line := range h.setCookies {
		if value, ok := strings.CutPrefix(line, routes.PageCookieName+"="); ok {
			handle, _, _ := strings.Cut(value, ";")
			if handle != "" {
				handles[handle] = true
			}
		}
	}
	if len(handles) != 2 {
		t.Fatalf("%d cookie handles were issued", len(handles))
	}
	secrets := h.secrets
	if len(secrets) < 8 {
		t.Fatalf("only %d secrets were collected", len(secrets))
	}
	var hexed []string
	for _, value := range secrets {
		hexed = append(hexed, hex.EncodeToString([]byte(value)))
		for _, prefix := range []string{session.BootstrapPrefix, ""} {
			if raw, ok := session.ParseToken(prefix, value); ok {
				hexed = append(hexed, hex.EncodeToString(raw[:]))
			}
		}
	}
	scan := func(where, text string, values []string) {
		t.Helper()
		for _, value := range values {
			if value != "" && strings.Contains(text, value) {
				t.Errorf("%s holds a secret", where)
			}
		}
	}
	rows, err := admin.Query(ctx, `SELECT table_schema || '.' || table_name FROM information_schema.tables
WHERE table_schema IN ('identity', 'device', 'platform', 'audit') AND table_type = 'BASE TABLE'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	if len(tables) < 12 {
		t.Fatalf("only %d tables", len(tables))
	}
	for _, table := range tables {
		var text string
		if err = admin.QueryRow(ctx, "SELECT coalesce(string_agg(row_to_json(t)::text, ''), '') FROM "+table+" t").Scan(&text); err != nil {
			t.Fatal(err)
		}
		scan(table, text, secrets)
		scan(table+" (bytea)", text, hexed)
	}
	var statistics string
	if err = admin.QueryRow(ctx, "SELECT coalesce(string_agg(query, ''), '') FROM pg_stat_statements").Scan(&statistics); err != nil {
		t.Fatal(err)
	}
	scan("pg_stat_statements", statistics, secrets)
	scan("the center's log", h.logs.String(), secrets)
	if log, ok := pgtest.ServerLog(t); ok {
		scan("the test server's log", log, secrets)
		if !strings.Contains(log, "identity.session") {
			t.Fatal("the server log does not show the identity statements, so the scan proves nothing")
		}
	}
	// A cookie handle is in a Set-Cookie header and nowhere else of a reply; the bootstrap token is in no reply at all; a CSRF token
	// is in no cookie.
	for _, body := range h.bodies {
		for handle := range handles {
			if strings.Contains(string(body), handle) {
				t.Error("a cookie handle is in a reply body")
			}
		}
		if strings.Contains(string(body), h.bootstrap) {
			t.Error("the bootstrap token is in a reply body")
		}
	}
	for _, line := range h.setCookies {
		if !cookiePattern.MatchString(line) && line != clearedCookie {
			t.Errorf("an unexpected Set-Cookie: %q", line)
		}
		if strings.Contains(line, h.bootstrap) {
			t.Error("the bootstrap token is in a cookie")
		}
	}
	if !strings.Contains(strings.Join(h.setCookies, "\n"), "Max-Age=") {
		t.Error("no cookie was seen")
	}
}
