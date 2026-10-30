// SPDX-License-Identifier: AGPL-3.0-only

package pages_test

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey/virtual"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// formSpec is a form of a rendered page: where it posts, its hidden fields and the step-up its script proves before it submits.
type formSpec struct {
	action string
	fields url.Values
	class  string
	target string
}

var (
	formPattern   = regexp.MustCompile(`(?s)<form([^>]*)>(.*?)</form>`)
	attrPattern   = regexp.MustCompile(`([a-z-]+)="([^"]*)"`)
	hiddenPattern = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)
)

// parseForms reads the forms of a page as a browser would submit them: the hidden fields as rendered.
func parseForms(page string) []formSpec {
	var forms []formSpec
	for _, match := range formPattern.FindAllStringSubmatch(page, -1) {
		spec := formSpec{fields: url.Values{}}
		attributes := map[string]string{}
		for _, attribute := range attrPattern.FindAllStringSubmatch(match[1], -1) {
			attributes[attribute[1]] = html.UnescapeString(attribute[2])
		}
		spec.action, spec.class, spec.target = attributes["action"], attributes["data-step-up-class"], attributes["data-step-up-target"]
		for _, field := range hiddenPattern.FindAllStringSubmatch(match[2], -1) {
			spec.fields.Set(field[1], html.UnescapeString(field[2]))
		}
		forms = append(forms, spec)
	}
	return forms
}

// formsTo are the forms of a page that post to a path below the pages' prefix.
func formsTo(t *testing.T, page response, path string) []formSpec {
	t.Helper()
	var found []formSpec
	for _, form := range parseForms(page.text()) {
		if form.action == basePath+path {
			found = append(found, form)
		}
	}
	return found
}

// submit posts a form as the browser would after the script proved the step-up it names.
func (b *browser) submit(form formSpec, extra url.Values) response {
	b.h.t.Helper()
	fields := url.Values{}
	for name, values := range form.fields {
		fields[name] = append([]string(nil), values...)
	}
	for name, values := range extra {
		fields[name] = values
	}
	return b.postForm(strings.TrimPrefix(form.action, basePath), fields)
}

func (b *browser) page(path string) response {
	b.h.t.Helper()
	reply := b.get(path)
	if reply.status != 200 {
		b.h.t.Fatalf("%s: %d %s", path, reply.status, reply.text())
	}
	return reply
}

// idOf reads a UUID text as a platform ID.
func idOf(t *testing.T, text string) platform.ID {
	t.Helper()
	var id platform.ID
	raw := unhex(strings.ReplaceAll(text, "-", ""))
	if len(raw) != 16 {
		t.Fatalf("not an ID: %q", text)
	}
	copy(id[:], raw)
	return id
}

func unhex(text string) []byte {
	out := make([]byte, 0, len(text)/2)
	for index := 0; index+1 < len(text); index += 2 {
		high, low := hexNibble(text[index]), hexNibble(text[index+1])
		out = append(out, high<<4|low)
	}
	return out
}

func hexNibble(c byte) byte {
	if c >= 'a' {
		return c - 'a' + 10
	}
	return c - '0'
}

// passkeyAccount is an account whose passkey is the one a virtual authenticator made for it.
func passkeyAccount(who account, authenticator *virtual.Authenticator, key *virtual.Key) account {
	return account{id: who.id, handle: who.handle, authenticator: authenticator, key: key}
}

// TestPasskeysThroughTheForms (F2): the passkeys page, the step-up the script proves, the registration of a passkey (the creation
// page and its completion), a form submitted twice (one receipt), the rename of a passkey and the removal of another with its
// evidence; and the removed passkey no longer signs in while the registered one does.
func TestPasskeysThroughTheForms(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)

	// With a single way in the page offers no removal.
	passkeys := b.page("/account/passkeys")
	if !strings.Contains(passkeys.text(), "Seeded key") || len(formsTo(t, passkeys, "/account/passkeys/remove")) != 0 ||
		len(formsTo(t, passkeys, "/account/passkeys/rename")) != 1 {
		t.Fatalf("the passkeys page of one passkey:\n%s", passkeys.text())
	}
	first := formsTo(t, passkeys, "/account/passkeys/rename")[0].fields.Get("credential_id")
	add := formsTo(t, passkeys, "/account/passkeys/add")[0]
	if add.class != identity.ClassBeginRegistration || add.target != hashOf(identity.ClassBeginRegistration, who.id, who.id) {
		t.Fatalf("the add form's step-up: %+v", add)
	}

	// A registration without the step-up is refused, and says so.
	refused := b.submit(add, url.Values{"display_name": {"Laptop"}})
	if refused.status != 403 || !strings.Contains(refused.text(), "needs a passkey check first") || !strings.Contains(refused.text(), `role="alert"`) {
		t.Fatalf("a registration without step-up: %d %s", refused.status, refused.text())
	}
	b.mustStepUp(who, identity.ClassBeginRegistration, who.id)
	begun := b.submit(add, url.Values{"display_name": {"Laptop"}})
	if begun.status != 200 || !strings.Contains(begun.text(), `id="create-passkey"`) {
		t.Fatalf("the registration page: %d %s", begun.status, begun.text())
	}
	register := parseRegister(t, begun)
	if register["data-rp-id"] != rpID || register["data-account-name"] != "Seeded" || register["data-excluded"] == "" || len(unb64(t, register["data-challenge"])) != 32 {
		t.Fatalf("the creation options: %v", register)
	}
	authenticator := virtual.New(rpID, origin)
	creation, key := authenticator.Create(unb64(t, register["data-challenge"]), unb64(t, register["data-user-handle"]))
	complete := formsTo(t, begun, "/account/passkeys/complete")[0]
	fields := url.Values{"credential_id": {b64(creation.CredentialID)}, "client_data_json": {b64(creation.ClientDataJSON)},
		"attestation_object": {b64(creation.AttestationObject)}, "transports": {""}}
	reply := b.submit(complete, fields)
	if reply.status != 303 || reply.header.Get("Location") != basePath+"/account/passkeys" {
		t.Fatalf("the registration's completion: %d %q %s", reply.status, reply.header.Get("Location"), reply.text())
	}
	if h.count("SELECT count(*) FROM identity.auth_identity WHERE user_id = $1 AND provider_id = 'passkey' AND revoked_at IS NULL AND label = 'Laptop'", who.id) != 1 ||
		h.audits("identity.passkey.registered") != 1 {
		t.Fatal("the registration stored no passkey")
	}
	// The same form submitted again replays its receipt: one credential, one audit event.
	if replayed := b.submit(complete, fields); replayed.status != 303 || h.audits("identity.passkey.registered") != 1 ||
		h.count("SELECT count(*) FROM identity.auth_identity WHERE user_id = $1 AND provider_id = 'passkey'", who.id) != 2 {
		t.Fatalf("a form submitted twice: %d", replayed.status)
	}
	laptop := passkeyAccount(who, authenticator, key)

	// Rename the new passkey; remove the first one, which needs the evidence.
	passkeys = b.page("/account/passkeys")
	var newForm, removeFirst formSpec
	for _, form := range formsTo(t, passkeys, "/account/passkeys/rename") {
		if form.fields.Get("credential_id") != first {
			newForm = form
		}
	}
	for _, form := range formsTo(t, passkeys, "/account/passkeys/remove") {
		if form.fields.Get("credential_id") == first {
			removeFirst = form
		}
	}
	if newForm.fields == nil || removeFirst.fields == nil {
		t.Fatalf("the passkeys page of two passkeys:\n%s", passkeys.text())
	}
	if renamed := b.submit(newForm, url.Values{"name": {"Work laptop"}}); renamed.status != 303 ||
		h.count("SELECT count(*) FROM identity.auth_identity WHERE label = 'Work laptop' AND user_id = $1", who.id) != 1 {
		t.Fatalf("rename: %d %s", renamed.status, renamed.text())
	}
	if removeFirst.class != identity.ClassRemoveCredential || removeFirst.target != hashOf(identity.ClassRemoveCredential, who.id, idOf(t, first)) {
		t.Fatalf("the removal's step-up: %+v", removeFirst)
	}
	if refusal := b.submit(removeFirst, nil); refusal.status != 403 || h.count("SELECT count(*) FROM identity.auth_identity WHERE user_id = $1 AND revoked_at IS NULL", who.id) != 2 {
		t.Fatalf("a removal without evidence: %d", refusal.status)
	}
	b.mustStepUp(laptop, identity.ClassRemoveCredential, idOf(t, first))
	if removed := b.submit(removeFirst, nil); removed.status != 303 || h.count("SELECT count(*) FROM identity.auth_identity WHERE user_id = $1 AND revoked_at IS NULL", who.id) != 1 {
		t.Fatalf("removal: %d %s", removed.status, removed.text())
	}
	// The removed passkey no longer signs in; the registered one does.
	stranger := h.newBrowser()
	if refusal := stranger.signIn(who); refusal.status != 403 {
		t.Fatalf("the removed passkey signs in: %d", refusal.status)
	}
	stranger.mustSignIn(laptop)
	// The last passkey cannot be removed: the page offers no removal and the form is refused even when posted.
	onlyOne := b.page("/account/passkeys")
	if len(formsTo(t, onlyOne, "/account/passkeys/remove")) != 0 || !strings.Contains(onlyOne.text(), "Add another passkey first") {
		t.Fatal("the page offers to remove the last passkey")
	}
	last := laptopCredential(t, h, who.id)
	b.mustStepUp(laptop, identity.ClassRemoveCredential, last)
	forced := b.postForm("/account/passkeys/remove", url.Values{"command_id": {uuid(platform.NewID())}, "credential_id": {uuid(last)}})
	if forced.status != 400 || !strings.Contains(forced.text(), "only way to sign in") {
		t.Fatalf("the last passkey removed by a posted form: %d %s", forced.status, forced.text())
	}
	h.verifyAudit()
}

// laptopCredential is the one live credential of an account.
func laptopCredential(t *testing.T, h *harness, userID platform.ID) platform.ID {
	t.Helper()
	var id platform.ID
	if err := h.migration.QueryRow(contextBackground(), "SELECT auth_identity_id FROM identity.auth_identity WHERE user_id = $1 AND revoked_at IS NULL", userID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestSessionsThroughTheForms (F2): the sessions page lists the account's sessions and the device each is on; another session is
// ended with evidence and the browser holding it is signed out at once; every other session is ended with evidence and the
// caller's own stays.
func TestSessionsThroughTheForms(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1)
	a, b, c := h.newBrowser(), h.newBrowser(), h.newBrowser()
	b.userAgent = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"
	for _, browser := range []*browser{a, b, c} {
		browser.mustSignIn(who)
	}
	sessions := a.page("/account/sessions")
	revokes := formsTo(t, sessions, "/account/sessions/revoke")
	if len(revokes) != 2 || !strings.Contains(sessions.text(), "Edge on Windows") || !strings.Contains(sessions.text(), "Firefox on Linux") ||
		strings.Count(sessions.text(), "(this session)") != 1 {
		t.Fatalf("the sessions page:\n%s", sessions.text())
	}
	stateB := b.bootstrapState()
	var revokeB formSpec
	for _, form := range revokes {
		if form.fields.Get("session_id") == stateB.Session.SessionID {
			revokeB = form
		}
	}
	if revokeB.fields == nil || revokeB.class != identity.ClassRevokeSession || revokeB.target != hashOf(identity.ClassRevokeSession, who.id, idOf(t, stateB.Session.SessionID)) {
		t.Fatalf("the revoke form of the second session: %+v", revokeB)
	}
	if refusal := a.submit(revokeB, nil); refusal.status != 403 || !h.live(idOf(t, stateB.Session.SessionID)) {
		t.Fatalf("a revocation without evidence: %d", refusal.status)
	}
	a.mustStepUp(who, identity.ClassRevokeSession, idOf(t, stateB.Session.SessionID))
	if ended := a.submit(revokeB, nil); ended.status != 303 || ended.header.Get("Location") != basePath+"/account/sessions" || h.live(idOf(t, stateB.Session.SessionID)) {
		t.Fatalf("a revocation: %d %q", ended.status, ended.header.Get("Location"))
	}
	if state := b.bootstrapState(); state.Authenticated {
		t.Fatal("the revoked session is still signed in")
	}
	// The cookie of the ended session is refused on every protected route.
	if page := b.get("/account/sessions"); page.status != 303 {
		t.Fatalf("a protected page with an ended session: %d", page.status)
	}
	// Every other session: evidence for the account, then the caller's own session stays and the third is gone.
	revokeAll := formsTo(t, a.page("/account/sessions"), "/account/sessions/revoke-all")[0]
	if revokeAll.class != identity.ClassRevokeAllSessions || revokeAll.target != hashOf(identity.ClassRevokeAllSessions, who.id, who.id) {
		t.Fatalf("the revoke-all form: %+v", revokeAll)
	}
	if refusal := a.submit(revokeAll, nil); refusal.status != 403 {
		t.Fatalf("revoke-all without evidence: %d", refusal.status)
	}
	a.mustStepUp(who, identity.ClassRevokeAllSessions, who.id)
	if ended := a.submit(revokeAll, nil); ended.status != 303 {
		t.Fatalf("revoke-all: %d %s", ended.status, ended.text())
	}
	if !a.bootstrapState().Authenticated || c.bootstrapState().Authenticated {
		t.Fatal("revoke-all did not keep exactly the caller's own session")
	}
	// Revoking this browser's own session from the form is a sign-out: the cookie goes with it.
	own := a.bootstrapState().Session.SessionID
	forged := a.postForm("/account/sessions/revoke", url.Values{"command_id": {uuid(platform.NewID())}, "session_id": {own}})
	if forged.status != 303 || forged.header.Get("Location") != basePath+"/account/sign-in" || forged.header.Get("Set-Cookie") != clearedCookie ||
		a.bootstrapState().Authenticated {
		t.Fatalf("the form that ends this browser's own session: %d %q %q", forged.status, forged.header.Get("Location"), forged.header.Get("Set-Cookie"))
	}
	h.verifyAudit()
}

const clearedCookie = "__Host-af_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"

// TestDevicesThroughTheForms (F2): the devices page lists the account's devices with their software; a device is renamed; another
// device is revoked with evidence and the session on it ends; this browser's own device is revoked without evidence and the cookie
// goes with it.
func TestDevicesThroughTheForms(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1)
	a, b := h.newBrowser(), h.newBrowser()
	b.userAgent = "Mozilla/5.0 (Android 15; Mobile; rv:130.0) Gecko/130.0 Firefox/130.0"
	a.mustSignIn(who)
	b.mustSignIn(who)
	devices := a.page("/account/devices")
	if strings.Count(devices.text(), "(this browser)") != 1 || !strings.Contains(devices.text(), "Edge on Windows") || !strings.Contains(devices.text(), "Firefox on Android") ||
		!strings.Contains(devices.text(), "arcforges-web pages-1") {
		t.Fatalf("the devices page:\n%s", devices.text())
	}
	stateA, stateB := a.bootstrapState(), b.bootstrapState()
	pick := func(forms []formSpec, id string) formSpec {
		for _, form := range forms {
			if form.fields.Get("device_id") == id {
				return form
			}
		}
		t.Fatalf("no form for the device %s", id)
		return formSpec{}
	}
	renames := formsTo(t, devices, "/account/devices/rename")
	revokes := formsTo(t, devices, "/account/devices/revoke")
	if len(renames) != 2 || len(revokes) != 2 {
		t.Fatalf("%d renames, %d revocations", len(renames), len(revokes))
	}
	if renamed := a.submit(pick(renames, stateB.Session.DeviceID), url.Values{"name": {"Phone"}}); renamed.status != 303 ||
		h.count("SELECT count(*) FROM device.device WHERE display_name = 'Phone' AND user_id = $1", who.id) != 1 {
		t.Fatalf("rename: %d %s", renamed.status, renamed.text())
	}
	// The same form with another name is another request under the same command ID; a fresh page has a fresh command.
	if reused := a.submit(pick(renames, stateB.Session.DeviceID), url.Values{"name": {"Tablet"}}); reused.status != 400 || !strings.Contains(reused.text(), "already used") {
		t.Fatalf("a command ID reused with another name: %d", reused.status)
	}
	renames = formsTo(t, a.page("/account/devices"), "/account/devices/rename")
	if tooLong := a.submit(pick(renames, stateB.Session.DeviceID), url.Values{"name": {strings.Repeat("x", 65)}}); tooLong.status != 400 ||
		!strings.Contains(tooLong.text(), "too long") {
		t.Fatalf("a name of 65 characters: %d %s", tooLong.status, tooLong.text())
	}
	other := pick(revokes, stateB.Session.DeviceID)
	own := pick(revokes, stateA.Session.DeviceID)
	if other.class != identity.ClassRevokeDevice || other.target != hashOf(identity.ClassRevokeDevice, who.id, idOf(t, stateB.Session.DeviceID)) || own.class != "" {
		t.Fatalf("the revoke forms: %+v %+v", other, own)
	}
	if refusal := a.submit(other, nil); refusal.status != 403 {
		t.Fatalf("a device revoked without evidence: %d", refusal.status)
	}
	a.mustStepUp(who, identity.ClassRevokeDevice, idOf(t, stateB.Session.DeviceID))
	if revoked := a.submit(other, nil); revoked.status != 303 || b.bootstrapState().Authenticated ||
		h.count("SELECT count(*) FROM device.device WHERE device_id = $1 AND revoked_at IS NOT NULL AND trust_level = 3 AND remote_enabled = false", idOf(t, stateB.Session.DeviceID)) != 1 {
		t.Fatalf("the other device's revocation: %d", revoked.status)
	}
	// This browser's own device needs no evidence; its session and cookie end with it.
	revoked := a.submit(own, nil)
	if revoked.status != 303 || revoked.header.Get("Location") != basePath+"/account/sign-in" || revoked.header.Get("Set-Cookie") != clearedCookie ||
		a.bootstrapState().Authenticated {
		t.Fatalf("this browser's own device: %d %q %q", revoked.status, revoked.header.Get("Location"), revoked.header.Get("Set-Cookie"))
	}
	// A browser's claim is no credential (DC-02): the same browser signs in again on a fresh device, never on the revoked one.
	again := h.newBrowser()
	again.installation = a.installation
	again.mustSignIn(who)
	if h.count("SELECT count(*) FROM device.installation WHERE client_installation_id = $1", a.installation) != 2 ||
		h.count("SELECT count(*) FROM device.installation WHERE client_installation_id = $1 AND revoked_at IS NULL", a.installation) != 1 {
		t.Fatal("a claim of a revoked device did not get fresh rows")
	}
	h.verifyAudit()
}

// TestTheSignOutRouteEndsTheSession (F2): logout answers a receipt that says the session ended, removes the cookie byte for byte,
// and the cookie opens nothing afterwards, not even a second sign-out.
func TestTheSignOutRouteEndsTheSession(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)
	cookie := b.cookie
	sessionID := idOf(t, b.bootstrapState().Session.SessionID)
	reply := b.postEmpty("/session/v1/web/logout")
	if reply.status != 200 || reply.header.Get("Set-Cookie") != clearedCookie || len(reply.header.Values("Set-Cookie")) != 1 {
		t.Fatalf("logout: %d %q", reply.status, reply.header.Values("Set-Cookie"))
	}
	var receipt struct{ CommandID, ResultRevision, Effect string }
	reply.json(t, &receipt)
	if receipt.Effect != "happened" || receipt.ResultRevision == "" || len(receipt.CommandID) != 36 || h.live(sessionID) ||
		h.count("SELECT count(*) FROM identity.session WHERE session_id = $1 AND revoke_reason = 1", sessionID) != 1 || h.audits("identity.session.revoked") != 1 {
		t.Fatalf("the sign-out receipt %+v", receipt)
	}
	b.cookie = cookie
	if again := b.postEmpty("/session/v1/web/logout"); again.status != 403 || again.refusal(t) != "authentication/unauthenticated" {
		t.Fatalf("a second sign-out: %d %s", again.status, again.text())
	}
	if state := b.bootstrapState(); state.Authenticated || state.CSRFToken == "" {
		t.Fatalf("the bootstrap read after sign-out: %+v", state)
	}
	h.verifyAudit()
}

// TestAProtectedPageWithoutASessionRedirectsToSignInWithItsReturnPath (DC-13): a page that needs a session answers 303 to the sign-in
// page, whose fragment carries the page it was asked for; the fragment holds a path only.
func TestAProtectedPageWithoutASessionRedirectsToSignInWithItsReturnPath(t *testing.T) {
	h := newHarness(t, settings{})
	for _, path := range []string{"/account/passkeys", "/account/sessions", "/account/devices", "/account/sign-out"} {
		reply := h.do(request{method: http.MethodGet, path: path})
		want := basePath + "/account/sign-in#return=" + url.QueryEscape(basePath+path)
		if reply.status != 303 || reply.header.Get("Location") != want || len(reply.body) != 0 {
			t.Errorf("%s: %d %q", path, reply.status, reply.header.Get("Location"))
		}
	}
	// A cookie that is no session is no session.
	reply := h.do(request{method: http.MethodGet, path: "/account/devices", cookie: "A" + strings.Repeat("b", 42)})
	if reply.status != 303 {
		t.Fatalf("an unknown cookie: %d", reply.status)
	}
}

// parseRegister reads the data attributes of the passkey creation page's form.
func parseRegister(t *testing.T, page response) map[string]string {
	t.Helper()
	match := regexp.MustCompile(`<form[^>]*id="register"([^>]*)>`).FindStringSubmatch(page.text())
	if match == nil {
		t.Fatalf("no creation form: %s", page.text())
	}
	result := map[string]string{}
	for _, attribute := range attrPattern.FindAllStringSubmatch(match[0], -1) {
		result[attribute[1]] = html.UnescapeString(attribute[2])
	}
	return result
}

func contextBackground() context.Context { return context.Background() }
