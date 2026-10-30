// SPDX-License-Identifier: AGPL-3.0-only

package pages_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey/virtual"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// enrollOwner enrolls the owner through the pages' routes with the harness's bootstrap token and returns the enrollment's reply, the
// owner's authenticator and key; on success the browser holds the cookie and the session's CSRF token.
func (b *browser) enrollOwner(token, displayName string) (response, *virtual.Authenticator, *virtual.Key) {
	b.h.t.Helper()
	b.bootstrapState()
	begun := b.postJSON("/session/v1/web/authentication/begin", map[string]any{"method": "passkey", "purpose": "enroll", "installation": b.claim()})
	if begun.status != 200 {
		b.h.t.Fatalf("begin enrollment: %d %s", begun.status, begun.text())
	}
	var challenge challengeReply
	begun.json(b.h.t, &challenge)
	authenticator := virtual.New(rpID, origin)
	creation, key := authenticator.Create(unb64(b.h.t, challenge.Challenge), unb64(b.h.t, challenge.Options.UserHandle))
	completed := b.postJSON("/session/v1/web/enrollment/complete", map[string]any{"flowId": challenge.FlowID, "proof": map[string]any{"localCode": token},
		"credential": map[string]any{"passkey": creationJSON(creation)}, "profile": map[string]any{"displayName": displayName}})
	if completed.status == 200 {
		b.cookie = completed.cookie()
		b.bootstrapState()
	}
	return completed, authenticator, key
}

// TestTheOwnerEnrollsThroughThePages (F2, PLT-5): the bootstrap page, then the owner bootstrap through the WebBrowserSession
// routes: begin(ENROLL), the one-time token, a passkey and a display name give one account, one passkey, a web device named for the
// browser and a cookie session of 12 hours absolute and 30 minutes idle; the cookie is byte-exact and the bootstrap one-shot.
func TestTheOwnerEnrollsThroughThePages(t *testing.T) {
	h := newHarness(t, settings{})
	page := h.do(request{method: http.MethodGet, path: "/account/bootstrap"})
	if page.status != 200 || page.header.Get("Content-Type") != routes.TypeHTML || !strings.Contains(page.text(), `id="token"`) ||
		!strings.Contains(page.text(), `<html lang="en">`) {
		t.Fatalf("the bootstrap page: %d %q", page.status, page.header.Get("Content-Type"))
	}
	owner := h.newBrowser()
	state := owner.bootstrapState()
	if state.Authenticated || state.Session != nil || state.Profile != nil || state.CSRFToken != session.PreSessionCSRF(origin) {
		t.Fatalf("before the owner exists: %+v", state)
	}
	completed, authenticator, key := owner.enrollOwner(h.bootstrap, "Owner")
	if completed.status != 200 {
		t.Fatalf("enrollment: %d %s", completed.status, completed.text())
	}
	cookie := completed.header.Get("Set-Cookie")
	if len(completed.header.Values("Set-Cookie")) != 1 || !cookiePattern.MatchString(cookie) || !strings.Contains(cookie, "Max-Age=43") {
		t.Fatalf("the session cookie: %q", completed.header.Values("Set-Cookie"))
	}
	if completed.header.Get("Content-Type") != routes.TypeJSON || completed.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("the enrollment reply's headers: %v", completed.header)
	}
	var view struct {
		SessionID, ExpiresAt, IdleExpiresAt, UserID, DeviceID, RecoveryGeneration, Purpose string
		WorkspaceIDs                                                                       []string
	}
	completed.json(t, &view)
	if view.Purpose != "enroll" || view.RecoveryGeneration != "0" || view.WorkspaceIDs == nil || len(view.WorkspaceIDs) != 0 {
		t.Fatalf("the session view: %+v", view)
	}
	issued, err := time.Parse(time.RFC3339Nano, view.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	idle, err := time.Parse(time.RFC3339Nano, view.IdleExpiresAt)
	if err != nil || issued.Sub(h.clock.Now()) > 12*time.Hour || issued.Sub(h.clock.Now()) < 12*time.Hour-time.Minute ||
		idle.Sub(h.clock.Now()) > 30*time.Minute || idle.Sub(h.clock.Now()) < 30*time.Minute-time.Minute {
		t.Fatalf("lifetimes: expires %s idle %s now %s", view.ExpiresAt, view.IdleExpiresAt, h.clock.Now())
	}
	if h.count("SELECT count(*) FROM identity.user") != 1 || h.count("SELECT count(*) FROM identity.auth_identity WHERE provider_id = 'passkey'") != 1 ||
		h.count("SELECT count(*) FROM identity.bootstrap") != 1 || h.audits("identity.bootstrap.completed") != 1 {
		t.Fatal("the bootstrap did not create exactly one account with one passkey")
	}
	if h.count(`SELECT count(*) FROM identity.session s JOIN device.installation i ON i.installation_id = s.installation_id JOIN device.device d ON d.device_id = s.device_id
WHERE s.credential_kind = 2 AND s.scope = 1 AND s.product_id = 'arcforges-web' AND s.browser_origin = $1 AND s.purpose = 2 AND i.product_id = 'arcforges-web'
    AND i.platform = 'web' AND d.platform = 6 AND d.display_name = 'Edge on Windows' AND i.client_installation_id = $2`, origin, owner.installation) != 1 {
		t.Fatal("the session is not a cookie session on the browser's own web device and installation")
	}
	state = owner.bootstrapState()
	if !state.Authenticated || state.Session == nil || state.Profile == nil || state.Profile.DisplayName != "Owner" || state.Profile.Locale != "en-US" ||
		state.Profile.Timezone != "UTC" || state.Profile.Revision != "1" || state.Session.UserID != view.UserID || state.Session.Purpose != "enroll" ||
		state.CSRFToken == session.PreSessionCSRF(origin) || len(state.CSRFToken) != 43 {
		t.Fatalf("the bootstrap read of the owner: %+v", state)
	}
	// The bootstrap is one-shot: the token and a new passkey create nothing a second time.
	second := h.newBrowser()
	again, _, _ := second.enrollOwner(h.bootstrap, "Second")
	if again.status != 403 || again.refusal(t) != "authentication/unauthenticated" || h.count("SELECT count(*) FROM identity.user") != 1 {
		t.Fatalf("a second bootstrap: %d %s", again.status, again.text())
	}
	// The owner signs in again with the passkey the bootstrap registered, from the same browser: the same device.
	owner.cookie = ""
	owner.mustSignIn(account{authenticator: authenticator, key: key})
	if h.count("SELECT count(*) FROM device.device WHERE platform = 6") != 1 || h.count("SELECT count(*) FROM identity.session WHERE credential_kind = 2") != 2 {
		t.Fatal("the same browser did not keep its device")
	}
	for _, secret := range h.secrets {
		if strings.Contains(h.logs.String(), secret) {
			t.Fatal("a credential reached the log")
		}
	}
	h.verifyAudit()
	_ = config.SurfacePages
}

// TestAPasskeySignsInThroughThePages: a seeded account signs in with its passkey; the browser's claimed installation is its device,
// a second claim is a second device, and a claim that belongs to another account never links to it.
func TestAPasskeySignsInThroughThePages(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1)
	first := h.newBrowser()
	first.mustSignIn(who)
	state := first.bootstrapState()
	if !state.Authenticated || state.Profile == nil || state.Profile.DisplayName != "Seeded" || state.Session.Purpose != "authenticate" {
		t.Fatalf("after sign-in: %+v", state)
	}
	// The same browser again: one device, two sessions.
	again := h.newBrowser()
	again.installation = first.installation
	again.mustSignIn(who)
	if h.count("SELECT count(*) FROM device.device WHERE user_id = $1 AND platform = 6", who.id) != 1 || len(h.sessionRows(who.id)) != 2 {
		t.Fatal("one claimed installation is not one device")
	}
	// Another browser: another device.
	other := h.newBrowser()
	other.userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
	other.mustSignIn(who)
	if h.count("SELECT count(*) FROM device.device WHERE user_id = $1 AND platform = 6", who.id) != 2 ||
		h.count("SELECT count(*) FROM device.device WHERE user_id = $1 AND display_name = 'Safari on macOS'", who.id) != 1 {
		t.Fatal("a second browser is not a second device named for its family")
	}
	// A claim that belongs to another account gets rows of its own, never the other account's device.
	stranger := h.seedAccount(1)
	thief := h.newBrowser()
	thief.installation = first.installation
	thief.mustSignIn(stranger)
	if h.count("SELECT count(*) FROM device.installation WHERE client_installation_id = $1", first.installation) != 2 ||
		h.count("SELECT count(*) FROM device.device WHERE user_id = $1", stranger.id) != 1 {
		t.Fatal("a claimed installation linked two accounts")
	}
	if h.audits("identity.sign_in.succeeded") != 4 {
		t.Fatalf("sign-in audits %d", h.audits("identity.sign_in.succeeded"))
	}
	h.verifyAudit()
}

// TestASignInRefusesWhatIsNotAPasskeyOfThisPage: a wrong assertion, an unknown credential, a flow completed twice and a method or
// purpose the pages do not offer are refused, with the one authentication answer for a wrong proof.
func TestASignInRefusesWhatIsNotAPasskeyOfThisPage(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.bootstrapState()
	begin := func(body map[string]any) response { return b.postJSON("/session/v1/web/authentication/begin", body) }
	for name, body := range map[string]map[string]any{
		"e-mail":              {"method": "email", "purpose": "authenticate", "installation": b.claim(), "loginHint": "a@b.test"},
		"password":            {"method": "password", "purpose": "authenticate", "installation": b.claim()},
		"recovery":            {"method": "passkey", "purpose": "recover", "installation": b.claim()},
		"step-up as sign-in":  {"method": "passkey", "purpose": "stepUp", "installation": b.claim()},
		"another product":     {"method": "passkey", "purpose": "authenticate", "installation": map[string]any{"installationId": b.installation, "product": "companion", "platform": "web", "appVersion": "1"}},
		"an unknown provider": {"method": "passkey", "purpose": "authenticate", "installation": b.claim(), "providerId": "github"},
	} {
		if reply := begin(body); reply.status != 400 || !strings.HasPrefix(reply.refusal(t), "validation/invalid_argument") {
			t.Errorf("%s: %d %s", name, reply.status, reply.text())
		}
	}
	var challenge challengeReply
	begin(map[string]any{"method": "passkey", "purpose": "authenticate", "installation": b.claim()}).json(t, &challenge)
	if challenge.Method != "passkey" || challenge.Purpose != "authenticate" || challenge.ProviderID != "passkey" || challenge.RPID != rpID || challenge.Options == nil ||
		challenge.Options.UserVerification != "required" || len(challenge.Options.Algorithms) != 1 || challenge.Options.Algorithms[0] != -7 ||
		len(unb64(t, challenge.Challenge)) != 32 || len(challenge.Options.AllowedCredentials) != 0 {
		t.Fatalf("the challenge: %+v", challenge)
	}
	// An assertion made for another challenge, a key that is not the account's and a flow that does not exist.
	complete := func(flowID string, assertion map[string]any) response {
		return b.postJSON("/session/v1/web/authentication/complete", map[string]any{"flowId": flowID, "proof": map[string]any{"passkey": assertion}})
	}
	wrong := complete(challenge.FlowID, assertionJSON(who.authenticator.Assert(who.key, randomBytes(t, 32))))
	if wrong.status != 403 || wrong.refusal(t) != "authentication/unauthenticated" || wrong.cookie() != "" {
		t.Fatalf("a wrong assertion: %d %s", wrong.status, wrong.text())
	}
	replay := complete(challenge.FlowID, assertionJSON(who.authenticator.Assert(who.key, unb64(t, challenge.Challenge))))
	if replay.status != 400 || replay.refusal(t) != "state/expired" {
		t.Fatalf("a flow after its only attempt: %d %s", replay.status, replay.text())
	}
	unknown := complete(uuid(platform.NewID()), assertionJSON(who.authenticator.Assert(who.key, unb64(t, challenge.Challenge))))
	if unknown.status != 404 || unknown.refusal(t) != "state/not_found" {
		t.Fatalf("an unknown flow: %d %s", unknown.status, unknown.text())
	}
	other := virtual.New(rpID, origin)
	_, strange := other.Create(randomBytes(t, 32), randomBytes(t, 32))
	var second challengeReply
	begin(map[string]any{"method": "passkey", "purpose": "authenticate", "installation": b.claim()}).json(t, &second)
	unknownKey := complete(second.FlowID, assertionJSON(other.Assert(strange, unb64(t, second.Challenge))))
	if unknownKey.status != 403 || unknownKey.refusal(t) != "authentication/unauthenticated" {
		t.Fatalf("an unknown credential: %d %s", unknownKey.status, unknownKey.text())
	}
	// Proofs other than a passkey are not offered.
	var third challengeReply
	begin(map[string]any{"method": "passkey", "purpose": "authenticate", "installation": b.claim()}).json(t, &third)
	for name, proof := range map[string]map[string]any{"e-mail code": {"emailCode": "ABCDEFGH"}, "recovery code": {"recoveryCode": "x"}, "password": {"password": "x"},
		"two proofs": {"emailCode": "x", "password": "y"}, "nothing": {}} {
		reply := b.postJSON("/session/v1/web/authentication/complete", map[string]any{"flowId": third.FlowID, "proof": proof})
		if reply.status != 400 || reply.cookie() != "" {
			t.Errorf("%s: %d %s", name, reply.status, reply.text())
		}
	}
	if h.audits("identity.sign_in.failed") == 0 {
		t.Fatal("a failed sign-in was not audited")
	}
	h.verifyAudit()
}
