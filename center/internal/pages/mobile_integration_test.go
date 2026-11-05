// SPDX-License-Identifier: AGPL-3.0-only

package pages_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/mobileauth"
	"github.com/ArcForges/Cloud/center/internal/mobiletest"
	"github.com/ArcForges/Cloud/center/internal/pages"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// The mobile surface (AF-CTR-04 part M, M-14) against a composed center and a real PostgreSQL: MobileProbe's library (mobiletest,
// MOCKED app) begins a flow over the native JSON route, an account reviews and decides it on /mobile/authorize in a browser session
// (the virtual authenticator, MOCKED, proves the step-up through the pages' routes), the test reads the callback from the done page's
// link as the app would receive it, and the app redeems the code. REAL: the center, its store, the routes, the tables. MOCKED: the
// app and the authenticator.

const (
	// releaseRedirect is the harness center's release App Link (the origin of its public base URL, /app/callback).
	releaseRedirect = origin + "/app/callback"
	// testFingerprint is a SHA-256 certificate fingerprint of the form Digital Asset Links write (a fixed test value, no key).
	testFingerprint = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"
)

func mobileHarness(t *testing.T, extra map[string]string) *harness {
	t.Helper()
	return newHarness(t, settings{surfaces: "identity,pages,mobile", policy: writePolicy, extra: extra})
}

// recording is the app's transport: every request goes to the harness's listener and counts for the route proof, its reply is held
// to the page handler's security headers, and its body joins the replies the secret scan reads.
type recording struct{ h *harness }

func (r recording) RoundTrip(request *http.Request) (*http.Response, error) {
	reply, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	recordProved(request.Method, request.URL.Path, reply.StatusCode, reply.Header.Get("Location"))
	return reply, nil
}

// app is a MOCKED app installation of the release client talking to the harness's center.
func (h *harness) app() *mobiletest.App {
	return &mobiletest.App{Center: publicBaseURL, Endpoint: h.url, HTTP: &http.Client{Transport: recording{h}}, Header: http.Header{config.ClientIPHeader: {"198.51.100.20"}},
		ClientID: mobileauth.ClientRelease, Redirect: releaseRedirect, InstallationID: platform.NewID(), Platform: "android-15", AppVersion: "1.2.3"}
}

// mustBegin begins an attempt and fails the test unless the center answers it.
func (h *harness) mustBegin(app *mobiletest.App) mobiletest.Attempt {
	h.t.Helper()
	attempt, reply, err := app.Begin(context.Background())
	if err != nil || reply.Status != 200 {
		h.t.Fatalf("begin: %v %d %s", err, reply.Status, reply.Body)
	}
	h.remember(attempt.State, attempt.Verifier)
	return attempt
}

var appLink = regexp.MustCompile(`id="app-link" class="button primary" href="([^"]+)"`)

// decide reviews a flow and decides it in a browser session, stepping up first for an approval, and returns the callback link of the
// done page (as the app would receive it) with the page's reply.
func (b *browser) decide(who account, attempt mobiletest.Attempt, approve bool) (string, response) {
	b.h.t.Helper()
	review := b.postForm("/mobile/authorize/review", url.Values{"flow_id": {attempt.FlowID}})
	if review.status != 200 {
		b.h.t.Fatalf("review: %d %s", review.status, review.text())
	}
	decision := "deny"
	if approve {
		decision = "approve"
		b.mustStepUp(who, mobileauth.Class, idOf(b.h.t, attempt.FlowID))
	}
	done := b.postForm("/mobile/authorize/decision", url.Values{"flow_id": {attempt.FlowID}, "decision": {decision}})
	found := appLink.FindStringSubmatch(done.text())
	if done.status != 200 || found == nil {
		return "", done
	}
	link := html.UnescapeString(found[1])
	b.h.remember(link)
	return link, done
}

func (h *harness) mobileState(flowID string) int16 {
	h.t.Helper()
	return int16(h.count("SELECT state FROM identity.mobile_authorization WHERE flow_id = $1", flowID))
}

// tokenJSON decodes a token reply's session.
type tokenJSON struct {
	SessionID        string `json:"sessionId"`
	AccessToken      string `json:"accessToken"`
	RefreshToken     string `json:"refreshToken"`
	AccessExpiresAt  string `json:"accessExpiresAt"`
	RefreshExpiresAt string `json:"refreshExpiresAt"`
	Device           struct {
		DeviceID  string `json:"deviceId"`
		Name      string `json:"name"`
		Platform  string `json:"platform"`
		Trust     string `json:"trust"`
		Revision  string `json:"revision"`
		Installed []struct {
			Product string `json:"product"`
			Version string `json:"version"`
		} `json:"installed"`
	} `json:"device"`
	RecoveryGeneration string `json:"recoveryGeneration"`
	Scope              string `json:"scope"`
	Purpose            string `json:"purpose"`
}

// TestTheMobileAuthorizationSignsTheAppIn (M-14: the whole flow): begin answers the derived authorization URL; the page is static;
// the review shows the claim as the app reports it; an approval consumes the step-up and hands a callback with the code, the state
// and the issuer; the token request issues an account session of the arcforges-mobile installation on a new "Android phone" device,
// which refreshes through IdentityService.RefreshSession; the audit chain holds.
func TestTheMobileAuthorizationSignsTheAppIn(t *testing.T) {
	h := mobileHarness(t, nil)
	who := h.seedAccount(1)
	app := h.app()
	attempt := h.mustBegin(app)
	if attempt.AuthorizeURL != publicBaseURL+"/mobile/authorize#flow="+attempt.FlowID {
		t.Fatalf("authorizeUrl %q", attempt.AuthorizeURL)
	}
	b := h.newBrowser()
	page := b.get("/mobile/authorize")
	if page.status != 200 || !strings.Contains(page.text(), `data-page="mobile-authorize"`) || strings.Contains(page.text(), attempt.FlowID) {
		t.Fatalf("the authorization page: %d", page.status)
	}
	b.mustSignIn(who)
	review := b.postForm("/mobile/authorize/review", url.Values{"flow_id": {attempt.FlowID}})
	for _, want := range []string{`<bdi id="mobile-platform">android-15</bdi> (as the app reports it)`, `<bdi id="mobile-version">1.2.3</bdi> (as the app reports it)`,
		`id="mobile-client">ArcForges app<`, `data-step-up-class="identity.authorizeMobile"`, "Origin unknown"} {
		if !strings.Contains(review.text(), want) {
			t.Errorf("the review lacks %q", want)
		}
	}
	link, done := b.decide(who, attempt, true)
	if link == "" {
		t.Fatalf("the done page: %d %s", done.status, done.text())
	}
	if !strings.HasPrefix(link, releaseRedirect+"#code=") || !strings.HasSuffix(link, "&state="+attempt.State+"&iss="+url.QueryEscape(publicBaseURL)) {
		t.Fatalf("the callback %q", link)
	}
	callback, err := app.ParseCallback(link, attempt)
	if err != nil || callback.Code == "" {
		t.Fatalf("the app's check of the callback: %v", err)
	}
	reply, err := app.Token(context.Background(), attempt, callback.Code)
	if err != nil || reply.Status != 200 {
		t.Fatalf("token: %v %d %s", err, reply.Status, reply.Body)
	}
	var issued tokenJSON
	if err = json.Unmarshal(reply.Body, &issued); err != nil {
		t.Fatal(err)
	}
	h.remember(issued.AccessToken, issued.RefreshToken)
	if issued.Scope != "account" || issued.Purpose != "authenticate" || issued.Device.Platform != "android" || issued.Device.Name != "Android phone" ||
		issued.Device.Trust != "untrusted" || issued.RecoveryGeneration != "0" || len(issued.Device.Installed) != 1 ||
		issued.Device.Installed[0].Product != "arcforges-mobile" || issued.Device.Installed[0].Version != "1.2.3" {
		t.Fatalf("the token reply: %+v", issued)
	}
	if h.mobileState(attempt.FlowID) != mobileauth.FlowCompleted || h.count(`SELECT count(*) FROM identity.session WHERE session_id = $1 AND scope = 1 AND
product_id = 'arcforges-mobile' AND installation_id = $2 AND credential_kind = 1`, issued.SessionID, app.InstallationID) != 1 {
		t.Fatal("the session or the flow")
	}
	for _, event := range []string{"identity.mobile_authorization.approved", "identity.mobile_authorization.completed"} {
		if h.audits(event) != 1 {
			t.Errorf("%s audited %d times", event, h.audits(event))
		}
	}
	// The session refreshes through IdentityService.RefreshSession like any native account session.
	if refused := h.refreshNative(issued.RefreshToken, app.InstallationID); refused != "" {
		t.Fatalf("refresh: %s", refused)
	}
	h.verifyAudit()
}

// TestTheMobileCallbacksNameTheIssuer (MB-2 / M-2): both callbacks carry iss, the center's own public base URL (never the request's
// host), percent-encoded, in the contract's order; the app (mobiletest) discards a callback of another issuer or another state, and a
// begin reply whose authorizeUrl is not the derived one.
func TestTheMobileCallbacksNameTheIssuer(t *testing.T) {
	h := mobileHarness(t, nil)
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)
	for _, approve := range []bool{true, false} {
		app := h.app()
		attempt := h.mustBegin(app)
		link, done := b.decide(who, attempt, approve)
		if link == "" {
			t.Fatalf("approve=%v: %d", approve, done.status)
		}
		issuer := "&iss=" + url.QueryEscape(publicBaseURL)
		if !strings.HasSuffix(link, issuer) || strings.Count(link, "iss=") != 1 {
			t.Errorf("approve=%v: the callback %q has no issuer", approve, link)
		}
		if !approve && link != releaseRedirect+"#error=access_denied&state="+attempt.State+issuer {
			t.Errorf("the denial %q", link)
		}
		callback, err := app.ParseCallback(link, attempt)
		if err != nil || callback.Denied == approve {
			t.Errorf("approve=%v: %+v %v", approve, callback, err)
		}
		other := strings.Replace(link, issuer, "&iss="+url.QueryEscape("https://evil.example/api"), 1)
		if _, err = app.ParseCallback(other, attempt); err != mobiletest.ErrMixUp {
			t.Errorf("another issuer: %v", err)
		}
		changed := attempt
		changed.State = mobiletest.NewState()
		if _, err = app.ParseCallback(link, changed); err != mobiletest.ErrState {
			t.Errorf("another state: %v", err)
		}
	}
	// A center configured as another center: its own begin reply is refused by the app (the relay of MB-2).
	relay := h.app()
	relay.Center = "https://other.example.test/api"
	if _, _, err := relay.Begin(context.Background()); err != mobiletest.ErrMixUp {
		t.Errorf("a reply that names another center: %v", err)
	}
}

// TestAReusedMobileCodeRevokesTheFamily (M-14 reuse, Q-9): the code presented again is CONFLICT/code_reused, the flow becomes REVOKED,
// the session family it delivered is revoked with reason 9, the reuse is audited once, and a third presentation changes nothing more.
func TestAReusedMobileCodeRevokesTheFamily(t *testing.T) {
	h := mobileHarness(t, nil)
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)
	app := h.app()
	attempt := h.mustBegin(app)
	link, _ := b.decide(who, attempt, true)
	callback, err := app.ParseCallback(link, attempt)
	if err != nil {
		t.Fatal(err)
	}
	first, err := app.Token(context.Background(), attempt, callback.Code)
	if err != nil || first.Status != 200 {
		t.Fatalf("first: %v %d", err, first.Status)
	}
	var issued tokenJSON
	_ = json.Unmarshal(first.Body, &issued)
	h.remember(issued.AccessToken, issued.RefreshToken)
	for range 2 {
		again, err := app.Token(context.Background(), attempt, callback.Code)
		if err != nil || again.Status != 400 || again.Refusal() != "conflict/code_reused" {
			t.Fatalf("again: %v %d %s", err, again.Status, again.Body)
		}
	}
	if h.mobileState(attempt.FlowID) != mobileauth.FlowRevoked || h.live(idOf(t, issued.SessionID)) ||
		h.count("SELECT revoke_reason FROM identity.session WHERE session_id = $1", issued.SessionID) != int(session.RevokedMobileCodeReused) ||
		h.audits("identity.mobile_authorization.code_reused") != 1 {
		t.Fatal("the reuse did not revoke the delivered family once")
	}
	if refused := h.refreshNative(issued.RefreshToken, app.InstallationID); refused != "AUTHENTICATION/credential_revoked" {
		t.Fatalf("a refresh of the revoked family: %q", refused)
	}
	h.verifyAudit()
}

// TestAWrongVerifierOrBindingEndsTheFlow (M-14): a matching code with a wrong PKCE verifier, or with another installation, client
// redirect or client, is AUTHENTICATION/unauthenticated and ends the flow REVOKED (the code may have been intercepted); the right
// verifier afterwards is code_reused, and no session was issued.
func TestAWrongVerifierOrBindingEndsTheFlow(t *testing.T) {
	h := mobileHarness(t, nil)
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)
	for name, wrong := range map[string]func(app *mobiletest.App, attempt mobiletest.Attempt, code string) []byte{
		"a wrong verifier": func(app *mobiletest.App, attempt mobiletest.Attempt, code string) []byte {
			verifier, _ := mobiletest.NewVerifier()
			return app.TokenBody(attempt, code, verifier)
		},
		"another installation": func(app *mobiletest.App, attempt mobiletest.Attempt, code string) []byte {
			other := *app
			other.InstallationID = platform.NewID()
			return other.TokenBody(attempt, code, attempt.Verifier)
		},
	} {
		app := h.app()
		attempt := h.mustBegin(app)
		link, _ := b.decide(who, attempt, true)
		callback, err := app.ParseCallback(link, attempt)
		if err != nil {
			t.Fatal(err)
		}
		sessions := h.count("SELECT count(*) FROM identity.session WHERE installation_id = $1", app.InstallationID)
		reply, err := app.Post(context.Background(), "/session/v1/mobile/token", wrong(app, attempt, callback.Code))
		if err != nil || reply.Status != 403 || reply.Refusal() != "authentication/unauthenticated" {
			t.Fatalf("%s: %v %d %s", name, err, reply.Status, reply.Body)
		}
		if h.mobileState(attempt.FlowID) != mobileauth.FlowRevoked {
			t.Errorf("%s: the flow is %d", name, h.mobileState(attempt.FlowID))
		}
		right, err := app.Token(context.Background(), attempt, callback.Code)
		if err != nil || right.Refusal() != "conflict/code_reused" {
			t.Errorf("%s: the right verifier afterwards: %v %s", name, err, right.Body)
		}
		if h.count("SELECT count(*) FROM identity.session WHERE installation_id = $1", app.InstallationID) != sessions {
			t.Errorf("%s: a session was issued", name)
		}
	}
	if h.audits("identity.mobile_authorization.verifier_failed") != 2 {
		t.Errorf("verifier_failed audited %d times", h.audits("identity.mobile_authorization.verifier_failed"))
	}
	h.verifyAudit()
}

// TestATokenRequestOrderMirrorsTheNodeSignIn (MB-4, protocol-1): an unknown flow is STATE/not_found, a code that does not match is
// AUTHENTICATION/unauthenticated in every state and changes nothing (a PENDING flow stays PENDING, an APPROVED one APPROVED), and a
// correct code after its lifetime (the policy's mobileCodeLifetime, at most 2 minutes) is STATE/expired and leaves the flow APPROVED.
func TestATokenRequestOrderMirrorsTheNodeSignIn(t *testing.T) {
	h := mobileHarness(t, nil)
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)
	app := h.app()
	attempt := h.mustBegin(app)
	wrong := strings.Repeat("A", 42) + "E"
	unknown := attempt
	unknown.FlowID = uuid(platform.NewID())
	if reply, _ := app.Token(context.Background(), unknown, wrong); reply.Status != 404 || reply.Refusal() != "state/not_found" {
		t.Fatalf("an unknown flow: %d %s", reply.Status, reply.Body)
	}
	if reply, _ := app.Token(context.Background(), attempt, wrong); reply.Status != 403 || reply.Refusal() != "authentication/unauthenticated" ||
		h.mobileState(attempt.FlowID) != mobileauth.FlowPending {
		t.Fatalf("a pending flow: %d %s", reply.Status, reply.Body)
	}
	link, _ := b.decide(who, attempt, true)
	callback, err := app.ParseCallback(link, attempt)
	if err != nil {
		t.Fatal(err)
	}
	if reply, _ := app.Token(context.Background(), attempt, wrong); reply.Refusal() != "authentication/unauthenticated" ||
		h.mobileState(attempt.FlowID) != mobileauth.FlowApproved {
		t.Fatalf("a wrong code on an approved flow: %s", reply.Body)
	}
	lifetime := h.count(`SELECT extract(epoch FROM code_expires_at - decided_at)::int FROM identity.mobile_authorization WHERE flow_id = $1`, attempt.FlowID)
	if config.MaxMobileCodeLifetime != 2*time.Minute || lifetime != int(config.MaxMobileCodeLifetime/time.Second) {
		t.Fatalf("the code lives %d seconds", lifetime)
	}
	h.clock.Advance(config.MaxMobileCodeLifetime)
	if reply, _ := app.Token(context.Background(), attempt, callback.Code); reply.Status != 400 || reply.Refusal() != "state/expired" ||
		h.mobileState(attempt.FlowID) != mobileauth.FlowApproved {
		t.Fatalf("a code past its lifetime: %d %s", reply.Status, reply.Body)
	}
}

// TestADeniedMobileFlowCannotBeRedeemed (M-14 denial): a denial needs no step-up, hands the access_denied callback, makes the flow
// DENIED, and its state is never told to a caller without a code.
func TestADeniedMobileFlowCannotBeRedeemed(t *testing.T) {
	h := mobileHarness(t, nil)
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)
	app := h.app()
	attempt := h.mustBegin(app)
	link, _ := b.decide(who, attempt, false)
	callback, err := app.ParseCallback(link, attempt)
	if err != nil || !callback.Denied || h.mobileState(attempt.FlowID) != mobileauth.FlowDenied || h.audits("identity.mobile_authorization.denied") != 1 {
		t.Fatalf("the denial: %+v %v", callback, err)
	}
	if reply, _ := app.Token(context.Background(), attempt, strings.Repeat("A", 42)+"E"); reply.Refusal() != "authentication/unauthenticated" {
		t.Fatalf("a token request of a denied flow: %s", reply.Body)
	}
}

// TestTheNativeRowsTakeNoCookieOriginOrCSRF (MB-3, M-14): a native request with a cookie of any name is refused (400), a media type
// other than exactly application/json is 415 (text/plain, form, a charset parameter), a GET is 405; a page's Origin and CSRF token
// gain nothing (the request is answered as without them); every reply carries the security headers and no Set-Cookie.
func TestTheNativeRowsTakeNoCookieOriginOrCSRF(t *testing.T) {
	h := mobileHarness(t, nil)
	app := h.app()
	body := app.BeginBody(app.NewAttempt())
	for _, path := range []string{routes.NativeMobileBegin, routes.NativeMobileToken} {
		send := func(r request) response {
			r.method, r.path, r.noOrigin = http.MethodPost, path, r.origin == ""
			if r.body == nil {
				r.body = body
			}
			return h.do(r)
		}
		if reply := send(request{contentType: "application/json", cookie: strings.Repeat("A", 43)}); reply.status != 400 {
			t.Errorf("%s with the session cookie: %d", path, reply.status)
		}
		if reply := send(request{contentType: "application/json", headers: http.Header{"Cookie": {"other=1"}}}); reply.status != 400 {
			t.Errorf("%s with another cookie: %d", path, reply.status)
		}
		for _, media := range []string{"text/plain", "application/x-www-form-urlencoded", "application/json; charset=utf-8", "Application/JSON", ""} {
			if reply := send(request{contentType: media}); reply.status != 415 {
				t.Errorf("%s as %q: %d", path, media, reply.status)
			}
		}
		if reply := h.do(request{method: http.MethodGet, path: path}); reply.status != 405 {
			t.Errorf("%s by GET: %d", path, reply.status)
		}
		for _, reply := range []response{send(request{contentType: "application/json"}), send(request{contentType: "application/json", origin: origin,
			csrf: session.PreSessionCSRF(origin)})} {
			if len(reply.header.Values("Set-Cookie")) != 0 || reply.header.Get("Cache-Control") != "no-store, no-transform" {
				t.Errorf("%s: a cookie or caching", path)
			}
		}
	}
	// The same begin with and without a page's Origin and CSRF token: both begin a flow, neither gains anything else.
	plain := h.do(request{method: http.MethodPost, path: routes.NativeMobileBegin, contentType: "application/json", body: body, noOrigin: true})
	dressed := h.do(request{method: http.MethodPost, path: routes.NativeMobileBegin, contentType: "application/json", body: body, origin: origin,
		csrf: session.PreSessionCSRF(origin)})
	if plain.status != 200 || dressed.status != 200 {
		t.Fatalf("begin: %d %d", plain.status, dressed.status)
	}
}

// TestTheMobilePagesHoldOriginAndCSRF (M-14): the review and the decision are form POSTs of the browser protocol: without the exact
// Origin, or with a CSRF token that is not the session's, they are 403 and record nothing.
func TestTheMobilePagesHoldOriginAndCSRF(t *testing.T) {
	h := mobileHarness(t, nil)
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)
	attempt := h.mustBegin(h.app())
	form := url.Values{"flow_id": {attempt.FlowID}, "csrf": {b.csrf}}
	for _, path := range []string{"/mobile/authorize/review", "/mobile/authorize/decision"} {
		fields := url.Values{"flow_id": form["flow_id"], "csrf": form["csrf"]}
		if path == "/mobile/authorize/decision" {
			fields.Set("decision", "deny")
		}
		if reply := h.do(request{method: http.MethodPost, path: path, contentType: routes.TypeForm, body: []byte(fields.Encode()), cookie: b.cookie,
			noOrigin: true}); reply.status != 403 {
			t.Errorf("%s without an Origin: %d", path, reply.status)
		}
		fields.Set("csrf", session.PreSessionCSRF(origin))
		if reply := h.do(request{method: http.MethodPost, path: path, contentType: routes.TypeForm, body: []byte(fields.Encode()), cookie: b.cookie}); reply.status != 403 {
			t.Errorf("%s with the pre-session constant: %d", path, reply.status)
		}
	}
	if h.count("SELECT count(*) FROM identity.mobile_authorization WHERE flow_id = $1 AND viewed_by IS NULL AND state = 1", attempt.FlowID) != 1 {
		t.Fatal("a refused form recorded something")
	}
}

// TestADisabledMobileSurfaceIsNotFound (M-14): with the mobile surface off, every route of it (the pages, the native JSON routes and
// the apex routes) is 404 with the security headers and no body.
func TestADisabledMobileSurfaceIsNotFound(t *testing.T) {
	h := newHarness(t, settings{surfaces: "identity,pages"})
	for _, route := range routes.MobilePageRoutes() {
		r := request{method: route.Method, path: route.Path, noOrigin: route.Kind == routes.PageNativeKind}
		if route.Method == http.MethodPost {
			r.contentType, r.body = route.RequestType, []byte("{}")
		}
		if reply := h.do(r); reply.status != 404 || len(reply.body) != 0 {
			t.Errorf("%s: %d %q", route.ID, reply.status, reply.body)
		}
	}
}

// TestTheAssetLinksStatementIsExact (MB-8, Q-2, M-14): unset, the statement list is []; configured, it is one statement per app with
// both relations and the android_app target, byte for byte, as application/json with the security headers, no redirect and no cookie.
func TestTheAssetLinksStatementIsExact(t *testing.T) {
	empty := mobileHarness(t, nil)
	if reply := empty.do(request{method: http.MethodGet, path: routes.ApexAssetLinks}); reply.status != 200 || reply.text() != "[]" ||
		reply.header.Get("Content-Type") != "application/json" {
		t.Fatalf("unset: %d %q", reply.status, reply.body)
	}
	h := mobileHarness(t, map[string]string{config.EnvAndroidApp: `[{"packageName":"com.arcforges.prooftest","sha256CertFingerprints":["` + testFingerprint +
		`"],"testOnly":true}]`})
	reply := h.do(request{method: http.MethodGet, path: routes.ApexAssetLinks})
	want := `[{"relation":["delegate_permission/common.handle_all_urls","delegate_permission/common.get_login_creds"],"target":{"namespace":"android_app",` +
		`"package_name":"com.arcforges.prooftest","sha256_cert_fingerprints":["` + testFingerprint + `"]}}]`
	if reply.status != 200 || reply.text() != want || reply.header.Get("Content-Type") != "application/json" || reply.header.Get("Location") != "" ||
		reply.header.Get("X-Content-Type-Options") != "nosniff" || reply.header.Get("Cache-Control") != "no-store, no-transform" {
		t.Fatalf("configured: %d %q", reply.status, reply.body)
	}
	if reply := h.do(request{method: http.MethodPost, path: routes.ApexAssetLinks, noOrigin: true}); reply.status != 405 {
		t.Errorf("POST: %d", reply.status)
	}
}

// TestTheAppCallbackPageIsFixed (M-13 (c), Q-4, M-14): /app/callback is the same page whatever its query or fragment would be: it
// reflects nothing, carries the security headers, loads only the pages' same-origin script (which strips the fragment) and sets no
// cookie; a query is refused.
func TestTheAppCallbackPageIsFixed(t *testing.T) {
	h := mobileHarness(t, nil)
	b := h.newBrowser()
	who := h.seedAccount(1)
	b.mustSignIn(who)
	reply := b.get(routes.ApexAppCallback)
	if reply.status != 200 || !strings.Contains(reply.text(), `data-page="app-callback"`) || len(reply.header.Values("Set-Cookie")) != 0 ||
		!strings.Contains(reply.header.Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatalf("the callback page: %d", reply.status)
	}
	scripts := regexp.MustCompile(`<script[^>]*>`).FindAllString(reply.text(), -1)
	if len(scripts) != 1 || scripts[0] != `<script type="module" src="`+basePath+`/account/account.js">` {
		t.Fatalf("the scripts %q", scripts)
	}
	if again := h.do(request{method: http.MethodGet, path: routes.ApexAppCallback}); string(again.body) != reply.text() {
		t.Error("the page depends on the session")
	}
	if refused := h.do(request{method: http.MethodGet, path: routes.ApexAppCallback + "?code=x"}); refused.status != 400 {
		t.Errorf("a query: %d", refused.status)
	}
}

// TestTheMobileBucketsBoundTheRoutes (MB-11, M-14): begin is counted per client network (mobile_begin_prefix) and refused over its
// limit; token requests that name no flow or present no matching code fill mobile_token_prefix, while a matching code never waits
// on it; the account's decisions are counted (mobile_approve_account).
func TestTheMobileBucketsBoundTheRoutes(t *testing.T) {
	h := newHarness(t, settings{surfaces: "identity,pages,mobile", policy: `{"stepUpPerAccountLimit": 1000, "signInPerPrefixLimit": 1000, ` +
		`"mobileBeginPrefixLimit": 2, "mobileTokenPrefixLimit": 2, "mobileApproveAccountLimit": 2}`})
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)
	app := h.app()
	first := h.mustBegin(app)
	second := h.mustBegin(app)
	if _, reply, _ := app.Begin(context.Background()); reply.Status != 429 || reply.Refusal() != "resource/rate_limited" {
		t.Fatalf("a third begin: %d %s", reply.Status, reply.Body)
	}
	link, _ := b.decide(who, first, true)
	callback, err := app.ParseCallback(link, first)
	if err != nil {
		t.Fatal(err)
	}
	wrong := strings.Repeat("A", 42) + "E"
	for range 2 {
		if reply, _ := app.Token(context.Background(), second, wrong); reply.Refusal() != "authentication/unauthenticated" {
			t.Fatalf("a wrong code: %s", reply.Body)
		}
	}
	if reply, _ := app.Token(context.Background(), second, wrong); reply.Status != 429 {
		t.Fatalf("a wrong code over the limit: %d", reply.Status)
	}
	if reply, _ := app.Token(context.Background(), first, callback.Code); reply.Status != 200 {
		t.Fatalf("a matching code waited on the failure bucket: %d %s", reply.Status, reply.Body)
	}
	b.decide(who, second, false)
	review := b.postForm("/mobile/authorize/review", url.Values{"flow_id": {second.FlowID}})
	if review.status != 200 {
		t.Fatalf("review: %d", review.status)
	}
	if reply := b.postForm("/mobile/authorize/decision", url.Values{"flow_id": {second.FlowID}, "decision": {"deny"}}); reply.status != 429 {
		t.Fatalf("a third decision: %d", reply.status)
	}
}

// TestTheClaimedInstallationMustBeTheAccounts (Q-7, M-12, M-14): an installation of another account is told on the review page before
// any step-up (only the denial is offered), its approval is AUTHORIZATION/permission_denied; at token, an installation another account
// claimed meanwhile is refused permission_denied after the code and the verifier, and the flow stays APPROVED.
func TestTheClaimedInstallationMustBeTheAccounts(t *testing.T) {
	h := mobileHarness(t, nil)
	who, other := h.seedAccount(1), h.seedAccount(1)
	theirs := h.app()
	b, them := h.newBrowser(), h.newBrowser()
	b.mustSignIn(who)
	them.mustSignIn(other)
	// The other account signs its phone in first: the installation is theirs.
	attempt := h.mustBegin(theirs)
	link, _ := them.decide(other, attempt, true)
	callback, _ := theirs.ParseCallback(link, attempt)
	if reply, _ := theirs.Token(context.Background(), attempt, callback.Code); reply.Status != 200 {
		t.Fatalf("their sign-in: %d", reply.Status)
	}
	// The same installation ID claimed for this account.
	mine := *theirs
	claimed := h.mustBegin(&mine)
	review := b.postForm("/mobile/authorize/review", url.Values{"flow_id": {claimed.FlowID}})
	if !strings.Contains(review.text(), "This phone is signed in to another account. Sign out in the app first.") ||
		strings.Contains(review.text(), `id="approve"`) || !strings.Contains(review.text(), `id="deny"`) {
		t.Fatalf("the review of a foreign installation: %s", review.text())
	}
	b.mustStepUp(who, mobileauth.Class, idOf(t, claimed.FlowID))
	refused := b.postForm("/mobile/authorize/decision", url.Values{"flow_id": {claimed.FlowID}, "decision": {"approve"}})
	if refused.status != 403 || !strings.Contains(refused.text(), "This phone is signed in to another account") || h.mobileState(claimed.FlowID) != mobileauth.FlowPending {
		t.Fatalf("the approval of a foreign installation: %d", refused.status)
	}
	// The evidence is consumed in the decision's own transaction (MB-4): the refused approval rolled it back, so it still stands.
	if h.count("SELECT count(*) FROM identity.step_up_challenge WHERE user_id = $1 AND operation_id = $2 AND state = 2", who.id, mobileauth.Class) != 1 {
		t.Fatal("the refused approval consumed the step-up evidence")
	}
	// Approved while the installation was new, claimed by the other account before the token request.
	fresh := h.app()
	pending := h.mustBegin(fresh)
	approved, _ := b.decide(who, pending, true)
	code, _ := fresh.ParseCallback(approved, pending)
	race := *fresh
	race.Redirect = releaseRedirect
	raced := h.mustBegin(&race)
	theirLink, _ := them.decide(other, raced, true)
	theirCode, _ := race.ParseCallback(theirLink, raced)
	if reply, _ := race.Token(context.Background(), raced, theirCode.Code); reply.Status != 200 {
		t.Fatalf("the other account's claim: %d", reply.Status)
	}
	if reply, _ := fresh.Token(context.Background(), pending, code.Code); reply.Status != 403 || reply.Refusal() != "authorization/permission_denied" ||
		h.mobileState(pending.FlowID) != mobileauth.FlowApproved {
		t.Fatalf("token for a foreign installation: %d %s", reply.Status, reply.Body)
	}
}

// TestANarrowerSessionCannotReviewOrApprove (the operation's access rule): an approval issues a mobile session of scope account, so a
// cookie session of a narrower scope (mobile.limited) or of another purpose (enroll) may neither review nor decide, even with the
// step-up proved: AUTHORIZATION/permission_denied, nothing recorded, the flow PENDING and the evidence unconsumed. The session model
// stores both columns for a browser session, so each narrowing is the stored row of the signed-in session.
func TestANarrowerSessionCannotReviewOrApprove(t *testing.T) {
	h := mobileHarness(t, nil)
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)
	attempt := h.mustBegin(h.app())
	if review := b.postForm("/mobile/authorize/review", url.Values{"flow_id": {attempt.FlowID}}); review.status != 200 {
		t.Fatalf("review: %d", review.status)
	}
	b.mustStepUp(who, mobileauth.Class, idOf(t, attempt.FlowID))
	narrow := func(column string, value int) {
		t.Helper()
		if _, err := h.migration.Exec(context.Background(), "UPDATE identity.session SET "+column+" = $2, rev = rev + 1 WHERE user_id = $1 AND credential_kind = 2",
			who.id, value); err != nil {
			t.Fatal(err)
		}
	}
	for _, column := range []string{"scope", "purpose"} {
		narrow(column, 2)
		reviewed := h.count("SELECT count(*) FROM audit.audit_event")
		if review := b.postForm("/mobile/authorize/review", url.Values{"flow_id": {attempt.FlowID}}); review.status != 403 {
			t.Errorf("a review by a session of %s 2: %d", column, review.status)
		}
		if decision := b.postForm("/mobile/authorize/decision", url.Values{"flow_id": {attempt.FlowID}, "decision": {"approve"}}); decision.status != 403 ||
			appLink.MatchString(decision.text()) {
			t.Errorf("an approval by a session of %s 2: %d", column, decision.status)
		}
		if h.mobileState(attempt.FlowID) != mobileauth.FlowPending || h.count("SELECT count(*) FROM audit.audit_event") != reviewed ||
			h.count("SELECT count(*) FROM identity.step_up_challenge WHERE user_id = $1 AND operation_id = $2 AND state = 2", who.id, mobileauth.Class) != 1 {
			t.Fatalf("a refused session of %s 2 changed the flow, the audit or the evidence", column)
		}
		narrow(column, 1)
	}
	// The same session, of scope account and purpose authenticate again, approves with the same evidence.
	if decision := b.postForm("/mobile/authorize/decision", url.Values{"flow_id": {attempt.FlowID}, "decision": {"approve"}}); decision.status != 200 ||
		h.mobileState(attempt.FlowID) != mobileauth.FlowApproved {
		t.Fatalf("the approval: %d", decision.status)
	}
}

// TestAMissingOperationRowRefusesTheDecision (fail closed): the decision takes its evidence rule from the center-defined operation
// identity.authorizeMobile; without that row it refuses (the internal failure, 503), never deciding without the step-up.
func TestAMissingOperationRowRefusesTheDecision(t *testing.T) {
	h := mobileHarness(t, nil)
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)
	attempt := h.mustBegin(h.app())
	if review := b.postForm("/mobile/authorize/review", url.Values{"flow_id": {attempt.FlowID}}); review.status != 200 {
		t.Fatalf("review: %d", review.status)
	}
	b.mustStepUp(who, mobileauth.Class, idOf(t, attempt.FlowID))
	restore := pages.RemoveMobileOperation()
	t.Cleanup(restore)
	for _, decision := range []string{"approve", "deny"} {
		if reply := b.postForm("/mobile/authorize/decision", url.Values{"flow_id": {attempt.FlowID}, "decision": {decision}}); reply.status != 503 ||
			appLink.MatchString(reply.text()) {
			t.Errorf("a %s without the operation row: %d", decision, reply.status)
		}
	}
	if h.mobileState(attempt.FlowID) != mobileauth.FlowPending ||
		h.count("SELECT count(*) FROM identity.step_up_challenge WHERE user_id = $1 AND operation_id = $2 AND state = 2", who.id, mobileauth.Class) != 1 {
		t.Fatal("a decision without the operation row changed the flow or the evidence")
	}
	restore()
	if reply := b.postForm("/mobile/authorize/decision", url.Values{"flow_id": {attempt.FlowID}, "decision": {"approve"}}); reply.status != 200 {
		t.Fatalf("the approval with the row: %d", reply.status)
	}
}

// TestAReviewThatShowsAForeignInstallationIsCounted (M-12, Q-7): the review page tells the person, before any step-up, that the claimed
// installation is another account's; such a review is counted in the reviewer's mobile_approve_account bucket, so the text is no
// unbounded oracle for a known installation ID. A review of a new installation is not counted.
func TestAReviewThatShowsAForeignInstallationIsCounted(t *testing.T) {
	h := newHarness(t, settings{surfaces: "identity,pages,mobile", policy: `{"stepUpPerAccountLimit": 1000, "signInPerPrefixLimit": 1000, ` +
		`"mobileApproveAccountLimit": 2}`})
	who, other := h.seedAccount(1), h.seedAccount(1)
	b, them := h.newBrowser(), h.newBrowser()
	b.mustSignIn(who)
	them.mustSignIn(other)
	fresh := h.mustBegin(h.app())
	for range 3 {
		if review := b.postForm("/mobile/authorize/review", url.Values{"flow_id": {fresh.FlowID}}); review.status != 200 {
			t.Fatalf("a review of a new installation: %d", review.status)
		}
	}
	theirs := h.app()
	attempt := h.mustBegin(theirs)
	link, _ := them.decide(other, attempt, true)
	callback, _ := theirs.ParseCallback(link, attempt)
	if reply, _ := theirs.Token(context.Background(), attempt, callback.Code); reply.Status != 200 {
		t.Fatalf("their sign-in: %d", reply.Status)
	}
	mine := *theirs
	claimed := h.mustBegin(&mine)
	for range 2 {
		if review := b.postForm("/mobile/authorize/review", url.Values{"flow_id": {claimed.FlowID}}); review.status != 200 ||
			!strings.Contains(review.text(), "This phone is signed in to another account") {
			t.Fatalf("a review of a foreign installation: %d", review.status)
		}
	}
	if review := b.postForm("/mobile/authorize/review", url.Values{"flow_id": {claimed.FlowID}}); review.status != 429 ||
		strings.Contains(review.text(), "This phone is signed in to another account") {
		t.Fatalf("a third review of a foreign installation: %d", review.status)
	}
	if h.audits("identity.rate_limited") != 1 {
		t.Fatalf("the exhausted bucket was audited %d times", h.audits("identity.rate_limited"))
	}
}

// TestARestrictedAccountSignsItsPhoneIn (Q-8, M-14): a restricted account may approve (a mobile authorization is a sign-in); a suspended
// account cannot sign in on the pages at all, so it never reaches the review (the existing texts).
func TestARestrictedAccountSignsItsPhoneIn(t *testing.T) {
	h := mobileHarness(t, nil)
	restricted := h.seedAccount(2)
	b := h.newBrowser()
	b.mustSignIn(restricted)
	app := h.app()
	attempt := h.mustBegin(app)
	link, done := b.decide(restricted, attempt, true)
	if link == "" {
		t.Fatalf("a restricted account's approval: %d %s", done.status, done.text())
	}
	callback, _ := app.ParseCallback(link, attempt)
	if reply, _ := app.Token(context.Background(), attempt, callback.Code); reply.Status != 200 {
		t.Fatalf("a restricted account's token: %d %s", reply.Status, reply.Body)
	}
	suspended := h.seedAccount(3)
	if reply := h.newBrowser().signIn(suspended); reply.status == 200 {
		t.Fatal("a suspended account signed in")
	}
}

// TestALapsedApprovalExpiresTheFlow (protocol-6, M-14): an approval whose approving session was revoked with its device before the
// token request ends the flow EXPIRED (STATE/expired, audited approval_lapsed) and issues nothing; an approval of an account that then
// signs out everywhere else is denied by the account participant.
func TestALapsedApprovalExpiresTheFlow(t *testing.T) {
	h := mobileHarness(t, nil)
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)
	app := h.app()
	attempt := h.mustBegin(app)
	link, _ := b.decide(who, attempt, true)
	callback, _ := app.ParseCallback(link, attempt)
	approver := h.sessionRows(who.id)[0]
	if _, err := h.migration.Exec(context.Background(), "UPDATE identity.session SET revoked_at = now(), revoke_reason = $2, rev = rev + 1 WHERE session_id = $1",
		approver, session.RevokedDevice); err != nil {
		t.Fatal(err)
	}
	if reply, _ := app.Token(context.Background(), attempt, callback.Code); reply.Status != 400 || reply.Refusal() != "state/expired" ||
		h.mobileState(attempt.FlowID) != mobileauth.FlowExpired || h.audits("identity.mobile_authorization.approval_lapsed") != 1 ||
		h.count("SELECT count(*) FROM device.installation WHERE installation_id = $1", app.InstallationID) != 0 {
		t.Fatalf("a lapsed approval: %d %s", reply.Status, reply.Body)
	}
	// The participant: "sign out all other sessions" denies the account's approved, uncollected flows.
	c := h.newBrowser()
	c.mustSignIn(who)
	second := h.app()
	pending := h.mustBegin(second)
	approved, _ := c.decide(who, pending, true)
	code, _ := second.ParseCallback(approved, pending)
	c.mustStepUp(who, identity.ClassRevokeAllSessions, who.id)
	if reply := c.postForm("/account/sessions/revoke-all", url.Values{"command_id": {uuid(platform.NewID())}}); reply.status != 303 && reply.status != 200 {
		t.Fatalf("revoke all: %d", reply.status)
	}
	if h.mobileState(pending.FlowID) != mobileauth.FlowDenied {
		t.Fatalf("the participant left the flow %d", h.mobileState(pending.FlowID))
	}
	if reply, _ := second.Token(context.Background(), pending, code.Code); reply.Refusal() != "authentication/unauthenticated" {
		t.Fatalf("a denied flow's code: %s", reply.Body)
	}
	h.verifyAudit()
}

// TestTheDebugClientTakesItsSchemeOnASelfHostedCenter (MB-9, M-14): with ARCFORGES_CENTER_MOBILE_DEBUG_REDIRECT set, the debug client
// (arcforges.android.local) is admitted with exactly <scheme>:/callback, its review says "debug build", and its callback is that
// redirect with the fragment; the release client keeps its App Link; any other pairing is redirectUri: not_admitted or client_mismatch.
func TestTheDebugClientTakesItsSchemeOnASelfHostedCenter(t *testing.T) {
	h := mobileHarness(t, map[string]string{config.EnvMobileDebugRedirect: "com.arcforges.android.debug"})
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)
	app := h.app()
	app.ClientID, app.Redirect = mobileauth.ClientDebug, "com.arcforges.android.debug:/callback"
	attempt := h.mustBegin(app)
	review := b.postForm("/mobile/authorize/review", url.Values{"flow_id": {attempt.FlowID}})
	if !strings.Contains(review.text(), "ArcForges app, debug build") || !strings.Contains(review.text(), `id="mobile-debug-note"`) {
		t.Fatal("the review does not say debug build")
	}
	link, _ := b.decide(who, attempt, true)
	if !strings.HasPrefix(link, "com.arcforges.android.debug:/callback#code=") {
		t.Fatalf("the debug callback %q", link)
	}
	callback, err := app.ParseCallback(link, attempt)
	if err != nil {
		t.Fatal(err)
	}
	if reply, _ := app.Token(context.Background(), attempt, callback.Code); reply.Status != 200 {
		t.Fatalf("the debug token: %d %s", reply.Status, reply.Body)
	}
	for _, pair := range [][3]string{{mobileauth.ClientDebug, "com.arcforges.other:/callback", "VALIDATION/invalid_argument"},
		{mobileauth.ClientRelease, "com.arcforges.android.debug:/callback", "VALIDATION/invalid_argument"},
		{mobileauth.ClientDebug, releaseRedirect, "VALIDATION/invalid_argument"},
		{mobileauth.ClientRelease, "https://other.example.test/app/callback", "VALIDATION/invalid_argument"}} {
		other := *app
		other.ClientID, other.Redirect = pair[0], pair[1]
		if _, reply, _ := other.Begin(context.Background()); reply.Status != 400 || !strings.EqualFold(reply.Refusal(), pair[2]) {
			t.Errorf("%s with %s: %d %s", pair[0], pair[1], reply.Status, reply.Body)
		}
	}
	// Without the variable, the debug client is not admitted at all.
	plain := mobileHarness(t, nil)
	debug := plain.app()
	debug.ClientID, debug.Redirect = mobileauth.ClientDebug, "com.arcforges.android.debug:/callback"
	if _, reply, _ := debug.Begin(context.Background()); reply.Status != 400 {
		t.Errorf("the debug client without its scheme: %d", reply.Status)
	}
}

// TestNoMobileSecretIsStoredLoggedOrAudited (SEC-14, E1-18, MB-11): no one-use code, PKCE verifier, callback link or token the flow
// saw is in any table (as text or as the hex of its bytes), the statement statistics, the center's log or the test server's log; only
// the code's digest is stored. The client state is stored in clear in identity.mobile_authorization only, to return it unchanged in
// the callback: it is in no other table (the audit events and the rate-limit rows included), the statement statistics or the
// center's log. (The test server logs every statement with its parameters, so the state of the begin insert is in that log.)
func TestNoMobileSecretIsStoredLoggedOrAudited(t *testing.T) {
	h := mobileHarness(t, nil)
	ctx := context.Background()
	admin := pgtest.Connect(t, pgtest.WithDatabase(t, pgtest.ServerURL(t), h.database))
	if _, err := admin.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS pg_stat_statements"); err != nil {
		t.Fatal(err)
	}
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)
	app := h.app()
	attempt := h.mustBegin(app)
	link, _ := b.decide(who, attempt, true)
	callback, _ := app.ParseCallback(link, attempt)
	reply, _ := app.Token(ctx, attempt, callback.Code)
	var issued tokenJSON
	_ = json.Unmarshal(reply.Body, &issued)
	again, _ := app.Token(ctx, attempt, callback.Code)
	if reply.Status != 200 || again.Refusal() != "conflict/code_reused" {
		t.Fatalf("the flow: %d %s", reply.Status, again.Body)
	}
	secrets := []string{callback.Code, attempt.Verifier, issued.AccessToken, issued.RefreshToken, link}
	var hexed []string
	for _, value := range secrets {
		hexed = append(hexed, hex.EncodeToString([]byte(value)))
	}
	if raw, ok := session.ParseHandle(callback.Code); ok {
		hexed = append(hexed, hex.EncodeToString(raw[:]))
	}
	withState := append(slices.Clone(secrets), attempt.State)
	scan := func(where, text string, values []string) {
		t.Helper()
		for _, value := range values {
			if value != "" && strings.Contains(text, value) {
				t.Errorf("%s holds a secret", where)
			}
		}
	}
	for _, table := range []string{"identity.mobile_authorization", "audit.audit_event", "identity.session", "platform.rate_limit"} {
		var text string
		if err := admin.QueryRow(ctx, "SELECT coalesce(string_agg(row_to_json(t)::text, ''), '') FROM "+table+" t").Scan(&text); err != nil {
			t.Fatal(err)
		}
		if table == "identity.mobile_authorization" {
			scan(table, text, secrets)
		} else {
			scan(table, text, withState)
		}
		scan(table+" (bytea)", text, hexed)
	}
	var statistics string
	if err := admin.QueryRow(ctx, "SELECT coalesce(string_agg(query, ''), '') FROM pg_stat_statements").Scan(&statistics); err != nil {
		t.Fatal(err)
	}
	scan("pg_stat_statements", statistics, withState)
	scan("the center's log", h.logs.String(), withState)
	if log, ok := pgtest.ServerLog(t); ok {
		scan("the test server's log", log, secrets)
		if !strings.Contains(log, "identity.mobile_authorization") {
			t.Fatal("the server log does not show the mobile statements, so the scan proves nothing")
		}
	}
}

// refreshNative refreshes a native session through IdentityService.RefreshSession over the API; "" is a rotation, else the refusal.
func (h *harness) refreshNative(token string, installationID platform.ID) string {
	h.t.Helper()
	reply := h.api("/arcforges.publicapi.v1.IdentityService/RefreshSession", &publicapiv1.IdentityServiceRefreshSessionRequest{Meta: &foundationv1.RequestMeta{},
		RefreshToken: proto.String(token), InstallationId: &foundationv1.Id{Value: installationID[:]}}, "")
	if reply.status != "0" || reply.body == nil {
		h.t.Fatalf("refresh: %q %q", reply.status, reply.message)
	}
	var response publicapiv1.IdentityServiceRefreshSessionResponse
	if err := proto.Unmarshal(reply.body, &response); err != nil {
		h.t.Fatal(err)
	}
	if failure := response.GetError(); failure != nil {
		return strings.TrimPrefix(failure.GetCategory().String(), "ERROR_CATEGORY_") + "/" + failure.GetCode()
	}
	h.remember(response.GetValue().GetSession().GetAccessToken(), response.GetValue().GetSession().GetRefreshToken())
	return ""
}

// TestConcurrentMobileTokensHaveOneWinner (M-14, MB-4 lock order): in each round two token requests with the correct code race an
// account remediation ("sign out all other sessions", whose participant locks the flows first) on one approved flow; PostgreSQL detects
// no deadlock in the test's database (pg_stat_database.deadlocks, E1-14), at most one session is issued and stays live, and a reuse
// that lost the race revoked the winner's family.
func TestConcurrentMobileTokensHaveOneWinner(t *testing.T) {
	h := mobileHarness(t, nil)
	who := h.seedAccount(1)
	const query = "SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()"
	before := h.count(query)
	for round := range 6 {
		approver, remediator := h.newBrowser(), h.newBrowser()
		approver.mustSignIn(who)
		remediator.mustSignIn(who)
		app := h.app()
		attempt := h.mustBegin(app)
		link, _ := approver.decide(who, attempt, true)
		callback, err := app.ParseCallback(link, attempt)
		if err != nil {
			t.Fatal(err)
		}
		remediator.mustStepUp(who, identity.ClassRevokeAllSessions, who.id)
		var wait sync.WaitGroup
		statuses := make([]int, 2)
		for index := range 2 {
			wait.Add(1)
			go func() {
				defer wait.Done()
				reply, err := app.Token(context.Background(), attempt, callback.Code)
				if err == nil {
					statuses[index] = reply.Status
				}
			}()
		}
		wait.Add(1)
		go func() {
			defer wait.Done()
			remediator.postForm("/account/sessions/revoke-all", url.Values{"command_id": {uuid(platform.NewID())}})
		}()
		wait.Wait()
		issued := h.count("SELECT count(*) FROM identity.session WHERE installation_id = $1", app.InstallationID)
		live := h.count("SELECT count(*) FROM identity.session WHERE installation_id = $1 AND revoked_at IS NULL", app.InstallationID)
		state := h.mobileState(attempt.FlowID)
		switch {
		case statuses[0] == 200 && statuses[1] == 200:
			t.Fatalf("round %d: two winners", round)
		case issued > 1 || live > issued:
			t.Fatalf("round %d: %d sessions issued, %d live", round, issued, live)
		case state == mobileauth.FlowRevoked && live != 0:
			t.Fatalf("round %d: the reuse left the winner's family live", round)
		case state != mobileauth.FlowRevoked && state != mobileauth.FlowCompleted && state != mobileauth.FlowDenied && state != mobileauth.FlowExpired:
			t.Fatalf("round %d: the flow ended %d", round, state)
		}
	}
	time.Sleep(1500 * time.Millisecond)
	if after := h.count(query); after != before {
		t.Fatalf("PostgreSQL detected %d deadlocks", after-before)
	}
}
