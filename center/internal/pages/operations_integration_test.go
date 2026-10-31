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

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// The operations surface's page on the official hosted center with the development fixtures (EVIDENCE: REAL ingress, REAL cookie
// session, REAL passkey ceremony by a virtual authenticator, REAL PostgreSQL; the catalogue is the MOCKED illustrative fixture).

var hiddenInput = regexp.MustCompile(`<input type="hidden" name="([a-z_]+)" value="([^"]*)">`)

// hiddenFields are the hidden fields of a page's form, as a browser would submit them.
func hiddenFields(t *testing.T, page string) url.Values {
	t.Helper()
	values := url.Values{}
	for _, match := range hiddenInput.FindAllStringSubmatch(page, -1) {
		values.Set(match[1], html.UnescapeString(match[2]))
	}
	return values
}

func (h *harness) makeOperator(who account) {
	h.t.Helper()
	if _, err := h.migration.Exec(context.Background(), `INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason)
VALUES (gen_random_uuid(), $1, now() - interval '1 hour', now() + interval '30 days', 'operator:cli', 'page test')`, who.id); err != nil {
		h.t.Fatal(err)
	}
}

func grantForm(target platform.ID, features ...string) url.Values {
	form := url.Values{"account": {uuid(target)}, "expires_days": {"30"}, "reason": {"goodwill for ticket 42"}, "source_ref": {"ticket-42"}}
	for _, key := range features {
		form.Set("feature-"+key, "on")
	}
	return form
}

// stepUpFor proves a passkey step-up for the operator grant class and a request hash through the pages' routes.
func (b *browser) stepUpFor(who account, class, targetHash string) response {
	b.h.t.Helper()
	begun := b.postJSON("/session/v1/web/step-up/begin", map[string]any{"operationClass": class, "method": "passkey", "targetHash": targetHash})
	if begun.status != 200 {
		return begun
	}
	var challenge challengeReply
	begun.json(b.h.t, &challenge)
	return b.postJSON("/session/v1/web/step-up/complete", map[string]any{"flowId": challenge.FlowID,
		"proof": map[string]any{"passkey": assertionJSON(who.authenticator.Assert(who.key, unb64(b.h.t, challenge.Challenge)))}})
}

func TestTheOperationsRoutesAreNotFoundWhereTheSurfaceIsOff(t *testing.T) {
	for name, options := range map[string]settings{"a self-hosted center": {}, "the hosted center without the surface": {hosted: true, surfaces: "identity,pages"}} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, options)
			who := h.seedAccount(1)
			h.makeOperator(who)
			b := h.newBrowser()
			b.mustSignIn(who)
			for _, route := range routes.OperationsPageRoutes() {
				var reply response
				if route.Method == http.MethodGet {
					reply = b.get(route.Path)
				} else {
					reply = b.postForm(route.Path, url.Values{})
				}
				if reply.status != http.StatusNotFound || len(reply.body) != 0 {
					t.Errorf("%s: %d %q", route.ID, reply.status, reply.body)
				}
			}
			// The pages surface is unaffected.
			if reply := b.get("/account/passkeys"); reply.status != http.StatusOK {
				t.Errorf("the pages surface: %d", reply.status)
			}
		})
	}
}

// TestEveryOperationsRouteHoldsTheBrowserProtocol: no query, no Authorization header, no body on a GET, the right method, the exact
// Origin, the media type and size of a POST, the session's CSRF token and a session at all (a GET goes to the sign-in page, a POST is
// refused), and the whole security header set on every reply (h.do checks it).
func TestEveryOperationsRouteHoldsTheBrowserProtocol(t *testing.T) {
	h := newHarness(t, settings{hosted: true, policy: writePolicy})
	who := h.seedAccount(1)
	h.makeOperator(who)
	b := h.newBrowser()
	b.mustSignIn(who)
	for _, route := range routes.OperationsPageRoutes() {
		send := func(r request) response {
			r.method, r.path = route.Method, route.Path+r.path
			r.cookie, r.csrf = b.cookie, b.csrf
			if route.Method == http.MethodPost {
				r.contentType, r.body = route.RequestType, []byte("csrf="+b.csrf)
			}
			return h.do(r)
		}
		for _, query := range []string{"?x=1", "?", "?%00"} {
			if reply := send(request{path: query}); reply.status != 400 {
				t.Errorf("%s with %q: %d", route.ID, query, reply.status)
			}
		}
		if reply := send(request{headers: http.Header{"Authorization": {"Bearer afa1." + strings.Repeat("A", 43)}}}); reply.status != 400 {
			t.Errorf("%s with Authorization: %d", route.ID, reply.status)
		}
		other := http.MethodPost
		if route.Method == http.MethodPost {
			other = http.MethodGet
		}
		if reply := h.do(request{method: other, path: route.Path, noOrigin: true}); reply.status != 405 {
			t.Errorf("%s by %s: %d", route.ID, other, reply.status)
		}
		if route.Method == http.MethodGet {
			if reply := h.do(request{method: http.MethodGet, path: route.Path, body: []byte("x"), contentType: "text/plain", cookie: b.cookie}); reply.status != 400 {
				t.Errorf("%s with a body: %d", route.ID, reply.status)
			}
			if reply := h.do(request{method: http.MethodGet, path: route.Path, cookie: b.cookie, headers: http.Header{"Origin": {"https://evil.example"}}}); reply.status != 403 {
				t.Errorf("%s with a wrong Origin: %d", route.ID, reply.status)
			}
			// Without a session the page sends the browser to the sign-in page with the way back in the fragment.
			reply := h.do(request{method: http.MethodGet, path: route.Path})
			if reply.status != 303 || !strings.HasPrefix(reply.header.Get("Location"), basePath+"/account/sign-in#return=") {
				t.Errorf("%s without a session: %d %q", route.ID, reply.status, reply.header.Get("Location"))
			}
			continue
		}
		for _, wrong := range []string{"https://evil.example", "null", origin + "/", ""} {
			reply := h.do(request{method: http.MethodPost, path: route.Path, contentType: route.RequestType, body: []byte("csrf=" + b.csrf), cookie: b.cookie, csrf: b.csrf,
				origin: wrong, noOrigin: wrong == ""})
			if reply.status != 403 {
				t.Errorf("%s with the Origin %q: %d", route.ID, wrong, reply.status)
			}
		}
		for _, mediaType := range []string{"application/json", "text/plain", ""} {
			if reply := h.do(request{method: http.MethodPost, path: route.Path, contentType: mediaType, body: []byte("csrf=" + b.csrf), cookie: b.cookie, csrf: b.csrf}); reply.status != 415 {
				t.Errorf("%s as %q: %d", route.ID, mediaType, reply.status)
			}
		}
		if reply := h.do(request{method: http.MethodPost, path: route.Path, contentType: route.RequestType, cookie: b.cookie, csrf: b.csrf,
			body: []byte("csrf=" + b.csrf + "&reason=" + strings.Repeat("a", route.MaxRequestBytes))}); reply.status != 413 {
			t.Errorf("%s over its bound: %d", route.ID, reply.status)
		}
		// No session: refused (the Unauthenticated refusal), never a redirect that would hide a lost form; a wrong CSRF token: refused.
		if reply := h.do(request{method: http.MethodPost, path: route.Path, contentType: route.RequestType, body: []byte("csrf=" + b.csrf)}); reply.status != 403 {
			t.Errorf("%s without a session: %d", route.ID, reply.status)
		}
		for _, token := range []string{"", strings.Repeat("A", len(b.csrf)), session.PreSessionCSRF(origin)} {
			if reply := h.do(request{method: http.MethodPost, path: route.Path, contentType: route.RequestType, body: []byte("csrf=" + token), cookie: b.cookie}); reply.status != 403 {
				t.Errorf("%s with the CSRF token %q: %d", route.ID, token, reply.status)
			}
		}
		// A field the form does not have, and a repeated field, are refused.
		for _, body := range []string{"csrf=" + b.csrf + "&extra=1", "csrf=" + b.csrf + "&reason=a&reason=b"} {
			if reply := h.do(request{method: http.MethodPost, path: route.Path, contentType: route.RequestType, body: []byte(body), cookie: b.cookie}); reply.status != 400 {
				t.Errorf("%s with %q: %d", route.ID, body, reply.status)
			}
		}
	}
}

// TestAnOperatorGrantsThroughThePageWithAFreshPasskey is the whole flow: the form, the review with its step-up target, the grant that
// is refused without the evidence, the step-up through the pages' routes, the grant, its replay, and the evidence that serves one
// request only.
func TestAnOperatorGrantsThroughThePageWithAFreshPasskey(t *testing.T) {
	h := newHarness(t, settings{hosted: true, policy: writePolicy})
	operator, target := h.seedAccount(1), h.seedAccount(1)
	h.makeOperator(operator)
	b := h.newBrowser()
	b.mustSignIn(operator)

	form := b.get("/operations/grant")
	if form.status != 200 || !strings.Contains(form.text(), `action="/api/operations/grant/review"`) || !strings.Contains(form.text(), `name="feature-remote.view"`) {
		t.Fatalf("the form: %d %s", form.status, form.text())
	}
	review := b.postForm("/operations/grant/review", grantForm(target.id, "remote.view", "push"))
	if review.status != 200 {
		t.Fatalf("the review: %d %s", review.status, review.text())
	}
	fields := hiddenFields(t, review.text())
	targetHash := regexp.MustCompile(`data-step-up-target="([0-9a-f]{64})"`).FindStringSubmatch(review.text())
	if targetHash == nil || !strings.Contains(review.text(), `data-step-up-class="center.operatorGrant"`) || fields.Get("features") != "push,remote.view" ||
		fields.Get("account") != uuid(target.id) || fields.Get("command_id") == "" {
		t.Fatalf("the review page: %s", review.text())
	}
	// The target the page names is the SHA-256 of the canonical request the confirmation will send.
	expires, _ := time0(fields.Get("expires_at"))
	request := entitlement.OperatorRequest{Account: fields.Get("account"), Features: []string{"push", "remote.view"}, Reason: fields.Get("reason"), SourceRef: fields.Get("source_ref"),
		ExpiresAt: expires}
	if request.TargetHashHex(operator.id) != targetHash[1] {
		t.Fatalf("the target hash %s is not the request's %s", targetHash[1], request.TargetHashHex(operator.id))
	}

	writes := func() int {
		return h.count("SELECT (SELECT count(*) FROM entitlement.grant) + (SELECT count(*) FROM entitlement.service_term)")
	}
	// Without the evidence the grant is refused, nothing is written and the refusal is audited.
	if refused := b.postForm("/operations/grant/confirm", cloneValues(fields)); refused.status != 403 || writes() != 0 ||
		h.count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1 AND reason = 'step_up_required'", entitlement.AuditOperatorGrantRefused) != 1 {
		t.Fatalf("a grant without evidence: %d, %d writes", refused.status, writes())
	}
	// Evidence for another request does not serve this one.
	other := request
	other.Reason += "!"
	if proved := b.stepUpFor(operator, access.OperatorGrantClass, other.TargetHashHex(operator.id)); proved.status != 200 {
		t.Fatalf("the step-up: %d %s", proved.status, proved.text())
	}
	if refused := b.postForm("/operations/grant/confirm", cloneValues(fields)); refused.status != 403 || writes() != 0 {
		t.Fatalf("a grant with the evidence of another request: %d, %d writes", refused.status, writes())
	}
	// The evidence for this request: the grant is written, the evidence is spent, and the audit holds the digest of the reason.
	if proved := b.stepUpFor(operator, access.OperatorGrantClass, targetHash[1]); proved.status != 200 {
		t.Fatalf("the step-up: %d %s", proved.status, proved.text())
	}
	done := b.postForm("/operations/grant/confirm", cloneValues(fields))
	if done.status != 200 || !strings.Contains(done.text(), "The grant was written.") || !strings.Contains(done.text(), "push, remote.view") {
		t.Fatalf("the grant: %d %s", done.status, done.text())
	}
	if h.count("SELECT count(*) FROM entitlement.grant WHERE account_id = $1 AND source = 5", target.id) != 2 ||
		h.count("SELECT count(*) FROM entitlement.service_term WHERE account_id = $1 AND kind = 3", target.id) != 1 ||
		h.count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1", entitlement.AuditOperatorGrantIssued) != 1 ||
		h.count("SELECT count(*) FROM identity.step_up_challenge WHERE operation_id = 'center.operatorGrant' AND state = 3") != 1 {
		t.Fatal("the records of the grant")
	}
	// The same form again is the same command: it answers the stored result and needs no evidence.
	again := b.postForm("/operations/grant/confirm", cloneValues(fields))
	if again.status != 200 || !strings.Contains(again.text(), "had already been issued") || h.count("SELECT count(*) FROM entitlement.grant WHERE account_id = $1", target.id) != 2 {
		t.Fatalf("the replay: %d %s", again.status, again.text())
	}
	// Another command for the same source reference is refused without effect (and needs fresh evidence first).
	next := cloneValues(fields)
	next.Set("command_id", uuid(platform.NewID()))
	if proved := b.stepUpFor(operator, access.OperatorGrantClass, targetHash[1]); proved.status != 200 {
		t.Fatalf("the step-up: %d %s", proved.status, proved.text())
	}
	if refused := b.postForm("/operations/grant/confirm", next); refused.status != 400 || !strings.Contains(refused.text(), "already granted with that source reference") ||
		h.count("SELECT count(*) FROM entitlement.grant WHERE account_id = $1", target.id) != 2 {
		t.Fatalf("a second grant with the same source reference: %d %s", refused.status, refused.text())
	}
	// The gate now says so: the target account is entitled to the two features and to nothing else.
	snapshot, err := h.center.Entitlements.Read(context.Background(), uuid(target.id))
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]bool{"remote.view": true, "push": true, "center.nodes": false, "center.mcp": false} {
		if entry, ok := snapshot.Capability(key); !ok || entry.Granted != want {
			t.Errorf("%s: %+v %v", key, entry, ok)
		}
	}
	h.verifyAudit()
}

// TestACatalogueWideGrantIsConfirmedAsReviewed: the shorthand for every feature goes through review, step-up and confirmation, and writes
// one grant per key of the catalogue (the development fixtures allow it; a production configuration does not, which the entitlement
// tests prove).
func TestACatalogueWideGrantIsConfirmedAsReviewed(t *testing.T) {
	h := newHarness(t, settings{hosted: true, policy: writePolicy})
	operator, target := h.seedAccount(1), h.seedAccount(1)
	h.makeOperator(operator)
	b := h.newBrowser()
	b.mustSignIn(operator)
	form := grantForm(target.id)
	form.Set("all", "on")
	review := b.postForm("/operations/grant/review", form)
	fields := hiddenFields(t, review.text())
	hash := regexp.MustCompile(`data-step-up-target="([0-9a-f]{64})"`).FindStringSubmatch(review.text())
	if review.status != 200 || hash == nil {
		t.Fatalf("the review: %d %s", review.status, review.text())
	}
	if proved := b.stepUpFor(operator, access.OperatorGrantClass, hash[1]); proved.status != 200 {
		t.Fatalf("the step-up: %d", proved.status)
	}
	if done := b.postForm("/operations/grant/confirm", fields); done.status != 200 || h.count("SELECT count(*) FROM entitlement.grant WHERE account_id = $1", target.id) != 6 ||
		h.count("SELECT count(*) FROM audit.audit_event WHERE convert_from(payload, 'UTF8') LIKE '%\"catalogueWide\":true%'") != 1 {
		t.Fatalf("the catalogue-wide grant: %d %s", done.status, done.text())
	}
}

// TestOnlyAnOperatorReachesTheOperationsPage: an account that is no operator (or whose role expired or was revoked) is refused on
// every route, with the grant's records untouched.
func TestOnlyAnOperatorReachesTheOperationsPage(t *testing.T) {
	h := newHarness(t, settings{hosted: true, policy: writePolicy})
	plain, expired, revoked, restricted := h.seedAccount(1), h.seedAccount(1), h.seedAccount(1), h.seedAccount(2)
	// A restricted account holds a live operator row and reaches only its security operations: it is no operator now.
	h.makeOperator(restricted)
	for _, row := range []struct {
		who     account
		from    string
		until   string
		revoked string
	}{{expired, "now() - interval '3 days'", "now() - interval '1 day'", "NULL"}, {revoked, "now() - interval '3 days'", "now() + interval '10 days'", "now() - interval '1 hour'"}} {
		if _, err := h.migration.Exec(context.Background(), `INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, revoked_at, granted_by, reason)
VALUES (gen_random_uuid(), $1, `+row.from+`, `+row.until+`, `+row.revoked+`, 'operator:cli', 'page test')`, row.who.id); err != nil {
			t.Fatal(err)
		}
	}
	target := h.seedAccount(1)
	accounts := map[string]account{"an account that is no operator": plain, "an operator that expired": expired, "an operator that was revoked": revoked,
		"an operator whose account is restricted": restricted}
	for name, who := range accounts {
		b := h.newBrowser()
		b.mustSignIn(who)
		if reply := b.get("/operations/grant"); reply.status != 403 || strings.Contains(reply.text(), "feature-") {
			t.Errorf("%s, the form: %d", name, reply.status)
		}
		if reply := b.postForm("/operations/grant/review", grantForm(target.id, "remote.view")); reply.status != 403 || strings.Contains(reply.text(), "center.operatorGrant") {
			t.Errorf("%s, the review: %d", name, reply.status)
		}
		confirm := url.Values{"command_id": {uuid(platform.NewID())}, "account": {uuid(target.id)}, "features": {"remote.view"}, "reason": {"x"}, "source_ref": {"t"},
			"self_approval": {""}, "expires_at": {"4102444800000000"}}
		if reply := b.postForm("/operations/grant/confirm", confirm); reply.status != 403 {
			t.Errorf("%s, the grant: %d", name, reply.status)
		}
	}
	if h.count("SELECT count(*) FROM entitlement.grant") != 0 || h.count("SELECT count(*) FROM entitlement.service_term") != 0 {
		t.Fatal("a refused operator wrote")
	}
	// Each refused account left one audit event for its three requests (once per window and account, so that a stranger cannot grow
	// the chain), with the actor, the reason and the first action asked for.
	for name, who := range accounts {
		var actor string
		var payload []byte
		if err := h.migration.QueryRow(context.Background(), "SELECT actor_ref, payload FROM audit.audit_event WHERE event_type = $1 AND target_id = $2 AND reason = 'not_operator'",
			entitlement.AuditOperatorGrantRefused, who.id.String()).Scan(&actor, &payload); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if actor != "account:"+who.id.String() || string(payload) != `{"action":"operations.grant","code":"AUTHORIZATION/permission_denied","reason":"not_operator"}` {
			t.Errorf("%s: %s %s", name, actor, payload)
		}
	}
	if h.audits(entitlement.AuditOperatorGrantRefused) != len(accounts) {
		t.Errorf("%d refusals audited for %d accounts", h.audits(entitlement.AuditOperatorGrantRefused), len(accounts))
	}
	h.verifyAudit()
}

// TestTheReviewRefusesWhatAGrantRefuses: the bounds of the request come back as the page's text, with nothing written and the form to
// go back to; a self-grant needs its justification.
func TestTheReviewRefusesWhatAGrantRefuses(t *testing.T) {
	h := newHarness(t, settings{hosted: true, policy: writePolicy})
	operator, target := h.seedAccount(1), h.seedAccount(1)
	h.makeOperator(operator)
	b := h.newBrowser()
	b.mustSignIn(operator)
	with := func(change func(url.Values)) response {
		form := grantForm(target.id, "remote.view")
		change(form)
		return b.postForm("/operations/grant/review", form)
	}
	for name, test := range map[string]struct {
		change func(url.Values)
		status int
		text   string
	}{
		"no feature":                                 {func(f url.Values) { f.Del("feature-remote.view") }, 400, "Choose at least one feature."},
		"every feature and one named":                {func(f url.Values) { f.Set("all", "on") }, 400, "Choose every feature or some of them, not both."},
		"a reason that is not valid text":            {func(f url.Values) { f.Set("reason", "bad \xff byte") }, 400, "The reason is not valid text."},
		"a source reference that is not valid text":  {func(f url.Values) { f.Set("source_ref", "ticket-\xfe") }, 400, "The source reference is not valid text."},
		"a blank reason":                             {func(f url.Values) { f.Set("reason", "   ") }, 400, "The reason needs 1 to 512 characters"},
		"a source with a slash":                      {func(f url.Values) { f.Set("source_ref", "a/b") }, 400, "The source reference needs"},
		"days that are no number":                    {func(f url.Values) { f.Set("expires_days", "ten") }, 400, "whole number from 1 to 400"},
		"zero days":                                  {func(f url.Values) { f.Set("expires_days", "0") }, 400, "whole number from 1 to 400"},
		"days with a leading zero":                   {func(f url.Values) { f.Set("expires_days", "030") }, 400, "whole number from 1 to 400"},
		"401 days":                                   {func(f url.Values) { f.Set("expires_days", "401") }, 400, "whole number from 1 to 400"},
		"an account that is no uuid":                 {func(f url.Values) { f.Set("account", "nobody") }, 400, "not a valid account identifier"},
		"a grant to oneself without a justification": {func(f url.Values) { f.Set("account", uuid(operator.id)) }, 400, "needs a justification"},
	} {
		if reply := with(test.change); reply.status != test.status || !strings.Contains(reply.text(), test.text) || !strings.Contains(reply.text(), `href="/api/operations/grant"`) {
			t.Errorf("%s: %d %s", name, reply.status, reply.text())
		}
	}
	// The catalogue-wide shorthand is allowed on the development fixtures and names every key at the review.
	reply := with(func(f url.Values) { f.Del("feature-remote.view"); f.Set("all", "on") })
	if reply.status != 200 || hiddenFields(t, reply.text()).Get("features") != "center.execute,center.mcp,center.nodes,push,remote.control,remote.view" {
		t.Errorf("the whole catalogue: %d %s", reply.status, reply.text())
	}
	// Every key named one by one is the same request as the shorthand: the review's target is that of the normalized request, which is
	// catalogue-wide, so the confirmation (which sends the normalized request) proves the target the page named.
	every := []string{"center.execute", "center.mcp", "center.nodes", "push", "remote.control", "remote.view"}
	explicit := grantForm(target.id, every...)
	reviewed := b.postForm("/operations/grant/review", explicit)
	fields := hiddenFields(t, reviewed.text())
	expires, _ := time0(fields.Get("expires_at"))
	wide := entitlement.OperatorRequest{Account: fields.Get("account"), Features: every, All: true, Reason: fields.Get("reason"), SourceRef: fields.Get("source_ref"), ExpiresAt: expires}
	if reviewed.status != 200 || !strings.Contains(reviewed.text(), `data-step-up-target="`+wide.TargetHashHex(operator.id)+`"`) {
		t.Errorf("the six keys one by one: %d %s", reviewed.status, reviewed.text())
	}
	// A grant to oneself with its justification reaches the review and says so.
	reply = with(func(f url.Values) {
		f.Set("account", uuid(operator.id))
		f.Set("self_approval", "covering the on-call shift")
	})
	if reply.status != 200 || !strings.Contains(reply.text(), "(your own account)") || !strings.Contains(reply.text(), "covering the on-call shift") {
		t.Errorf("a self-grant: %d %s", reply.status, reply.text())
	}
	// A confirmation whose expiry is no number, or whose command is no uuid, is refused before anything is read.
	confirm := url.Values{"command_id": {uuid(platform.NewID())}, "account": {uuid(target.id)}, "features": {"remote.view"}, "reason": {"x"}, "source_ref": {"t"},
		"self_approval": {""}, "expires_at": {"soon"}}
	if reply := b.postForm("/operations/grant/confirm", confirm); reply.status != 400 || !strings.Contains(reply.text(), "Some of the information was not accepted") {
		t.Errorf("an expiry that is no number: %d %s", reply.status, reply.text())
	}
	confirm.Set("expires_at", "4102444800000000")
	confirm.Set("command_id", "not-a-command")
	if reply := b.postForm("/operations/grant/confirm", confirm); reply.status != 400 {
		t.Errorf("a command that is no uuid: %d", reply.status)
	}
	if h.count("SELECT count(*) FROM entitlement.grant") != 0 {
		t.Fatal("a review wrote")
	}
}

// TestTheWorstCaseOfTheOperationsFormsFitsTheirBounds: a reason of 512 characters (alone, or with the longest justification that fits
// the 512 of the stored reason) whose bytes percent-encode to the most (three-byte characters) is accepted by the review, and the
// reply that repeats it, escaped, fits the route's bound.
func TestTheWorstCaseOfTheOperationsFormsFitsTheirBounds(t *testing.T) {
	h := newHarness(t, settings{hosted: true, policy: writePolicy})
	operator, target := h.seedAccount(1), h.seedAccount(1)
	h.makeOperator(operator)
	b := h.newBrowser()
	b.mustSignIn(operator)
	var bound int
	for _, route := range routes.OperationsPageRoutes() {
		if route.ID == "operations.review" {
			bound = route.MaxResponseBytes
		}
	}
	for name, form := range map[string]url.Values{
		"a reason of 512 characters": func() url.Values {
			form := grantForm(target.id, "remote.view")
			form.Set("reason", strings.Repeat("\u20ac", 256)+strings.Repeat("&", 256))
			return form
		}(),
		"a self-grant at the combined bound": func() url.Values {
			form := grantForm(operator.id, "remote.view")
			form.Set("reason", strings.Repeat("\u20ac", 128)+strings.Repeat("&", 128))
			form.Set("self_approval", strings.Repeat("\u20ac", 100)+strings.Repeat("\"", 138))
			return form
		}(),
	} {
		review := b.postForm("/operations/grant/review", form)
		if review.status != 200 || len(review.body) > bound {
			t.Fatalf("%s: %d, %d of %d bytes", name, review.status, len(review.body), bound)
		}
		confirm := hiddenFields(t, review.text())
		if confirm.Get("reason") != form.Get("reason") || confirm.Get("self_approval") != form.Get("self_approval") {
			t.Fatalf("%s: the review did not repeat the request exactly", name)
		}
		if encoded := len(confirm.Encode()); encoded > 12_288 {
			t.Fatalf("%s: the confirmation form is %d bytes", name, encoded)
		}
	}
	// One character more than the combined bound is refused.
	over := grantForm(operator.id, "remote.view")
	over.Set("reason", strings.Repeat("a", 256))
	over.Set("self_approval", strings.Repeat("b", 239))
	if reply := b.postForm("/operations/grant/review", over); reply.status != 400 {
		t.Fatalf("a justification one character too long: %d", reply.status)
	}
}

func cloneValues(values url.Values) url.Values {
	clone := url.Values{}
	for name, list := range values {
		clone[name] = append([]string(nil), list...)
	}
	return clone
}

// time0 reads the review's expiry (microseconds since the epoch).
func time0(text string) (entitlement.Micros, bool) {
	var value int64
	for _, digit := range text {
		if digit < '0' || digit > '9' {
			return 0, false
		}
		value = value*10 + int64(digit-'0')
	}
	return entitlement.Micros(value), true
}
