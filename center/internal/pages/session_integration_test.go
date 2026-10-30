// SPDX-License-Identifier: AGPL-3.0-only

package pages_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"

	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey/virtual"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// TestACookieOpensNothingOnceItsSessionIsNotLive (pages-2): the pages and the API's cookie routes judge a cookie by one predicate
// (session.Verifier.ResolveSession; Resolve is its answer without the page-only fields). A session idle for 31 minutes, a session
// whose stored origin is not this center's and a session of a suspended account each open nothing: no bootstrap state, no
// sign-out, no step-up and no form, though the cookie and its CSRF token are exactly the ones the live session had.
func TestACookieOpensNothingOnceItsSessionIsNotLive(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	ctx := context.Background()
	for name, ruin := range map[string]func(who account, sessionID platform.ID){
		"idle for 31 minutes": func(account, platform.ID) { h.clock.Advance(31 * time.Minute) },
		"another origin": func(_ account, sessionID platform.ID) {
			if _, err := h.migration.Exec(ctx, "UPDATE identity.session SET browser_origin = 'https://other.example.test' WHERE session_id = $1", sessionID); err != nil {
				t.Fatal(err)
			}
		},
		"a suspended account": func(who account, _ platform.ID) {
			if _, err := h.migration.Exec(ctx, "UPDATE identity.user SET state = 3 WHERE user_id = $1", who.id); err != nil {
				t.Fatal(err)
			}
		},
	} {
		who := h.seedAccount(1)
		b := h.newBrowser()
		b.mustSignIn(who)
		cookie, csrf := b.cookie, b.csrf
		if !b.bootstrapState().Authenticated {
			t.Fatalf("%s: the session was never live", name)
		}
		ruin(who, idOf(t, b.bootstrapPeek()))
		// The browser still holds the live session's cookie and token: only the session's state differs.
		as := func() *browser { b.cookie, b.csrf = cookie, csrf; return b }
		if state := as().bootstrapState(); state.Authenticated || state.Session != nil {
			t.Errorf("%s: the bootstrap read still signs the cookie in: %+v", name, state)
		}
		if reply := as().postEmpty("/session/v1/web/logout"); reply.status != 403 || reply.refusal(t) != "authentication/unauthenticated" || reply.cookie() != "" {
			t.Errorf("%s: a sign-out: %d %s", name, reply.status, reply.text())
		}
		if reply := as().postJSON("/session/v1/web/step-up/begin", map[string]any{"operationClass": identity.ClassRevokeAllSessions, "method": "passkey",
			"targetHash": hashOf(identity.ClassRevokeAllSessions, who.id, who.id)}); reply.status != 403 || reply.refusal(t) != "authentication/unauthenticated" {
			t.Errorf("%s: a step-up: %d %s", name, reply.status, reply.text())
		}
		if reply := as().postForm("/account/sessions/revoke-all", url.Values{"command_id": {uuid(platform.NewID())}}); reply.status != 403 {
			t.Errorf("%s: a form: %d %s", name, reply.status, reply.text())
		}
		if reply := as().get("/account/passkeys"); reply.status != 303 {
			t.Errorf("%s: a page: %d", name, reply.status)
		}
		// The API's own cookie route judges the cookie alike (Verifier.Resolve shares the predicate).
		if reply := as().grpcCall("/arcforges.publicapi.v1.IdentityService/ListSessions", &publicapiv1.IdentityServiceListSessionsRequest{Meta: &foundationv1.RequestMeta{},
			Page: &foundationv1.PageRequest{}}); reply.status != 200 || !strings.Contains(reply.text(), "grpc-status: 16") {
			t.Errorf("%s: the API with the cookie: %d %.100s", name, reply.status, reply.body)
		}
	}
	if h.audits("identity.session.revoked") != 0 || h.audits("identity.step_up.proved") != 0 {
		t.Fatal("a refused request changed something")
	}
	h.verifyAudit()
}

// TestAFlowOfAnotherOriginIsRefusedLikeAFailedProof (pages-3): a stored flow whose browser origin is not the relying party's origin
// refuses its completion exactly as a failed proof does (the same refusal, the flow ended as exhausted, no session), for a sign-in
// and for the enrollment, so a flow stored under another origin can never be completed.
func TestAFlowOfAnotherOriginIsRefusedLikeAFailedProof(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	ctx := context.Background()
	who := h.seedAccount(1)
	b := h.newBrowser()
	exhausted := func(h *harness, flowID string) bool {
		return h.count("SELECT count(*) FROM identity.auth_flow WHERE flow_id = $1 AND outcome = 2 AND consumed_at IS NOT NULL", idOf(t, flowID)) == 1
	}

	// The reference: a proof that fails (a signature over another challenge) ends the flow with the refusal every failed proof has.
	flow := b.beginSignIn()
	reference := b.postJSON("/session/v1/web/authentication/complete", map[string]any{"flowId": flow.FlowID,
		"proof": map[string]any{"passkey": assertionJSON(who.authenticator.Assert(who.key, []byte("not the challenge")))}})
	if reference.status != 403 || reference.refusal(t) != "authentication/unauthenticated" || !exhausted(h, flow.FlowID) {
		t.Fatalf("a failed proof: %d %s", reference.status, reference.text())
	}

	// A flow stored under another origin: the proof is a valid one, and it is refused as the failed proof was.
	flow = b.beginSignIn()
	if _, err := h.migration.Exec(ctx, "UPDATE identity.auth_flow SET origin = 'https://other.example.test' WHERE flow_id = $1", idOf(t, flow.FlowID)); err != nil {
		t.Fatal(err)
	}
	reply := b.completeSignIn(flow.FlowID, who, unb64(t, flow.Challenge))
	if reply.status != reference.status || reply.refusal(t) != "authentication/unauthenticated" || reply.cookie() != "" || !exhausted(h, flow.FlowID) {
		t.Fatalf("a flow of another origin: %d %s", reply.status, reply.text())
	}
	if again := b.completeSignIn(flow.FlowID, who, unb64(t, flow.Challenge)); again.status != 400 || again.refusal(t) != "state/expired" {
		t.Fatalf("the ended flow of another origin: %d %s", again.status, again.text())
	}
	if sessions := len(h.sessionRows(who.id)); sessions != 0 {
		t.Fatalf("%d sessions after the refused completions", sessions)
	}

	// The enrollment: the same origin check on the owner's first account.
	fresh := newHarness(t, settings{})
	visitor := fresh.newBrowser()
	visitor.bootstrapState()
	begun := visitor.postJSON("/session/v1/web/authentication/begin", map[string]any{"method": "passkey", "purpose": "enroll", "installation": visitor.claim()})
	if begun.status != 200 {
		t.Fatalf("the enrollment begin: %d %s", begun.status, begun.text())
	}
	var challenge challengeReply
	begun.json(t, &challenge)
	if _, err := fresh.migration.Exec(ctx, "UPDATE identity.auth_flow SET origin = 'https://other.example.test' WHERE flow_id = $1", idOf(t, challenge.FlowID)); err != nil {
		t.Fatal(err)
	}
	creation, _ := virtual.New(rpID, origin).Create(unb64(t, challenge.Challenge), unb64(t, challenge.Options.UserHandle))
	completed := visitor.postJSON("/session/v1/web/enrollment/complete", map[string]any{"flowId": challenge.FlowID, "proof": map[string]any{"localCode": fresh.bootstrap},
		"credential": map[string]any{"passkey": creationJSON(creation)}, "profile": map[string]any{"displayName": "Owner"}})
	if completed.status != 403 || completed.refusal(t) != "authentication/unauthenticated" || completed.cookie() != "" || fresh.count("SELECT count(*) FROM identity.user") != 0 ||
		fresh.count("SELECT count(*) FROM identity.bootstrap") != 0 || !exhausted(fresh, challenge.FlowID) {
		t.Fatalf("an enrollment flow of another origin: %d %s", completed.status, completed.text())
	}
}

// TestAFormKeepsTheCookieUnlessItEndedItsOwnSession (pages-4): the cookie is removed only by a route whose rule removes it and only
// when a second look positively finds the session no longer live. A look that fails, and a form whose rule keeps the cookie, land
// on the page the form came from with the cookie untouched, though the session's time ran out inside the handler.
func TestAFormKeepsTheCookieUnlessItEndedItsOwnSession(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	ctx := context.Background()
	who := h.seedAccount(1)
	a, other := h.newBrowser(), h.newBrowser()
	a.mustSignIn(who)
	other.mustSignIn(who)

	// A rule that keeps the cookie (rename of this browser's device) while the session's idle time runs out inside the handler:
	// the second look finds no live session, and the page it lands on sends the browser to the sign-in itself.
	deviceID := a.bootstrapState().Session.DeviceID
	h.clock.whenThen(func() bool {
		return h.count("SELECT count(*) FROM device.device WHERE device_id = $1 AND display_name = 'Renamed laptop'", idOf(t, deviceID)) == 1
	}, func() { h.clock.Advance(31 * time.Minute) })
	renamed := a.postForm("/account/devices/rename", url.Values{"command_id": {uuid(platform.NewID())}, "device_id": {deviceID}, "name": {"Renamed laptop"}})
	h.clock.disarm()
	if renamed.status != 303 || renamed.header.Get("Location") != basePath+"/account/devices" || len(renamed.header.Values("Set-Cookie")) != 0 {
		t.Fatalf("a rename when the session ran out inside the handler: %d %q %q", renamed.status, renamed.header.Get("Location"), renamed.header.Values("Set-Cookie"))
	}

	// A rule that removes the cookie (revocation of another session) when the second look fails: the session is not known to be
	// gone, so the cookie stays and the browser lands on the sessions page.
	a.mustSignIn(who)
	other.mustSignIn(who)
	otherID := idOf(t, other.bootstrapState().Session.SessionID)
	sessions := a.page("/account/sessions")
	var revoke formSpec
	for _, form := range formsTo(t, sessions, "/account/sessions/revoke") {
		if form.fields.Get("session_id") == uuid(otherID) {
			revoke = form
		}
	}
	if revoke.fields == nil {
		t.Fatalf("no revoke form of the second session:\n%s", sessions.text())
	}
	a.mustStepUp(who, identity.ClassRevokeSession, otherID)
	// The store fails right after the revocation commits: the center's role loses its read of the session table when the revocation
	// commits (a deferred trigger of the revoking update), so the form's second look fails and the first one, before it, did not.
	group := h.database + "_runtime"
	for _, statement := range []string{
		`CREATE FUNCTION public.break_the_session_reads() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN EXECUTE format('REVOKE SELECT ON identity.session FROM %I', '` + group + `'); RETURN NULL; END $$`,
		`CREATE CONSTRAINT TRIGGER break_the_session_reads AFTER UPDATE ON identity.session DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL) EXECUTE FUNCTION public.break_the_session_reads()`,
	} {
		if _, err := h.migration.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	ended := a.submit(revoke, nil)
	var readable bool
	if err := h.migration.QueryRow(ctx, `SELECT has_table_privilege($1, 'identity.session', 'SELECT')`, group).Scan(&readable); err != nil || readable {
		t.Fatalf("the store was never broken by the revocation (readable: %v, %v)", readable, err)
	}
	if _, err := h.migration.Exec(ctx, `GRANT SELECT ON identity.session TO "`+group+`"`); err != nil {
		t.Fatal(err)
	}
	if ended.status != 303 || ended.header.Get("Location") != basePath+"/account/sessions" || len(ended.header.Values("Set-Cookie")) != 0 || h.live(otherID) {
		t.Fatalf("a revocation when the second look failed: %d %q %q", ended.status, ended.header.Get("Location"), ended.header.Values("Set-Cookie"))
	}
	if !a.bootstrapState().Authenticated {
		t.Fatal("the browser's own session did not survive the revocation of another one")
	}
	h.verifyAudit()
}
