// SPDX-License-Identifier: AGPL-3.0-only

package pages_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey/virtual"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// beginSignIn begins a browser sign-in and returns its challenge.
func (b *browser) beginSignIn() challengeReply {
	b.h.t.Helper()
	b.bootstrapState()
	begun := b.postJSON("/session/v1/web/authentication/begin", map[string]any{"method": "passkey", "purpose": "authenticate", "installation": b.claim()})
	if begun.status != 200 {
		b.h.t.Fatalf("begin: %d %s", begun.status, begun.text())
	}
	var challenge challengeReply
	begun.json(b.h.t, &challenge)
	return challenge
}

func (b *browser) completeSignIn(flowID string, who account, challenge []byte) response {
	return b.postJSON("/session/v1/web/authentication/complete", map[string]any{"flowId": flowID,
		"proof": map[string]any{"passkey": assertionJSON(who.authenticator.Assert(who.key, challenge))}})
}

// TestTheFlowsOfTheBrowserHaveTheirOwnChannelAndLifetime (SEC-07, decision 4.3): a flow is bound by its channel, its kind, its
// purpose, its exact origin and its 122-bit identifier, with no flow cookie; it serves one completion; and it expires.
func TestTheFlowsOfTheBrowserHaveTheirOwnChannelAndLifetime(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1)
	b := h.newBrowser()

	// A browser flow expires after the policy's five minutes (STATE/expired), whoever completes it.
	challenge := b.beginSignIn()
	if expires, err := time.Parse(time.RFC3339Nano, challenge.ExpiresAt); err != nil || expires.Sub(h.clock.Now()) > 5*time.Minute || expires.Sub(h.clock.Now()) < 4*time.Minute {
		t.Fatalf("the flow's expiry %s", challenge.ExpiresAt)
	}
	h.clock.Advance(5*time.Minute + time.Second)
	late := b.completeSignIn(challenge.FlowID, who, unb64(t, challenge.Challenge))
	if late.status != 400 || late.refusal(t) != "state/expired" || late.cookie() != "" {
		t.Fatalf("a flow after its expiry: %d %s", late.status, late.text())
	}

	// A browser flow is no native flow, and a native flow is no browser flow (no flow cookie joins them): each is STATE/not_found on
	// the other channel's completion.
	native, refusal := h.apiBegin("")
	if refusal != "" {
		t.Fatal(refusal)
	}
	nativeFlow := uuid(platformIDOf(native.GetFlowId()))
	crossed := b.completeSignIn(nativeFlow, who, native.GetChallenge())
	if crossed.status != 404 || crossed.refusal(t) != "state/not_found" {
		t.Fatalf("a native flow completed as a browser's: %d %s", crossed.status, crossed.text())
	}
	web := b.beginSignIn()
	webID := idOf(t, web.FlowID)
	reply := h.api("/arcforges.publicapi.v1.IdentityService/CompleteAuthentication", &publicapiv1.IdentityServiceCompleteAuthenticationRequest{
		Meta: &foundationv1.RequestMeta{}, FlowId: &foundationv1.Id{Value: webID[:]}, Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_Passkey{Passkey: &publicapiv1.WebAuthnAssertion{
			CredentialId: who.key.ID, ClientDataJson: []byte("{}"), AuthenticatorData: []byte("x"), Signature: []byte("x"), UserHandle: who.handle}}}}, "")
	var nativeComplete publicapiv1.IdentityServiceCompleteAuthenticationResponse
	if reply.status != "0" || proto.Unmarshal(reply.body, &nativeComplete) != nil || nativeComplete.GetError().GetCode() != "not_found" {
		t.Fatalf("a browser flow completed as a native one: %q %v", reply.status, nativeComplete.GetError())
	}
	// The failed native attempt did not spend the browser flow: it still serves its one completion.
	if done := b.completeSignIn(web.FlowID, who, unb64(t, web.Challenge)); done.status != 200 {
		t.Fatalf("the browser flow after a native probe: %d %s", done.status, done.text())
	}

	// One completion each: the same flow again is expired (a flow whose attempt was used).
	again := b.completeSignIn(web.FlowID, who, unb64(t, web.Challenge))
	if again.status != 400 || again.refusal(t) != "conflict/code_reused" && again.refusal(t) != "state/expired" {
		t.Fatalf("a flow completed twice: %d %s", again.status, again.text())
	}

	// The kind and the purpose of a flow are fixed: an enrollment flow signs nobody in, a sign-in flow enrolls nobody.
	enroll := b.postJSON("/session/v1/web/authentication/begin", map[string]any{"method": "passkey", "purpose": "enroll", "installation": b.claim()})
	var creation challengeReply
	enroll.json(t, &creation)
	if creation.Options == nil || creation.Options.UserHandle == "" || creation.Purpose != "enroll" {
		t.Fatalf("the enrollment challenge: %+v", creation)
	}
	if wrong := b.completeSignIn(creation.FlowID, who, unb64(t, creation.Challenge)); wrong.status != 404 || wrong.refusal(t) != "state/not_found" {
		t.Fatalf("an enrollment flow used to sign in: %d %s", wrong.status, wrong.text())
	}
	// On a center with no account yet, the owner token and a creation do not turn a sign-in flow into an enrollment either.
	fresh := newHarness(t, settings{})
	visitor := fresh.newBrowser()
	sessionFlow := visitor.beginSignIn()
	authenticator := virtual.New(rpID, origin)
	made, _ := authenticator.Create(unb64(t, sessionFlow.Challenge), randomBytes(t, 32))
	hijack := visitor.postJSON("/session/v1/web/enrollment/complete", map[string]any{"flowId": sessionFlow.FlowID, "proof": map[string]any{"localCode": fresh.bootstrap},
		"credential": map[string]any{"passkey": creationJSON(made)}, "profile": map[string]any{"displayName": "Mallory"}})
	if hijack.status != 404 || hijack.refusal(t) != "state/not_found" || fresh.count("SELECT count(*) FROM identity.bootstrap") != 0 || fresh.count("SELECT count(*) FROM identity.user") != 0 {
		t.Fatalf("a sign-in flow used to enroll: %d %s", hijack.status, hijack.text())
	}
	h.verifyAudit()
}

// TestALostRaceForANewBrowserInstallationGivesTheAttemptBack (pages-1, as D4 for a native installation): two first sign-ins of one
// new browser installation with two passkeys of one account race; the loser meets the winner's installation on the unique index of
// the live web claim, which is a store contention (RESOURCE/overloaded, did not happen), not an internal failure: nothing is logged
// as a failed call, and the identical retry signs in on the winner's installation. The audit chain's head is held until both
// completions wait (one on it, one on the other's installation), so the race is deterministic.
func TestALostRaceForANewBrowserInstallationGivesTheAttemptBack(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	ctx := context.Background()
	first := h.seedAccount(1)
	accounts := [2]account{first, h.addPasskey(first)}
	installation := uuid(platform.NewID())
	browsers := [2]*browser{h.newBrowser(), h.newBrowser()}
	var bodies [2]map[string]any
	for i, b := range browsers {
		b.installation = installation
		challenge := b.beginSignIn()
		bodies[i] = map[string]any{"flowId": challenge.FlowID,
			"proof": map[string]any{"passkey": assertionJSON(accounts[i].authenticator.Assert(accounts[i].key, unb64(t, challenge.Challenge)))}}
	}
	tx, err := h.migration.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, "SELECT 1 FROM audit.chain_head WHERE singleton FOR UPDATE"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var replies [2]response
	for i := range browsers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			replies[i] = browsers[i].postJSON("/session/v1/web/authentication/complete", bodies[i])
		}()
	}
	waiting := 0
	for deadline := time.Now().Add(10 * time.Second); waiting < 2 && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if err = tx.QueryRow(ctx, `WITH RECURSIVE blocked(pid) AS (
    SELECT l.pid FROM pg_locks l WHERE NOT l.granted AND pg_backend_pid() = ANY(pg_blocking_pids(l.pid))
    UNION SELECT l.pid FROM pg_locks l JOIN blocked b ON b.pid = ANY(pg_blocking_pids(l.pid)) WHERE NOT l.granted)
SELECT count(DISTINCT pid) FROM blocked`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if waiting < 2 {
		t.Fatalf("the sign-ins never both waited (%d)", waiting)
	}
	loser, won := -1, 0
	for i, reply := range replies {
		if reply.status == 200 {
			won++
			continue
		}
		if reply.status != 503 || reply.refusal(t) != "resource/overloaded" || loser != -1 {
			t.Fatalf("completion %d: %d %s", i, reply.status, reply.text())
		}
		loser = i
	}
	if won != 1 || loser == -1 {
		t.Fatalf("%d of the first sign-ins of one installation succeeded, the other one was refused with %d", won, loser)
	}
	if text := replies[loser].text(); !strings.Contains(text, `"effect":"didNotHappen"`) || !strings.Contains(text, `"mode":"afterTime"`) {
		t.Fatalf("the loser's refusal does not give the attempt back: %s", replies[loser].text())
	}
	if lines := strings.Count(h.logs.String(), "identity call failed"); lines != 0 {
		t.Fatalf("the lost race was logged as %d failed identity calls", lines)
	}
	if retried := browsers[loser].postJSON("/session/v1/web/authentication/complete", bodies[loser]); retried.status != 200 {
		t.Fatalf("the identical retry of the loser: %d %s", retried.status, retried.text())
	}
	if rows := h.count("SELECT count(*) FROM device.installation WHERE client_installation_id = $1", installation); rows != 1 {
		t.Fatalf("%d installations for one claim", rows)
	}
	h.verifyAudit()
}

func platformIDOf(value *foundationv1.Id) platform.ID {
	var id platform.ID
	copy(id[:], value.GetValue())
	return id
}

// TestTheBootstrapTokenIsCheckedFirstAndRefusesAlike (SEC-09, A2 part): a wrong token, a malformed one, an expired bootstrap and a
// center without one all refuse like the API (AUTHENTICATION/unauthenticated, the reason only in the audit), before the passkey is
// looked at; a mismatch counts only in its client prefix's bucket, so the owner is never locked out by anyone else.
func TestTheBootstrapTokenIsCheckedFirstAndRefusesAlike(t *testing.T) {
	h := newHarness(t, settings{policy: `{"bootstrapPerPrefixLimit": 3, "signInPerPrefixLimit": 1000}`})
	outsider := h.newBrowser()
	outsider.ip = "198.51.100.20"
	refuse := func(b *browser, token string) response {
		t.Helper()
		reply, _, _ := b.enrollOwner(token, "Owner")
		return reply
	}
	secret := session.NewSecret()
	for name, token := range map[string]string{"another token": secret.Token(session.BootstrapPrefix), "no prefix": secret.Text(), "a wrong prefix": "afa1." + secret.Text(),
		"an empty token": "x", "a long token": strings.Repeat("a", 129)} {
		if token == "x" || len(token) > 128 {
			// Shape errors of the member are validation errors (the document's bounds), decided before anything else.
			continue
		}
		reply := refuse(outsider, token)
		if reply.status != 403 || reply.refusal(t) != "authentication/unauthenticated" {
			t.Errorf("%s: %d %s", name, reply.status, reply.text())
		}
	}
	// The outsider's prefix is now over its limit; the owner on another network is not affected, and the right token works.
	if limited := refuse(outsider, secret.Token(session.BootstrapPrefix)); limited.status != 429 || limited.refusal(t) != "resource/rate_limited" {
		t.Fatalf("the outsider's fourth mismatch: %d %s", limited.status, limited.text())
	}
	owner := h.newBrowser()
	owner.ip = "192.0.2.77"
	if done := refuse(owner, h.bootstrap); done.status != 200 {
		t.Fatalf("the owner after an outsider's mismatches: %d %s", done.status, done.text())
	}
	if h.audits("identity.bootstrap.refused") == 0 || h.audits("identity.bootstrap.completed") != 1 {
		t.Fatal("the bootstrap audit")
	}
	// Past its expiry the bootstrap is refused alike (nothing else says why), and an account that exists refuses it too.
	h.clock.Advance(49 * time.Hour)
	late := h.newBrowser()
	late.ip = "192.0.2.78"
	if reply := refuse(late, h.bootstrap); reply.status != 403 || reply.refusal(t) != "authentication/unauthenticated" {
		t.Fatalf("an expired or used bootstrap: %d %s", reply.status, reply.text())
	}
	// A center that has no bootstrap answers the same.
	none := newHarness(t, settings{noBootstrap: true})
	nobody := none.newBrowser()
	if reply, _, _ := nobody.enrollOwner("afb1."+session.NewSecret().Text(), "Owner"); reply.status != 403 || reply.refusal(t) != "authentication/unauthenticated" ||
		none.count("SELECT count(*) FROM identity.user") != 0 {
		t.Fatalf("a center without a bootstrap: %d %s", reply.status, reply.text())
	}
	h.verifyAudit()
}

// TestTheJSONRoutesRefuseWhatTheDocumentDoesNotAdmit: the strict reading of the request bodies (the schema's closed objects, its
// patterns and bounds, repeated and unknown members) is VALIDATION/invalid_argument naming the member by its JSON path.
func TestTheJSONRoutesRefuseWhatTheDocumentDoesNotAdmit(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)
	post := func(path, body string) response {
		t.Helper()
		return h.do(request{method: http.MethodPost, path: path, contentType: "application/json", body: []byte(body), cookie: b.cookie, csrf: b.csrf})
	}
	claim := `{"installationId":"` + b.installation + `","product":"arcforges-web","platform":"web","appVersion":"1"}`
	for name, body := range map[string]string{
		"not an object":             `[]`,
		"not JSON":                  `{`,
		"trailing data":             `{"method":"passkey","purpose":"authenticate","installation":` + claim + `} {}`,
		"an unknown member":         `{"method":"passkey","purpose":"authenticate","installation":` + claim + `,"extra":1}`,
		"a repeated member":         `{"method":"passkey","method":"passkey","purpose":"authenticate","installation":` + claim + `}`,
		"a repeated nested member":  `{"method":"passkey","purpose":"authenticate","installation":{"installationId":"` + b.installation + `","installationId":"` + b.installation + `","product":"arcforges-web","platform":"web","appVersion":"1"}}`,
		"a missing method":          `{"purpose":"authenticate","installation":` + claim + `}`,
		"a method of another type":  `{"method":1,"purpose":"authenticate","installation":` + claim + `}`,
		"an unknown method":         `{"method":"sms","purpose":"authenticate","installation":` + claim + `}`,
		"a missing installation":    `{"method":"passkey","purpose":"authenticate"}`,
		"an installation of a type": `{"method":"passkey","purpose":"authenticate","installation":"x"}`,
		"the nil installation":      `{"method":"passkey","purpose":"authenticate","installation":{"installationId":"00000000-0000-0000-0000-000000000000","product":"arcforges-web","platform":"web","appVersion":"1"}}`,
		"an upper-case id":          `{"method":"passkey","purpose":"authenticate","installation":{"installationId":"` + strings.ToUpper(b.installation) + `","product":"arcforges-web","platform":"web","appVersion":"1"}}`,
		"a platform with a space":   `{"method":"passkey","purpose":"authenticate","installation":{"installationId":"` + b.installation + `","product":"arcforges-web","platform":"a b","appVersion":"1"}}`,
		"a login hint of no shape":  `{"method":"passkey","purpose":"authenticate","installation":` + claim + `,"loginHint":"nobody"}`,
		"a deep nesting":            `{"a":` + strings.Repeat(`[`, 20) + strings.Repeat(`]`, 20) + `}`,
	} {
		reply := post("/session/v1/web/authentication/begin", body)
		if reply.status != 400 || !strings.HasPrefix(reply.refusal(t), "validation/invalid_argument") {
			t.Errorf("%s: %d %.160s", name, reply.status, reply.text())
		}
	}
	// A path in the refusal names the member by its JSON name.
	reply := post("/session/v1/web/authentication/begin", `{"method":"passkey","purpose":"authenticate","installation":{"installationId":"`+b.installation+`","product":"arcforges-web","platform":"a b","appVersion":"1"}}`)
	if !strings.Contains(reply.text(), "installation.platform: pattern") {
		t.Fatalf("the refusal's reason: %s", reply.text())
	}
	// The same bounds hold for the other routes.
	for _, probe := range []struct{ path, body string }{
		{"/session/v1/web/authentication/complete", `{"flowId":"x","proof":{"passkey":{}}}`},
		{"/session/v1/web/authentication/complete", `{"flowId":"` + b.installation + `","proof":{"passkey":{"credentialId":"@@","clientDataJson":"AA","authenticatorData":"AA","signature":"AA","userHandle":"AA"}}}`},
		{"/session/v1/web/authentication/complete", `{"flowId":"` + b.installation + `","proof":{"passkey":{"credentialId":"AA","clientDataJson":"AA","authenticatorData":"AA","signature":"AA"}}}`},
		{"/session/v1/web/enrollment/complete", `{"flowId":"` + b.installation + `","proof":{"localCode":"x"},"credential":{"password":"x"},"profile":{"displayName":"x"}}`},
		{"/session/v1/web/enrollment/complete", `{"flowId":"` + b.installation + `","proof":{"emailCode":"x"},"credential":{"passkey":{"credentialId":"AA","clientDataJson":"AA","attestationObject":"AA"}},"profile":{"displayName":"x"}}`},
		{"/session/v1/web/enrollment/complete", `{"flowId":"` + b.installation + `","proof":{"localCode":"x"},"credential":{"passkey":{"credentialId":"AA","clientDataJson":"AA","attestationObject":"AA"}},"profile":{"clearAvatar":true}}`},
		{"/session/v1/web/step-up/begin", `{"operationClass":"x","method":"email"}`},
		{"/session/v1/web/step-up/begin", `{"operationClass":"x y","method":"passkey"}`},
		{"/session/v1/web/step-up/begin", `{"operationClass":"identity.revokeAllSessions","method":"passkey","targetHash":"` + strings.Repeat("A", 64) + `"}`},
		{"/session/v1/web/step-up/begin", `{"operationClass":"identity.revokeAllSessions","method":"passkey","targetHash":"` + strings.Repeat("a", 63) + `"}`},
		{"/session/v1/web/step-up/complete", `{"flowId":"` + b.installation + `","proof":{"emailCode":"x"}}`},
		{"/session/v1/web/step-up/complete", `{"flowId":"` + b.installation + `","proof":{}}`},
	} {
		if reply := post(probe.path, probe.body); reply.status != 400 {
			t.Errorf("%s %s: %d %.160s", probe.path, probe.body, reply.status, reply.text())
		}
	}
	// The error body names what the document leaves to the center: category, code, message key, retry and effect, the correlation id.
	var body struct {
		Error struct {
			Category, Code, MessageKey, Effect, CorrelationID string
			Retry                                             struct{ Mode string }
		}
	}
	reply = post("/session/v1/web/authentication/begin", `{}`)
	reply.json(t, &body)
	if body.Error.Category != "validation" || body.Error.Code != "invalid_argument" || body.Error.MessageKey != "error.validation.invalid_argument" ||
		body.Error.Effect != "didNotHappen" || body.Error.Retry.Mode != "never" || len(body.Error.CorrelationID) != 36 {
		t.Fatalf("the error body: %+v", body)
	}
	var _ = identity.ClassBeginRegistration
	var _ = config.SurfacePages
}
