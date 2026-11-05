// SPDX-License-Identifier: AGPL-3.0-only

package mobiletest

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
)

// The scenarios of MobileProbe (H3): approve (token, then one refresh), deny (the callback says access_denied), reuse (token, then the
// same code again, and the delivered family is refused at refresh) and wrong-verifier (a token request with another verifier, then
// the right one: the flow was ended).
const (
	ScenarioApprove       = "approve"
	ScenarioDeny          = "deny"
	ScenarioReuse         = "reuse"
	ScenarioWrongVerifier = "wrong-verifier"
)

// Scenarios are the scenarios RunScenario knows.
var Scenarios = []string{ScenarioApprove, ScenarioDeny, ScenarioReuse, ScenarioWrongVerifier}

// The refusals the scenarios expect, in the one form every compare of the stand-in uses: "<category>/<code>" with the category in
// lower case, as the native JSON routes write it (Reply.Refusal). A gRPC ArcError (the RefreshSession reply) is brought to the same
// form by RefusalOf, so a JSON reply and a gRPC reply are never compared in two spellings.
const (
	RefusalCodeReused        = "conflict/code_reused"
	RefusalUnauthenticated   = "authentication/unauthenticated"
	RefusalCredentialRevoked = "authentication/credential_revoked"
)

// RefusalOf is a gRPC ArcError in the form of Reply.Refusal: the category's enum name without ERROR_CATEGORY_, in lower case, "/",
// the code.
func RefusalOf(failure *foundationv1.ArcError) string {
	return strings.ToLower(strings.TrimPrefix(failure.GetCategory().String(), "ERROR_CATEGORY_")) + "/" + failure.GetCode()
}

// Hooks are what a scenario needs besides the app's own requests.
type Hooks struct {
	// Link hands the begun attempt and the decision ("approve" or "deny") to the person, and returns the callback link of the done
	// page (MobileProbe: the handshake files with the browser flow; a test: the center's pages decided directly).
	Link func(ctx context.Context, attempt Attempt, decision string) (string, error)
	// Refresh calls IdentityService.RefreshSession with a delivered refresh token: "" for a rotation, else the refusal (RefusalOf).
	Refresh func(ctx context.Context, refreshToken string) (string, error)
	// Record receives each checked step, and returns ok.
	Record func(name string, ok bool, outcome string) bool
	// Requested is called before each request to the center (MobileProbe counts the requests of the edge minute); nil is none.
	Requested func()
}

// Decision is the decision a scenario asks of the person.
func Decision(scenario string) string {
	if scenario == ScenarioDeny {
		return "deny"
	}
	return "approve"
}

// deviceIDShape is a device ID as the token reply writes it: a canonical lower-case UUID.
var deviceIDShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// outcome is a reply as a step's outcome text.
func outcome(reply Reply) string {
	if refusal := reply.Refusal(); refusal != "" {
		return fmt.Sprintf("HTTP %d %s", reply.Status, refusal)
	}
	return fmt.Sprintf("HTTP %d", reply.Status)
}

// scenarioRun is one scenario's state.
type scenarioRun struct {
	app     *App
	hooks   Hooks
	devices []string
}

func (r *scenarioRun) requested() {
	if r.hooks.Requested != nil {
		r.hooks.Requested()
	}
}

// token redeems a code: with want "", a session reply of the contract's shape (scope account, purpose authenticate, a refresh token,
// an android device with a canonical device ID, which it keeps); otherwise exactly the refusal want. It returns the refresh token.
func (r *scenarioRun) token(ctx context.Context, name string, attempt Attempt, code, verifier, want string) (string, bool) {
	r.requested()
	reply, err := r.app.TokenWith(ctx, attempt, code, verifier)
	if err != nil {
		return "", r.hooks.Record(name, false, "transport: "+err.Error())
	}
	if want != "" {
		return "", r.hooks.Record(name, reply.Refusal() == want, outcome(reply))
	}
	scope, _ := reply.JSON["scope"].(string)
	purpose, _ := reply.JSON["purpose"].(string)
	refresh, _ := reply.JSON["refreshToken"].(string)
	device, _ := reply.JSON["device"].(map[string]any)
	platformName, _ := device["platform"].(string)
	deviceID, _ := device["deviceId"].(string)
	ok := reply.Status == http.StatusOK && scope == "account" && purpose == "authenticate" && refresh != "" && platformName == "android" &&
		deviceIDShape.MatchString(deviceID)
	if ok {
		r.devices = append(r.devices, deviceID)
	}
	return refresh, r.hooks.Record(name, ok, outcome(reply)+" scope "+scope+" purpose "+purpose+" device "+platformName)
}

// refresh refreshes a delivered session: want "" is a rotation, otherwise exactly the refusal want.
func (r *scenarioRun) refresh(ctx context.Context, name, token, want string) bool {
	r.requested()
	got, err := r.hooks.Refresh(ctx, token)
	switch {
	case err != nil:
		return r.hooks.Record(name, false, "transport: "+err.Error())
	case got == "":
		return r.hooks.Record(name, want == "", "refreshed")
	}
	return r.hooks.Record(name, got == want, got)
}

// RunScenario runs one scenario as the app does: it begins (the authorizeUrl required byte-equal to the derived one), hands the
// attempt to the person through hooks.Link, checks the callback's state and issuer against the attempt, and redeems the code as the
// scenario says, checking every reply against the contract. It returns whether every step passed and the device IDs of the
// delivered sessions (not secret: the browser flow's clean-up revokes exactly those).
func (a *App) RunScenario(ctx context.Context, scenario string, hooks Hooks) (bool, []string) {
	r := &scenarioRun{app: a, hooks: hooks}
	known := false
	for _, name := range Scenarios {
		known = known || name == scenario
	}
	if !known {
		return hooks.Record("scenario", false, "unknown scenario "+scenario), nil
	}
	r.requested()
	attempt, reply, err := a.Begin(ctx)
	if err != nil || reply.Status != http.StatusOK {
		text := outcome(reply)
		if err != nil {
			text = err.Error()
		}
		return hooks.Record("begin", false, text), nil
	}
	hooks.Record("begin", true, "the authorizeUrl is the derived one")
	link, err := hooks.Link(ctx, attempt, Decision(scenario))
	if err != nil {
		return hooks.Record("link", false, err.Error()), nil
	}
	callback, err := a.ParseCallback(link, attempt)
	if err != nil {
		return hooks.Record("callback", false, err.Error()), nil
	}
	if scenario == ScenarioDeny {
		return hooks.Record("callback", callback.Denied, "access_denied, state and iss checked"), nil
	}
	if !hooks.Record("callback", callback.Code != "", "a code, state and iss checked") {
		return false, nil
	}
	ok := false
	switch scenario {
	case ScenarioApprove:
		var token string
		token, ok = r.token(ctx, "token", attempt, callback.Code, attempt.Verifier, "")
		ok = ok && r.refresh(ctx, "refresh", token, "")
	case ScenarioReuse:
		var token string
		token, ok = r.token(ctx, "token", attempt, callback.Code, attempt.Verifier, "")
		if ok {
			_, ok = r.token(ctx, "token again", attempt, callback.Code, attempt.Verifier, RefusalCodeReused)
		}
		ok = ok && r.refresh(ctx, "refresh of the revoked family", token, RefusalCredentialRevoked)
	case ScenarioWrongVerifier:
		wrong, _ := NewVerifier()
		_, ok = r.token(ctx, "token with another verifier", attempt, callback.Code, wrong, RefusalUnauthenticated)
		if ok {
			_, ok = r.token(ctx, "token with the right verifier after", attempt, callback.Code, attempt.Verifier, RefusalCodeReused)
		}
	}
	return ok, r.devices
}
