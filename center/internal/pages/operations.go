// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/jackc/pgx/v5"
)

// The operations surface's page: the interim form of the operator grant (AF-CTR-03 B; AF-OPS-01's OperatorService replaces it). It
// decides nothing the entitlement package does not: the review calls Operator.Review (the same checks a grant makes, without any
// effect), and the confirmation calls Operator.Grant with the step-up evidence the script proved, consumed in the grant's own
// transaction. Only an operator reaches it (an account with a live operator row, or the owner who bootstrapped the center), and
// only on a center that has a plan catalogue.

// featureField is the name of the check box of a feature key.
func featureField(key string) string { return "feature-" + key }

// grantFields are the fields of the request form; the confirmation form repeats the review's normalized request in its own.
func grantFields() []string {
	fields := []string{"account", "expires_days", "reason", "source_ref", "self_approval", "all"}
	for _, key := range feature.Gated() {
		fields = append(fields, featureField(string(key)))
	}
	return fields
}

// keyChoice is one feature of the form.
type keyChoice struct {
	Key     string
	Field   string
	Checked bool
}

// operationsView is everything the operations templates read besides the page frame.
type operationsView struct {
	Keys      []keyChoice
	AllowWide bool
	MaxDays   int
	// The request as the form shows it, and as the review normalized it.
	Account, Reason, SourceRef, SelfApproval string
	ExpiresDays                              string
	All                                      bool
	Features                                 []string
	FeatureList                              string
	ExpiresAt                                string
	ExpiresText                              string
	Self                                     bool
	// Target is the step-up target the review names; Command the idempotency key of the confirmation.
	Target  string
	Command string
	// The result.
	TermID   string
	Replayed bool
	Version  int64
}

// operatorSession is the common start of the three routes: the cookie session of an operator. A request without a session goes to
// the sign-in page (a GET), a request of an account that is no operator is 403, and a center without the operator grant (no store
// for it) does not know the route.
func (e *exchange) operatorSession(post bool) (*session.BrowserSession, url.Values, bool) {
	if e.h.options.Operator == nil {
		e.notFound()
		return nil, nil, false
	}
	var resolved *session.BrowserSession
	var values url.Values
	var ok bool
	if post {
		fields := grantFields()
		if e.route.ID == "operations.confirm" {
			fields = []string{"command_id", "account", "features", "reason", "source_ref", "self_approval", "expires_at"}
		}
		if values, resolved, ok = e.formSession(fields...); !ok {
			return nil, nil, false
		}
	} else if resolved, ok = e.protected(); !ok {
		return nil, nil, false
	}
	operator, err := e.h.options.Operator.CanOperate(e.r.Context(), resolved.UserID)
	switch {
	case err != nil:
		e.fail(err)
		return nil, nil, false
	case !operator:
		e.refuse(refuse(arc.PermissionDenied(access.OperatorGrantClass), http.StatusForbidden))
		return nil, nil, false
	}
	return resolved, values, true
}

func (e *exchange) operatorCaller(resolved *session.BrowserSession) entitlement.OperatorCaller {
	return entitlement.OperatorCaller{UserID: resolved.UserID, Scope: resolved.Credential.Caller.Scope}
}

// policy is the operator grant policy now, or the refusal that says why there is none.
func (e *exchange) policy() (entitlement.OperatorPolicy, bool) {
	policy, err := e.h.options.Operator.Policy()
	switch {
	case errors.Is(err, entitlement.ErrGrantsSelfHosted):
		e.fail(arc.InvalidState("operator_grant", "self_hosted"))
	case err != nil:
		e.fail(arc.InvalidState("operator_grant", "no_catalogue"))
	default:
		return policy, true
	}
	return entitlement.OperatorPolicy{}, false
}

func choices(policy entitlement.OperatorPolicy, checked func(string) bool) []keyChoice {
	var result []keyChoice
	for _, key := range feature.Gated() {
		if slices.Contains(policy.Keys, string(key)) {
			result = append(result, keyChoice{Key: string(key), Field: featureField(string(key)), Checked: checked(string(key))})
		}
	}
	return result
}

// operationsGrantPage is GET /operations/grant: the request form.
func (e *exchange) operationsGrantPage() {
	resolved, _, ok := e.operatorSession(false)
	if !ok {
		return
	}
	policy, ok := e.policy()
	if !ok {
		return
	}
	days := int(policy.MaxExpiry / (24 * time.Hour))
	e.serve("operations-grant", pageData{Title: "Operator grant", Signed: true, CSRF: resolved.CSRF, Ops: operationsView{
		Keys: choices(policy, func(string) bool { return false }), AllowWide: policy.AllowCatalogueWide, MaxDays: days, ExpiresDays: "30"}})
}

// requestOf reads the request form: the account, the features its check boxes name (or the whole catalogue), the reason, the source
// reference, the self-approval and the number of days the grant lasts, which becomes an instant now. The review shows that instant
// and the confirmation repeats it, so the step-up target does not move between them.
func (e *exchange) requestOf(values url.Values) (entitlement.OperatorRequest, bool) {
	days, err := strconv.Atoi(values.Get("expires_days"))
	if err != nil || strconv.Itoa(days) != values.Get("expires_days") || days < 1 || days > 400 {
		e.fail(arc.InvalidArgument("expires_days", "pattern"))
		return entitlement.OperatorRequest{}, false
	}
	request := entitlement.OperatorRequest{Account: strings.TrimSpace(values.Get("account")), Reason: values.Get("reason"), SourceRef: values.Get("source_ref"),
		SelfApproval: values.Get("self_approval"), All: values.Get("all") == "on",
		ExpiresAt: entitlement.FromTime(e.h.options.Clock().Add(time.Duration(days) * 24 * time.Hour))}
	for _, key := range feature.Gated() {
		if values.Get(featureField(string(key))) == "on" {
			request.Features = append(request.Features, string(key))
		}
	}
	return request, true
}

// confirmedRequest reads the review's normalized request back from the confirmation form. Whether it is catalogue-wide is not sent:
// the grant derives it from the keys, as the review did.
func (e *exchange) confirmedRequest(values url.Values) (entitlement.OperatorRequest, bool) {
	expires, err := strconv.ParseInt(values.Get("expires_at"), 10, 64)
	if err != nil {
		e.fail(arc.InvalidArgument("expires_at", "pattern"))
		return entitlement.OperatorRequest{}, false
	}
	request := entitlement.OperatorRequest{Account: values.Get("account"), Reason: values.Get("reason"), SourceRef: values.Get("source_ref"),
		SelfApproval: values.Get("self_approval"), ExpiresAt: entitlement.Micros(expires)}
	if list := values.Get("features"); list != "" {
		request.Features = strings.Split(list, ",")
	}
	return request, true
}

// operationsReview is POST /operations/grant/review: the request, checked and normalized as a grant would, shown with the step-up
// target that the confirmation form proves before it is submitted. It changes nothing.
func (e *exchange) operationsReview() {
	resolved, values, ok := e.operatorSession(true)
	if !ok {
		return
	}
	request, ok := e.requestOf(values)
	if !ok {
		return
	}
	normalized, err := e.h.options.Operator.Review(e.r.Context(), e.operatorCaller(resolved), request)
	if err != nil {
		e.fail(err)
		return
	}
	expires := normalized.ExpiresAt.Time()
	e.serve("operations-review", pageData{Title: "Review the operator grant", Signed: true, CSRF: resolved.CSRF, Ops: operationsView{
		Account: normalized.Account, Reason: normalized.Reason, SourceRef: normalized.SourceRef, SelfApproval: normalized.SelfApproval, All: normalized.All,
		Features: normalized.Features, FeatureList: strings.Join(normalized.Features, ","), Self: normalized.SelfApproval != "",
		ExpiresAt: strconv.FormatInt(int64(normalized.ExpiresAt), 10), ExpiresText: timeText(expires),
		Target: normalized.TargetHashHex(resolved.UserID), Command: newCommand()}})
}

// operationsConfirm is POST /operations/grant/confirm: the grant. The step-up evidence the script proved for the review's target is
// consumed in the grant's transaction; a grant without it is AUTHENTICATION/step_up_required, and nothing is written.
func (e *exchange) operationsConfirm() {
	resolved, values, ok := e.operatorSession(true)
	if !ok {
		return
	}
	commandID, ok := e.formID(values, "command_id")
	if !ok {
		return
	}
	request, ok := e.confirmedRequest(values)
	if !ok {
		return
	}
	caller := identity.Caller{Request: e.request(), UserID: resolved.UserID, SessionID: resolved.SessionID, DeviceID: resolved.DeviceID,
		Scope: resolved.Credential.Caller.Scope, Browser: true, AuthEpoch: resolved.Credential.Caller.AuthEpoch, RecoveryGeneration: resolved.RecoveryGeneration}
	call := entitlement.GrantCall{Caller: e.operatorCaller(resolved), Request: request, CommandID: commandID, Correlation: caller.Request.CorrelationID,
		Consume: func(ctx context.Context, tx pgx.Tx, target [32]byte, now time.Time) error {
			return identity.ConsumeEvidenceFor(ctx, tx, caller, access.OperatorGrantClass, target[:], now)
		}}
	result, err := e.h.options.Operator.Grant(e.r.Context(), call)
	if err != nil {
		e.fail(err)
		return
	}
	e.serve("operations-done", pageData{Title: "Operator grant issued", Signed: true, CSRF: resolved.CSRF, Ops: operationsView{
		Account: request.Account, Features: result.Features, FeatureList: strings.Join(result.Features, ", "), TermID: result.TermID, Replayed: result.Replayed,
		Version: result.Version, ExpiresText: timeText(entitlement.Micros(result.ExpiresAt).Time())}})
}
