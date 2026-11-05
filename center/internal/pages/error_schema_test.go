// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/correlation"
)

// The rules of Contracts public/http/v1/web-browser-error.schema.json (cohort 1.0.0-ci.433.1, AF-CTR-05 C1; Plan Q14), restated here
// because the Go module carries no HTTP schema: WebBrowserErrorReply is {"error": WebBrowserArcError} and nothing else; the ArcError
// has exactly its members, each in its range; the details are one of state, limit or revision with their required members; and the
// rule webBrowserErrorAdvice ties messageKey, retryAt, reconciliationOperation and the effect together. (C1 review N-6: the center's
// error bodies rest on conventions of the arc constructors that errorOf alone does not enforce.)
var (
	errorCodePattern   = regexp.MustCompile(`^[a-z][a-z_]*$`)
	messageKeyPattern  = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)
	schemaUUIDPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	instantPattern     = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`)
	tokenPattern       = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)
	decimalPattern     = regexp.MustCompile(`^(0|-?[1-9][0-9]*|-?(0|[1-9][0-9]*)\.[0-9]{0,8}[1-9])$`)
	int64Pattern       = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	errorCategories    = []string{"validation", "authentication", "authorization", "entitlement", "conflict", "state", "resource", "execution", "internal"}
	errorRetryModes    = []string{"never", "afterTime", "sameCommand", "reconcile"}
	errorEffectChoices = []string{"didNotHappen", "happened", "unknown"}
)

// schemaViolations lists every rule of the schema a reply body breaks.
func schemaViolations(body []byte) []string {
	var problems []string
	fail := func(format string) { problems = append(problems, format) }
	var reply map[string]json.RawMessage
	if err := json.Unmarshal(body, &reply); err != nil {
		return []string{"not an object"}
	}
	if len(body) > 16384 {
		fail("over x-arcforges-max-bytes")
	}
	if len(reply) != 1 || reply["error"] == nil {
		return append(problems, "the reply is not exactly {error}")
	}
	var value map[string]json.RawMessage
	if json.Unmarshal(reply["error"], &value) != nil {
		return append(problems, "error is not an object")
	}
	allowed := map[string]bool{"category": true, "code": true, "messageKey": true, "retry": true, "effect": true, "correlationId": true, "details": true}
	for name := range value {
		if !allowed[name] {
			fail("an unknown member " + name)
		}
	}
	text := func(raw json.RawMessage) (string, bool) {
		var s string
		return s, raw != nil && json.Unmarshal(raw, &s) == nil
	}
	one := func(choices []string, value string) bool {
		for _, choice := range choices {
			if choice == value {
				return true
			}
		}
		return false
	}
	category, ok := text(value["category"])
	if !ok || !one(errorCategories, category) {
		fail("category")
	}
	code, ok := text(value["code"])
	if !ok || len(code) > 64 || !errorCodePattern.MatchString(code) {
		fail("code")
	}
	key, ok := text(value["messageKey"])
	if !ok || !messageKeyPattern.MatchString(key) || key != "error."+strings.ToLower(category)+"."+code {
		fail("messageKey (webBrowserErrorAdvice)")
	}
	effect, ok := text(value["effect"])
	if !ok || !one(errorEffectChoices, effect) {
		fail("effect")
	}
	if id, ok := text(value["correlationId"]); !ok || !schemaUUIDPattern.MatchString(id) || strings.Trim(id, "0-") == "" {
		fail("correlationId (required, a nonzero UUID)")
	}
	var retry map[string]json.RawMessage
	if json.Unmarshal(value["retry"], &retry) != nil {
		fail("retry")
	}
	for name := range retry {
		if name != "mode" && name != "retryAt" && name != "reconciliationOperation" {
			fail("an unknown retry member " + name)
		}
	}
	mode, ok := text(retry["mode"])
	if !ok || !one(errorRetryModes, mode) {
		fail("retry.mode")
	}
	at, hasAt := text(retry["retryAt"])
	if hasAt && (len(at) < 20 || len(at) > 30 || !instantPattern.MatchString(at)) {
		fail("retry.retryAt")
	}
	operation, hasOperation := text(retry["reconciliationOperation"])
	if hasOperation && !messageKeyPattern.MatchString(operation) {
		fail("retry.reconciliationOperation")
	}
	if hasAt != (mode == "afterTime") || hasOperation != (mode == "reconcile") {
		fail("the retry advice (webBrowserErrorAdvice)")
	}
	if effect == "unknown" && mode == "afterTime" {
		fail("unknown with afterTime (arcError)")
	}
	if raw := value["details"]; raw != nil {
		var details map[string]map[string]json.RawMessage
		if json.Unmarshal(raw, &details) != nil || len(details) != 1 {
			return append(problems, "details is not exactly one of state, limit, revision")
		}
		for kind, member := range details {
			switch kind {
			case "state":
				state, okState := text(member["state"])
				reason, okReason := text(member["reason"])
				if !okState || !tokenPattern.MatchString(state) || !okReason || reason == "" || len(reason) > 1024 {
					fail("details.state needs state and reason")
				}
				if resource := member["resource"]; resource != nil {
					var fields map[string]string
					if json.Unmarshal(resource, &fields) != nil || len(fields) != 2 || !tokenPattern.MatchString(fields["kind"]) || !schemaUUIDPattern.MatchString(fields["id"]) {
						fail("details.state.resource needs kind and id")
					}
				}
				for name := range member {
					if name != "state" && name != "reason" && name != "resource" {
						fail("an unknown state member " + name)
					}
				}
			case "limit":
				name, okName := text(member["limitName"])
				if !okName || !tokenPattern.MatchString(name) {
					fail("details.limit.limitName")
				}
				if maximum, has := text(member["maximum"]); has && !decimalPattern.MatchString(maximum) {
					fail("details.limit.maximum")
				}
				if recovery, has := text(member["recoveryAt"]); has && !instantPattern.MatchString(recovery) {
					fail("details.limit.recoveryAt")
				}
				for name := range member {
					if name != "limitName" && name != "maximum" && name != "recoveryAt" {
						fail("an unknown limit member " + name)
					}
				}
			case "revision":
				expected, okExpected := text(member["expected"])
				actual, okActual := text(member["actual"])
				if !okExpected || !int64Pattern.MatchString(expected) || !okActual || !int64Pattern.MatchString(actual) || len(member) != 2 {
					fail("details.revision needs expected and actual")
				}
			default:
				fail("an unknown detail " + kind)
			}
		}
	}
	return problems
}

// TestEveryRefusalsErrorBodyIsAWebBrowserErrorReply (C1 review N-6, routed to AF-CTR-05 E1): the JSON error body of every refusal a page
// or JSON route can answer, and of the node channel's refusals before the upgrade (the same body, hub.ServeHTTP), meets the schema.
func TestEveryRefusalsErrorBodyIsAWebBrowserErrorReply(t *testing.T) {
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	call := correlation.New()
	refusals := append(everyRefusal(at), arc.NotActivated("relay"), arc.FeatureNotEntitled("center.nodes"), arc.InvalidArgument("subprotocol", "not_admitted"),
		arc.RateLimited("channel_upgrades_per_node", 60, at.Add(time.Hour)))
	for _, refusal := range refusals {
		body, err := ErrorBody(refusal.Dated(at).ArcError(call))
		if err != nil {
			t.Fatal(err)
		}
		if problems := schemaViolations(body); len(problems) != 0 {
			t.Errorf("%s: %v (%s)", refusal.Key(), problems, body)
		}
	}
	// The checker refuses what the schema refuses (its own negative controls).
	for name, body := range map[string]string{
		"no correlation":            `{"error":{"category":"state","code":"expired","messageKey":"error.state.expired","retry":{"mode":"never"},"effect":"didNotHappen"}}`,
		"a state without reason":    `{"error":{"category":"state","code":"x","messageKey":"error.state.x","retry":{"mode":"never"},"effect":"didNotHappen","correlationId":"` + call.CorrelationID + `","details":{"state":{"state":"x"}}}}`,
		"afterTime without retryAt": `{"error":{"category":"resource","code":"overloaded","messageKey":"error.resource.overloaded","retry":{"mode":"afterTime"},"effect":"didNotHappen","correlationId":"` + call.CorrelationID + `"}}`,
		"an extra member":           `{"error":{"category":"state","code":"x","messageKey":"error.state.x","retry":{"mode":"never"},"effect":"didNotHappen","correlationId":"` + call.CorrelationID + `","message":"x"}}`,
	} {
		if len(schemaViolations([]byte(body))) == 0 {
			t.Errorf("the checker admitted %s", name)
		}
	}
}
