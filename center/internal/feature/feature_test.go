// SPDX-License-Identifier: AGPL-3.0-only

package feature

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
)

// fakeReader answers with a fixed snapshot text or a fixed error, and counts its calls (MOCKED: a stand-in for the entitlement
// service, to show what the gate asks it and what it does with the answer; the PostgreSQL tests use the real service).
type fakeReader struct {
	content string
	err     error
	calls   int
	account string
}

func (f *fakeReader) Read(_ context.Context, account string) (entitlement.StoredSnapshot, error) {
	f.calls++
	f.account = account
	return entitlement.StoredSnapshot{AccountID: account, Content: f.content}, f.err
}

func hosted(plan config.PlanConfiguration) Configuration {
	return Configure(Settings{Mode: config.OfficialHosted, Plan: plan})
}

func TestOfficialHostedEnablesNoGatedFeatureWithoutPlanConfiguration(t *testing.T) {
	reader := &fakeReader{content: "cap=remote.view|1|Available|\n"}
	gate := NewGate(hosted(config.PlanNone), reader)
	for _, key := range Gated() {
		// With an account that would be entitled if a catalogue existed: the missing catalogue decides, not the store.
		if decision := gate.Availability(WithAccount(t.Context(), "acc"), key); decision.Available || decision.Reason != ReasonPlanConfigurationMissing {
			t.Fatalf("%s: %+v", key, decision)
		}
	}
	if reader.calls != 0 {
		t.Fatal("a missing catalogue asked the store")
	}
}

func TestSelfHostedEnablesTheGatedFeaturesByDefaultExceptPushWithoutASender(t *testing.T) {
	gate := NewGate(Configure(Settings{Mode: config.SelfHosted}), nil)
	for _, key := range Gated() {
		want, reason := true, ReasonSelfHostedDefault
		if key == Push {
			want, reason = false, ReasonPushSenderNotConfigured
		}
		if decision := gate.Availability(t.Context(), key); decision.Available != want || decision.Reason != reason {
			t.Fatalf("%s: %+v", key, decision)
		}
	}
	withSender := NewGate(Configure(Settings{Mode: config.SelfHosted, PushSender: true}), nil)
	for _, key := range Gated() {
		if decision := withSender.Availability(t.Context(), key); !decision.Available || decision.Reason != ReasonSelfHostedDefault {
			t.Fatalf("%s with a push sender: %+v", key, decision)
		}
	}
}

func TestSelfHostedOperatorLimitsDisableTheNamedKeysOnly(t *testing.T) {
	gate := NewGate(Configure(Settings{Mode: config.SelfHosted, PushSender: true, Disabled: []Key{RemoteControl, Push}}), nil)
	for _, key := range Gated() {
		disabled := key == RemoteControl || key == Push
		decision := gate.Availability(t.Context(), key)
		if decision.Available == disabled || disabled && decision.Reason != ReasonOperatorLimit || !disabled && decision.Reason != ReasonSelfHostedDefault {
			t.Fatalf("%s: %+v", key, decision)
		}
	}
}

func TestUnknownKeysAndModesFailClosed(t *testing.T) {
	for _, mode := range []config.Mode{config.OfficialHosted, config.SelfHosted, "", "hosted"} {
		for _, key := range []Key{"", "center.Nodes", "hello", "remote", "center.nodes "} {
			if decision := NewGate(Configure(Settings{Mode: mode}), nil).Availability(t.Context(), key); decision.Available || decision.Reason != ReasonUnknownFeature {
				t.Fatalf("%s/%q: %+v", mode, key, decision)
			}
		}
	}
	for _, mode := range []config.Mode{"", "hosted", "Official-Hosted"} {
		if decision := NewGate(Configure(Settings{Mode: mode}), nil).Availability(t.Context(), CenterNodes); decision.Available || decision.Reason != ReasonModeInvalid {
			t.Fatalf("%q: %+v", mode, decision)
		}
	}
	if len(Gated()) != 6 {
		t.Fatal("the catalogue keys of AD-0021 section 13a")
	}
}

func TestTheKeysOfTheGateAreTheKeysOfTheConfiguration(t *testing.T) {
	var keys []string
	for _, key := range Gated() {
		keys = append(keys, string(key))
	}
	if !slices.Equal(keys, config.GatedFeatureKeys()) {
		t.Fatalf("package feature %v, package config %v", keys, config.GatedFeatureKeys())
	}
}

// TestOperationKeysAreTheRoutedTaskControlTable pins the routed task control table (plan section (g)): every gated key gates one
// group of routed operations, once.
func TestOperationKeysAreTheRoutedTaskControlTable(t *testing.T) {
	want := map[Key]string{
		RemoteControl: "control of existing tasks (cancel, retry, priority)",
		CenterExecute: "submission, and file and workspace operations",
		RemoteView:    "status and output",
		CenterNodes:   "node connection",
		CenterMCP:     "MCP",
		Push:          "push",
	}
	rows := OperationKeys()
	if len(rows) != len(want) {
		t.Fatalf("%d rows", len(rows))
	}
	for _, row := range rows {
		if want[row.Key] != row.Gates || !IsGated(row.Key) {
			t.Errorf("%s gates %q", row.Key, row.Gates)
		}
		delete(want, row.Key)
	}
	if len(want) != 0 {
		t.Errorf("rows missing: %v", want)
	}
}

// TestTheCenterDocumentPrintsTheRoutedTaskControlTable: docs/center.md carries the table of OperationKeys, row for row and in order.
func TestTheCenterDocumentPrintsTheRoutedTaskControlTable(t *testing.T) {
	document, err := os.ReadFile("../../../docs/center.md")
	if err != nil {
		t.Fatal(err)
	}
	_, after, found := strings.Cut(string(document), "### Routed task control\n")
	if !found {
		t.Fatal("docs/center.md has no routed task control table")
	}
	var printed [][2]string
	for _, line := range strings.Split(after, "\n") {
		if !strings.HasPrefix(line, "|") {
			if len(printed) > 0 {
				break
			}
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) != 2 {
			t.Fatalf("a row of the table: %q", line)
		}
		key, gates := strings.TrimSpace(cells[0]), strings.TrimSpace(cells[1])
		if key == "Key" || strings.HasPrefix(key, "-") {
			continue
		}
		printed = append(printed, [2]string{strings.Trim(key, "`"), gates})
	}
	var want [][2]string
	for _, row := range OperationKeys() {
		want = append(want, [2]string{string(row.Key), row.Gates})
	}
	if !slices.Equal(printed, want) {
		t.Fatalf("docs/center.md prints %v, the code has %v", printed, want)
	}
}

func TestTheDevelopmentFixturesAreTheIllustrativeEmbeddedCatalogue(t *testing.T) {
	catalogue, err := DevelopmentFixtures()
	if err != nil {
		t.Fatal(err)
	}
	if !catalogue.Fixture || !strings.HasPrefix(catalogue.Version, "dev-") || catalogue.Class != ClassDevelopment || !strings.Contains(catalogue.Notice, "not approved prices") {
		t.Fatalf("%+v", catalogue)
	}
	if !slices.Equal(catalogue.Capabilities, Gated()) {
		t.Fatalf("the capabilities %v", catalogue.Capabilities)
	}
	prices := map[string]int{}
	for _, plan := range catalogue.Plans {
		prices[plan.ID] = plan.IllustrativePriceUSD
		if !strings.HasPrefix(plan.Name, "Fixture ") || !strings.Contains(plan.Name, "illustrative") {
			t.Errorf("the plan %s is not labelled illustrative: %q", plan.ID, plan.Name)
		}
	}
	if len(prices) != 2 || prices["fixture-all"] != 15 || prices["fixture-view"] != 5 {
		t.Fatalf("plans %v", prices)
	}
	definitions := catalogue.Definitions(false)
	if definitions.Version != catalogue.Version || definitions.IsSelfHostRealm || len(definitions.Capabilities) != 6 || len(definitions.Quotas) != 0 || len(definitions.Allowances) != 0 {
		t.Fatalf("%+v", definitions)
	}
	for _, capability := range definitions.Capabilities {
		if !capability.RequiresPaidTerm || capability.FeatureGate != nil {
			t.Errorf("%+v", capability)
		}
	}
	if !catalogue.Definitions(true).IsSelfHostRealm {
		t.Fatal("IsSelfHostRealm follows the mode")
	}
}

// validProduction is a catalogue of the production classification: no fixture marker, no notice, no price (this code invents none).
const validProduction = `{"version":"2026-q4","fixture":false,"capabilities":["center.nodes","center.execute","remote.view","remote.control","center.mcp","push"],
"plans":[{"id":"plan-test","name":"Plan under test","features":["remote.view","push"]}]}`

func TestACatalogueOfTheProductionClassificationStatesNoFixtureNoNoticeAndNoPrice(t *testing.T) {
	catalogue, err := ParseCatalogue([]byte(validProduction), ClassProduction)
	if err != nil || catalogue.Fixture || !catalogue.Production() || len(catalogue.Plans) != 1 || catalogue.Plans[0].IllustrativePriceUSD != 0 {
		t.Fatalf("%+v %v", catalogue, err)
	}
	// A non-fixture catalogue is just as valid under the development classification.
	if _, err = ParseCatalogue([]byte(validProduction), ClassDevelopment); err != nil {
		t.Fatal(err)
	}
}

func TestEveryInvalidCatalogueIsRefusedWithoutEchoingItsValues(t *testing.T) {
	fixture, err := DevelopmentFixtures()
	if err != nil {
		t.Fatal(err)
	}
	_ = fixture
	replace := func(old, new string) string { return strings.Replace(validProduction, old, new, 1) }
	fixtureJSON := strings.Replace(strings.Replace(validProduction, `"fixture":false`, `"fixture":true,"notice":"Illustrative."`, 1), `"Plan under test"`, `"Fixture plan (illustrative)","illustrativePriceUsd":5`, 1)
	cases := map[string]struct {
		document string
		class    Classification
	}{
		"not JSON":                          {`catalogue`, ClassDevelopment},
		"an array":                          {`[]`, ClassDevelopment},
		"empty":                             {``, ClassDevelopment},
		"trailing data":                     {validProduction + `{}`, ClassDevelopment},
		"an unknown field":                  {replace(`"fixture":false`, `"fixture":false,"extra":1`), ClassDevelopment},
		"a repeated field":                  {replace(`"fixture":false`, `"fixture":false,"fixture":false`), ClassDevelopment},
		"a repeated plan field":             {replace(`"id":"plan-test"`, `"id":"plan-test","id":"x"`), ClassDevelopment},
		"an unknown classification":         {validProduction, Classification(9)},
		"a fixture under production":        {fixtureJSON, ClassProduction},
		"a fixture whose version lacks dev": {strings.Replace(fixtureJSON, `"2026-q4"`, `"2026-q5"`, 1), ClassDevelopment},
		"a dev version without the marker":  {replace(`"2026-q4"`, `"dev-2026"`), ClassDevelopment},
		"a notice without the marker":       {replace(`"fixture":false`, `"fixture":false,"notice":"x"`), ClassDevelopment},
		"a price without the marker":        {replace(`"Plan under test"`, `"Plan under test","illustrativePriceUsd":5`), ClassDevelopment},
		"a fixture price of seven":          {strings.Replace(fixtureJSON, `"illustrativePriceUsd":5`, `"illustrativePriceUsd":7`, 1), ClassDevelopment},
		"a fixture plan not named Fixture":  {strings.Replace(fixtureJSON, `Fixture plan`, `Plan`, 1), ClassDevelopment},
		"a missing capability":              {strings.Replace(replace(`,"push"],`, `],`), `"features":["remote.view","push"]`, `"features":["remote.view"]`, 1), ClassDevelopment},
		"an unknown capability":             {replace(`"push"],`, `"push.extra"],`), ClassDevelopment},
		"a repeated capability":             {replace(`"center.mcp","push"],`, `"center.mcp","center.mcp"],`), ClassDevelopment},
		"a plan feature outside":            {replace(`"remote.view","push"`, `"remote.view","unknown"`), ClassDevelopment},
		"a repeated plan feature":           {replace(`"remote.view","push"`, `"remote.view","remote.view"`), ClassDevelopment},
		"a plan without features":           {replace(`"features":["remote.view","push"]`, `"features":[]`), ClassDevelopment},
		"no plans":                          {replace(`"plans":[{"id":"plan-test","name":"Plan under test","features":["remote.view","push"]}]`, `"plans":[]`), ClassDevelopment},
		"a plan ID in capitals":             {replace(`"plan-test"`, `"Plan-Test"`), ClassDevelopment},
		"a blank plan name":                 {replace(`"Plan under test"`, `"  "`), ClassDevelopment},
		"a plan name with a control":        {replace(`"Plan under test"`, `"Plan\u0007"`), ClassDevelopment},
		"a malformed version":               {replace(`"2026-q4"`, `"2026 q4"`), ClassDevelopment},
		"more than the bound":               {validProduction + strings.Repeat(" ", MaxCatalogueBytes), ClassDevelopment},
	}
	for name, item := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseCatalogue([]byte(item.document), item.class)
			if !errors.Is(err, ErrInvalidCatalogue) {
				t.Fatalf("not refused: %v", err)
			}
			if strings.Contains(err.Error(), "plan-test") || strings.Contains(err.Error(), "2026-q4") {
				t.Fatalf("the error repeats the document: %v", err)
			}
		})
	}
}

func TestAnInvalidCatalogueDisablesEveryGatedKeyAndEnablesNothingByItself(t *testing.T) {
	reader := &fakeReader{content: "cap=remote.view|1|Available|\n"}
	for name, settings := range map[string]Settings{
		"a broken injected document":       {Mode: config.OfficialHosted, Injected: []byte(`{`), InjectedClass: ClassProduction},
		"a fixture injected as production": {Mode: config.OfficialHosted, Injected: developmentFixtures, InjectedClass: ClassProduction},
	} {
		configuration := Configure(settings)
		if configuration.State != StateInvalid || configuration.Problem == "" || configuration.Catalogue != nil {
			t.Fatalf("%s: %+v", name, configuration)
		}
		gate := NewGate(configuration, reader)
		for _, key := range Gated() {
			if decision := gate.Availability(WithAccount(t.Context(), "acc"), key); decision.Available || decision.Reason != ReasonPlanConfigurationInvalid {
				t.Fatalf("%s/%s: %+v", name, key, decision)
			}
		}
	}
	if reader.calls != 0 {
		t.Fatal("an invalid catalogue asked the store")
	}
}

func TestTheConfigurationStatesAndTheirOperatorGrantPolicy(t *testing.T) {
	production := Configure(Settings{Mode: config.OfficialHosted, Injected: []byte(validProduction), InjectedClass: ClassProduction})
	cases := []struct {
		name          string
		configuration Configuration
		state         State
		class         Classification
		refusal       error
		expiry        time.Duration
		wide          bool
	}{
		{"production configuration without a catalogue", Configure(Settings{Mode: config.OfficialHosted}), StateMissing, ClassProduction, entitlement.ErrGrantsNoCatalogue, 0, false},
		{"the development fixtures", hosted(config.PlanDevelopmentFixtures), StateValid, ClassDevelopment, nil, 400 * 24 * time.Hour, true},
		{"a production-classified test catalogue", production, StateValid, ClassProduction, nil, 90 * 24 * time.Hour, false},
		{"an invalid catalogue", Configure(Settings{Mode: config.OfficialHosted, Injected: []byte("{"), InjectedClass: ClassProduction}), StateInvalid, ClassProduction, entitlement.ErrGrantsNoCatalogue, 0, false},
		{"a self-hosted center", Configure(Settings{Mode: config.SelfHosted}), StateMissing, ClassProduction, entitlement.ErrGrantsSelfHosted, 0, false},
		{"a self-hosted center with an injected catalogue", Configure(Settings{Mode: config.SelfHosted, Injected: []byte(validProduction), InjectedClass: ClassProduction}), StateMissing, ClassProduction, entitlement.ErrGrantsSelfHosted, 0, false},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			if item.configuration.State != item.state || item.configuration.Class != item.class {
				t.Fatalf("state %d class %v", item.configuration.State, item.configuration.Class)
			}
			policy, err := item.configuration.OperatorGrants()
			if !errors.Is(err, item.refusal) || policy.MaxExpiry != item.expiry || policy.AllowCatalogueWide != item.wide {
				t.Fatalf("%+v %v", policy, err)
			}
		})
	}
}

func TestTheGateAsksForTheAccountOfTheContextAndMapsTheResolversReasons(t *testing.T) {
	reader := &fakeReader{}
	gate := NewGate(hosted(config.PlanDevelopmentFixtures), reader)
	if decision := gate.Availability(t.Context(), RemoteView); decision.Available || decision.Reason != ReasonNoAccount || reader.calls != 0 {
		t.Fatalf("a call without an account: %+v (%d reads)", decision, reader.calls)
	}
	ctx := WithAccount(t.Context(), "account-one")
	for line, want := range map[string]Reason{
		"cap=remote.view|1|Available|g1\n":                     ReasonEntitled,
		"cap=remote.view|0|NoEntitlement|\n":                   ReasonNoEntitlement,
		"cap=remote.view|0|SubscriptionExpired|\n":             ReasonSubscriptionExpired,
		"cap=remote.view|0|PaymentGrace|\n":                    ReasonPaymentGrace,
		"cap=remote.view|0|TemporarilyRestricted|\n":           ReasonTemporarilyRestricted,
		"cap=remote.view|0|WorkspaceSuspended|\n":              ReasonAccountSuspended,
		"cap=remote.view|0|FeatureUnavailable|\n":              ReasonFeatureUnavailable,
		"cap=remote.view|0|QuotaExceeded|\n":                   ReasonNoEntitlement,
		"cap=push|1|Available|\n":                              ReasonFeatureUnavailable, // no entry for the key asked
		"cap=remote.view|1|Available\n":                        ReasonFeatureUnavailable, // an entry that does not read back
		"cap=remote.view|2|Available|\n":                       ReasonFeatureUnavailable,
		"cap=remote.view|1|Sometimes|\n":                       ReasonFeatureUnavailable,
		"service=Active|-|-|1\ncap=remote.view|1|Available|\n": ReasonEntitled,
	} {
		reader.content = line
		decision := gate.Availability(ctx, RemoteView)
		if decision.Reason != want || decision.Available != (want == ReasonEntitled) || reader.account != "account-one" {
			t.Errorf("%q: %+v for %s", line, decision, reader.account)
		}
	}
	reader.err = errors.New("the store is down")
	if decision := gate.Availability(ctx, RemoteView); decision.Available || decision.Reason != ReasonEntitlementUnavailable || decision.Err == nil {
		t.Fatalf("a failing store: %+v", decision)
	}
}
