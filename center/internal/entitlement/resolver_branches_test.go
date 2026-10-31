// SPDX-License-Identifier: AGPL-3.0-only

package entitlement

import (
	"fmt"
	"strings"
	"testing"
)

// Direct tests of the Go resolver's validator and of the evaluation branches the parity corpus does not pin (fix round 1,
// resolver-1, -4 and -5; EVIDENCE: REAL logic, no database). The C# resolver is retired by AF-CTR-09, so these tests pin the Go
// port by itself instead of adding more recorded rows: one case for every refusal text Validate can produce, at its boundary, and one
// case for each evaluation branch a mutant survived.

func sp(value string) *string { return &value }

// baseDefinitions and baseRecords are a valid input that touches every record kind; each case below changes one thing.
func baseDefinitions() Definitions { return testDefinitions(false) }

func baseRecords() RecordSet {
	until := Micros(100)
	return RecordSet{AccountID: "acc",
		Grants: []Grant{{GrantID: "g1", AccountID: "acc", Kind: KindCapability, Subject: "cloud.sync", Value: CapabilityValue{}, Source: SourceSubscription, SourceRef: sp("s1"),
			EffectiveFrom: 0, EffectiveUntil: &until, IssuedByActor: "commerce", CreatedAt: 0}},
		Revocations:     []Revocation{{RevocationID: "r1", GrantID: "g1", ReasonCode: "refund", EffectiveFrom: 50, IssuedByActor: "operator", CreatedAt: 5}},
		Terms:           []ServiceTermFact{{TermID: "t1", Kind: TermSubscription, StartsAt: 0, EndsAt: 30, GraceEndsAt: microsPtr(35), AuthorizedAt: 0, CreatedAt: 3}},
		TermActions:     []TermActionFact{{TermID: "t1", Kind: ActionSupersede, EffectiveAt: 20, RecordedAt: 10}},
		StatusFacts:     []StatusFact{{RecordedAt: 1, Status: StatusNormal, AutoRenew: true}},
		FeatureReleases: []FeatureReleaseFact{{Feature: "feature.ai", ReleasedAt: 1}},
		Activations:     []DefinitionsActivation{{Version: "bundle-1", ActivatedAt: 0}}}
}

func TestEveryValidationRefusalIsReachedByItsOwnDefectAtItsBoundary(t *testing.T) {
	if err := Validate(baseRecords(), baseDefinitions()); err != nil {
		t.Fatalf("the base of the cases is refused: %v", err)
	}
	type change func(*RecordSet, *Definitions)
	refused := []struct {
		name string
		do   change
		want string
	}{
		{"a malformed definitions version", func(_ *RecordSet, d *Definitions) { d.Version = "bad version" }, "The definitions version is malformed."},
		{"a malformed capability key", func(_ *RecordSet, d *Definitions) { d.Capabilities[0].Key = "Bad" }, "A capability definition is malformed or repeated."},
		{"a repeated capability key", func(_ *RecordSet, d *Definitions) { d.Capabilities[1].Key = d.Capabilities[0].Key }, "A capability definition is malformed or repeated."},
		{"a malformed feature gate", func(_ *RecordSet, d *Definitions) { d.Capabilities[1].FeatureGate = sp("Bad Gate") }, "A capability feature gate is malformed."},
		{"a malformed quota key", func(_ *RecordSet, d *Definitions) { d.Quotas[0].Key = "Bad" }, "A quota definition is malformed or repeated."},
		{"an undefined quota combination", func(_ *RecordSet, d *Definitions) { d.Quotas[0].Combination = QuotaCombination(9) }, "A quota definition is malformed or repeated."},
		{"a repeated quota key", func(_ *RecordSet, d *Definitions) { d.Quotas[1].Key = d.Quotas[0].Key }, "A quota definition is malformed or repeated."},
		{"a malformed allowance key", func(_ *RecordSet, d *Definitions) { d.Allowances[0].Key = "Bad" }, "An allowance definition is malformed or repeated."},
		{"a repeated allowance key", func(_ *RecordSet, d *Definitions) { d.Allowances = append(d.Allowances, d.Allowances[0]) }, "An allowance definition is malformed or repeated."},
		{"a malformed account", func(r *RecordSet, _ *Definitions) { r.AccountID = "a b" }, "The workspace identifier is malformed."},
		{"an empty account", func(r *RecordSet, _ *Definitions) { r.AccountID = "" }, "The workspace identifier is malformed."},
		{"a history over the bound", func(r *RecordSet, _ *Definitions) { fill(r, MaxRecords+1) }, "The record history exceeds the replay bound."},
		{"a malformed grant ID", func(r *RecordSet, _ *Definitions) { r.Grants[0].GrantID = "bad id" }, "A grant identifier is malformed or repeated."},
		{"a repeated grant ID", func(r *RecordSet, _ *Definitions) { r.Grants = append(r.Grants, r.Grants[0]) }, "A grant identifier is malformed or repeated."},
		{"a grant of another account", func(r *RecordSet, _ *Definitions) { r.Grants[0].AccountID = "other" }, "A grant belongs to another workspace: g1"},
		{"an undefined grant kind", func(r *RecordSet, _ *Definitions) { r.Grants[0].Kind = GrantKind(9) }, "A grant has an unknown kind or source: g1"},
		{"an undefined grant source", func(r *RecordSet, _ *Definitions) { r.Grants[0].Source = GrantSource(9) }, "A grant has an unknown kind or source: g1"},
		{"a malformed subject", func(r *RecordSet, _ *Definitions) { r.Grants[0].Subject = "Bad" }, "A grant subject is malformed: g1"},
		{"a malformed source reference", func(r *RecordSet, _ *Definitions) { r.Grants[0].SourceRef = sp("a b") }, "A grant source reference is malformed: g1"},
		{"a grant without an actor", func(r *RecordSet, _ *Definitions) { r.Grants[0].IssuedByActor = "" }, "A grant has no issuing actor: g1"},
		{"a grant that ends where it starts", func(r *RecordSet, _ *Definitions) { r.Grants[0].EffectiveUntil = microsPtr(0) }, "A grant ends before it starts: g1"},
		{"a grant that ends before it starts", func(r *RecordSet, _ *Definitions) {
			r.Grants[0].EffectiveFrom, r.Grants[0].EffectiveUntil = 10, microsPtr(9)
		}, "A grant ends before it starts: g1"},
		{"a capability with a quota value", func(r *RecordSet, _ *Definitions) { r.Grants[0].Value = QuotaValue{} }, "A grant value does not match its kind: g1"},
		{"a quota with a negative limit", func(r *RecordSet, _ *Definitions) {
			r.Grants[0].Kind, r.Grants[0].Value = KindQuota, QuotaValue{Limit: -1}
		}, "A grant value does not match its kind: g1"},
		{"a quota over the limit bound", func(r *RecordSet, _ *Definitions) {
			r.Grants[0].Kind, r.Grants[0].Value = KindQuota, QuotaValue{Limit: MaxQuotaLimit + 1}
		}, "A grant value does not match its kind: g1"},
		{"a quota with a negative priority", func(r *RecordSet, _ *Definitions) {
			r.Grants[0].Kind, r.Grants[0].Value = KindQuota, QuotaValue{Priority: -1}
		}, "A grant value does not match its kind: g1"},
		{"an allowance with a malformed plan", func(r *RecordSet, _ *Definitions) {
			r.Grants[0].Kind, r.Grants[0].Value = KindAllowance, AllowanceValue{CapacityPlanRef: "a b"}
		}, "A grant value does not match its kind: g1"},
		{"an allowance with a negative priority", func(r *RecordSet, _ *Definitions) {
			r.Grants[0].Kind, r.Grants[0].Value = KindAllowance, AllowanceValue{CapacityPlanRef: "plan", Priority: -1}
		}, "A grant value does not match its kind: g1"},
		{"a malformed revocation ID", func(r *RecordSet, _ *Definitions) { r.Revocations[0].RevocationID = "bad id" }, "A revocation identifier is malformed or repeated."},
		{"a repeated revocation ID", func(r *RecordSet, _ *Definitions) { r.Revocations = append(r.Revocations, r.Revocations[0]) }, "A revocation identifier is malformed or repeated."},
		{"a revocation of no grant", func(r *RecordSet, _ *Definitions) { r.Revocations[0].GrantID = "nope" }, "A revocation names no known grant: r1"},
		{"a revocation without a reason code", func(r *RecordSet, _ *Definitions) { r.Revocations[0].ReasonCode = "Bad" }, "A revocation lacks a reason code or actor: r1"},
		{"a revocation without an actor", func(r *RecordSet, _ *Definitions) { r.Revocations[0].IssuedByActor = "" }, "A revocation lacks a reason code or actor: r1"},
		{"a revocation before its grant", func(r *RecordSet, _ *Definitions) { r.Grants[0].CreatedAt, r.Revocations[0].CreatedAt = 5, 4 }, "A revocation predates its grant: r1"},
		{"a malformed term ID", func(r *RecordSet, _ *Definitions) { r.Terms[0].TermID = "bad id" }, "A service term identifier is malformed or repeated."},
		{"a repeated term ID", func(r *RecordSet, _ *Definitions) { r.Terms = append(r.Terms, r.Terms[0]) }, "A service term identifier is malformed or repeated."},
		{"an undefined term kind", func(r *RecordSet, _ *Definitions) { r.Terms[0].Kind = ServiceTermKind(9) }, "A service term has an unknown kind: t1"},
		{"a term that ends where it starts", func(r *RecordSet, _ *Definitions) { r.Terms[0].EndsAt = r.Terms[0].StartsAt }, "A service term ends before it starts: t1"},
		{"a term whose grace ends before the term", func(r *RecordSet, _ *Definitions) { r.Terms[0].GraceEndsAt = microsPtr(29) }, "A service term grace ends before the term: t1"},
		{"an undefined term action kind", func(r *RecordSet, _ *Definitions) { r.TermActions[0].Kind = TermActionKind(9) }, "A term action has an unknown kind."},
		{"an action of no term", func(r *RecordSet, _ *Definitions) { r.TermActions[0].TermID = "nope" }, "A term action names no known term: nope"},
		{"an action before its term", func(r *RecordSet, _ *Definitions) { r.TermActions[0].RecordedAt = 2 }, "A term action predates its term: t1"},
		{"an undefined account status", func(r *RecordSet, _ *Definitions) { r.StatusFacts[0].Status = AccountStatus(9) }, "A workspace status fact has an unknown status."},
		{"a malformed feature release", func(r *RecordSet, _ *Definitions) { r.FeatureReleases[0].Feature = "Bad" }, "A feature release names a malformed feature."},
		{"a malformed activation version", func(r *RecordSet, _ *Definitions) { r.Activations[0].Version = "bad version" }, "A definitions activation is malformed or repeated."},
		{"a repeated activation", func(r *RecordSet, _ *Definitions) { r.Activations = append(r.Activations, r.Activations[0]) }, "A definitions activation is malformed or repeated."},
		{"definitions that were never activated last", func(r *RecordSet, d *Definitions) { d.Version = "bundle-2" }, "The definitions version being applied has no recorded activation."},
	}
	for _, item := range refused {
		t.Run(item.name, func(t *testing.T) {
			records, definitions := baseRecords(), baseDefinitions()
			item.do(&records, &definitions)
			err := Validate(records, definitions)
			var input *InputError
			if err == nil || !asInputError(err, &input) || !strings.HasPrefix(input.Message, item.want) {
				t.Fatalf("%v, want %q", err, item.want)
			}
		})
	}

	// The same rules from the admitted side: each boundary one step inside is valid.
	admitted := []struct {
		name string
		do   change
	}{
		{"a history exactly at the bound", func(r *RecordSet, _ *Definitions) { fill(r, MaxRecords) }},
		{"a grant that ends one microsecond after it starts", func(r *RecordSet, _ *Definitions) { r.Grants[0].EffectiveUntil = microsPtr(1) }},
		{"a revocation created with its grant", func(r *RecordSet, _ *Definitions) { r.Grants[0].CreatedAt, r.Revocations[0].CreatedAt = 5, 5 }},
		{"a term one microsecond long", func(r *RecordSet, _ *Definitions) {
			r.Terms[0].EndsAt = r.Terms[0].StartsAt + 1
			r.Terms[0].GraceEndsAt = nil
		}},
		{"a grace that ends with the term", func(r *RecordSet, _ *Definitions) { r.Terms[0].GraceEndsAt = microsPtr(r.Terms[0].EndsAt) }},
		{"an action recorded with its term", func(r *RecordSet, _ *Definitions) { r.TermActions[0].RecordedAt = r.Terms[0].CreatedAt }},
		{"a quota limit exactly at the bound", func(r *RecordSet, _ *Definitions) {
			r.Grants[0].Kind, r.Grants[0].Value = KindQuota, QuotaValue{Limit: MaxQuotaLimit}
		}},
		{"a zero quota", func(r *RecordSet, _ *Definitions) { r.Grants[0].Kind, r.Grants[0].Value = KindQuota, QuotaValue{} }},
		{"the same activation version at another instant", func(r *RecordSet, _ *Definitions) {
			r.Activations = append(r.Activations, DefinitionsActivation{Version: "bundle-1", ActivatedAt: 1})
		}},
		{"a capability and a quota under one key", func(_ *RecordSet, d *Definitions) { d.Quotas[0].Key = d.Capabilities[0].Key }},
	}
	for _, item := range admitted {
		t.Run("admitted: "+item.name, func(t *testing.T) {
			records, definitions := baseRecords(), baseDefinitions()
			item.do(&records, &definitions)
			if err := Validate(records, definitions); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// fill pads a record set with valid status facts up to the given number of records.
func fill(records *RecordSet, total int) {
	for index := 0; records.Count() < total; index++ {
		records.StatusFacts = append(records.StatusFacts, StatusFact{RecordedAt: Micros(10 + index), Status: StatusNormal, AutoRenew: true})
	}
}

// TestTheValidationRunsInTheOrderOfItsRefusals: when a set breaks two rules, the first rule of the order decides the refusal.
func TestTheValidationRunsInTheOrderOfItsRefusals(t *testing.T) {
	records, definitions := baseRecords(), baseDefinitions()
	definitions.Version, records.AccountID = "bad version", "a b"
	if err := Validate(records, definitions); err == nil || !strings.HasPrefix(err.Error(), "The definitions version is malformed.") {
		t.Fatalf("definitions come first: %v", err)
	}
	definitions = baseDefinitions()
	fill(&records, MaxRecords+1)
	if err := Validate(records, definitions); err == nil || !strings.HasPrefix(err.Error(), "The workspace identifier is malformed.") {
		t.Fatalf("the account comes before the bound: %v", err)
	}
	records.AccountID = "acc"
	records.Grants[0].Subject = "Bad"
	if err := Validate(records, definitions); err == nil || !strings.HasPrefix(err.Error(), "The record history exceeds the replay bound.") {
		t.Fatalf("the bound comes before the records: %v", err)
	}
	records, definitions = baseRecords(), baseDefinitions()
	records.Grants[0].Subject, records.Revocations[0].GrantID = "Bad", "nope"
	if err := Validate(records, definitions); err == nil || !strings.HasPrefix(err.Error(), "A grant subject is malformed: g1") {
		t.Fatalf("grants come before revocations: %v", err)
	}
	// Count includes every kind of record, the activations among them.
	records = baseRecords()
	before := records.Count()
	records.Activations = append(records.Activations, DefinitionsActivation{Version: "bundle-1", ActivatedAt: 7})
	if records.Count() != before+1 {
		t.Fatal("the activations are not counted")
	}
}

// ---- the evaluation branches ------------------------------------------------------------------------------------------------------

func quotaGrant(id, subject string, limit, priority int64, source GrantSource, from Micros, until *Micros) Grant {
	return Grant{GrantID: id, AccountID: "acc", Kind: KindQuota, Subject: subject, Value: QuotaValue{Limit: limit, Priority: priority}, Source: source, SourceRef: sp("ref-" + id),
		EffectiveFrom: from, EffectiveUntil: until, IssuedByActor: "commerce"}
}

func evaluate(t *testing.T, records RecordSet, at Micros) Content {
	t.Helper()
	records.AccountID = "acc"
	definitions := baseDefinitions()
	for index := range records.Grants {
		records.Grants[index].AccountID = "acc"
	}
	content, err := EvaluateAt(records, definitions, at)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func line(content Content, prefix string) string {
	for text := range strings.SplitSeq(content.Canonical(), "\n") {
		if strings.HasPrefix(text, prefix) {
			return text
		}
	}
	return ""
}

func TestAMaxQuotaTakesTheLargestGrantNotTheSum(t *testing.T) {
	content := evaluate(t, RecordSet{Grants: []Grant{quotaGrant("g1", "cloud.devices.max", 3, 0, SourceSubscription, 0, nil), quotaGrant("g2", "cloud.devices.max", 7, 0, SourceStorageAddOn, 0, nil)}}, 1)
	if got := line(content, "quota=cloud.devices.max|"); got != "quota=cloud.devices.max|7|Available|g1:Subscription:3,g2:StorageAddOn:7" {
		t.Fatalf("%q", got)
	}
}

func TestAPriorityReplaceQuotaTakesTheHighestPriorityAndTheEarlierGrantOnATie(t *testing.T) {
	content := evaluate(t, RecordSet{Grants: []Grant{quotaGrant("g1", "support.level", 1, 2, SourceSubscription, 0, nil), quotaGrant("g2", "support.level", 9, 2, SourceSubscription, 0, nil),
		quotaGrant("g3", "support.level", 5, 1, SourceSubscription, 0, nil)}}, 1)
	if got := line(content, "quota=support.level|"); !strings.HasPrefix(got, "quota=support.level|1|Available|") {
		t.Fatalf("a tie goes to the first grant by identifier: %q", got)
	}
}

func allowanceGrant(id string, priority int64) Grant {
	return Grant{GrantID: id, AccountID: "acc", Kind: KindAllowance, Subject: "ai.capacity", Value: AllowanceValue{CapacityPlanRef: "plan-" + id, Priority: priority}, Source: SourceSubscription,
		SourceRef: sp("ref-" + id), IssuedByActor: "commerce"}
}

func TestEqualPriorityAllowancesAreDecidedByTheGrantIdentifier(t *testing.T) {
	term := []ServiceTermFact{{TermID: "t1", Kind: TermSubscription, StartsAt: 0, EndsAt: 100}}
	tie := evaluate(t, RecordSet{Terms: term, Grants: []Grant{allowanceGrant("g2", 5), allowanceGrant("g1", 5)}}, 1)
	if got := line(tie, "allow=ai.capacity|"); got != "allow=ai.capacity|1|Available|plan-g1|g1|g2" {
		t.Fatalf("a tie: %q", got)
	}
	higher := evaluate(t, RecordSet{Terms: term, Grants: []Grant{allowanceGrant("g1", 5), allowanceGrant("g2", 6)}}, 1)
	if got := line(higher, "allow=ai.capacity|"); got != "allow=ai.capacity|1|Available|plan-g2|g2|g1" {
		t.Fatalf("a higher priority: %q", got)
	}
}

func TestAnAllowanceOfARestrictedAccountIsTemporarilyRestricted(t *testing.T) {
	records := RecordSet{Terms: []ServiceTermFact{{TermID: "t1", Kind: TermSubscription, StartsAt: 0, EndsAt: 100}}, Grants: []Grant{allowanceGrant("g1", 1)},
		StatusFacts: []StatusFact{{RecordedAt: 0, Status: StatusRestricted, AutoRenew: true}}}
	if got := line(evaluate(t, records, 1), "allow=ai.capacity|"); got != "allow=ai.capacity|0|TemporarilyRestricted|plan-g1|g1|" {
		t.Fatalf("%q", got)
	}
	records.StatusFacts = nil
	if got := line(evaluate(t, records, 1), "allow=ai.capacity|"); got != "allow=ai.capacity|1|Available|plan-g1|g1|" {
		t.Fatalf("%q", got)
	}
}

func TestAPendingPurchaseOrAFutureTermIsPending(t *testing.T) {
	pending := evaluate(t, RecordSet{StatusFacts: []StatusFact{{RecordedAt: 0, Status: StatusNormal, AutoRenew: true, PurchasePending: true}}}, 1)
	if got := line(pending, "service="); !strings.HasPrefix(got, "service=Pending|") {
		t.Fatalf("a pending purchase: %q", got)
	}
	future := evaluate(t, RecordSet{Terms: []ServiceTermFact{{TermID: "t1", Kind: TermSubscription, StartsAt: 50, EndsAt: 100}}}, 1)
	if got := line(future, "service="); !strings.HasPrefix(got, "service=Pending|") {
		t.Fatalf("a future term: %q", got)
	}
	none := evaluate(t, RecordSet{StatusFacts: []StatusFact{{RecordedAt: 0, Status: StatusNormal, AutoRenew: true}}}, 1)
	if got := line(none, "service="); !strings.HasPrefix(got, "service=None|") {
		t.Fatalf("nothing: %q", got)
	}
}

func TestALapsedQuotaGrantExplainsItselfByTheServiceState(t *testing.T) {
	until := Micros(10)
	grants := []Grant{quotaGrant("g1", "cloud.storage.bytes", 5, 0, SourceSubscription, 0, &until)}
	ended := RecordSet{Grants: grants, Terms: []ServiceTermFact{{TermID: "t1", Kind: TermSubscription, StartsAt: 0, EndsAt: 15}}}
	if got := line(evaluate(t, ended, 20), "quota=cloud.storage.bytes|"); got != "quota=cloud.storage.bytes|0|SubscriptionExpired|" {
		t.Fatalf("a lapsed quota after the term ended: %q", got)
	}
	grace := RecordSet{Grants: grants, Terms: []ServiceTermFact{{TermID: "t1", Kind: TermSubscription, StartsAt: 0, EndsAt: 15, GraceEndsAt: microsPtr(30)}}}
	if got := line(evaluate(t, grace, 20), "quota=cloud.storage.bytes|"); got != "quota=cloud.storage.bytes|0|PaymentGrace|" {
		t.Fatalf("a lapsed quota in grace: %q", got)
	}
	active := RecordSet{Grants: grants, Terms: []ServiceTermFact{{TermID: "t1", Kind: TermSubscription, StartsAt: 0, EndsAt: 100}}}
	if got := line(evaluate(t, active, 20), "quota=cloud.storage.bytes|"); got != "quota=cloud.storage.bytes|0|NoEntitlement|" {
		t.Fatalf("a lapsed quota under an active term: %q", got)
	}
	revoked := RecordSet{Grants: grants, Terms: ended.Terms, Revocations: []Revocation{{RevocationID: "r1", GrantID: "g1", ReasonCode: "x", EffectiveFrom: 5, IssuedByActor: "operator"}}}
	if got := line(evaluate(t, revoked, 20), "quota=cloud.storage.bytes|"); got != "quota=cloud.storage.bytes|0|NoEntitlement|" {
		t.Fatalf("a revoked quota is not a lapsed one: %q", got)
	}
	never := RecordSet{Terms: ended.Terms}
	if got := line(evaluate(t, never, 20), "quota=cloud.storage.bytes|"); got != "quota=cloud.storage.bytes|0|NoEntitlement|" {
		t.Fatalf("no grant: %q", got)
	}
}

// TestTheNextBoundaryIsLimitedToWhatIsKnownThen: a grant recorded after the instant, and a revocation recorded after it, set no
// boundary at that instant.
func TestTheNextBoundaryIsLimitedToWhatIsKnownThen(t *testing.T) {
	later := quotaGrant("g1", "cloud.devices.max", 3, 0, SourceSubscription, 200, nil)
	later.CreatedAt = 100
	if content := evaluate(t, RecordSet{Grants: []Grant{later}}, 50); content.ValidUntil != nil {
		t.Fatalf("a grant recorded later set the boundary %d", *content.ValidUntil)
	}
	if content := evaluate(t, RecordSet{Grants: []Grant{later}}, 150); content.ValidUntil == nil || *content.ValidUntil != 200 {
		t.Fatalf("a grant known then: %v", content.ValidUntil)
	}
	known := quotaGrant("g2", "cloud.devices.max", 3, 0, SourceSubscription, 0, nil)
	revoked := RecordSet{Grants: []Grant{known}, Revocations: []Revocation{{RevocationID: "r1", GrantID: "g2", ReasonCode: "x", EffectiveFrom: 300, IssuedByActor: "operator", CreatedAt: 100}}}
	if content := evaluate(t, revoked, 50); content.ValidUntil != nil {
		t.Fatalf("a revocation recorded later set the boundary %d", *content.ValidUntil)
	}
	if content := evaluate(t, revoked, 150); content.ValidUntil == nil || *content.ValidUntil != 300 {
		t.Fatalf("a revocation known then: %v", content.ValidUntil)
	}
}

// TestATermActionShortensOnlyItsOwnTerm: an action recorded for one term does not end another.
func TestATermActionShortensOnlyItsOwnTerm(t *testing.T) {
	records := RecordSet{Terms: []ServiceTermFact{{TermID: "t1", Kind: TermSubscription, StartsAt: 0, EndsAt: 100}, {TermID: "t2", Kind: TermPass, StartsAt: 200, EndsAt: 300}},
		TermActions: []TermActionFact{{TermID: "t2", Kind: ActionRevoke, EffectiveAt: 50, RecordedAt: 0}}}
	content := evaluate(t, records, 10)
	if got := line(content, "service="); got != "service=Active|100|-|1" {
		t.Fatalf("the action of t2 ended t1: %q", got)
	}
	own := RecordSet{Terms: records.Terms, TermActions: []TermActionFact{{TermID: "t1", Kind: ActionRevoke, EffectiveAt: 50, RecordedAt: 0}}}
	if got := line(evaluate(t, own, 10), "service="); got != "service=Active|50|-|1" {
		t.Fatalf("the action of t1: %q", got)
	}
}

func TestAGrantCountsOnlyUnderItsOwnKind(t *testing.T) {
	// A quota grant under the key of a capability grants nothing, and a capability grant under the key of a quota adds nothing.
	records := RecordSet{Terms: []ServiceTermFact{{TermID: "t1", Kind: TermSubscription, StartsAt: 0, EndsAt: 100}},
		Grants: []Grant{quotaGrant("g1", "cloud.sync", 5, 0, SourceSubscription, 0, nil),
			{GrantID: "g2", AccountID: "acc", Kind: KindCapability, Subject: "cloud.devices.max", Value: CapabilityValue{}, Source: SourceSubscription, SourceRef: sp("ref-g2"), IssuedByActor: "commerce"}}}
	content := evaluate(t, records, 1)
	if got := line(content, "cap=cloud.sync|"); got != "cap=cloud.sync|0|NoEntitlement|" {
		t.Fatalf("a quota under a capability key: %q", got)
	}
	if got := line(content, "quota=cloud.devices.max|"); got != "quota=cloud.devices.max|0|NoEntitlement|" {
		t.Fatalf("a capability under a quota key: %q", got)
	}
	if got := line(content, "unrecognized="); got != "unrecognized=g1,g2" {
		t.Fatalf("both are unrecognized: %q", got)
	}
}

func TestUnrecognizedGrantsAreListedInAscendingOrder(t *testing.T) {
	grants := []Grant{quotaGrant("g3", "other.one", 1, 0, SourceSubscription, 0, nil), quotaGrant("g1", "other.two", 1, 0, SourceSubscription, 0, nil), quotaGrant("g2", "other.three", 1, 0, SourceSubscription, 0, nil)}
	if got := line(evaluate(t, RecordSet{Grants: grants}, 1), "unrecognized="); got != "unrecognized=g1,g2,g3" {
		t.Fatalf("%q", got)
	}
}

// TestTheCanonicalNamesOfTheSourcesAndTheTermKindsAreTheCSharpEnumNames: the canonical text keeps them byte for byte, so the stored
// snapshot reads the same on both sides (DC-19).
func TestTheCanonicalNamesOfTheSourcesAndTheTermKindsAreTheCSharpEnumNames(t *testing.T) {
	sources := map[GrantSource]string{SourceSubscription: "Subscription", SourceCloudPass: "CloudPass", SourceStorageAddOn: "StorageAddOn", SourcePurchasedCredit: "PurchasedCredit",
		SourceAdminGrant: "AdminGrant", SourceMigration: "Migration", SourceCompensation: "Compensation"}
	for source, name := range sources {
		if source.String() != name {
			t.Errorf("source %d is %q, want %q", int(source), source.String(), name)
		}
		content := evaluate(t, RecordSet{Grants: []Grant{quotaGrant("g1", "cloud.storage.bytes", 5, 0, source, 0, nil)}}, 1)
		if want := fmt.Sprintf("quota=cloud.storage.bytes|5|Available|g1:%s:5", name); line(content, "quota=cloud.storage.bytes|") != want {
			t.Errorf("the canonical text of %s: %q", name, line(content, "quota=cloud.storage.bytes|"))
		}
	}
	for kind, name := range map[ServiceTermKind]string{TermSubscription: "Subscription", TermPass: "Pass", TermCompensation: "Compensation", TermSelfHostGrant: "SelfHostGrant"} {
		if kind.String() != name {
			t.Errorf("term kind %d is %q, want %q", int(kind), kind.String(), name)
		}
	}
	for kind, name := range map[GrantKind]string{KindCapability: "Capability", KindQuota: "Quota", KindAllowance: "Allowance"} {
		if kind.String() != name {
			t.Errorf("grant kind %d is %q, want %q", int(kind), kind.String(), name)
		}
	}
	if !SourceAdminGrant.Administrative() || !SourceMigration.Administrative() || !SourceCompensation.Administrative() || SourceSubscription.Administrative() || SourceCloudPass.Administrative() ||
		SourceStorageAddOn.Administrative() || SourcePurchasedCredit.Administrative() {
		t.Error("the administrative sources are AdminGrant, Migration and Compensation")
	}
}

// ---- equality ---------------------------------------------------------------------------------------------------------------------

func TestSnapshotEqualityIsFullForTheResolvedAndTheStoredForm(t *testing.T) {
	base := Snapshot{AccountID: "acc", Version: 3, ComputedAt: 10, Content: Content{DefinitionsVersion: "bundle-1", ValidUntil: microsPtr(20), Service: ServiceStateResult{State: StateActive}}}
	other := map[string]func(*Snapshot){
		"account":     func(s *Snapshot) { s.AccountID = "other" },
		"version":     func(s *Snapshot) { s.Version++ },
		"computed at": func(s *Snapshot) { s.ComputedAt++ },
		"valid until": func(s *Snapshot) { s.Content.ValidUntil = microsPtr(21) },
		"no validity": func(s *Snapshot) { s.Content.ValidUntil = nil },
		"content":     func(s *Snapshot) { s.Content.Service.State = StateEnded },
	}
	if !base.SameAs(base) || !base.Stored().SameAs(base.Stored()) {
		t.Fatal("a snapshot differs from itself")
	}
	for name, change := range other {
		changed := base
		change(&changed)
		if base.SameAs(changed) || changed.SameAs(base) {
			t.Errorf("a snapshot that differs in its %s is the same", name)
		}
		if base.Stored().SameAs(changed.Stored()) {
			t.Errorf("a stored snapshot that differs in its %s is the same", name)
		}
	}
	stored := base.Stored()
	for name, change := range map[string]func(*StoredSnapshot){
		"definitions version": func(s *StoredSnapshot) { s.DefinitionsVersion = "bundle-2" },
		"content text":        func(s *StoredSnapshot) { s.Content += "x" },
		"version":             func(s *StoredSnapshot) { s.Version++ },
		"computed at":         func(s *StoredSnapshot) { s.ComputedAt++ },
		"valid until":         func(s *StoredSnapshot) { s.ValidUntil = nil },
	} {
		changed := stored
		change(&changed)
		if stored.SameAs(changed) {
			t.Errorf("a stored snapshot that differs in its %s is the same", name)
		}
	}
}

// TestAReplayIsTheSameIssuanceOnlyWhenEveryComparedFieldIsTheSame (resolver-5): at its only call site the stored grant already matched
// on source and source reference, so each other field is varied alone.
func TestAReplayIsTheSameIssuanceOnlyWhenEveryComparedFieldIsTheSame(t *testing.T) {
	until := Micros(50)
	request := IssueGrantRequest{AccountID: "acc", Kind: KindQuota, Subject: "cloud.storage.bytes", Value: QuotaValue{Limit: 5, Priority: 1}, Source: SourceSubscription, SourceRef: sp("order-1"),
		EffectiveFrom: 10, EffectiveUntil: &until, IssuedByActor: "commerce"}
	existing := Grant{GrantID: "g1", AccountID: "acc", Kind: KindQuota, Subject: "cloud.storage.bytes", Value: QuotaValue{Limit: 5, Priority: 1}, Source: SourceSubscription, SourceRef: sp("order-1"),
		EffectiveFrom: 10, EffectiveUntil: &until, IssuedByActor: "commerce", CreatedAt: 99}
	if !IsSameIssuance(existing, request) {
		t.Fatal("the same request is not the same issuance")
	}
	different := map[string]func(*IssueGrantRequest){
		"account":        func(r *IssueGrantRequest) { r.AccountID = "other" },
		"kind and value": func(r *IssueGrantRequest) { r.Kind = KindCapability; r.Value = CapabilityValue{} },
		// The kind alone (an inadmissible request, which the comparison must still not call the same issuance).
		"kind":           func(r *IssueGrantRequest) { r.Kind = KindAllowance },
		"subject":        func(r *IssueGrantRequest) { r.Subject = "cloud.devices.max" },
		"limit":          func(r *IssueGrantRequest) { r.Value = QuotaValue{Limit: 6, Priority: 1} },
		"priority":       func(r *IssueGrantRequest) { r.Value = QuotaValue{Limit: 5, Priority: 2} },
		"source":         func(r *IssueGrantRequest) { r.Source = SourceCloudPass },
		"source ref":     func(r *IssueGrantRequest) { r.SourceRef = sp("order-2") },
		"no source ref":  func(r *IssueGrantRequest) { r.SourceRef = nil },
		"effective from": func(r *IssueGrantRequest) { r.EffectiveFrom = 11 },
		"effective until": func(r *IssueGrantRequest) {
			later := until + 1
			r.EffectiveUntil = &later
		},
		"no end":   func(r *IssueGrantRequest) { r.EffectiveUntil = nil },
		"an actor": func(r *IssueGrantRequest) { r.IssuedByActor = "operator" },
	}
	for name, change := range different {
		changed := request
		change(&changed)
		if IsSameIssuance(existing, changed) {
			t.Errorf("a request that differs in its %s is the same issuance", name)
		}
	}
}
