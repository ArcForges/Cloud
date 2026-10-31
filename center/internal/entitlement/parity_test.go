// SPDX-License-Identifier: AGPL-3.0-only

package entitlement

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// The parity corpus: every resolver input and output, and every grant admission, the C# suites of the Entitlement module reach,
// recorded by tests/ArcForges.Cloud.Tests/Entitlement/ResolverVectorsTests.cs (EVIDENCE: REAL logic, recorded data).
const corpusPath = "testdata/csharp-resolver-vectors.json"

// The vectors of the committed corpus, as docs/entitlement-resolver.md states them: a truncated or a padded file is a change of the
// corpus, made on purpose with these two numbers.
const (
	corpusResolverVectors  = 284
	corpusAdmissionVectors = 61
)

type enumValue int

// UnmarshalJSON reads a C# enum as its name, or as its number when the value was undefined.
func (e *enumValue) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err == nil {
		value, ok := enumNumbers[name]
		if !ok {
			return fmt.Errorf("unknown enum name %q", name)
		}
		*e = enumValue(value)
		return nil
	}
	var number int
	if err := json.Unmarshal(data, &number); err != nil {
		return err
	}
	*e = enumValue(number)
	return nil
}

// enumNumbers maps the enum names of the corpus to their numbers. The service term kinds share two names with the grant sources
// (Subscription is 0 in both, Compensation is 6 and 2), so they read through termKinds below.
var enumNumbers = map[string]int{
	"Capability": 0, "Quota": 1, "Allowance": 2,
	"Subscription": 0, "CloudPass": 1, "StorageAddOn": 2, "PurchasedCredit": 3, "AdminGrant": 4, "Migration": 5, "Compensation": 6,
	"Supersede": 0, "Revoke": 1,
	"Normal": 0, "Restricted": 1, "Suspended": 2,
	"Sum": 0, "Max": 1, "PriorityReplace": 2,
}

type kindEnum = enumValue

// termKinds are the service term kinds by name.
var termKinds = map[string]int{"Subscription": 0, "Pass": 1, "Compensation": 2, "SelfHostGrant": 3}

type termKindEnum int

func (e *termKindEnum) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err == nil {
		value, ok := termKinds[name]
		if !ok {
			return fmt.Errorf("unknown term kind %q", name)
		}
		*e = termKindEnum(value)
		return nil
	}
	var number int
	if err := json.Unmarshal(data, &number); err != nil {
		return err
	}
	*e = termKindEnum(number)
	return nil
}

type valueJSON struct {
	Type            string `json:"type"`
	Limit           int64  `json:"limit"`
	Priority        int64  `json:"priority"`
	CapacityPlanRef string `json:"capacityPlanRef"`
}

func (v *valueJSON) value() (GrantValue, error) {
	if v == nil {
		return nil, nil
	}
	switch v.Type {
	case "Capability":
		return CapabilityValue{}, nil
	case "Quota":
		return QuotaValue{Limit: v.Limit, Priority: v.Priority}, nil
	case "Allowance":
		return AllowanceValue{CapacityPlanRef: v.CapacityPlanRef, Priority: v.Priority}, nil
	}
	return nil, fmt.Errorf("unknown grant value type %q", v.Type)
}

type grantJSON struct {
	GrantID        string     `json:"grantId"`
	WorkspaceID    string     `json:"workspaceId"`
	Kind           kindEnum   `json:"kind"`
	Subject        string     `json:"subject"`
	Value          *valueJSON `json:"value"`
	Source         enumValue  `json:"source"`
	SourceRef      *string    `json:"sourceRef"`
	EffectiveFrom  int64      `json:"effectiveFrom"`
	EffectiveUntil *int64     `json:"effectiveUntil"`
	IssuedByActor  string     `json:"issuedByActor"`
	CreatedAt      int64      `json:"createdAt"`
	Reason         *string    `json:"reason"`
}

type recordsJSON struct {
	WorkspaceID string      `json:"workspaceId"`
	Grants      []grantJSON `json:"grants"`
	Revocations []struct {
		RevocationID  string `json:"revocationId"`
		GrantID       string `json:"grantId"`
		ReasonCode    string `json:"reasonCode"`
		EffectiveFrom int64  `json:"effectiveFrom"`
		IssuedByActor string `json:"issuedByActor"`
		CreatedAt     int64  `json:"createdAt"`
	} `json:"revocations"`
	Terms []struct {
		TermID       string       `json:"termId"`
		Kind         termKindEnum `json:"kind"`
		StartsAt     int64        `json:"startsAt"`
		EndsAt       int64        `json:"endsAt"`
		GraceEndsAt  *int64       `json:"graceEndsAt"`
		AuthorizedAt int64        `json:"authorizedAt"`
		CreatedAt    int64        `json:"createdAt"`
	} `json:"terms"`
	TermActions []struct {
		TermID      string    `json:"termId"`
		Kind        enumValue `json:"kind"`
		EffectiveAt int64     `json:"effectiveAt"`
		RecordedAt  int64     `json:"recordedAt"`
	} `json:"termActions"`
	StatusFacts []struct {
		RecordedAt      int64     `json:"recordedAt"`
		Status          enumValue `json:"status"`
		AutoRenew       bool      `json:"autoRenew"`
		PurchasePending bool      `json:"purchasePending"`
	} `json:"statusFacts"`
	FeatureReleases []struct {
		Feature    string `json:"feature"`
		ReleasedAt int64  `json:"releasedAt"`
	} `json:"featureReleases"`
	Activations []struct {
		Version     string `json:"version"`
		ActivatedAt int64  `json:"activatedAt"`
	} `json:"activations"`
}

func micros(value *int64) *Micros {
	if value == nil {
		return nil
	}
	converted := Micros(*value)
	return &converted
}

func (r recordsJSON) records() (RecordSet, error) {
	records := RecordSet{AccountID: r.WorkspaceID}
	for _, grant := range r.Grants {
		value, err := grant.Value.value()
		if err != nil {
			return RecordSet{}, err
		}
		records.Grants = append(records.Grants, Grant{GrantID: grant.GrantID, AccountID: grant.WorkspaceID, Kind: GrantKind(grant.Kind), Subject: grant.Subject,
			Value: value, Source: GrantSource(grant.Source), SourceRef: grant.SourceRef, EffectiveFrom: Micros(grant.EffectiveFrom),
			EffectiveUntil: micros(grant.EffectiveUntil), IssuedByActor: grant.IssuedByActor, CreatedAt: Micros(grant.CreatedAt), Reason: grant.Reason})
	}
	for _, item := range r.Revocations {
		records.Revocations = append(records.Revocations, Revocation{RevocationID: item.RevocationID, GrantID: item.GrantID, ReasonCode: item.ReasonCode,
			EffectiveFrom: Micros(item.EffectiveFrom), IssuedByActor: item.IssuedByActor, CreatedAt: Micros(item.CreatedAt)})
	}
	for _, item := range r.Terms {
		records.Terms = append(records.Terms, ServiceTermFact{TermID: item.TermID, Kind: ServiceTermKind(item.Kind), StartsAt: Micros(item.StartsAt),
			EndsAt: Micros(item.EndsAt), GraceEndsAt: micros(item.GraceEndsAt), AuthorizedAt: Micros(item.AuthorizedAt), CreatedAt: Micros(item.CreatedAt)})
	}
	for _, item := range r.TermActions {
		records.TermActions = append(records.TermActions, TermActionFact{TermID: item.TermID, Kind: TermActionKind(item.Kind),
			EffectiveAt: Micros(item.EffectiveAt), RecordedAt: Micros(item.RecordedAt)})
	}
	for _, item := range r.StatusFacts {
		records.StatusFacts = append(records.StatusFacts, StatusFact{RecordedAt: Micros(item.RecordedAt), Status: AccountStatus(item.Status),
			AutoRenew: item.AutoRenew, PurchasePending: item.PurchasePending})
	}
	for _, item := range r.FeatureReleases {
		records.FeatureReleases = append(records.FeatureReleases, FeatureReleaseFact{Feature: item.Feature, ReleasedAt: Micros(item.ReleasedAt)})
	}
	for _, item := range r.Activations {
		records.Activations = append(records.Activations, DefinitionsActivation{Version: item.Version, ActivatedAt: Micros(item.ActivatedAt)})
	}
	return records, nil
}

type definitionsJSON struct {
	Version         string `json:"version"`
	IsSelfHostRealm bool   `json:"isSelfHostRealm"`
	Capabilities    []struct {
		Key              string  `json:"key"`
		RequiresPaidTerm bool    `json:"requiresPaidTerm"`
		FeatureGate      *string `json:"featureGate"`
	} `json:"capabilities"`
	Quotas []struct {
		Key         string    `json:"key"`
		Combination enumValue `json:"combination"`
	} `json:"quotas"`
	Allowances []struct {
		Key string `json:"key"`
	} `json:"allowances"`
}

func (d definitionsJSON) definitions() Definitions {
	definitions := Definitions{Version: d.Version, IsSelfHostRealm: d.IsSelfHostRealm}
	for _, item := range d.Capabilities {
		definitions.Capabilities = append(definitions.Capabilities, CapabilityDefinition{Key: item.Key, RequiresPaidTerm: item.RequiresPaidTerm, FeatureGate: item.FeatureGate})
	}
	for _, item := range d.Quotas {
		definitions.Quotas = append(definitions.Quotas, QuotaDefinition{Key: item.Key, Combination: QuotaCombination(item.Combination)})
	}
	for _, item := range d.Allowances {
		definitions.Allowances = append(definitions.Allowances, AllowanceDefinition{Key: item.Key})
	}
	return definitions
}

type resolverVector struct {
	ID          string          `json:"id"`
	Rows        []string        `json:"rows"`
	Definitions definitionsJSON `json:"definitions"`
	Records     recordsJSON     `json:"records"`
	AsOf        int64           `json:"asOf"`
	Expect      struct {
		Version    *int64  `json:"version"`
		ComputedAt *int64  `json:"computedAt"`
		ValidUntil *int64  `json:"validUntil"`
		Canonical  *string `json:"canonical"`
		Error      *string `json:"error"`
	} `json:"expect"`
}

type admissionVector struct {
	ID      string   `json:"id"`
	Rows    []string `json:"rows"`
	Request struct {
		WorkspaceID    string     `json:"workspaceId"`
		Kind           kindEnum   `json:"kind"`
		Subject        string     `json:"subject"`
		Value          *valueJSON `json:"value"`
		Source         enumValue  `json:"source"`
		SourceRef      *string    `json:"sourceRef"`
		EffectiveFrom  int64      `json:"effectiveFrom"`
		EffectiveUntil *int64     `json:"effectiveUntil"`
		IssuedByActor  string     `json:"issuedByActor"`
		Reason         *string    `json:"reason"`
	} `json:"request"`
	Refusal *string `json:"refusal"`
}

type corpus struct {
	SchemaVersion int               `json:"schemaVersion"`
	Resolver      []resolverVector  `json:"resolver"`
	Admission     []admissionVector `json:"admission"`
	Rows          map[string]struct {
		Resolver  int `json:"resolver"`
		Admission int `json:"admission"`
	} `json:"rows"`
	Excluded map[string]string `json:"excluded"`
}

func loadCorpus(t *testing.T) corpus {
	t.Helper()
	data, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read the corpus: %v", err)
	}
	var loaded corpus
	if err = json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("parse the corpus: %v", err)
	}
	if loaded.SchemaVersion != 1 {
		t.Fatalf("the corpus has schema version %d", loaded.SchemaVersion)
	}
	return loaded
}

// TestResolverParityWithEveryCSharpVector replays every resolver vector the C# suites produce through the Go resolver and requires
// the same canonical text, version, computation instant, validity and refusal message (F1/N2). EVIDENCE: REAL (the Go resolver)
// against recorded data (the C# resolver's answers).
func TestResolverParityWithEveryCSharpVector(t *testing.T) {
	loaded := loadCorpus(t)
	if len(loaded.Resolver) != corpusResolverVectors {
		t.Fatalf("the corpus holds %d resolver vectors, the documented number is %d (a corpus rewritten on purpose changes this number and docs/entitlement-resolver.md)",
			len(loaded.Resolver), corpusResolverVectors)
	}
	refusals, answers := 0, 0
	for _, vector := range loaded.Resolver {
		records, err := vector.Records.records()
		if err != nil {
			t.Fatalf("%s: %v", vector.ID, err)
		}
		snapshot, err := Resolve(records, vector.Definitions.definitions(), Micros(vector.AsOf))
		if vector.Expect.Error != nil {
			refusals++
			var input *InputError
			if err == nil || !asInputError(err, &input) || input.Message != *vector.Expect.Error {
				t.Errorf("%s (%s): want the refusal %q, got %v", vector.ID, strings.Join(vector.Rows, ", "), *vector.Expect.Error, err)
			}
			continue
		}
		answers++
		if err != nil {
			t.Errorf("%s (%s): unexpected refusal: %v", vector.ID, strings.Join(vector.Rows, ", "), err)
			continue
		}
		if vector.Expect.Version == nil || vector.Expect.ComputedAt == nil || vector.Expect.Canonical == nil {
			t.Fatalf("%s: the vector states no answer", vector.ID)
		}
		if snapshot.Version != *vector.Expect.Version || int64(snapshot.ComputedAt) != *vector.Expect.ComputedAt {
			t.Errorf("%s (%s): version %d computedAt %d, want %d %d", vector.ID, strings.Join(vector.Rows, ", "), snapshot.Version, snapshot.ComputedAt,
				*vector.Expect.Version, *vector.Expect.ComputedAt)
		}
		if !sameMicros(snapshot.Content.ValidUntil, vector.Expect.ValidUntil) {
			t.Errorf("%s (%s): validUntil %v, want %v", vector.ID, strings.Join(vector.Rows, ", "), snapshot.Content.ValidUntil, vector.Expect.ValidUntil)
		}
		if got := snapshot.Content.Canonical(); got != *vector.Expect.Canonical {
			t.Errorf("%s (%s): canonical text differs\n got: %q\nwant: %q", vector.ID, strings.Join(vector.Rows, ", "), got, *vector.Expect.Canonical)
		}
	}
	if refusals == 0 || answers == 0 {
		t.Fatalf("the corpus must hold answers and refusals (%d, %d)", answers, refusals)
	}
	t.Logf("replayed %d resolver vectors (%d answers, %d refusals)", len(loaded.Resolver), answers, refusals)
}

func sameMicros(got *Micros, want *int64) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	return int64(*got) == *want
}

func asInputError(err error, target **InputError) bool {
	input, ok := err.(*InputError)
	if ok {
		*target = input
	}
	return ok
}

// TestGrantAdmissionParityWithEveryCSharpVector replays every admission vector: the Go admission answers the same reason, or admits,
// exactly when the C# GrantAdmission did.
func TestGrantAdmissionParityWithEveryCSharpVector(t *testing.T) {
	loaded := loadCorpus(t)
	if len(loaded.Admission) != corpusAdmissionVectors {
		t.Fatalf("the corpus holds %d admission vectors, the documented number is %d (a corpus rewritten on purpose changes this number and docs/entitlement-resolver.md)",
			len(loaded.Admission), corpusAdmissionVectors)
	}
	refused, admitted := 0, 0
	for _, vector := range loaded.Admission {
		value, err := vector.Request.Value.value()
		if err != nil {
			t.Fatalf("%s: %v", vector.ID, err)
		}
		got := ValidateIssue(IssueGrantRequest{AccountID: vector.Request.WorkspaceID, Kind: GrantKind(vector.Request.Kind), Subject: vector.Request.Subject,
			Value: value, Source: GrantSource(vector.Request.Source), SourceRef: vector.Request.SourceRef, EffectiveFrom: Micros(vector.Request.EffectiveFrom),
			EffectiveUntil: micros(vector.Request.EffectiveUntil), IssuedByActor: vector.Request.IssuedByActor, Reason: vector.Request.Reason})
		want := ""
		if vector.Refusal != nil {
			want = *vector.Refusal
			refused++
		} else {
			admitted++
		}
		if got != want {
			t.Errorf("%s (%s): admission %q, want %q", vector.ID, strings.Join(vector.Rows, ", "), got, want)
		}
	}
	if refused == 0 || admitted == 0 {
		t.Fatalf("the corpus must hold admissions and refusals (%d, %d)", admitted, refused)
	}
}

// TestEveryCorpusRowHasAVectorOrAReason pins the corpus' own accounting, and only that: the vectors that name a row are at most its
// count of calls and at least one when the count is positive, a row without a vector is excluded with a stated reason, and every
// vector names a row of the corpus. That every row of the C# suites is in the corpus, and that a count is the number of calls the
// suite makes, is the C# drift test's job (ResolverVectorsTests), which runs them.
func TestEveryCorpusRowHasAVectorOrAReason(t *testing.T) {
	loaded := loadCorpus(t)
	for name, counts := range loaded.Rows {
		reason, excluded := loaded.Excluded[name]
		switch {
		case counts.Resolver+counts.Admission == 0 && (!excluded || strings.TrimSpace(reason) == ""):
			t.Errorf("the row %s has no vector and no stated reason", name)
		case counts.Resolver+counts.Admission > 0 && excluded:
			t.Errorf("the row %s has vectors and is excluded", name)
		}
	}
	resolverBy, admissionBy := map[string]int{}, map[string]int{}
	for _, vector := range loaded.Resolver {
		if len(vector.Rows) == 0 {
			t.Errorf("%s names no row", vector.ID)
		}
		for _, row := range vector.Rows {
			resolverBy[row]++
		}
	}
	for _, vector := range loaded.Admission {
		if len(vector.Rows) == 0 {
			t.Errorf("%s names no row", vector.ID)
		}
		for _, row := range vector.Rows {
			admissionBy[row]++
		}
	}
	// A row's count is the number of calls its suite made; equal calls share one vector, so the vectors that name the row are at most
	// the count, and at least one exactly when the count is positive.
	for name, counts := range loaded.Rows {
		if resolverBy[name] > counts.Resolver || admissionBy[name] > counts.Admission || (resolverBy[name] == 0) != (counts.Resolver == 0) ||
			(admissionBy[name] == 0) != (counts.Admission == 0) {
			t.Errorf("the row %s made %d resolver and %d admission calls, and the vectors name it %d and %d times", name, counts.Resolver, counts.Admission,
				resolverBy[name], admissionBy[name])
		}
	}
	for _, by := range []map[string]int{resolverBy, admissionBy} {
		for name := range by {
			if _, known := loaded.Rows[name]; !known {
				t.Errorf("a vector names the row %s, which the corpus does not list", name)
			}
		}
	}
	for name := range loaded.Excluded {
		if _, known := loaded.Rows[name]; !known {
			t.Errorf("the excluded row %s is not a row of the corpus", name)
		}
	}
}
