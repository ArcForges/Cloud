// SPDX-License-Identifier: AGPL-3.0-only

package feature

import (
	"bytes"
	_ "embed" // the development fixtures are part of the executable
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"unicode"

	"github.com/ArcForges/Cloud/center/internal/entitlement"
)

// Classification says which configuration a catalogue belongs to. Production is the hosted center that sells (today: no catalogue at
// all, until H-07); Development is the acceptance environment and the tests, which may use the embedded fixtures. There is no
// production environment slot for a catalogue (DC-12): a production-classified catalogue exists only injected in a test, until the
// owner decides prices and limits.
type Classification int

// The classifications.
const (
	ClassProduction Classification = iota + 1
	ClassDevelopment
)

func (c Classification) String() string {
	if c == ClassProduction {
		return "production"
	}
	return "development"
}

// Bounds of the catalogue document.
const (
	// MaxCatalogueBytes bounds a catalogue document.
	MaxCatalogueBytes = 65_536
	maxPlans          = 16
)

// Plan is one plan of the catalogue: the features it carries. The plans are configuration for the commerce task (AF-CTR-09), which
// turns a purchase into grants of a plan's features; this task issues grants only through the operator (names features, not plans).
type Plan struct {
	ID       string
	Name     string
	Features []Key
	// IllustrativePriceUSD is a price of a development fixture, 5 or 15, never an approved price. A catalogue that is not a fixture
	// states none: this code invents no price.
	IllustrativePriceUSD int
}

// Catalogue is the plan catalogue of an official-hosted center: the version of the definitions, the capabilities it defines (the six
// gated keys, each requiring a paid term) and its plans.
type Catalogue struct {
	Version string
	// Fixture marks an illustrative development fixture.
	Fixture      bool
	Notice       string
	Class        Classification
	Capabilities []Key
	Plans        []Plan
}

// ErrInvalidCatalogue is the error of every catalogue that does not validate. The message names the rule, never a value of the
// document.
var ErrInvalidCatalogue = errors.New("invalid plan catalogue")

func invalidCatalogue(format string, arguments ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidCatalogue}, arguments...)...)
}

//go:embed fixtures/development.json
var developmentFixtures []byte

// DevelopmentFixtures is the embedded development catalogue (version dev-..., marker "fixture": true, illustrative plans and prices
// of USD 5 and USD 15): it serves the tests and the acceptance environment and never production.
func DevelopmentFixtures() (Catalogue, error) {
	return ParseCatalogue(developmentFixtures, ClassDevelopment)
}

type catalogueDocument struct {
	Version      string   `json:"version"`
	Fixture      bool     `json:"fixture"`
	Notice       string   `json:"notice"`
	Capabilities []string `json:"capabilities"`
	Plans        []struct {
		ID                   string   `json:"id"`
		Name                 string   `json:"name"`
		IllustrativePriceUSD int      `json:"illustrativePriceUsd"`
		Features             []string `json:"features"`
	} `json:"plans"`
}

var (
	planIDPattern    = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+){0,7}$`)
	fixtureVersion   = regexp.MustCompile(`^dev-[A-Za-z0-9._:-]{1,120}$`)
	productionPrefix = "dev-"
)

// ParseCatalogue reads and validates a catalogue document under a classification. It is strict: one JSON object, no unknown or
// repeated field, no trailing data, at most 64 KiB. A fixture (marker true) is only valid under the development classification and is
// the only catalogue that may carry a price, USD 5 or USD 15; a non-fixture catalogue states no price. It defines exactly the six
// gated keys. Every refusal is ErrInvalidCatalogue.
func ParseCatalogue(data []byte, class Classification) (Catalogue, error) {
	if class != ClassProduction && class != ClassDevelopment {
		return Catalogue{}, invalidCatalogue("the classification is unknown")
	}
	if len(data) == 0 || len(data) > MaxCatalogueBytes {
		return Catalogue{}, invalidCatalogue("the document is empty or longer than %d bytes", MaxCatalogueBytes)
	}
	if err := refuseRepeatedFields(data); err != nil {
		return Catalogue{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document catalogueDocument
	if err := decoder.Decode(&document); err != nil {
		return Catalogue{}, invalidCatalogue("the document is not the catalogue's JSON object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return Catalogue{}, invalidCatalogue("the document holds more than one value")
	}
	catalogue := Catalogue{Version: document.Version, Fixture: document.Fixture, Notice: document.Notice, Class: class}
	switch {
	case !entitlement.IsOpaqueReference(document.Version):
		return Catalogue{}, invalidCatalogue("the version is malformed")
	case document.Fixture && class == ClassProduction:
		return Catalogue{}, invalidCatalogue("a fixture catalogue under the production classification")
	case document.Fixture && !fixtureVersion.MatchString(document.Version):
		return Catalogue{}, invalidCatalogue("a fixture's version starts with dev-")
	case !document.Fixture && len(document.Version) >= len(productionPrefix) && document.Version[:len(productionPrefix)] == productionPrefix:
		return Catalogue{}, invalidCatalogue("only a fixture has a dev- version")
	case document.Fixture && !validText(document.Notice, 1, 256):
		return Catalogue{}, invalidCatalogue("a fixture carries its illustrative notice")
	case !document.Fixture && document.Notice != "":
		return Catalogue{}, invalidCatalogue("only a fixture carries a notice")
	}
	if len(document.Capabilities) != len(Gated()) {
		return Catalogue{}, invalidCatalogue("the catalogue defines exactly the %d gated keys", len(Gated()))
	}
	for _, name := range document.Capabilities {
		key := Key(name)
		if !IsGated(key) || slices.Contains(catalogue.Capabilities, key) {
			return Catalogue{}, invalidCatalogue("a capability is not a gated key or is repeated")
		}
		catalogue.Capabilities = append(catalogue.Capabilities, key)
	}
	if len(document.Plans) < 1 || len(document.Plans) > maxPlans {
		return Catalogue{}, invalidCatalogue("the catalogue has from 1 to %d plans", maxPlans)
	}
	ids := map[string]bool{}
	for _, item := range document.Plans {
		plan := Plan{ID: item.ID, Name: item.Name, IllustrativePriceUSD: item.IllustrativePriceUSD}
		switch {
		case !planIDPattern.MatchString(item.ID) || len(item.ID) > 64 || ids[item.ID]:
			return Catalogue{}, invalidCatalogue("a plan ID is malformed or repeated")
		case !validText(item.Name, 1, 64):
			return Catalogue{}, invalidCatalogue("a plan name is blank, long or holds a control character")
		case document.Fixture && (item.IllustrativePriceUSD != 5 && item.IllustrativePriceUSD != 15):
			return Catalogue{}, invalidCatalogue("a fixture plan's illustrative price is USD 5 or USD 15")
		case !document.Fixture && item.IllustrativePriceUSD != 0:
			return Catalogue{}, invalidCatalogue("only a fixture may state a price")
		case document.Fixture && !bytes.HasPrefix([]byte(item.Name), []byte("Fixture ")):
			return Catalogue{}, invalidCatalogue("a fixture plan's name starts with Fixture")
		case len(item.Features) < 1 || len(item.Features) > len(Gated()):
			return Catalogue{}, invalidCatalogue("a plan carries from 1 to %d features", len(Gated()))
		}
		ids[item.ID] = true
		for _, name := range item.Features {
			key := Key(name)
			if !slices.Contains(catalogue.Capabilities, key) || slices.Contains(plan.Features, key) {
				return Catalogue{}, invalidCatalogue("a plan feature is not a capability of the catalogue or is repeated")
			}
			plan.Features = append(plan.Features, key)
		}
		catalogue.Plans = append(catalogue.Plans, plan)
	}
	return catalogue, nil
}

func validText(value string, minimum, maximum int) bool {
	count := 0
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
		count++
	}
	blank := true
	for _, r := range value {
		blank = blank && unicode.IsSpace(r)
	}
	return count >= minimum && count <= maximum && !blank
}

// refuseRepeatedFields refuses an object that names a field twice at its top level or in a plan (encoding/json would keep the last).
func refuseRepeatedFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return invalidCatalogue("the document is not a JSON object")
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return invalidCatalogue("the document is not a JSON object")
		}
		name, _ := token.(string)
		if seen[name] {
			return invalidCatalogue("a field is repeated")
		}
		seen[name] = true
		var value json.RawMessage
		if err = decoder.Decode(&value); err != nil {
			return invalidCatalogue("the document is not a JSON object")
		}
		if name == "plans" {
			var plans []json.RawMessage
			if json.Unmarshal(value, &plans) != nil {
				continue // the strict decode reports the shape
			}
			for _, plan := range plans {
				if err = refuseRepeatedPlanFields(plan); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func refuseRepeatedPlanFields(plan []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(plan))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil
		}
		name, _ := token.(string)
		if seen[name] {
			return invalidCatalogue("a plan field is repeated")
		}
		seen[name] = true
		var skip json.RawMessage
		if err = decoder.Decode(&skip); err != nil {
			return nil
		}
	}
	return nil
}

// Definitions are the definitions the resolver evaluates under (BN-02): the catalogue's version, its six capabilities each requiring
// a paid term, and no quota or allowance (the resources they would bound are enforced by the tasks whose operations they bound).
// IsSelfHostRealm comes from the center mode (DC-20); the catalogue serves official-hosted centers.
func (c Catalogue) Definitions(selfHostRealm bool) entitlement.Definitions {
	definitions := entitlement.Definitions{Version: c.Version, IsSelfHostRealm: selfHostRealm}
	for _, key := range c.Capabilities {
		definitions.Capabilities = append(definitions.Capabilities, entitlement.CapabilityDefinition{Key: string(key), RequiresPaidTerm: true})
	}
	return definitions
}

// Production reports the production classification.
func (c Catalogue) Production() bool { return c.Class == ClassProduction }
