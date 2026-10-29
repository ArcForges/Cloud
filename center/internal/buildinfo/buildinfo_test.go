// SPDX-License-Identifier: AGPL-3.0-only

package buildinfo

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const commit = "0123456789abcdef0123456789abcdef01234567"

func TestALocalBuildIdentifiesGoWithoutClaimingDotNetAOT(t *testing.T) {
	health, err := Document("stateless", Center{Mode: "self-hosted", PublicBaseURL: "https://center.example", Surfaces: "identity"})
	if err != nil {
		t.Fatal(err)
	}
	if health.Runtime != "go" || health.NativeAOT || health.Service != "arcforges-cloud" || health.Revision != "local-dirty" ||
		health.Center.Binary != Binary || health.Build.RunID != nil {
		t.Fatalf("health: %+v", health)
	}
	data, err := json.Marshal(health)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"nativeAot":false`, `"runtime":"go"`, `"helloBackend":"stateless"`, `"runId":null`, `"center":{"binary":"arcforges-center","mode":"self-hosted","publicBaseUrl":"https://center.example","surfaces":"identity"}`} {
		if !strings.Contains(string(data), field) {
			t.Fatalf("missing %s in %s", field, data)
		}
	}
}

func TestACIBuildCarriesItsRun(t *testing.T) {
	health, err := document("neon-postgresql", Center{}, "0.1.0-ci.7.2", commit, "false", "ci", "123.2", "https://github.com/ArcForges/Cloud/actions/runs/123", "1700000000")
	if err != nil {
		t.Fatal(err)
	}
	if *health.Build.RunID != "123" || *health.Build.RunAttempt != 2 || health.Revision != commit || health.Artifact.Version != "0.1.0-ci.7.2" {
		t.Fatalf("ci identity: %+v", health.Build)
	}
	for _, invalid := range [][]string{
		{commit, "true", "ci", "123.2", "run", "1"},
		{commit, "false", "ci", "123", "run", "1"},
		{commit, "false", "ci", "123.0", "run", "1"},
		{commit, "false", "ci", "123.2.1", "run", "1"},
		{commit, "false", "ci", "123.2", "", "1"},
		{commit, "false", "ci", "123.2", "run", "0"},
		{"short", "false", "ci", "123.2", "run", "1"},
		{commit, "maybe", "local", "local", "", "0"},
		{commit, "false", "local", "local", "", "x"},
	} {
		if _, err := document("stateless", Center{}, "v", invalid[0], invalid[1], invalid[2], invalid[3], invalid[4], invalid[5]); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted %v", invalid)
		}
	}
}
