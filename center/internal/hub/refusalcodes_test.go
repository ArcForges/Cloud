// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/fleet"
)

// pinnedRefusalCodes is SHA-256 of the refusal code table's first 67 rows ("<value> <category>/<code>\n" in value order), the codes of
// cohort 1.0.0-ci.437.1: a value of them that changes, or a code that moves, changes it.
const pinnedRefusalCodes = "37a396b72048a7244a85797a2b2acde81074ee07aacb66ca8a8f464c48cc2fd8"

// TestTheRefusalCodesAreFixed (decisions B-2): every CATEGORY/code of the vendored catalogue maps to a value of the routing record's
// fixed table (never RefusalOther), every value is used once, and the values of the pinned cohort never change; a later code is only
// appended (a higher value). The migration's rows are the same table (TestTheRefusalCodeTableIsTheMigrations, an integration test).
func TestTheRefusalCodesAreFixed(t *testing.T) {
	codes := fleet.RefusalCodes()
	seen := map[int16]string{}
	for key, value := range codes {
		if value <= fleet.RefusalOther {
			t.Fatalf("%s has the value %d", key, value)
		}
		if other, ok := seen[value]; ok {
			t.Fatalf("%s and %s share the value %d", key, other, value)
		}
		seen[value] = key
	}
	for key := range refusalCatalogue {
		if fleet.RefusalCode(key) == fleet.RefusalOther {
			t.Fatalf("the catalogue code %s has no value", key)
		}
	}
	if fleet.RefusalCode("state/not_a_code") != fleet.RefusalOther {
		t.Fatal("a code outside the table is other")
	}
	values := make([]int, 0, len(seen))
	for value := range seen {
		values = append(values, int(value))
	}
	sort.Ints(values)
	text := ""
	for _, value := range values {
		if value <= 67 {
			text += fmt.Sprintf("%d %s\n", value, seen[int16(value)])
		}
	}
	digest := sha256.Sum256([]byte(text))
	if got := hex.EncodeToString(digest[:]); got != pinnedRefusalCodes {
		t.Fatalf("the values of the pinned codes changed: %s", got)
	}
}
