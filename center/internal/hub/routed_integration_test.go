// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The historical storage checks use the schema11 database and the shared lease,
// without enabling or calling a retired FleetService route.
func routedHarness(t *testing.T) *harness {
	t.Helper()
	return newHarness(t, settings{legacyRouting: true})
}

func (h *harness) record(user, command platform.ID) *fleet.RoutedRecord {
	h.t.Helper()
	value, err := fleet.ReadRouted(context.Background(), h.db.Runtime, user, command)
	if err != nil {
		h.t.Fatal(err)
	}
	return value
}

func TestTheRefusalCodeTableIsTheMigrations(t *testing.T) {
	h := routedHarness(t)
	rows, err := h.db.Migration.Query(context.Background(), "SELECT value, category || '/' || code FROM fleet.refusal_code")
	if err != nil {
		t.Fatal(err)
	}
	stored := map[string]int16{}
	for rows.Next() {
		var value int16
		var key string
		if err := rows.Scan(&value, &key); err != nil {
			t.Fatal(err)
		}
		stored[key] = value
	}
	rows.Close()
	want := fleet.RefusalCodes()
	want["other/other"] = fleet.RefusalOther
	if len(stored) != len(want) {
		t.Fatalf("%d rows, %d codes", len(stored), len(want))
	}
	for key, value := range want {
		if stored[key] != value {
			t.Fatalf("%s: %d in the migration, %d in the table", key, stored[key], value)
		}
	}
	for _, statement := range []string{"UPDATE fleet.refusal_code SET code = 'renamed' WHERE value = 1", "DELETE FROM fleet.refusal_code WHERE value = 1"} {
		if _, err := h.db.Migration.Exec(context.Background(), statement); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}
