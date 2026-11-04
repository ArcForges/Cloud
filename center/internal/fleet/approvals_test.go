// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import "testing"

// TestTheAccountParticipantsRunTheBrowserFlowsFirst (E1b N-8, P(iv)): the composition registers the browser sign-in's participant and
// then the device-code sign-in's, the lock order between their tables.
func TestTheAccountParticipantsRunTheBrowserFlowsFirst(t *testing.T) {
	participants := AccountParticipants()
	if len(participants) != 2 || participants[0].Name() != "fleet.node_sign_in" || participants[1].Name() != "fleet.device_authorization" {
		t.Fatalf("participants %v", participants)
	}
}
