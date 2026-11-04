// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// AccountParticipant is a part of the center that holds approvals an account granted and that a remediation of the account must end
// (AF-CTR-04 protocol-6): revoking all other sessions and removing a credential cancel the account's approved node sign-ins that no
// node collected yet, because an approval otherwise outlives the remediation that the approving session itself performs (that
// session is neither revoked nor moved to a new epoch by "sign out all other sessions"). The identity composition (server.New)
// registers the fleet's participants, one per sign-in flow table, in a fixed order: fleet.node_sign_in now, part E2's
// fleet.device_authorization after it; that order will be the lock order between the two tables.
type AccountParticipant interface {
	// Name is the participant's name in the audit counts.
	Name() string
	// CancelApprovals ends the account's approved, uncollected approvals in the remediation's transaction and returns how many it
	// ended. Its rows come first in the global lock order (a sign-in flow row before the account), so it runs before the
	// remediation locks the account.
	CancelApprovals(ctx context.Context, tx pgx.Tx, userID platform.ID, now time.Time) (int64, error)
}

// Cancellations counts the approvals each account participant cancelled, by its name (the participants member of the audit
// payloads of identity.sessions.revoked_all and identity.credential.removed).
type Cancellations map[string]int64

// CancelApprovals runs every account participant in its registration order in the caller's transaction. RevokeAllSessions and
// RemoveAuthIdentity call it first in their receipt's run, before their step-up evidence locks the account, and pass the counts to
// RevokeAllSessions and RemoveCredential; a refusal later in the run (no evidence) rolls the cancellations back with the rest.
func (s *Service) CancelApprovals(ctx context.Context, tx pgx.Tx, userID platform.ID, now time.Time) (Cancellations, error) {
	cancelled := Cancellations{}
	for _, participant := range s.accountParticipants {
		count, err := participant.CancelApprovals(ctx, tx, userID, now)
		if err != nil {
			return nil, fmt.Errorf("the approvals of %s: %w", participant.Name(), err)
		}
		cancelled[participant.Name()] = count
	}
	return cancelled, nil
}
