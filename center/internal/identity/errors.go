// SPDX-License-Identifier: AGPL-3.0-only

package identity

import "github.com/ArcForges/Cloud/center/internal/arc"

// The refusals of the account core's rules (errors.md rows; DC-14).
var (
	// ErrNotPermitted: the account's state does not allow the change (STATE/invalid_state, state account).
	ErrNotPermitted = arc.InvalidState("account", "credentials_locked")
	// ErrNotFound: the credential does not exist or is not the caller's (a caller that names it answers with its ID instead).
	ErrNotFound = arc.NotFound("credential", nil)
	// ErrLastCredential: removing it would leave the account without a credential (STATE/invalid_state, reason last_credential).
	ErrLastCredential = arc.InvalidState("credential", "last_credential")
)
