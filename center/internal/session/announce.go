// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"context"
	"sync"

	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// Revocation names the sessions a committed revocation may have ended (AF-CTR-05 E1a, CTR5-HUB-08): by session, by installation, by
// account, or every session. It is a hint, never an authority: a listener (the node channel hub) re-checks each credential it holds
// against the store before it acts, so a notice that names too much ends nothing that is still live.
type Revocation struct {
	Sessions      []platform.ID
	Installations []platform.ID
	Users         []platform.ID
	// All names every session (the operator's revocation of every account).
	All bool
}

// Names reports whether the notice may concern a session of an installation and an account.
func (r Revocation) Names(sessionID, installationID, userID platform.ID) bool {
	if r.All {
		return true
	}
	for _, id := range r.Sessions {
		if id == sessionID {
			return true
		}
	}
	for _, id := range r.Installations {
		if id == installationID {
			return true
		}
	}
	for _, id := range r.Users {
		if id == userID {
			return true
		}
	}
	return false
}

// listeners are the in-process listeners of committed revocations, keyed by their registration.
var listeners = struct {
	mu   sync.Mutex
	next int
	fns  map[int]func(Revocation)
}{fns: map[int]func(Revocation){}}

// ListenRevocations registers a listener of committed revocations and returns the function that removes it. The listener runs on the
// committing goroutine after the commit (store.AfterCommit), so it must not block: the hub hands the notice to its own goroutine.
func ListenRevocations(fn func(Revocation)) (stop func()) {
	listeners.mu.Lock()
	defer listeners.mu.Unlock()
	key := listeners.next
	listeners.next++
	listeners.fns[key] = fn
	return func() {
		listeners.mu.Lock()
		defer listeners.mu.Unlock()
		delete(listeners.fns, key)
	}
}

// Announce tells the listeners, once the transaction of ctx has committed, that it revoked the sessions the notice names. Outside a
// transaction it announces nothing. A revocation committed by another process (the operator's `admin revoke-sessions`) reaches no
// listener here: the hub's periodic re-check of every credential it holds ends it within one interval.
func Announce(ctx context.Context, notice Revocation) {
	store.AfterCommit(ctx, func() {
		listeners.mu.Lock()
		fns := make([]func(Revocation), 0, len(listeners.fns))
		for _, fn := range listeners.fns {
			fns = append(fns, fn)
		}
		listeners.mu.Unlock()
		for _, fn := range fns {
			fn(notice)
		}
	})
}
