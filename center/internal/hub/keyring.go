// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// KeyRefresh is how often the hub re-reads the command keys' rows (fleet.signing_key): a registered successor or a retirement takes
// effect for signing within it.
const KeyRefresh = time.Minute

// keyring is the command keys the hub signs calls with (Plan CTR5-SIG-02, CTR5-KEY-01): the private halves the start loaded (each under
// its binding, never logged) and the rows of fleet.signing_key that name a loaded binding with the same public key, valid now or later.
// A call is signed with the newest of them valid at the call's instant, so a successor takes over at its not_before.
type keyring struct {
	mu        sync.Mutex
	private   map[string]*ecdsa.PrivateKey // by binding
	public    map[string][]byte            // the loaded key's PKIX public half, by binding
	rows      []platform.SigningKey        // published rows of a held binding, oldest first
	refreshed time.Time
}

// UseCommandKeys gives the hub the loaded command keys (the start's config.CommandKeys, after CheckCommandKeys accepted them).
func (h *Hub) UseCommandKeys(keys []config.CommandKey) {
	h.keys.mu.Lock()
	defer h.keys.mu.Unlock()
	h.keys.private, h.keys.public = map[string]*ecdsa.PrivateKey{}, map[string][]byte{}
	for _, key := range keys {
		if key.Signer() != nil {
			h.keys.private[key.Binding], h.keys.public[key.Binding] = key.Signer(), key.PublicKey()
		}
	}
	h.keys.rows, h.keys.refreshed = nil, time.Time{}
}

// RefreshKeys re-reads the command keys' rows: every published key (valid now or registered for later; a retired one ends at its
// retirement) whose binding names a loaded key with the same public half. A row whose public key differs from the loaded key is never
// used (the start refuses it; a row registered later is skipped and logged by its kid).
func (h *Hub) RefreshKeys(ctx context.Context, now time.Time) error {
	var published []platform.SigningKey
	err := h.db.InTx(ctx, "read the command keys", store.TxOptions{ReadOnly: true, Timeout: presenceTimeout}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		published, err = platform.PublishedKeys(ctx, tx, platform.CommandSigning, now)
		return err
	})
	if err != nil {
		return err
	}
	h.keys.mu.Lock()
	defer h.keys.mu.Unlock()
	rows := published[:0:0]
	for _, row := range published {
		public, held := h.keys.public[row.SecretBinding]
		switch {
		case !held:
		case !bytes.Equal(public, row.PublicKey):
			h.logger.Warn("a command key row names a loaded binding with another public key; it is not used", "kid", row.KID)
		default:
			rows = append(rows, row)
		}
	}
	h.keys.rows, h.keys.refreshed = rows, now
	return nil
}

// keyLoop re-reads the command keys' rows every KeyRefresh, apart from the lease loop (a slow store never holds a lease step back).
func (h *Hub) keyLoop(ctx context.Context) {
	defer close(h.keyed)
	ticker := time.NewTicker(KeyRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.refreshKeysIfDue(ctx, h.clock())
		}
	}
}

// refreshKeysIfDue re-reads the rows once KeyRefresh passed since the last read.
func (h *Hub) refreshKeysIfDue(ctx context.Context, now time.Time) {
	h.keys.mu.Lock()
	due := now.Sub(h.keys.refreshed) >= KeyRefresh
	h.keys.mu.Unlock()
	if !due {
		return
	}
	if err := h.RefreshKeys(ctx, now); err != nil {
		h.logger.Warn("the command keys could not be re-read; the held set stays", "error", err.Error())
	}
}

// SigningKID is the kid of the command key a call would be signed with at an instant (the health document's signingKid); ok is false
// when no held key is valid then.
func (h *Hub) SigningKID(at time.Time) (string, bool) {
	kid, _, ok := h.signingKey(at)
	return kid, ok
}

// signingKey is the newest held command key valid at an instant (the latest not_before, then the lowest kid, as platform.ValidKeys
// orders them), with its private half; ok is false when none is.
func (h *Hub) signingKey(at time.Time) (string, *ecdsa.PrivateKey, bool) {
	h.keys.mu.Lock()
	defer h.keys.mu.Unlock()
	var chosen *platform.SigningKey
	for i := range h.keys.rows {
		row := &h.keys.rows[i]
		if row.NotBefore.After(at) || !row.NotAfter.After(at) || (row.RetiredAt != nil && !row.RetiredAt.After(at)) {
			continue
		}
		if chosen == nil || row.NotBefore.After(chosen.NotBefore) || (row.NotBefore.Equal(chosen.NotBefore) && row.KID < chosen.KID) {
			chosen = row
		}
	}
	if chosen == nil {
		return "", nil, false
	}
	return chosen.KID, h.keys.private[chosen.SecretBinding], true
}
