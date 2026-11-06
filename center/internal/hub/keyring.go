// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// DefaultKeyRefresh is how often the hub re-reads the command keys' rows (fleet.signing_key): Settings.KeyRefresh, one minute. The rows
// are also re-read at every hello, before ChannelAccepted lists the signing kids.
const DefaultKeyRefresh = time.Minute

// KeyStalePeriods is how many refresh periods the keyring may go without a successful read before it stops signing (fail closed): a
// key retired, or expired early, in the store while the store does not answer may still sign for at most about three refresh periods
// (three minutes by default) after its retirement, never longer.
const KeyStalePeriods = 3

// keyring is the command keys the hub signs calls with (Plan CTR5-SIG-02, CTR5-KEY-01): the private halves the start loaded (each under
// its binding, never logged) and the rows of fleet.signing_key that name a loaded binding with the same public key, valid now or later.
// A call is signed with the newest of them valid at the call's instant, so a successor takes over at its not_before; an expiry is
// checked at each call; a retirement takes effect at the next successful read, at most a refresh period later.
type keyring struct {
	mu        sync.Mutex
	private   map[string]*ecdsa.PrivateKey // by binding
	public    map[string][]byte            // the loaded key's PKIX public half, by binding
	rows      []platform.SigningKey        // published rows of a held binding, oldest first
	refreshed time.Time                    // the last successful read
	// missing is set while no held key may sign, so the transition is logged once.
	missing atomic.Bool
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
// used (the start refuses it; a row registered later is skipped and logged by its kid). A read that fails leaves the rows last read,
// which sign only until the keyring is stale (KeyStalePeriods).
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
	h.storeKeys(published, now)
	return nil
}

// storeKeys keeps the rows of a read that started at now, unless a read that started later is already kept (review B C-N1): a slow read
// (a hello's) that finishes after a newer one (the loop's) never puts the older snapshot back, so a retirement the newer read saw stays
// seen. It reports whether the rows were kept.
func (h *Hub) storeKeys(published []platform.SigningKey, now time.Time) bool {
	h.keys.mu.Lock()
	defer h.keys.mu.Unlock()
	if now.Before(h.keys.refreshed) {
		return false
	}
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
	return true
}

// keyLoop re-reads the command keys' rows every KeyRefresh, apart from the lease loop (a slow store never holds a lease step back); each
// read is bounded by its own timeout and by the loop's context, so Stop never waits for the store.
func (h *Hub) keyLoop(ctx context.Context) {
	defer close(h.keyed)
	ticker := time.NewTicker(h.keyRefresh())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if err := h.RefreshKeys(ctx, h.clock()); err != nil && ctx.Err() == nil {
			h.logger.Warn("the command keys could not be re-read; the rows last read sign until the keyring is stale", "error", err.Error())
		}
	}
}

// keyRefresh is the refresh period of the settings (DefaultKeyRefresh when unset).
func (h *Hub) keyRefresh() time.Duration {
	if h.settings.KeyRefresh > 0 {
		return h.settings.KeyRefresh
	}
	return DefaultKeyRefresh
}

// SigningKID is the kid of the command key a call would be signed with at an instant (the health document's signingKid); ok is false
// when no held key may sign then.
func (h *Hub) SigningKID(at time.Time) (string, bool) {
	kid, _, ok := h.signingKey(at)
	return kid, ok
}

// signingKey is the newest held command key valid at an instant, with its private half: the first of validKids, so the call's kid, the
// health document's and the first of ChannelAccepted.signing_kids are always the same key. ok is false when none is valid, or when the
// keyring is stale.
func (h *Hub) signingKey(at time.Time) (string, *ecdsa.PrivateKey, bool) {
	h.keys.mu.Lock()
	defer h.keys.mu.Unlock()
	rows := h.validRowsLocked(at)
	if len(rows) == 0 {
		return "", nil, false
	}
	return rows[0].KID, h.keys.private[rows[0].SecretBinding], true
}

// validKids are the kids of the held command keys valid at an instant, newest first, at most eight (ChannelAccepted.signing_kids); none
// while the keyring is stale.
func (h *Hub) validKids(at time.Time) []string {
	h.keys.mu.Lock()
	defer h.keys.mu.Unlock()
	var kids []string
	for _, row := range h.validRowsLocked(at) {
		if len(kids) < maxSigningKids {
			kids = append(kids, row.KID)
		}
	}
	return kids
}

// validRowsLocked are the held rows valid at an instant, newest first (the latest not_before, then the lowest kid, as
// platform.ValidKeys orders them); none when the last successful read is older than KeyStalePeriods refresh periods.
func (h *Hub) validRowsLocked(at time.Time) []platform.SigningKey {
	if h.keys.refreshed.IsZero() || at.Sub(h.keys.refreshed) > KeyStalePeriods*h.keyRefresh() {
		return nil
	}
	var rows []platform.SigningKey
	for _, row := range h.keys.rows {
		if row.NotBefore.After(at) || !row.NotAfter.After(at) || (row.RetiredAt != nil && !row.RetiredAt.After(at)) {
			continue
		}
		rows = append(rows, row)
	}
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0 && newer(rows[j], rows[j-1]); j-- {
			rows[j], rows[j-1] = rows[j-1], rows[j]
		}
	}
	return rows
}

// newer orders two rows as platform.ValidKeys does: the later not_before first, then the lower kid.
func newer(a, b platform.SigningKey) bool {
	return a.NotBefore.After(b.NotBefore) || (a.NotBefore.Equal(b.NotBefore) && a.KID < b.KID)
}

// noKey records that no held key may sign, and logs it once per transition (review B N-4); hasKey clears it.
func (h *Hub) noKey() {
	if h.keys.missing.CompareAndSwap(false, true) {
		h.logger.Warn("no held command key may sign: routed calls are refused and new channels closed until one does")
	}
}

func (h *Hub) hasKey() { h.keys.missing.Store(false) }
