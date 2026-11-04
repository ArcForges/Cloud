// SPDX-License-Identifier: AGPL-3.0-only

package platform

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/store"
)

// KeyPurpose is what a signing key signs (fleet.signing_key_purpose).
type KeyPurpose int16

// The key purposes.
const (
	// CommandSigning signs every call the center routes to a node (ES256; AD-0021 section 10, AF-CTR-05).
	CommandSigning KeyPurpose = 1
	// EntitlementToken signs entitlement tokens (ES256; AF-CLD-03).
	EntitlementToken KeyPurpose = 2
	// RelayHMAC authenticates relay frames (HS256).
	RelayHMAC KeyPurpose = 3
)

// Rotation bounds: a key is valid for at most MaxKeyValidity, and its successor must become valid at least MinKeyOverlap before
// it expires, so a node that refreshed its center keys within that window verifies both (AF-CTR-04 delivers keys with
// credential refresh).
const (
	MaxKeyValidity = 400 * 24 * time.Hour
	MinKeyOverlap  = 7 * 24 * time.Hour
	maxBackdating  = time.Minute
)

var (
	keyID         = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	secretBinding = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
)

// SigningKey is the metadata of one key; the private key lives only in the platform secret its binding names.
type SigningKey struct {
	KID           string
	Purpose       KeyPurpose
	Algorithm     string
	PublicKey     []byte // PKIX (SubjectPublicKeyInfo) DER of an ES256 key; nil for HS256
	SecretBinding string
	NotBefore     time.Time
	NotAfter      time.Time
	RetiredAt     *time.Time
}

// ValidKeys returns the keys of a purpose valid at an instant, newest first: the verification set. The first is the signing
// key.
func ValidKeys(ctx context.Context, q interface {
	Query(ctx context.Context, sql string, arguments ...any) (pgx.Rows, error)
}, purpose KeyPurpose, at time.Time) ([]SigningKey, error) {
	rows, err := q.Query(ctx, `SELECT kid, purpose, algorithm, public_key, secret_binding, not_before, not_after, retired_at FROM fleet.signing_key
WHERE purpose = $1 AND not_before <= $2 AND not_after > $2 AND (retired_at IS NULL OR retired_at > $2)
ORDER BY not_before DESC, kid`, purpose, at)
	if err != nil {
		return nil, store.Sanitize("read the signing keys", err)
	}
	keys, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (SigningKey, error) {
		var key SigningKey
		err := row.Scan(&key.KID, &key.Purpose, &key.Algorithm, &key.PublicKey, &key.SecretBinding, &key.NotBefore, &key.NotAfter, &key.RetiredAt)
		return key, err
	})
	return keys, store.Sanitize("read the signing keys", err)
}

// PublishedKeys returns the keys of a purpose that a node is given with its credentials (AF-CTR-04, CTR4-KEY-03): every key that is
// neither retired nor expired at the instant, including a registered successor whose not_before lies ahead, so a node holds it before
// the center signs with it. A key retired at a later instant is published with that instant as its not_after, so a node stops
// trusting it then. Oldest first. ValidKeys stays the signing and verification set.
func PublishedKeys(ctx context.Context, q interface {
	Query(ctx context.Context, sql string, arguments ...any) (pgx.Rows, error)
}, purpose KeyPurpose, at time.Time) ([]SigningKey, error) {
	rows, err := q.Query(ctx, `SELECT kid, purpose, algorithm, public_key, secret_binding, not_before, least(not_after, coalesce(retired_at, not_after)),
    retired_at FROM fleet.signing_key
WHERE purpose = $1 AND not_after > $2 AND (retired_at IS NULL OR retired_at > $2)
ORDER BY not_before, kid`, purpose, at)
	if err != nil {
		return nil, store.Sanitize("read the published keys", err)
	}
	keys, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (SigningKey, error) {
		var key SigningKey
		err := row.Scan(&key.KID, &key.Purpose, &key.Algorithm, &key.PublicKey, &key.SecretBinding, &key.NotBefore, &key.NotAfter, &key.RetiredAt)
		return key, err
	})
	return keys, store.Sanitize("read the published keys", err)
}

// ErrKeyNotRetirable refuses the retirement of a key that does not exist or is already retired.
var ErrKeyNotRetirable = errors.New("no unretired key has this key ID")

// RetireKey retires a key at an instant (with the migration role; AF-CTR-04 `admin retire-signing-key`, Q6): from then on it is
// neither published nor valid. An emergency retirement may leave a purpose without a valid key; the caller reports it.
func RetireKey(ctx context.Context, tx pgx.Tx, kid string, at time.Time) (SigningKey, error) {
	var key SigningKey
	err := tx.QueryRow(ctx, `UPDATE fleet.signing_key SET retired_at = $2 WHERE kid = $1 AND retired_at IS NULL
RETURNING kid, purpose, algorithm, public_key, secret_binding, not_before, not_after, retired_at`, kid, at).
		Scan(&key.KID, &key.Purpose, &key.Algorithm, &key.PublicKey, &key.SecretBinding, &key.NotBefore, &key.NotAfter, &key.RetiredAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SigningKey{}, ErrKeyNotRetirable
	}
	return key, store.Sanitize("retire a signing key", err)
}

// RegisterKey records a new key's metadata (with the migration role; the runtime role can only read). It refuses an invalid
// key, a validity longer than MaxKeyValidity, and a rotation gap: while keys of the purpose are valid, the new key must become
// valid at least MinKeyOverlap before the latest of them expires and must outlive it.
func RegisterKey(ctx context.Context, tx pgx.Tx, key SigningKey, now time.Time) error {
	if err := key.check(now); err != nil {
		return err
	}
	current, err := ValidKeys(ctx, tx, key.Purpose, now)
	if err != nil {
		return err
	}
	if len(current) > 0 {
		latest := current[0].NotAfter
		for _, existing := range current {
			if existing.NotAfter.After(latest) {
				latest = existing.NotAfter
			}
		}
		if key.NotBefore.After(latest.Add(-MinKeyOverlap)) || !key.NotAfter.After(latest) {
			return fmt.Errorf("the new key must become valid at least %s before the current keys expire (%s) and outlive them", MinKeyOverlap, latest.UTC().Format(time.RFC3339))
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO fleet.signing_key (kid, purpose, algorithm, public_key, secret_binding, not_before, not_after, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, now())`, key.KID, key.Purpose, key.Algorithm, key.PublicKey, key.SecretBinding, key.NotBefore, key.NotAfter)
	return store.Sanitize("register a signing key", err)
}

func (k SigningKey) check(now time.Time) error {
	if !keyID.MatchString(k.KID) || !secretBinding.MatchString(k.SecretBinding) {
		return errors.New("a key needs a key ID of 8 to 64 URL-safe characters and an uppercase secret binding name")
	}
	if !k.NotAfter.After(k.NotBefore) || k.NotAfter.Sub(k.NotBefore) > MaxKeyValidity || k.NotBefore.Before(now.Add(-maxBackdating)) {
		return fmt.Errorf("a key's validity must start now or later and last at most %s", MaxKeyValidity)
	}
	switch k.Purpose {
	case CommandSigning, EntitlementToken:
		if k.Algorithm != "ES256" {
			return errors.New("command-signing and entitlement-token keys are ES256")
		}
		parsed, err := x509.ParsePKIXPublicKey(k.PublicKey)
		if err != nil {
			return errors.New("an ES256 key needs its PKIX public key")
		}
		public, ok := parsed.(*ecdsa.PublicKey)
		if !ok || public.Curve != elliptic.P256() {
			return errors.New("an ES256 key must be a P-256 ECDSA public key")
		}
	case RelayHMAC:
		if k.Algorithm != "HS256" || k.PublicKey != nil {
			return errors.New("a relay key is HS256 and has no public key")
		}
	default:
		return errors.New("unknown key purpose")
	}
	return nil
}
