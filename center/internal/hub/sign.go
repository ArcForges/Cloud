// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"math/big"
	"sync/atomic"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
)

// The signatures of the node channel (Contracts relay.proto, "Signatures of the node channel"; ArcForges-Design 11 section 3,
// "Signature domain strings"; Plan PB-3): each is ES256 over a fixed ASCII domain string of its own followed by its signed bytes, in
// IEEE P1363 form r||s with r and s in [1, n-1] and s <= n/2 (the signer normalizes s, the verifier refuses a high-S signature). No
// signature is valid as another kind, and a signature over the signed bytes without their domain string is refused.
const (
	// CallDomain leads the center's signature of a routed call: CallDomain || the exact CallHeader bytes (24 bytes of ASCII).
	CallDomain = "ArcForges relay-call v1\n"
	// ResultDomain leads the node's signature of a routed result: ResultDomain || the exact ResultHeader bytes (26 bytes).
	ResultDomain = "ArcForges relay-result v1\n"
	// OriginDomain leads the relaying node's signature of a relay assertion: OriginDomain || the canonical fields (26 bytes).
	OriginDomain = "ArcForges relay-origin v1\n"
	// OriginMessageBytes is the length of a relay assertion's signed message (the domain string included).
	OriginMessageBytes = 228
)

var p256HalfOrder = new(big.Int).Rsh(elliptic.P256().Params().N, 1)

// signingInputs counts the signing inputs built from a message (tests read it to see that a message failing its shape rules never
// reaches one: relay.proto, "Verifier pre-conditions").
var signingInputs atomic.Int64

// callSigningInput is the signed message of a routed call: the domain string, then the header exactly as it is sent.
func callSigningInput(header []byte) []byte {
	signingInputs.Add(1)
	return append([]byte(CallDomain), header...)
}

// resultSigningInput is the signed message of a routed result: the domain string, then the header exactly as it was received (a
// decoded header is never re-encoded for verification).
func resultSigningInput(header []byte) []byte {
	signingInputs.Add(1)
	return append([]byte(ResultDomain), header...)
}

// originSigningInput is the signed message of a relay assertion (228 bytes): the domain string, SHA-256 of the canonical center URL,
// then every field at its fixed length: the relaying node and installation IDs, the local origin (1 byte), the local session ID, the
// method (1 byte), the request digest, the target node ID (16 zero bytes for LIST_NODES), the command ID (16 zero bytes for a read),
// the relay nonce, and issued_at and expires_at as 8 bytes of big-endian seconds and 4 of nanos. It must only be built from an
// assertion that passed validRelayAssertion: it pads nothing and truncates nothing.
func originSigningInput(audience [32]byte, value *relayv1.RelayAssertion) []byte {
	signingInputs.Add(1)
	message := make([]byte, 0, OriginMessageBytes)
	message = append(message, OriginDomain...)
	message = append(message, audience[:]...)
	message = append(message, value.RelayingNodeId.GetValue()...)
	message = append(message, value.RelayingInstallationId.GetValue()...)
	message = append(message, byte(value.GetLocalOrigin()))
	message = append(message, value.LocalSessionId.GetValue()...)
	message = append(message, byte(value.GetMethod()))
	message = append(message, value.RequestSha256...)
	message = append(message, optionalIDBytes(value.TargetNodeId)...)
	message = append(message, optionalIDBytes(value.CommandId)...)
	message = append(message, value.RelayNonce...)
	message = append(message, canonicalInstant(value.IssuedAt)...)
	return append(message, canonicalInstant(value.ExpiresAt)...)
}

// optionalIDBytes is an ID's 16 bytes, or 16 zero bytes for an absent ID.
func optionalIDBytes(value *foundationv1.Id) []byte {
	if value == nil {
		return make([]byte, 16)
	}
	return value.GetValue()
}

// canonicalInstant is an instant's 12 canonical bytes: unix_seconds big-endian two's complement, then nanos big-endian.
func canonicalInstant(value *foundationv1.Instant) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint64(out, uint64(value.GetUnixSeconds()))
	binary.BigEndian.PutUint32(out[8:], value.GetNanos())
	return out
}

// signES256 signs a message with a P-256 key: P1363 r||s, s normalized to the lower half.
func signES256(key *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	if s.Cmp(p256HalfOrder) > 0 {
		s = new(big.Int).Sub(elliptic.P256().Params().N, s)
	}
	signature := make([]byte, SignatureBytes)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature, nil
}

// verifyES256 verifies a P1363 signature over a message against a PKIX (SubjectPublicKeyInfo) P-256 key: 64 bytes, r in [1, n-1] and
// s in [1, n/2] (a high-S signature is refused before verification).
func verifyES256(publicKey, message, signature []byte) bool {
	if len(signature) != SignatureBytes {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return false
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return false
	}
	r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
	if r.Sign() <= 0 || r.Cmp(elliptic.P256().Params().N) >= 0 || s.Sign() <= 0 || s.Cmp(p256HalfOrder) > 0 {
		return false
	}
	digest := sha256.Sum256(message)
	return ecdsa.Verify(key, digest[:], r, s)
}
