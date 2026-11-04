// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"math/big"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// ProofDomain is the leading domain string of a node key proof (C0, fleet.proto "Node key proof"): 28 bytes of ASCII. Every other
// signature of the node key uses a different leading domain string, and this message is not a SignedBlob payload.
const ProofDomain = "ArcForges node-key-proof v1\n"

// The purposes of a node key proof; other values are reserved.
const (
	// ProofComplete is CompleteNodeSignIn's: binding = flow_id (16 bytes) || code (UTF-8, 43 characters).
	ProofComplete byte = 0x01
	// ProofPoll is PollDeviceAuthorization's (AF-CTR-04 E2): binding = device_code (UTF-8, 43 characters).
	ProofPoll byte = 0x02
)

// ProofLength is the length of a node key proof: an ES256 signature in IEEE P1363 form, r || s, 32 bytes each.
const ProofLength = 64

// ProofMessage is the signed message of a node key proof: the domain, the purpose, the SHA-256 of the audience (the full canonical
// center URL, which is not sent: the center uses its own public base URL in this position), the node ID's 16 bytes, then the binding.
// Every field before the binding has a fixed length.
func ProofMessage(purpose byte, audience string, nodeID platform.ID, binding []byte) []byte {
	audienceDigest := sha256.Sum256([]byte(audience))
	message := make([]byte, 0, len(ProofDomain)+1+len(audienceDigest)+len(nodeID)+len(binding))
	message = append(message, ProofDomain...)
	message = append(message, purpose)
	message = append(message, audienceDigest[:]...)
	message = append(message, nodeID[:]...)
	return append(message, binding...)
}

// CompleteBinding is the binding of CompleteNodeSignIn's proof: the flow ID's 16 bytes, then the code as presented.
func CompleteBinding(flowID platform.ID, code string) []byte {
	return append(append(make([]byte, 0, len(flowID)+len(code)), flowID[:]...), code...)
}

// halfOrder is n/2 of P-256: a proof's s must not exceed it (low-S).
var halfOrder = new(big.Int).Rsh(elliptic.P256().Params().N, 1)

// VerifyNodeKeyProof reports whether proof is a valid node key proof of message by the node key publicKey (the PKIX DER of a P-256
// key): 64 bytes r || s with r and s in [1, n-1] and s <= n/2 (the node normalizes s; a high-S proof is refused), an ES256 signature
// over the SHA-256 of message.
func VerifyNodeKeyProof(publicKey, message, proof []byte) bool {
	if len(proof) != ProofLength || !ValidNodeKey(publicKey) {
		return false
	}
	parsed, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return false
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	order := elliptic.P256().Params().N
	r, s := new(big.Int).SetBytes(proof[:32]), new(big.Int).SetBytes(proof[32:])
	if r.Sign() <= 0 || r.Cmp(order) >= 0 || s.Sign() <= 0 || s.Cmp(halfOrder) > 0 {
		return false
	}
	digest := sha256.Sum256(message)
	return ecdsa.Verify(key, digest[:], r, s)
}
