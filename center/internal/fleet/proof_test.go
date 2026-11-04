// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/oneuse"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// EVIDENCE: REAL (the center's verifier) against a MOCKED node (center/internal/nodetest: a software ES256 key that builds the proof
// as the node does).

const audience = "https://center.example.test/api"

// TestTheProofMessageIsTheContractLayout pins the preimage byte for byte (C0, fleet.proto "Node key proof"): 28 ASCII bytes of the
// domain, the purpose, the SHA-256 of the audience, the node ID, then the flow ID and the code; and the node's builder agrees.
func TestTheProofMessageIsTheContractLayout(t *testing.T) {
	nodeID, flowID := platform.NewID(), platform.NewID()
	code, _ := oneuse.NewCode()
	message := ProofMessage(ProofComplete, audience, nodeID, CompleteBinding(flowID, code))
	digest := sha256.Sum256([]byte(audience))
	want := append(append(append(append([]byte("ArcForges node-key-proof v1\n"), 0x01), digest[:]...), nodeID[:]...), append(flowID[:], code...)...)
	if len(ProofDomain) != 28 || len(message) != 28+1+32+16+16+43 || !bytes.Equal(message, want) {
		t.Fatalf("message %x", message)
	}
	if !bytes.Equal(message, nodetest.ProofMessage(0x01, audience, nodeID, CompleteBinding(flowID, code))) {
		t.Fatal("the node's builder and the center's disagree")
	}
}

// TestKeyProofVectors (E1-9; protocol-4 corrected fix, C0 E-2/E-3): a proof verifies only for its own message, purpose, audience,
// node, flow, code and key, only as 64 bytes r || s with r and s in [1, n-1] and s in the lower half of the order.
func TestKeyProofVectors(t *testing.T) {
	node, err := nodetest.New()
	if err != nil {
		t.Fatal(err)
	}
	other, err := nodetest.New()
	if err != nil {
		t.Fatal(err)
	}
	flowID := platform.NewID()
	code, _ := oneuse.NewCode()
	otherCode, _ := oneuse.NewCode()
	message := ProofMessage(ProofComplete, audience, node.ID, CompleteBinding(flowID, code))
	proof := node.CompleteProof(audience, flowID, code)
	if !VerifyNodeKeyProof(node.PublicKey, message, proof) {
		t.Fatal("the node's proof does not verify")
	}
	refused := map[string][]byte{
		"another path of the same host":  ProofMessage(ProofComplete, "https://center.example.test/other", node.ID, CompleteBinding(flowID, code)),
		"the origin without the path":    ProofMessage(ProofComplete, "https://center.example.test", node.ID, CompleteBinding(flowID, code)),
		"another host":                   ProofMessage(ProofComplete, "https://other.example.test/api", node.ID, CompleteBinding(flowID, code)),
		"a trailing slash":               ProofMessage(ProofComplete, audience+"/", node.ID, CompleteBinding(flowID, code)),
		"the device-code purpose":        ProofMessage(ProofPoll, audience, node.ID, CompleteBinding(flowID, code)),
		"another flow":                   ProofMessage(ProofComplete, audience, node.ID, CompleteBinding(platform.NewID(), code)),
		"another node ID":                ProofMessage(ProofComplete, audience, other.ID, CompleteBinding(flowID, code)),
		"another code":                   ProofMessage(ProofComplete, audience, node.ID, CompleteBinding(flowID, otherCode)),
		"the binding without the flow":   ProofMessage(ProofComplete, audience, node.ID, []byte(code)),
		"the message without its domain": message[len(ProofDomain):],
	}
	for name, candidate := range refused {
		if VerifyNodeKeyProof(node.PublicKey, candidate, proof) {
			t.Errorf("%s verified", name)
		}
	}
	if VerifyNodeKeyProof(other.PublicKey, message, proof) {
		t.Error("another key verified the proof")
	}
	if VerifyNodeKeyProof(other.PublicKey, message, other.CompleteProof(audience, flowID, code)) {
		t.Error("another node's own proof verified for this node's message")
	}
	order := elliptic.P256().Params().N
	r, s := new(big.Int).SetBytes(proof[:32]), new(big.Int).SetBytes(proof[32:])
	high := make([]byte, 64)
	copy(high, proof[:32])
	new(big.Int).Sub(order, s).FillBytes(high[32:])
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal(err)
	}
	zeroR, zeroS, bigR := append([]byte(nil), proof...), append([]byte(nil), proof...), append([]byte(nil), proof...)
	for i := range 32 {
		zeroR[i], zeroS[32+i] = 0, 0
	}
	order.FillBytes(bigR[:32])
	for name, candidate := range map[string][]byte{
		"the high-S twin of a valid proof": high, "the node's own high-S proof": node.SignMessage(message, false), "63 bytes": proof[:63],
		"65 bytes": append(append([]byte(nil), proof...), 0), "an ASN.1 DER signature": der, "r = 0": zeroR, "s = 0": zeroS, "r = n": bigR,
		"empty": nil,
	} {
		if VerifyNodeKeyProof(node.PublicKey, message, candidate) {
			t.Errorf("%s verified", name)
		}
	}
	if s.Cmp(new(big.Int).Rsh(order, 1)) > 0 {
		t.Fatal("the node did not normalize s")
	}
	if VerifyNodeKeyProof(node.PublicKey[:90], message, proof) || VerifyNodeKeyProof(nil, message, proof) {
		t.Error("a malformed key verified")
	}
	if VerifyNodeKeyProof([]byte(strings.Repeat("x", 91)), message, proof) {
		t.Error("91 bytes that are no P-256 DER verified")
	}
}
