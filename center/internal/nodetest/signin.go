// SPDX-License-Identifier: AGPL-3.0-only

package nodetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/url"
	"strconv"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// SignIn is what a node keeps of a browser sign-in it starts: its PKCE verifier and challenge, its loopback redirect and its state.
type SignIn struct {
	Verifier    string
	Challenge   string
	RedirectURI string
	State       string
}

// NewSignIn draws a node's PKCE pair (a 43-character verifier and its S256 challenge), a loopback redirect on a port of the range,
// and a 43-character state, as the node does at BeginNodeSignIn.
func NewSignIn() SignIn {
	verifier := randomText(32)
	digest := sha256.Sum256([]byte(verifier))
	port, err := rand.Int(rand.Reader, big.NewInt(65535-1024+1))
	if err != nil {
		panic(err)
	}
	return SignIn{Verifier: verifier, Challenge: base64.RawURLEncoding.EncodeToString(digest[:]),
		RedirectURI: "http://127.0.0.1:" + strconv.FormatInt(port.Int64()+1024, 10) + "/callback", State: randomText(32)}
}

func randomText(size int) string {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

// BeginRequest is the node's BeginNodeSignIn request for a sign-in.
func (n *Node) BeginRequest(signIn SignIn) *fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest {
	return &fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest{Meta: &foundationv1.RequestMeta{}, CodeChallenge: proto.String(signIn.Challenge),
		RedirectUri: proto.String(signIn.RedirectURI), Node: n.Info(), State: proto.String(signIn.State), NodePublicKey: append([]byte(nil), n.PublicKey...)}
}

// DerivedAuthorizeURL is the consent URL a node derives from its configured center for a flow ID (C0: <center>/connect#flow=<flow_id>
// with the lower-case 8-4-4-4-12 hex form of the 16 bytes in order); the node requires the center's string to equal it.
func DerivedAuthorizeURL(center string, flowID []byte) string {
	return fmt.Sprintf("%s/connect#flow=%x-%x-%x-%x-%x", center, flowID[0:4], flowID[4:6], flowID[6:8], flowID[8:10], flowID[10:16])
}

// LoopbackCode reads what the browser brings to the node's loopback receiver: the redirect must be the node's own redirect URI with
// exactly code and state, the state the node's; it returns the code. A denial (error=access_denied) is an error.
func (s SignIn) LoopbackCode(redirect string) (string, error) {
	parsed, err := url.Parse(redirect)
	if err != nil {
		return "", err
	}
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != s.RedirectURI || parsed.Fragment != "" {
		return "", fmt.Errorf("the redirect %q is not the node's loopback %q", redirect, s.RedirectURI)
	}
	query := parsed.Query()
	if query.Get("state") != s.State {
		return "", fmt.Errorf("the redirect carries another state")
	}
	if query.Get("error") != "" {
		return "", fmt.Errorf("the sign-in was refused: %s", query.Get("error"))
	}
	if len(query) != 2 || len(query.Get("code")) != 43 {
		return "", fmt.Errorf("the redirect %q carries more than a code and the state", redirect)
	}
	return query.Get("code"), nil
}

// The node key proof (C0, fleet.proto "Node key proof"): its domain and purposes, as the node builds it.
const (
	proofDomain   = "ArcForges node-key-proof v1\n"
	proofComplete = 0x01
)

// CompleteProof is the node key proof of a CompleteNodeSignIn: ES256 over domain || 0x01 || SHA-256(audience) || node ID || flow ID ||
// code, the audience being the center the node is configured with (never a value from a center's reply), r || s with s normalized to
// the lower half of the order.
func (n *Node) CompleteProof(audience string, flowID platform.ID, code string) []byte {
	return n.Sign(proofComplete, audience, append(append([]byte(nil), flowID[:]...), code...))
}

// Sign is a node key proof of any purpose and binding (the tests also build proofs a node never sends).
func (n *Node) Sign(purpose byte, audience string, binding []byte) []byte {
	return n.SignMessage(ProofMessage(purpose, audience, n.ID, binding), true)
}

// ProofMessage is the signed message of a node key proof.
func ProofMessage(purpose byte, audience string, nodeID platform.ID, binding []byte) []byte {
	audienceDigest := sha256.Sum256([]byte(audience))
	message := append([]byte(proofDomain), purpose)
	message = append(message, audienceDigest[:]...)
	message = append(message, nodeID[:]...)
	return append(message, binding...)
}

// SignMessage signs a message with the node key in IEEE P1363 form; lowS false keeps a high s (the center refuses it).
func (n *Node) SignMessage(message []byte, lowS bool) []byte {
	digest := sha256.Sum256(message)
	order := elliptic.P256().Params().N
	half := new(big.Int).Rsh(order, 1)
	r, s, err := ecdsa.Sign(rand.Reader, n.Key, digest[:])
	if err != nil {
		panic(err)
	}
	// (r, n-s) is the same signature: the node normalizes to the lower half (a test asks for the upper half to see it refused).
	if high := s.Cmp(half) > 0; high == lowS {
		s = new(big.Int).Sub(order, s)
	}
	proof := make([]byte, 64)
	r.FillBytes(proof[:32])
	s.FillBytes(proof[32:])
	return proof
}

// CompleteRequest is the node's CompleteNodeSignIn request.
func (n *Node) CompleteRequest(flowID platform.ID, code string, signIn SignIn, proof []byte) *fleetv1.NodeEnrollmentServiceCompleteNodeSignInRequest {
	return &fleetv1.NodeEnrollmentServiceCompleteNodeSignInRequest{Meta: &foundationv1.RequestMeta{}, FlowId: &foundationv1.Id{Value: append([]byte(nil), flowID[:]...)},
		Code: proto.String(code), CodeVerifier: proto.String(signIn.Verifier), NodeKeyProof: proof}
}
