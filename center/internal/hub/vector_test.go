// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// helloVector is testdata/relay-hello-vector.json: the hello vector of the C2 relay vectors (Contracts e67a6b0), copied value for value.
type helloVector struct {
	Source         string `json:"source"`
	SourceSHA256   string `json:"sourceSha256"`
	Audience       string `json:"audience"`
	AudienceSHA256 string `json:"audienceSha256"`
	HelloDomain    string `json:"helloDomain"`
	NodeSPKI       string `json:"nodeSpki"`
	IDs            struct {
		Node         string `json:"node"`
		Installation string `json:"installation"`
		Connection   string `json:"connection"`
	} `json:"ids"`
	Hello struct {
		ChallengeFrame string  `json:"challengeFrame"`
		Nonce          string  `json:"nonce"`
		HelloDeadline  []int64 `json:"helloDeadline"`
		HelloFrame     string  `json:"helloFrame"`
		SigningInput   string  `json:"signingInput"`
		Signature      string  `json:"signature"`
		Version        string  `json:"version"`
		HighSSignature string  `json:"highSSignature"`
	} `json:"hello"`
}

// TestTheHelloMatchesTheContractsVector (review A N-3; EVIDENCE: REAL hub code over the FIXED C2 golden vector): the hub's own
// HelloMessage of the vector's nonce, connection, audience, node and installation is the vector's 137-byte signing input; the hub's
// codec encodes the vector's challenge frame byte for byte and decodes its hello frame to the vector's IDs and signature; and the
// center's verifier accepts the vector's signature with the vector's node key and refuses its high-S twin. nodetest.HelloMessage is a
// second copy of the layout by the same author, so only this vector catches a mistake both share.
func TestTheHelloMatchesTheContractsVector(t *testing.T) {
	data, err := os.ReadFile("testdata/relay-hello-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector helloVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	decode := func(text string) []byte {
		t.Helper()
		raw, err := hex.DecodeString(text)
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		return raw
	}
	id := func(text string) platform.ID {
		t.Helper()
		var value platform.ID
		raw := decode(text)
		if len(raw) != len(value) {
			t.Fatalf("%q is not an ID", text)
		}
		copy(value[:], raw)
		return value
	}
	if vector.HelloDomain != HelloDomain {
		t.Fatalf("the hello domain: %q, the hub's %q", vector.HelloDomain, HelloDomain)
	}
	if audience := sha256.Sum256([]byte(vector.Audience)); hex.EncodeToString(audience[:]) != vector.AudienceSHA256 {
		t.Fatal("the vector's audience digest")
	}
	nonce, connection := decode(vector.Hello.Nonce), id(vector.IDs.Connection)
	node, installation := id(vector.IDs.Node), id(vector.IDs.Installation)
	if len(nonce) != NonceBytes {
		t.Fatalf("the vector's nonce has %d bytes", len(nonce))
	}
	message := HelloMessage(nonce, connection, vector.Audience, node, installation)
	if want := decode(vector.Hello.SigningInput); !bytes.Equal(message, want) || len(message) != 137 {
		t.Fatalf("HelloMessage of the vector:\n%x\nwant\n%x", message, want)
	}
	var codec RelayCodec
	if len(vector.Hello.HelloDeadline) != 2 {
		t.Fatal("the vector's hello deadline")
	}
	deadline := time.Unix(vector.Hello.HelloDeadline[0], vector.Hello.HelloDeadline[1]).UTC()
	challenge, err := codec.Challenge(1, nonce, connection, deadline)
	if err != nil || !bytes.Equal(challenge, decode(vector.Hello.ChallengeFrame)) {
		t.Fatalf("the challenge frame:\n%x %v\nwant\n%s", challenge, err, vector.Hello.ChallengeFrame)
	}
	frame, err := codec.Decode(decode(vector.Hello.HelloFrame))
	signature := decode(vector.Hello.Signature)
	if err != nil || frame.kind != inboundHello || frame.hello.Malformed || frame.hello.NodeID != node || frame.hello.InstallationID != installation ||
		!bytes.Equal(frame.hello.Signature, signature) {
		t.Fatalf("the hello frame decodes to %+v %v", frame.hello, err)
	}
	key := decode(vector.NodeSPKI)
	if !fleet.VerifyNodeKeyProof(key, message, signature) {
		t.Fatal("the vector's signature is refused")
	}
	if fleet.VerifyNodeKeyProof(key, message, decode(vector.Hello.HighSSignature)) {
		t.Fatal("the vector's high-S signature is accepted")
	}
	if fleet.VerifyNodeKeyProof(key, HelloMessage(nonce, connection, "https://other.example/api", node, installation), signature) {
		t.Fatal("the signature verifies for another audience")
	}
}
