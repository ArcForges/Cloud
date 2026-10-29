// SPDX-License-Identifier: AGPL-3.0-only

package identityapi_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"

	"github.com/ArcForges/Cloud/center/internal/identity/passkey/virtual"
)

// TestConcurrentWrongCodesNeverPassTheAddressLimit (E6): twenty-five wrong codes sent at once over five flows of one address (five
// attempts each) reach the code check exactly the address's limit of times (ten); the rest are refused rate_limited, and the bucket
// never counts past the limit.
func TestConcurrentWrongCodesNeverPassTheAddressLimit(t *testing.T) {
	h := newHarness(t, settings{policy: `{"signInPerPrefixLimit": 1000, "emailPerAddressLimit": 100, "emailPerPrefixLimit": 100}`})
	address := "contended@example.org"
	h.seedAccount(1, address)
	h.remember(address)
	var flows []*foundationv1.Id
	for range 5 {
		flow := h.beginEmail(address, caller{}).GetValue().GetChallenge().GetFlowId()
		if refusal := h.requestCode(flow, address, caller{}).GetError(); refusal != nil {
			t.Fatalf("send: %s", failure(refusal))
		}
		flows = append(flows, flow)
	}
	var wait sync.WaitGroup
	var mu sync.Mutex
	outcomes := map[string]int{}
	for index := range 25 {
		wait.Go(func() {
			result := failure(h.redeem(flows[index%5], "ZZZZ-ZZZZ", caller{}).GetError())
			mu.Lock()
			outcomes[result]++
			mu.Unlock()
		})
	}
	wait.Wait()
	if outcomes["AUTHENTICATION/unauthenticated"] != 10 || outcomes["RESOURCE/rate_limited"] != 15 {
		t.Fatalf("outcomes %v", outcomes)
	}
	digest := sha256.Sum256([]byte(address))
	bucket := sha256.Sum256([]byte("redeem_failures_address\x00" + hex.EncodeToString(digest[:])))
	if count := h.count("SELECT count FROM platform.rate_limit WHERE bucket_hash = $1", bucket[:]); count != 10 {
		t.Fatalf("the address's failure count %d", count)
	}
	// A right code is no failure: its reservation is given back with its sign-in.
	h.exec("UPDATE platform.rate_limit SET count = 5 WHERE bucket_hash = '\\x" + hex.EncodeToString(bucket[:]) + "'")
	flow := h.beginEmail(address, caller{}).GetValue().GetChallenge().GetFlowId()
	h.requestCode(flow, address, caller{})
	if response := h.redeem(flow, h.lastCode(address), caller{}); response.GetError() != nil {
		t.Fatalf("the right code: %s", failure(response.GetError()))
	}
	if count := h.count("SELECT count FROM platform.rate_limit WHERE bucket_hash = $1", bucket[:]); count != 5 {
		t.Fatalf("a right code counted as a failure: %d", count)
	}
	h.verifyAudit()
}

// TestAnonymousFailuresAreAuditedOncePerPrefix (E10): failures whose bucket key the client chooses (unknown credential IDs, e-mail
// addresses) are audited once per client prefix and window, whatever keys they name; failures that name an account are audited once
// per account and window.
func TestAnonymousFailuresAreAuditedOncePerPrefix(t *testing.T) {
	h := newHarness(t, settings{policy: `{"signInPerPrefixLimit": 1000, "emailPerAddressLimit": 100, "emailPerPrefixLimit": 100}`})
	stranger := h.seedAccount(1, "")
	unknown := func(ip string) {
		t.Helper()
		credential := virtual.New(rpID, origin)
		_, key := credential.Create(randomBytes(t, 32), stranger.handle)
		challenge := h.beginPasskey(newClaim(t), caller{ip: ip})
		response := rpc(h, completePath, &publicapiv1.IdentityServiceCompleteAuthenticationRequest{Meta: meta(), FlowId: challenge.GetFlowId(),
			Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_Passkey{Passkey: assertionOf(credential.Assert(key, challenge.GetChallenge()))}}},
			caller{ip: ip}, &publicapiv1.IdentityServiceCompleteAuthenticationResponse{})
		if failure(response.GetError()) != "AUTHENTICATION/unauthenticated" {
			t.Fatalf("an unknown credential: %s", failure(response.GetError()))
		}
	}
	failed := func() int { return h.audits("identity.sign_in.failed") }
	for range 6 {
		unknown("192.0.2.10")
	}
	if failed() != 1 {
		t.Fatalf("six unknown credentials from one prefix: %d audits", failed())
	}
	unknown("198.51.100.10")
	unknown("198.51.100.11")
	if failed() != 2 {
		t.Fatalf("a second prefix: %d audits", failed())
	}
	// Failures naming an account: the account's first failure is audited, from a prefix already audited too.
	for range 3 {
		challenge := h.beginPasskey(newClaim(t), caller{ip: "192.0.2.20"})
		bad := stranger.authenticator.Assert(stranger.key, randomBytes(t, 32))
		response := rpc(h, completePath, &publicapiv1.IdentityServiceCompleteAuthenticationRequest{Meta: meta(), FlowId: challenge.GetFlowId(),
			Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_Passkey{Passkey: assertionOf(bad)}}}, caller{ip: "192.0.2.20"},
			&publicapiv1.IdentityServiceCompleteAuthenticationResponse{})
		if failure(response.GetError()) != "AUTHENTICATION/unauthenticated" {
			t.Fatalf("a wrong proof of an account: %s", failure(response.GetError()))
		}
	}
	if failed() != 3 {
		t.Fatalf("an account's failures: %d audits", failed())
	}
	// Wrong e-mail codes for different addresses from one prefix are one event.
	for index := range 4 {
		address := fmt.Sprintf("guess%d@example.org", index)
		h.remember(address)
		flow := h.beginEmail(address, caller{ip: "203.0.113.30"}).GetValue().GetChallenge().GetFlowId()
		h.requestCode(flow, address, caller{ip: "203.0.113.30"})
		if result := failure(h.redeem(flow, "BCDF-GHJK", caller{ip: "203.0.113.30"}).GetError()); result != "AUTHENTICATION/unauthenticated" {
			t.Fatalf("a wrong code: %s", result)
		}
	}
	if failed() != 4 {
		t.Fatalf("wrong codes of four addresses from one prefix: %d audits", failed())
	}
	h.verifyAudit()
}
