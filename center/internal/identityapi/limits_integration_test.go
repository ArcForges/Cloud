// SPDX-License-Identifier: AGPL-3.0-only

package identityapi_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"google.golang.org/protobuf/proto"

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

// TestTheAnonymousFlowCeilingBoundsEveryNewFlow (C1): with the opt-in ceiling, every flow an anonymous call creates (a passkey
// sign-in, the owner's enrollment, an e-mail flow) counts in one global bucket, whatever its client; past the ceiling begin is
// RESOURCE/rate_limited with a retry instant, writes no flow, and the first refusal of the window is audited. Without the ceiling no
// global bucket is counted.
func TestTheAnonymousFlowCeilingBoundsEveryNewFlow(t *testing.T) {
	h := newHarness(t, settings{policy: `{"anonymousFlowsLimit": 3, "anonymousFlowsWindow": "10m", "signInPerPrefixLimit": 1000}`})
	begin := func(method publicapiv1.AuthMethod, purpose publicapiv1.AuthPurpose, ip string) *foundationv1.ArcError {
		t.Helper()
		request := &publicapiv1.IdentityServiceBeginAuthenticationRequest{Meta: meta(), Method: method.Enum(), Purpose: purpose.Enum(), Installation: newClaim(t)}
		if method == publicapiv1.AuthMethod_AUTH_METHOD_EMAIL {
			request.LoginHint = proto.String("someone@example.org")
		}
		return rpc(h, beginPath, request, caller{ip: ip}, &publicapiv1.IdentityServiceBeginAuthenticationResponse{}).GetError()
	}
	h.remember("someone@example.org")
	passkey, email := publicapiv1.AuthMethod_AUTH_METHOD_PASSKEY, publicapiv1.AuthMethod_AUTH_METHOD_EMAIL
	authenticate, enroll := publicapiv1.AuthPurpose_AUTH_PURPOSE_AUTHENTICATE, publicapiv1.AuthPurpose_AUTH_PURPOSE_ENROLL
	if begin(passkey, authenticate, "192.0.2.1") != nil || begin(passkey, enroll, "198.51.100.1") != nil || begin(email, authenticate, "203.0.113.1") != nil {
		t.Fatal("within the ceiling")
	}
	for _, ip := range []string{"100.64.0.1", "2001:db8::1"} {
		refusal := begin(passkey, authenticate, ip)
		if failure(refusal) != "RESOURCE/rate_limited" || refusal.GetDetails().GetLimit().GetLimitName() != "anonymous_flows" ||
			refusal.GetDetails().GetLimit().GetMaximum().GetValue() != "3" || refusal.GetRetry().GetRetryAt().GetUnixSeconds() <= h.clock.Now().Unix() {
			t.Fatalf("past the ceiling from %s: %v", ip, refusal)
		}
	}
	if h.count("SELECT count(*) FROM identity.auth_flow") != 3 || h.audits("identity.rate_limited") != 1 {
		t.Fatalf("%d flows, %d audits", h.count("SELECT count(*) FROM identity.auth_flow"), h.audits("identity.rate_limited"))
	}
	h.clock.Advance(11 * time.Minute)
	if refusal := begin(passkey, authenticate, "100.64.0.1"); refusal != nil {
		t.Fatalf("a new window: %s", failure(refusal))
	}
	h.verifyAudit()

	open := newHarness(t, settings{})
	for range 5 {
		open.beginPasskey(newClaim(t), caller{})
	}
	bucket := sha256.Sum256([]byte("anonymous_flows\x00all"))
	if open.count("SELECT count(*) FROM platform.rate_limit WHERE bucket_hash = $1", bucket[:]) != 0 {
		t.Fatal("a global bucket was counted without the ceiling")
	}
}
