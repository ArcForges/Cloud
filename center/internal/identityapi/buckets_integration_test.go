// SPDX-License-Identifier: AGPL-3.0-only

package identityapi_test

import (
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"google.golang.org/protobuf/proto"
)

// TestEveryIdentityBucketRefusesOnePastItsLimit (F12) pushes the e-mail send buckets of an address and of a prefix, the wrong-code
// bucket of an address across flows and the refresh bucket of a prefix one call past their limits: each refusal is
// RESOURCE/rate_limited naming its bucket, its maximum and a later retry_at; the request buckets audit their first refusal, and the
// wrong-code bucket refuses even the right code before a flow attempt is taken.
func TestEveryIdentityBucketRefusesOnePastItsLimit(t *testing.T) {
	h := newHarness(t, settings{policy: `{"emailPerAddressLimit": 2, "emailPerPrefixLimit": 2, "redeemFailuresAddressLimit": 2, "refreshPerPrefixLimit": 2}`})
	limited := func(refusal *foundationv1.ArcError, name string) {
		t.Helper()
		if failure(refusal) != "RESOURCE/rate_limited" || refusal.GetDetails().GetLimit().GetLimitName() != name ||
			refusal.GetDetails().GetLimit().GetMaximum().GetValue() != "2" || refusal.GetRetry().GetRetryAt().GetUnixSeconds() <= h.clock.Now().Unix() {
			t.Fatalf("%s: %v", name, refusal)
		}
	}
	// email_address: two sends to one address from two prefixes; the third, from a third prefix, is refused.
	address := "probe@example.org"
	h.seedAccount(1, address)
	h.remember(address)
	for _, ip := range []string{"192.0.2.1", "198.51.100.1"} {
		flow := h.beginEmail(address, caller{ip: ip}).GetValue().GetChallenge().GetFlowId()
		if refusal := h.requestCode(flow, address, caller{ip: ip}).GetError(); refusal != nil {
			t.Fatalf("within the address limit: %s", failure(refusal))
		}
	}
	third := h.beginEmail(address, caller{ip: "100.64.0.1"}).GetValue().GetChallenge().GetFlowId()
	limited(h.requestCode(third, address, caller{ip: "100.64.0.1"}).GetError(), "email_address")
	// email_prefix: two addresses from one /24; a third address from the same /24 is refused.
	for index, other := range []string{"a@example.org", "b@example.org", "c@example.org"} {
		flow := h.beginEmail(other, caller{ip: "203.0.113.9"}).GetValue().GetChallenge().GetFlowId()
		refusal := h.requestCode(flow, other, caller{ip: "203.0.113.9"}).GetError()
		if index < 2 && refusal != nil {
			t.Fatalf("within the prefix limit: %s", failure(refusal))
		}
		if index == 2 {
			limited(refusal, "email_prefix")
		}
	}
	// redeem_failures_address: one wrong code on each of two flows of one address; then even the right code is refused, and the
	// refused redemption takes no attempt of its flow.
	victim := "victim@example.org"
	h.seedAccount(1, victim)
	h.remember(victim)
	first := h.beginEmail(victim, caller{ip: "192.0.2.50"}).GetValue().GetChallenge().GetFlowId()
	h.requestCode(first, victim, caller{ip: "192.0.2.50"})
	second := h.beginEmail(victim, caller{ip: "198.51.100.50"}).GetValue().GetChallenge().GetFlowId()
	h.requestCode(second, victim, caller{ip: "198.51.100.50"})
	if failure(h.redeem(first, "BBBB-BBBB", caller{ip: "192.0.2.50"}).GetError()) != "AUTHENTICATION/unauthenticated" ||
		failure(h.redeem(second, "BBBB-BBBB", caller{ip: "198.51.100.50"}).GetError()) != "AUTHENTICATION/unauthenticated" {
		t.Fatal("wrong codes within the limit")
	}
	limited(h.redeem(first, h.lastCode(victim), caller{ip: "192.0.2.50"}).GetError(), "redeem_failures_address")
	var flowID [16]byte
	copy(flowID[:], first.GetValue())
	if h.count("SELECT attempts FROM identity.auth_flow WHERE flow_id = $1", flowID) != 1 {
		t.Fatal("a refused redemption took an attempt")
	}
	// refresh_prefix: two refreshes from one /24; the third is refused.
	who := h.seedAccount(1, "")
	claim := newClaim(t)
	token := h.signIn(who, claim, caller{ip: "100.64.9.1"}).GetRefreshToken()
	refresh := func() *publicapiv1.IdentityServiceRefreshSessionResponse {
		response := rpc(h, refreshPath, &publicapiv1.IdentityServiceRefreshSessionRequest{Meta: meta(), RefreshToken: proto.String(token),
			InstallationId: claim.GetInstallationId()}, caller{ip: "100.64.9.2"}, &publicapiv1.IdentityServiceRefreshSessionResponse{})
		if value := response.GetValue().GetSession(); value != nil {
			h.remember(value.GetAccessToken(), value.GetRefreshToken())
			token = value.GetRefreshToken()
		}
		return response
	}
	for range 2 {
		if refusal := refresh().GetError(); refusal != nil {
			t.Fatalf("within the refresh limit: %s", failure(refusal))
		}
	}
	limited(refresh().GetError(), "refresh_prefix")
	limited(refresh().GetError(), "refresh_prefix")
	// One audit per refused request bucket and window (email_address, email_prefix, refresh_prefix); a failure bucket's refusal is
	// not audited (its failures are).
	if h.audits("identity.rate_limited") != 3 {
		t.Fatalf("rate-limit audits %d", h.audits("identity.rate_limited"))
	}
	h.verifyAudit()
}
