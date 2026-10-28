// SPDX-License-Identifier: AGPL-3.0-only

package identityapi_test

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
)

const (
	requestCodePath = "/arcforges.publicapi.v1.IdentityService/RequestEmailCode"
	redeemPath      = "/arcforges.publicapi.v1.IdentityService/RedeemEmailCode"
)

var codePattern = regexp.MustCompile(`code is ([A-Z]{4})-([A-Z]{4})\.`)

func (h *harness) beginEmail(address string, from caller) *publicapiv1.IdentityServiceBeginAuthenticationResponse {
	h.t.Helper()
	return rpc(h, beginPath, &publicapiv1.IdentityServiceBeginAuthenticationRequest{Meta: meta(), Method: publicapiv1.AuthMethod_AUTH_METHOD_EMAIL.Enum(),
		Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_AUTHENTICATE.Enum(), LoginHint: proto.String(address), Installation: newClaim(h.t)}, from,
		&publicapiv1.IdentityServiceBeginAuthenticationResponse{})
}

func (h *harness) requestCode(flow *foundationv1.Id, address string, from caller) *publicapiv1.IdentityServiceRequestEmailCodeResponse {
	h.t.Helper()
	return rpc(h, requestCodePath, &publicapiv1.IdentityServiceRequestEmailCodeRequest{Meta: meta(), FlowId: flow, Email: proto.String(address),
		Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_AUTHENTICATE.Enum()}, from, &publicapiv1.IdentityServiceRequestEmailCodeResponse{})
}

func (h *harness) redeem(flow *foundationv1.Id, code string, from caller) *publicapiv1.IdentityServiceRedeemEmailCodeResponse {
	h.t.Helper()
	response := rpc(h, redeemPath, &publicapiv1.IdentityServiceRedeemEmailCodeRequest{Meta: meta(), FlowId: flow, Code: proto.String(code)}, from,
		&publicapiv1.IdentityServiceRedeemEmailCodeResponse{})
	if value := response.GetValue().GetSession(); value != nil {
		h.remember(value.GetAccessToken(), value.GetRefreshToken())
	}
	return response
}

// lastCode is the code of the newest fake message to an address.
func (h *harness) lastCode(address string) string {
	h.t.Helper()
	messages := h.mail.Messages()
	for index := len(messages) - 1; index >= 0; index-- {
		if messages[index].To == address {
			match := codePattern.FindStringSubmatch(messages[index].Text)
			if match == nil {
				h.t.Fatal("a message without a code")
			}
			h.remember(match[1]+match[2], match[1]+"-"+match[2])
			return match[1] + "-" + match[2]
		}
	}
	h.t.Fatalf("no message to the address")
	return ""
}

func TestTheEmailCodeClosedLoop(t *testing.T) {
	h := newHarness(t, settings{policy: `{"emailPerAddressLimit": 100, "emailPerPrefixLimit": 100}`})
	address := "grace@example.org"
	who := h.seedAccount(1, address)
	h.remember(address)
	begun := h.beginEmail("Grace@Example.ORG", caller{})
	if begun.GetError() != nil {
		t.Fatalf("begin: %s", failure(begun.GetError()))
	}
	challenge := begun.GetValue().GetChallenge()
	if challenge.GetMethod() != publicapiv1.AuthMethod_AUTH_METHOD_EMAIL || challenge.GetOptions() != nil || len(challenge.GetChallenge()) != 32 ||
		challenge.RpId != nil || len(h.mail.Messages()) != 0 {
		t.Fatalf("begin(EMAIL) sends nothing and returns a flow: %v", challenge)
	}
	// RequestEmailCode needs the flow and the same address and purpose.
	if result := failure(h.requestCode(nil, address, caller{}).GetError()); result != "VALIDATION/invalid_argument" {
		t.Fatalf("no flow: %s", result)
	}
	if result := failure(h.requestCode(challenge.GetFlowId(), "other@example.org", caller{}).GetError()); result != "STATE/not_found" {
		t.Fatalf("another address: %s", result)
	}
	sent := h.requestCode(challenge.GetFlowId(), address, caller{})
	if sent.GetError() != nil || len(h.mail.Messages()) != 1 {
		t.Fatalf("send: %s", failure(sent.GetError()))
	}
	first := h.lastCode(address)
	// A resend replaces the code; the old one no longer works and the attempt counts.
	if h.requestCode(challenge.GetFlowId(), address, caller{}).GetError() != nil {
		t.Fatal("resend")
	}
	second := h.lastCode(address)
	if first != second {
		if result := failure(h.redeem(challenge.GetFlowId(), first, caller{}).GetError()); result != "AUTHENTICATION/unauthenticated" {
			t.Fatalf("the replaced code: %s", result)
		}
	}
	redeemed := h.redeem(challenge.GetFlowId(), strings.ToLower(second), caller{})
	if redeemed.GetError() != nil {
		t.Fatalf("redeem: %s", failure(redeemed.GetError()))
	}
	native := redeemed.GetValue().GetSession()
	var method int16
	if err := h.migration.QueryRow(context.Background(), "SELECT auth_method FROM identity.session WHERE user_id = $1", who.id).Scan(&method); err != nil || method != 2 {
		t.Fatalf("the session's method %d %v", method, err)
	}
	if rpc(h, profilePath, &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, caller{bearer: native.GetAccessToken()},
		&publicapiv1.IdentityServiceGetProfileResponse{}).GetValue().GetProfile().GetPrimaryEmail() != address {
		t.Fatal("the profile after an e-mail sign-in")
	}
	// The flow is consumed: the code again is code_reused, a resend is refused.
	if result := failure(h.redeem(challenge.GetFlowId(), second, caller{}).GetError()); result != "CONFLICT/code_reused" {
		t.Fatalf("a redeemed code again: %s", result)
	}
	if result := failure(h.requestCode(challenge.GetFlowId(), address, caller{}).GetError()); result != "CONFLICT/code_reused" {
		t.Fatalf("a resend of a consumed flow: %s", result)
	}

	// CompleteAuthentication accepts an e-mail code on an e-mail flow.
	other := h.beginEmail(address, caller{}).GetValue().GetChallenge()
	h.requestCode(other.GetFlowId(), address, caller{})
	completed := rpc(h, completePath, &publicapiv1.IdentityServiceCompleteAuthenticationRequest{Meta: meta(), FlowId: other.GetFlowId(),
		Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_EmailCode{EmailCode: h.lastCode(address)}}}, caller{},
		&publicapiv1.IdentityServiceCompleteAuthenticationResponse{})
	if completed.GetError() != nil {
		t.Fatalf("CompleteAuthentication with an e-mail code: %s", failure(completed.GetError()))
	}
	h.remember(completed.GetValue().GetSession().GetAccessToken(), completed.GetValue().GetSession().GetRefreshToken())

	// Sends are capped per flow and never reset the attempts.
	capped := h.beginEmail(address, caller{ip: "198.51.100.40"}).GetValue().GetChallenge()
	for range 3 {
		if h.requestCode(capped.GetFlowId(), address, caller{ip: "198.51.100.40"}).GetError() != nil {
			t.Fatal("a send within the cap")
		}
	}
	if result := h.requestCode(capped.GetFlowId(), address, caller{ip: "198.51.100.40"}).GetError(); failure(result) != "RESOURCE/rate_limited" ||
		result.GetDetails().GetLimit().GetLimitName() != "email_code_sends" {
		t.Fatalf("a fourth send: %v", result)
	}
	// Wrong codes exhaust the flow after its attempts; the flow is then expired.
	for range 5 {
		if result := failure(h.redeem(capped.GetFlowId(), "BBBB-BBBB", caller{ip: "198.51.100.40"}).GetError()); result != "AUTHENTICATION/unauthenticated" {
			t.Fatalf("a wrong code: %s", result)
		}
	}
	if result := failure(h.redeem(capped.GetFlowId(), h.lastCode(address), caller{ip: "198.51.100.40"}).GetError()); result != "STATE/expired" {
		t.Fatalf("the right code after the attempts: %s", result)
	}
	// An expired flow.
	late := h.beginEmail(address, caller{}).GetValue().GetChallenge()
	h.requestCode(late.GetFlowId(), address, caller{})
	h.clock.Advance(11 * time.Minute)
	if result := failure(h.redeem(late.GetFlowId(), h.lastCode(address), caller{}).GetError()); result != "STATE/expired" {
		t.Fatalf("an expired flow: %s", result)
	}
	h.verifyAudit()
}

// TestAnUnknownAddressLooksLikeAKnownOne checks SEC-05: an address without an account gets the same reply (apart from its IDs and
// instants), the same statements and no mail; its codes never sign in.
func TestAnUnknownAddressLooksLikeAKnownOne(t *testing.T) {
	h := newHarness(t, settings{})
	known, unknown := "known@example.org", "unknown@example.org"
	h.seedAccount(1, known)
	h.remember(known, unknown)
	admin := pgtest.Connect(t, pgtest.WithDatabase(t, pgtest.ServerURL(t), h.database))
	if _, err := admin.Exec(context.Background(), "CREATE EXTENSION IF NOT EXISTS pg_stat_statements"); err != nil {
		t.Fatalf("the test server must preload pg_stat_statements: %v", err)
	}
	statements := func(run func()) map[int64]int64 {
		t.Helper()
		read := func() map[int64]int64 {
			rows, err := admin.Query(context.Background(), `SELECT queryid, calls FROM pg_stat_statements
WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database()) AND userid <> (SELECT usesysid FROM pg_user WHERE usename = current_user)`)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			result := map[int64]int64{}
			for rows.Next() {
				var id, calls int64
				if err = rows.Scan(&id, &calls); err != nil {
					t.Fatal(err)
				}
				result[id] += calls
			}
			return result
		}
		before := read()
		run()
		after := read()
		delta := map[int64]int64{}
		for id, calls := range after {
			if calls != before[id] {
				delta[id] = calls - before[id]
			}
		}
		return delta
	}
	flows := map[string]*foundationv1.Id{}
	for _, address := range []string{known, unknown} {
		flows[address] = h.beginEmail(address, caller{}).GetValue().GetChallenge().GetFlowId()
	}
	// Warm both paths once so a first-use statement is not counted on one side only.
	h.requestCode(flows[known], known, caller{})
	h.requestCode(flows[unknown], unknown, caller{})
	var replies [2]*publicapiv1.IdentityServiceRequestEmailCodeResponse
	sequences := [2]map[int64]int64{}
	for index, address := range []string{known, unknown} {
		sequences[index] = statements(func() { replies[index] = h.requestCode(flows[address], address, caller{}) })
	}
	if len(sequences[0]) == 0 || len(sequences[0]) != len(sequences[1]) {
		t.Fatalf("statement sets differ: %v %v", sequences[0], sequences[1])
	}
	for id, calls := range sequences[0] {
		if sequences[1][id] != calls {
			t.Fatalf("statement %d: %d calls for a known address, %d for an unknown one", id, calls, sequences[1][id])
		}
	}
	for index := range replies {
		value := replies[index].GetValue().GetChallenge()
		if replies[index].GetError() != nil || value == nil {
			t.Fatal("a reply failed")
		}
		value.FlowId, value.Challenge, value.ExpiresAt = nil, nil, nil
		replies[index].Meta = nil
	}
	if !proto.Equal(replies[0], replies[1]) {
		t.Fatalf("the replies differ:\n%v\n%v", replies[0], replies[1])
	}
	for _, message := range h.mail.Messages() {
		if message.To == unknown {
			t.Fatal("a message to an unknown address")
		}
	}
	// A guessed code for the unknown address is refused like any wrong code.
	if result := failure(h.redeem(flows[unknown], "BCDF-GHJK", caller{}).GetError()); result != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("a code for an unknown address: %s", result)
	}
}

// TestParallelGuessesNeverExceedTheAttempts checks SEC-06: fifty concurrent wrong codes on one flow reach the code check at most
// the flow's attempts times; every other guess is refused before it.
func TestParallelGuessesNeverExceedTheAttempts(t *testing.T) {
	h := newHarness(t, settings{policy: `{"signInPerPrefixLimit": 1000, "redeemFailuresAddressLimit": 1000}`})
	address := "parallel@example.org"
	h.seedAccount(1, address)
	flow := h.beginEmail(address, caller{}).GetValue().GetChallenge().GetFlowId()
	h.requestCode(flow, address, caller{})
	var wait sync.WaitGroup
	var mu sync.Mutex
	outcomes := map[string]int{}
	for range 50 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result := failure(h.redeem(flow, "ZZZZ-ZZZZ", caller{}).GetError())
			mu.Lock()
			outcomes[result]++
			mu.Unlock()
		}()
	}
	wait.Wait()
	if outcomes["AUTHENTICATION/unauthenticated"] != 5 || outcomes["AUTHENTICATION/unauthenticated"]+outcomes["STATE/expired"]+outcomes["CONFLICT/code_reused"] != 50 {
		t.Fatalf("outcomes %v", outcomes)
	}
	var attempts int
	if err := h.migration.QueryRow(context.Background(), "SELECT attempts FROM identity.auth_flow WHERE kind = 4 AND sends = 1").Scan(&attempts); err != nil || attempts != 5 {
		t.Fatalf("attempts %d %v", attempts, err)
	}
}

func TestDisabledMailIsNotOffered(t *testing.T) {
	h := newHarness(t, settings{mailOff: true})
	listed := rpc(h, providers, &publicapiv1.IdentityServiceListAuthProvidersRequest{Meta: meta()}, caller{}, &publicapiv1.IdentityServiceListAuthProvidersResponse{})
	if len(listed.GetValue().GetProviders()) != 1 || listed.GetValue().GetProviders()[0].GetProviderId() != "passkey" || listed.GetValue().GetProviders()[0].GetEnrollment() {
		t.Fatalf("providers %v", listed)
	}
	begun := h.beginEmail("a@example.org", caller{})
	if failure(begun.GetError()) != "VALIDATION/invalid_argument" || begun.GetError().GetDetails().GetState().GetReason() != "method: not_offered" {
		t.Fatalf("begin(EMAIL): %v", begun.GetError())
	}
	if result := h.requestCode(&foundationv1.Id{Value: randomBytes(t, 16)}, "a@example.org", caller{}).GetError(); result.GetDetails().GetState().GetReason() != "method: not_offered" {
		t.Fatalf("RequestEmailCode: %v", result)
	}
	enabled := newHarness(t, settings{})
	listed = rpc(enabled, providers, &publicapiv1.IdentityServiceListAuthProvidersRequest{Meta: meta()}, caller{}, &publicapiv1.IdentityServiceListAuthProvidersResponse{})
	if len(listed.GetValue().GetProviders()) != 2 || listed.GetValue().GetProviders()[1].GetMethod() != publicapiv1.AuthMethod_AUTH_METHOD_EMAIL {
		t.Fatalf("providers with mail %v", listed)
	}
}
