// SPDX-License-Identifier: AGPL-3.0-only

package access

import (
	"context"
	"errors"
	"testing"

	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The authorizer's own verification of a node-relayed call (AF-CTR-05 E2a; Plan addendum C-N6; decisions B-4; EVIDENCE: REAL code,
// MOCKED verifier: the hub's verification is tested in package hub and through the composed center there). These calls are refused or
// admitted before any stage that reads or writes the store, so the authorizer runs without one.

type relayStub struct {
	verified     bool
	installation platform.ID
}

func (r relayStub) Verified() bool                      { return r.verified }
func (r relayStub) RelayingInstallationID() platform.ID { return r.installation }

// TestAuthorizeVerifiesTheRelayOfANodeCaller: on a relayed row, a node credential is admitted only when the authorizer's verifier
// answers a verified relay of the credential's own installation, which Authorize hands back; without a verifier, with the verifier's
// refusal, with an unverified relay or with a relay of another installation it is refused AUTHENTICATION/unauthenticated with the
// relay_assertion reason, and the claim the verifier receives is the request's (or an empty one when the request states none). An
// account session without a claim is admitted without asking the verifier.
func TestAuthorizeVerifiesTheRelayOfANodeCaller(t *testing.T) {
	installation := platform.NewID()
	node := ingress.Caller{Credential: ingress.CredentialNativeBearer, Scope: "node", UserID: platform.NewID().String(), InstallationID: installation.String()}
	call := func(caller ingress.Caller) *ingress.Call {
		return &ingress.Call{Policy: ingress.Policy{FullName: fleetv1connect.FleetServiceListNodesProcedure}, Caller: caller}
	}
	reason := func(err error) string {
		var refusal *arc.Refusal
		if !errors.As(err, &refusal) || refusal.Key() != "AUTHENTICATION/unauthenticated" || refusal.State != "relay_assertion" {
			return "not a relay refusal: " + errorText(err)
		}
		return refusal.Reason
	}
	stated := &RelayClaim{Assertion: []byte{7}, RequestSHA256: make([]byte, 32)}
	var asked []RelayClaim
	verifier := func(answer Relay, err error) RelayVerifier {
		return func(_ context.Context, credential ingress.Caller, claim RelayClaim) (Relay, error) {
			if credential.InstallationID != node.InstallationID {
				t.Error("the verifier is asked for another credential")
			}
			asked = append(asked, claim)
			return answer, err
		}
	}
	refusedByVerifier := arc.RelayAssertionRefused(arc.RelayNonceReused)
	for name, c := range map[string]struct {
		verifier RelayVerifier
		claim    *RelayClaim
		want     string
	}{
		"no verifier":                     {nil, stated, arc.RelayMissing},
		"the verifier's refusal":          {verifier(nil, refusedByVerifier), stated, arc.RelayNonceReused},
		"an unverified relay":             {verifier(relayStub{installation: installation}, nil), stated, arc.RelaySignatureInvalid},
		"a relay of another installation": {verifier(relayStub{verified: true, installation: platform.NewID()}, nil), stated, arc.RelayCredentialMismatch},
		"a nil relay":                     {verifier(nil, nil), stated, arc.RelaySignatureInvalid},
	} {
		authorizer := NewAuthorizer(nil, nil, WithRelayVerifier(c.verifier))
		if _, relay, err := authorizer.AuthorizeRelayed(context.Background(), call(node), nil, c.claim); reason(err) != c.want || relay != nil {
			t.Errorf("%s: %s", name, reason(err))
		}
	}
	asked = nil
	authorizer := NewAuthorizer(nil, nil, WithRelayVerifier(verifier(relayStub{verified: true, installation: installation}, nil)))
	if _, relay, err := authorizer.AuthorizeRelayed(context.Background(), call(node), nil, nil); err != nil || relay == nil || !relay.Verified() ||
		len(asked) != 1 || asked[0].Assertion != nil {
		t.Fatalf("a request without a claim is verified as one without an assertion: %v %v %v", relay, err, asked)
	}
	if _, relay, err := authorizer.AuthorizeRelayed(context.Background(), call(node), nil, stated); err != nil || relay == nil || len(asked) != 2 ||
		string(asked[1].Assertion) != string(stated.Assertion) {
		t.Fatalf("a verified relay of the credential's installation: %v %v", relay, err)
	}
	account := ingress.Caller{Credential: ingress.CredentialNativeBearer, Scope: "account", UserID: platform.NewID().String()}
	if _, relay, err := authorizer.AuthorizeRelayed(context.Background(), call(account), nil, nil); err != nil || relay != nil || len(asked) != 2 {
		t.Fatalf("an account session: %v %v, verifier asked %d times", relay, err, len(asked))
	}
}

func errorText(err error) string {
	if err == nil {
		return "admitted"
	}
	return err.Error()
}
