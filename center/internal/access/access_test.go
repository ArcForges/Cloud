// SPDX-License-Identifier: AGPL-3.0-only

package access

import (
	"testing"

	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

func identityPolicies(t *testing.T) []ingress.Policy {
	t.Helper()
	module, err := routes.Identity()
	if err != nil {
		t.Fatal(err)
	}
	return module.Policies
}

func TestTheOperationTableIsExactlyTheServedMethods(t *testing.T) {
	policies := identityPolicies(t)
	if err := Check(policies); err != nil {
		t.Fatal(err)
	}
	if err := Check(policies[1:]); err == nil {
		t.Fatal("a row without a served method was admitted")
	}
	extra, err := ingress.NewUnary("/arcforges.publicapi.v1.IdentityService/RevokeSession", ingress.Session, ingress.NoScope, 4096, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = Check(append(policies, extra)); err == nil {
		t.Fatal("a served method without a row was admitted")
	}
	flipped := append([]ingress.Policy(nil), policies...)
	for index, policy := range flipped {
		if policy.Authentication == ingress.Session {
			anonymous, err := ingress.NewUnary(policy.FullName, ingress.Anonymous, ingress.NoScope, policy.MaxRequestBytes, true)
			if err != nil {
				t.Fatal(err)
			}
			flipped[index] = anonymous
			break
		}
	}
	if err = Check(flipped); err == nil {
		t.Fatal("a session method served anonymously was admitted")
	}
	for _, operation := range Operations() {
		if operation.Risk != "R1" || operation.MobileLimited != Allowed {
			t.Errorf("%s: A1a serves only reads open to mobile.limited", operation.ID)
		}
	}
	if _, ok := Lookup("/arcforges.publicapi.v1.IdentityService/RemoveAuthIdentity"); ok {
		t.Fatal("an unserved method has a row")
	}
}
