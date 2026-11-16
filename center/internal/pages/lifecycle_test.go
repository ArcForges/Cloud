// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"strings"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

func TestLifecycleProtocolRequiresPlanBindingAndBoundedRange(t *testing.T) {
	id := platform.NewID().String()
	for _, probe := range []struct{ kind, body string }{
		{"confirm", `{"commandId":"` + id + `","planRevision":"1"}`},
		{"confirm", `{"commandId":"` + id + `","planId":"` + id + `","planRevision":"01"}`},
		{"confirm", `{"commandId":"` + id + `","planId":"` + id + `","planRevision":"1","proof":"invented"}`},
		{"confirm", `{"commandId":"` + id + `","planId":"` + id + `","planRevision":"1","planRevision":"2"}`},
		{"read", `{"operationId":"` + id + `","offset":0,"limit":32769}`},
		{"read", `{"operationId":"` + id + `","offset":-1,"limit":32768}`},
		{"read", `{"operationId":"` + id + `","offset":null,"limit":1}`},
		{"read", `{"operationId":"` + id + `","offset":0.1,"limit":1}`},
	} {
		if _, refusal := parseLifecycle([]byte(probe.body), probe.kind); refusal == nil {
			t.Errorf("admitted %s %s", probe.kind, probe.body)
		}
	}
	value, refusal := parseLifecycle([]byte(`{"commandId":"`+id+`","planId":"`+id+`","planRevision":"3"}`), "confirm")
	if refusal != nil || value.PlanRevision != 3 || value.PlanID.String() != id {
		t.Fatalf("valid confirmation: %+v %v", value, refusal)
	}
	if _, refusal := parseLifecycle([]byte(`{"operationId":"`+id+`","offset":0,"limit":32768}`), "read"); refusal != nil {
		t.Fatal(refusal)
	}
}

func TestLifecycleTemplatesExposeOnlyPendingAccountRemediation(t *testing.T) {
	views, err := loadViews("/api")
	if err != nil {
		t.Fatal(err)
	}
	item := lifecycleOf(identity.Lifecycle{ID: platform.NewID(), Kind: identity.LifecycleDeletion, State: identity.LifecycleProcessing}, platform.NewID())
	body, err := views.render("lifecycle", pageData{Lifecycle: lifecycleView{Pending: true, Operation: &item}})
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, `id="cancel-deletion"`) || strings.Contains(text, `id="prepare-deletion"`) || strings.Contains(text, `id="export-account"`) || strings.Contains(text, `id="confirm-deletion"`) {
		t.Fatalf("pending account controls: %s", text)
	}
}

func TestRecoveryProtocolOffersOnlyVerifiedEmailAndPasskeyReplacement(t *testing.T) {
	id := platform.NewID().String()
	claim := `"installation":{"installationId":"` + id + `","product":"arcforges-web","platform":"web","appVersion":"pages-1"}`
	for _, body := range []string{
		`{"method":"adminGrant","email":"owner@example.test",` + claim + `}`,
		`{"method":"emailCode","email":"owner@example.test","email":"other@example.test",` + claim + `}`,
		`{"method":"emailCode","email":"owner@example.test","accountHint":"claimed-owner",` + claim + `}`,
	} {
		if _, refusal := parseRecoveryBegin([]byte(body)); refusal == nil {
			t.Errorf("admitted unsupported recovery request: %s", body)
		}
	}
	value, refusal := parseRecoveryBegin([]byte(`{"method":"emailCode","email":"owner@example.test",` + claim + `}`))
	if refusal != nil || !value.Browser || !value.HasClaim {
		t.Fatalf("browser recovery: %+v %v", value, refusal)
	}
	for _, body := range []string{
		`{"flowId":"` + id + `","commandId":"` + id + `","proof":{"adminGrant":"invented"},"replacement":{"passkey":{}}}`,
		`{"flowId":"` + id + `","commandId":"` + id + `","proof":{"emailCode":"ABCDEFGH"},"replacement":{"password":"invented"}}`,
		`{"flowId":"` + id + `","proof":{"emailCode":"ABCDEFGH"},"replacement":{"passkey":{}}}`,
	} {
		if _, refusal := parseRecoveryComplete([]byte(body)); refusal == nil {
			t.Errorf("admitted unsupported recovery completion: %s", body)
		}
	}
}
