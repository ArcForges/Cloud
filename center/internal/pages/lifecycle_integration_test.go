// SPDX-License-Identifier: AGPL-3.0-only

package pages_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey/virtual"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

type lifecycleAnswer struct {
	Operation struct {
		ID           string `json:"operationId"`
		State        string `json:"state"`
		PlanRevision string `json:"planRevision"`
		ExportBytes  int    `json:"exportBytes"`
	} `json:"operation"`
}

func mustLifecycle(t *testing.T, reply response) lifecycleAnswer {
	t.Helper()
	if reply.status != 200 {
		t.Fatalf("lifecycle: %d %s", reply.status, reply.text())
	}
	var value lifecycleAnswer
	reply.json(t, &value)
	if value.Operation.ID == "" {
		t.Fatal("no operation identity")
	}
	return value
}

// The HTTP protocol reaches real account fences, command receipts and passkey
// evidence. Database fixtures seed identities only, never a successful decision.
func TestLifecyclePlansExportAndPendingAccountRemediation(t *testing.T) {
	h := newHarness(t, settings{surfaces: "identity,pages,fleet", policy: writePolicy})
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)
	b.page("/account/lifecycle")
	prepare := map[string]any{"commandId": platform.NewID().String()}
	plan := mustLifecycle(t, b.postJSON("/session/v1/web/account/deletion/prepare", prepare))
	if again := mustLifecycle(t, b.postJSON("/session/v1/web/account/deletion/prepare", prepare)); again.Operation.ID != plan.Operation.ID {
		t.Fatal("prepare was not idempotent")
	}
	planID := idOf(t, plan.Operation.ID)
	if reply := b.postJSON("/session/v1/web/account/deletion/confirm", map[string]any{"commandId": prepare["commandId"], "planId": plan.Operation.ID, "planRevision": plan.Operation.PlanRevision}); reply.refusal(t) != "conflict/command_id_reused" {
		t.Fatalf("cross-operation command: %s", reply.text())
	}
	if reply := b.postJSON("/session/v1/web/account/deletion/confirm", map[string]any{"commandId": platform.NewID().String(), "planId": plan.Operation.ID, "planRevision": "2"}); reply.refusal(t) != "conflict/revision_conflict" {
		t.Fatalf("plan revision: %s", reply.text())
	}
	confirm := map[string]any{"commandId": platform.NewID().String(), "planId": plan.Operation.ID, "planRevision": plan.Operation.PlanRevision}
	if reply := b.postJSON("/session/v1/web/account/deletion/confirm", confirm); reply.refusal(t) != "authentication/step_up_required" {
		t.Fatalf("unproved deletion: %s", reply.text())
	}

	b.mustStepUp(who, identity.ClassExportAccount, who.id)
	export := mustLifecycle(t, b.postJSON("/session/v1/web/account/export/prepare", map[string]any{"commandId": platform.NewID().String()}))
	read := map[string]any{"operationId": export.Operation.ID, "offset": 0, "limit": 32768}
	page := b.postJSON("/session/v1/web/account/export/read", read)
	if page.status != 200 {
		t.Fatalf("export read: %d %s", page.status, page.text())
	}
	var bytes struct {
		Data  string `json:"data"`
		Total int    `json:"total"`
		Done  bool   `json:"done"`
	}
	page.json(t, &bytes)
	if !bytes.Done || bytes.Total != export.Operation.ExportBytes || !json.Valid(unb64(t, bytes.Data)) {
		t.Fatal("invalid bounded export")
	}
	other := h.newBrowser()
	other.mustSignIn(h.seedAccount(1))
	if reply := other.postJSON("/session/v1/web/account/export/read", read); reply.status != 404 {
		t.Fatalf("foreign export: %d %s", reply.status, reply.text())
	}
	// The plan proof cannot be replaced by the account export proof.
	if reply := b.postJSON("/session/v1/web/account/deletion/confirm", confirm); reply.refusal(t) != "authentication/step_up_required" {
		t.Fatal("cross-class proof was accepted")
	}
	b.mustStepUp(who, identity.ClassConfirmDeletion, planID)
	confirmed := mustLifecycle(t, b.postJSON("/session/v1/web/account/deletion/confirm", confirm))
	if confirmed.Operation.State != "processing" || h.count("SELECT count(*) FROM identity.user WHERE user_id=$1 AND state=4", who.id) != 1 {
		t.Fatal("deletion did not become pending")
	}
	if b.bootstrapState().Authenticated {
		t.Fatal("the old cookie survived account deletion")
	}
	if reply := b.postJSON("/session/v1/web/account/export/read", read); reply.status != 403 {
		t.Fatalf("old export credential: %d", reply.status)
	}

	// A newly proved passkey may obtain only the status/cancel authority. Old
	// installations remain revoked and no remote or account management is opened.
	pending := h.newBrowser()
	pending.mustSignIn(who)
	receipts := h.count("SELECT count(*) FROM platform.command_receipt")
	if replay := mustLifecycle(t, pending.postJSON("/session/v1/web/account/deletion/confirm", confirm)); replay.Operation.ID != plan.Operation.ID {
		t.Fatal("fresh status replay lost operation identity")
	}
	if reply := pending.postJSON("/session/v1/web/account/deletion/confirm", map[string]any{"commandId": platform.NewID().String(), "planId": plan.Operation.ID, "planRevision": plan.Operation.PlanRevision}); reply.status != 403 {
		t.Fatalf("pending account created a new confirm: %d", reply.status)
	}
	if reply := pending.postJSON("/session/v1/web/account/deletion/confirm", map[string]any{"commandId": confirm["commandId"], "planId": plan.Operation.ID, "planRevision": "2"}); reply.refusal(t) != "conflict/command_id_reused" {
		t.Fatal("pending changed intent replay")
	}
	// Concurrent retries are reads of the same receipt, never new proof/effect.
	results := make(chan response, 4)
	for range 4 {
		go func() { results <- rawLifecycleRequest(h, pending, confirm) }()
	}
	for range 4 {
		if replay := <-results; replay.status != 200 {
			t.Fatalf("concurrent receipt read: %d %s", replay.status, replay.text())
		}
	}
	if h.count("SELECT count(*) FROM platform.command_receipt") != receipts || h.audits("identity.deletion.confirmed") != 1 {
		t.Fatal("reconciliation created a mutation or receipt")
	}
	racing := h.newBrowser()
	racing.mustSignIn(who)
	racingID := idOf(t, racing.bootstrapPeek())
	tx, err := h.migration.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err = tx.Exec(context.Background(), `SELECT 1 FROM identity.user WHERE user_id=$1 FOR UPDATE`, who.id); err != nil {
		t.Fatal(err)
	}
	go func() { results <- rawLifecycleRequest(h, racing, confirm) }()
	if _, err = tx.Exec(context.Background(), `UPDATE identity.session SET revoked_at=$2,revoke_reason=1,rev=rev+1 WHERE session_id=$1`, racingID, h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if replay := <-results; replay.status != 403 {
		t.Fatalf("receipt read raced with revocation: %d %s", replay.status, replay.text())
	}
	view := pending.page("/account/lifecycle")
	if !strings.Contains(view.text(), `id="cancel-deletion"`) || strings.Contains(view.text(), `id="export-account"`) {
		t.Fatal("pending page authority")
	}
	for _, path := range []string{"/account/passkeys", "/account/devices", "/account/sessions"} {
		if reply := pending.get(path); reply.status != 403 {
			t.Errorf("pending %s: %d", path, reply.status)
		}
	}
	for _, path := range []string{"/account/deletion/prepare", "/account/export/prepare"} {
		if reply := pending.postJSON("/session/v1/web"+path, map[string]any{"commandId": platform.NewID().String()}); reply.status != 403 {
			t.Errorf("pending %s: %d", path, reply.status)
		}
	}
	if reply := pending.postForm("/connect/review", url.Values{"flow_id": {platform.NewID().String()}}); reply.status != 403 {
		t.Errorf("pending node enrollment page: %d %s", reply.status, reply.text())
	}
	if reply := pending.stepUp(who, identity.ClassExportAccount, who.id); reply.status != 403 {
		t.Fatalf("pending unrelated step-up: %d %s", reply.status, reply.text())
	}
	pending.mustStepUp(who, identity.ClassCancelDeletion, planID)
	cancel := mustLifecycle(t, pending.postJSON("/session/v1/web/account/deletion/cancel", map[string]any{"commandId": platform.NewID().String(), "planId": plan.Operation.ID}))
	if cancel.Operation.State != "revoked" || h.count("SELECT count(*) FROM identity.user WHERE user_id=$1 AND state=1", who.id) != 1 {
		t.Fatal("pending deletion not cancelled")
	}
	if b.bootstrapState().Authenticated {
		t.Fatal("cancel reactivated a revoked old cookie")
	}
	h.verifyAudit()
}

// This helper avoids the harness's response collection when requests run in
// parallel. It is an actual HTTP request to the same composed production handler.
func rawLifecycleRequest(h *harness, b *browser, body any) response {
	encoded, err := json.Marshal(body)
	if err != nil {
		return response{status: 599}
	}
	request, err := http.NewRequest(http.MethodPost, h.url+"/session/v1/web/account/deletion/confirm", bytes.NewReader(encoded))
	if err != nil {
		return response{status: 599}
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", origin)
	request.Header.Set("Cookie", routes.PageCookieName+"="+b.cookie)
	request.Header.Set(ingress.CSRFHeader, b.csrf)
	request.Header.Set("X-Arcforges-Client-Ip", "203.0.113.10")
	answer, err := http.DefaultClient.Do(request)
	if err != nil {
		return response{status: 599}
	}
	defer func() { _ = answer.Body.Close() }()
	data, err := io.ReadAll(answer.Body)
	if err != nil {
		return response{status: 599}
	}
	return response{status: answer.StatusCode, header: answer.Header, body: data}
}

func TestLifecycleHTTPRequiresOriginCSRFAndCurrentEpoch(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)
	body, err := json.Marshal(map[string]any{"commandId": platform.NewID().String()})
	if err != nil {
		t.Fatal(err)
	}
	for _, probe := range []request{
		{method: http.MethodPost, path: "/session/v1/web/account/deletion/prepare", contentType: "application/json", body: body, cookie: b.cookie, csrf: b.csrf, origin: "https://foreign.example.test"},
		{method: http.MethodPost, path: "/session/v1/web/account/deletion/prepare", contentType: "application/json", body: body, cookie: b.cookie},
	} {
		if reply := h.do(probe); reply.status != 403 {
			t.Errorf("missing browser proof: %d %s", reply.status, reply.text())
		}
	}
	if h.count("SELECT count(*) FROM identity.lifecycle_operation") != 0 {
		t.Fatal("refused HTTP wrote a lifecycle effect")
	}
	b.mustStepUp(who, identity.ClassExportAccount, who.id)
	export := mustLifecycle(t, b.postJSON("/session/v1/web/account/export/prepare", map[string]any{"commandId": platform.NewID().String()}))
	h.clock.Advance(16 * time.Minute)
	read := map[string]any{"operationId": export.Operation.ID, "offset": 0, "limit": 32768}
	if reply := b.postJSON("/session/v1/web/account/export/read", read); reply.refusal(t) != "state/expired" {
		t.Fatalf("expired export: %s", reply.text())
	}
	if _, err := h.migration.Exec(context.Background(), `UPDATE identity.account_security_state SET auth_epoch=auth_epoch+1,rev=rev+1 WHERE user_id=$1`, who.id); err != nil {
		t.Fatal(err)
	}
	if reply := b.postJSON("/session/v1/web/account/export/read", read); reply.status != 403 {
		t.Fatalf("old epoch: %d %s", reply.status, reply.text())
	}
}

func TestRecoveryPageUsesTheVerifiedChannelAndReconcilesItsCommand(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1)
	email := "recovery-owner@example.test"
	if _, err := h.migration.Exec(context.Background(), `INSERT INTO identity.auth_identity(auth_identity_id,user_id,method,provider_id,subject,created_at,rev) VALUES($1,$2,2,'email',$3,$4,1)`, platform.NewID(), who.id, email, h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	old := h.newBrowser()
	old.mustSignIn(who)
	b := h.newBrowser()
	b.page("/account/recovery")
	b.bootstrapState()
	begun := b.postJSON("/session/v1/web/recovery/begin", map[string]any{"method": "emailCode", "email": email, "installation": b.claim()})
	if begun.status != 200 {
		t.Fatalf("begin recovery: %d %s", begun.status, begun.text())
	}
	var challenge challengeReply
	begun.json(t, &challenge)
	if challenge.Method != "emailCode" || challenge.Purpose != "recover" || challenge.Options == nil {
		t.Fatal("recovery ceremony metadata")
	}
	// A repeated known address has a fresh handle, just as an unknown address;
	// stable public creation metadata must not become an enumeration oracle.
	for _, address := range []string{email, "unknown-recovery@example.test"} {
		repeated := b.postJSON("/session/v1/web/recovery/begin", map[string]any{"method": "emailCode", "email": address, "installation": b.claim()})
		if repeated.status != 200 {
			t.Fatalf("non-enumerating recovery begin: %d", repeated.status)
		}
		var next challengeReply
		repeated.json(t, &next)
		if next.Options == nil || next.Options.UserHandle == challenge.Options.UserHandle || next.Method != challenge.Method || next.Purpose != challenge.Purpose {
			t.Fatal("recovery challenge exposed stable account metadata")
		}
	}
	messages := h.mail.Messages()
	if len(messages) != 2 {
		t.Fatal("no recovery channel delivery")
	}
	code := regexp.MustCompile(`[A-Z0-9]{4}-[A-Z0-9]{4}`).FindString(messages[0].Text)
	if code == "" {
		t.Fatal("no bounded recovery code")
	}
	h.remember(code, strings.ReplaceAll(code, "-", ""))
	authenticator := virtual.New(rpID, origin)
	creation, key := authenticator.Create(unb64(t, challenge.Challenge), unb64(t, challenge.Options.UserHandle))
	complete := map[string]any{"flowId": challenge.FlowID, "commandId": platform.NewID().String(),
		"proof": map[string]any{"emailCode": code}, "replacement": map[string]any{"passkey": creationJSON(creation)}}
	for attempt := range 2 {
		reply := b.postJSON("/session/v1/web/recovery/complete", complete)
		if reply.status != 200 || reply.cookie() != "" {
			t.Fatalf("recovery completion %d: %d %s", attempt, reply.status, reply.text())
		}
	}
	if old.bootstrapState().Authenticated {
		t.Fatal("old session survived recovery")
	}
	fresh := h.newBrowser()
	fresh.mustSignIn(account{id: who.id, handle: unb64(t, challenge.Options.UserHandle), authenticator: authenticator, key: key})
	if state := fresh.bootstrapState(); state.Session.RecoveryGeneration != "1" {
		t.Fatalf("generation: %s", state.Session.RecoveryGeneration)
	}
	if h.count("SELECT count(*) FROM identity.lifecycle_operation WHERE user_id=$1 AND kind=1 AND state=4", who.id) != 1 {
		t.Fatal("recovery did not record one completed operation")
	}
	h.verifyAudit()
}
