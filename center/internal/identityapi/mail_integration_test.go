// SPDX-License-Identifier: AGPL-3.0-only

package identityapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	netmail "net/mail"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/mail"
	"github.com/ArcForges/Cloud/center/internal/mail/mailtest"
)

// Everything in this file is MOCKED: the real adapters (mail.NewPostmark and mail.NewSMTP behind the real mail.Guard) talk to the
// in-process doubles of package mailtest on 127.0.0.1, in front of a real PostgreSQL and the real identity service. Nothing proves
// what Postmark or Amazon SES do; the PR evidence table says so. The tests run on the Linux leg only (they need the database).

// letter is one message as the provider received it.
type letter struct{ to, text string }

// inbox is what reached the provider, in the order it arrived: the Fake's messages, or the requests and sessions of a double. It
// lets lastCode read a code whichever sender the harness holds.
type inbox interface{ letters() []letter }

type fakeInbox struct{ fake *mail.Fake }

func (f fakeInbox) letters() []letter {
	var all []letter
	for _, message := range f.fake.Messages() {
		all = append(all, letter{to: message.To, text: message.Text})
	}
	return all
}

// postmarkInbox reads the JSON the adapter posted.
type postmarkInbox struct{ server *mailtest.PostmarkServer }

func (p postmarkInbox) letters() []letter {
	var all []letter
	for _, request := range p.server.Requests() {
		var body struct{ To, TextBody string }
		if json.Unmarshal(request.Body, &body) == nil {
			all = append(all, letter{to: body.To, text: body.TextBody})
		}
	}
	return all
}

// smtpInbox reads the message the adapter sent in DATA: the To header and the quoted-printable text.
type smtpInbox struct{ server *mailtest.SMTPServer }

func (s smtpInbox) letters() []letter {
	var all []letter
	for _, capture := range s.server.Captures() {
		if len(capture.Data) == 0 {
			continue
		}
		parsed, err := netmail.ReadMessage(bytes.NewReader(capture.Data))
		if err != nil {
			continue
		}
		text, err := io.ReadAll(quotedprintable.NewReader(parsed.Body))
		if err != nil {
			continue
		}
		all = append(all, letter{to: parsed.Header.Get("To"), text: string(text)})
	}
	return all
}

const (
	rigFrom     = "no-reply@mail.example.test"
	rigSMTPHost = "smtp.example.test"
)

// word is a synthetic credential or marker built from words, never a literal that looks like a credential.
func word(role string) string {
	return strings.Join([]string{"synthetic", "word", "built", role, "sentinel"}, "-")
}

// providerRig is a real adapter in front of its double.
type providerRig struct {
	sender mail.Sender
	inbox  inbox
	// secrets are the credentials the adapter holds.
	secrets []string
	// reached is how many requests (Postmark) or connections (SMTP) arrived at the double.
	reached func() int
	// postmark is the stand-in when the rig is Postmark's, so that a test can script the next answer.
	postmark *mailtest.PostmarkServer
}

func newPostmarkRig(t *testing.T, reply mailtest.PostmarkReply, timeout time.Duration) *providerRig {
	t.Helper()
	token := word("postmark-token")
	server := mailtest.StartPostmark(t, token, reply)
	sender := mail.NewGuard(mail.NewPostmark(mail.PostmarkOptions{Token: config.NewSecret(token), From: rigFrom, FromName: "ArcForges",
		Stream: "outbound", Timeout: timeout, BaseURL: server.URL()}))
	return &providerRig{sender: sender, inbox: postmarkInbox{server}, secrets: []string{token}, postmark: server,
		reached: func() int { return len(server.Requests()) }}
}

func newSMTPRig(t *testing.T, change func(*mailtest.SMTPOptions), timeout time.Duration) *providerRig {
	t.Helper()
	ca := mailtest.NewCA(t, "identity mail test CA")
	options := mailtest.SMTPOptions{Certificate: ca.Leaf(t, rigSMTPHost)}
	if change != nil {
		change(&options)
	}
	server := mailtest.StartSMTP(t, options)
	user, password := word("smtp-user"), word("smtp-password")
	sender := mail.NewGuard(mail.NewSMTP(mail.SMTPOptions{Host: rigSMTPHost, Port: 2587, Mode: mail.StartTLS, Username: config.NewSecret(user),
		Password: config.NewSecret(password), From: rigFrom, FromName: "ArcForges", Timeout: timeout, RootCAs: ca.Pool(),
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", server.Addr())
		}}))
	return &providerRig{sender: sender, inbox: smtpInbox{server}, secrets: []string{user, password}, reached: server.Connections}
}

// settings turns the rig into harness settings.
func (r *providerRig) settings(policy string, async bool) settings {
	return settings{policy: policy, sender: r.sender, inbox: r.inbox, asyncMail: async}
}

const loosePolicy = `{"emailPerAddressLimit": 100, "emailPerPrefixLimit": 100, "stepUpPerAccountLimit": 1000, "signInFailuresAccountLimit": 1000, "signInPerPrefixLimit": 1000}`

// emailSends reads the email_send counter by outcome from the operator-only metrics text.
func (h *harness) emailSends() map[string]int {
	h.t.Helper()
	recorder := httptest.NewRecorder()
	h.center.Admin().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	counts := map[string]int{}
	for _, line := range strings.Split(recorder.Body.String(), "\n") {
		rest, ok := strings.CutPrefix(line, `arcforges_center_identity_events_total{event="email_send",outcome="`)
		if !ok {
			continue
		}
		outcome, number, _ := strings.Cut(rest, `"} `)
		value, err := strconv.Atoi(strings.TrimSpace(number))
		if err != nil {
			h.t.Fatalf("a metrics line with the count %q", number)
		}
		counts[outcome] = value
	}
	return counts
}

// awaitSends waits until the email_send counter reads exactly want. The counter moves after the provider call returned, so the
// provider already holds the message when this returns; no sleep stands in for it.
func (h *harness) awaitSends(want map[string]int) {
	h.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		got := h.emailSends()
		if maps.Equal(got, want) {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("email_send reads %v, want %v", got, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// blank removes what differs between two replies of the same request apart from the address: the flow, the challenge, the instant.
func blank(reply *publicapiv1.IdentityServiceRequestEmailCodeResponse) *publicapiv1.IdentityServiceRequestEmailCodeResponse {
	if challenge := reply.GetValue().GetChallenge(); challenge != nil {
		challenge.FlowId, challenge.Challenge, challenge.ExpiresAt = nil, nil, nil
	}
	reply.Meta = nil
	return reply
}

// beginEmailStepUp begins an e-mail step-up of a class whose target is the account itself and returns the reply; the caller waits for
// the delivery (the existing stepUpByEmail reads the code at once, which only works with the inline background).
func (h *harness) beginEmailStepUp(from caller, who account, class string) *publicapiv1.IdentityServiceBeginStepUpResponse {
	h.t.Helper()
	return rpc(h, beginStepUpPath, &publicapiv1.IdentityServiceBeginStepUpRequest{Meta: meta(), OperationClass: proto.String(class),
		Method: publicapiv1.AuthMethod_AUTH_METHOD_EMAIL.Enum(), TargetHash: proto.String(identity.TargetHash(class, who.id, who.id))}, from,
		&publicapiv1.IdentityServiceBeginStepUpResponse{})
}

// TestTheEmailClosedLoopsRunThroughEachAdapter: the sign-in by e-mail, a resend, the step-up by e-mail and the provider list, with
// the production goroutine for every delivery, through the real Postmark adapter and the real SMTP adapter. An address without an
// account produces no request at all at the provider. MOCKED: the doubles speak the documented protocols; no real service answered.
func TestTheEmailClosedLoopsRunThroughEachAdapter(t *testing.T) {
	rigs := map[string]func(*testing.T) *providerRig{
		"postmark": func(t *testing.T) *providerRig { return newPostmarkRig(t, mailtest.PostmarkReply{}, 5*time.Second) },
		"smtp":     func(t *testing.T) *providerRig { return newSMTPRig(t, nil, 5*time.Second) },
	}
	for _, name := range []string{"postmark", "smtp"} {
		t.Run(name, func(t *testing.T) {
			rig := rigs[name](t)
			h := newHarness(t, rig.settings(loosePolicy, true))
			known, unknown := "grace@example.org", "ghost@example.org"
			who := h.seedAccount(1, known)
			h.remember(known, unknown)
			h.remember(rig.secrets...)

			listed := rpc(h, providers, &publicapiv1.IdentityServiceListAuthProvidersRequest{Meta: meta()}, caller{}, &publicapiv1.IdentityServiceListAuthProvidersResponse{})
			if len(listed.GetValue().GetProviders()) != 2 || listed.GetValue().GetProviders()[1].GetMethod() != publicapiv1.AuthMethod_AUTH_METHOD_EMAIL {
				t.Fatalf("an adapter must list the e-mail provider: %v", listed)
			}

			// An unknown address: the same reply, and not one request at the provider.
			ghost := h.beginEmail(unknown, caller{}).GetValue().GetChallenge()
			if reply := h.requestCode(ghost.GetFlowId(), unknown, caller{}); reply.GetError() != nil {
				t.Fatalf("an unknown address: %s", failure(reply.GetError()))
			}

			begun := h.beginEmail("Grace@Example.ORG", caller{})
			if begun.GetError() != nil {
				t.Fatalf("begin: %s", failure(begun.GetError()))
			}
			flow := begun.GetValue().GetChallenge().GetFlowId()
			if reply := h.requestCode(flow, known, caller{}); reply.GetError() != nil {
				t.Fatalf("send: %s", failure(reply.GetError()))
			}
			h.awaitSends(map[string]int{"sent": 1})
			first := h.lastCode(known)
			if reply := h.requestCode(flow, known, caller{}); reply.GetError() != nil {
				t.Fatalf("resend: %s", failure(reply.GetError()))
			}
			h.awaitSends(map[string]int{"sent": 2})
			second := h.lastCode(known)
			if first == second {
				t.Fatal("a resend must carry a new code")
			}
			if result := failure(h.redeem(flow, first, caller{}).GetError()); result != "AUTHENTICATION/unauthenticated" {
				t.Fatalf("the replaced code: %s", result)
			}
			redeemed := h.redeem(flow, second, caller{})
			if redeemed.GetError() != nil || redeemed.GetValue().GetSession().GetAccessToken() == "" {
				t.Fatalf("redeem: %s", failure(redeemed.GetError()))
			}

			// The step-up by e-mail, proved with the code that arrived through the adapter.
			from := caller{bearer: redeemed.GetValue().GetSession().GetAccessToken()}
			step := h.beginEmailStepUp(from, who, identity.ClassRevokeAllSessions)
			if step.GetError() != nil {
				t.Fatalf("begin the step-up: %s", failure(step.GetError()))
			}
			h.awaitSends(map[string]int{"sent": 3})
			proved := rpc(h, completeStepUpPath, &publicapiv1.IdentityServiceCompleteStepUpRequest{Meta: meta(), FlowId: step.GetValue().GetChallenge().GetFlowId(),
				Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_EmailCode{EmailCode: h.lastCode(known)}}}, from, &publicapiv1.IdentityServiceCompleteStepUpResponse{})
			if proved.GetError() != nil {
				t.Fatalf("the step-up by e-mail: %s", failure(proved.GetError()))
			}

			// Three deliveries, all to the one known address, in normalized form; three requests reached the double.
			for _, one := range rig.inbox.letters() {
				if one.to != known {
					t.Errorf("a message went to %q", one.to)
				}
			}
			if got := rig.reached(); got != 3 || len(rig.inbox.letters()) != 3 {
				t.Fatalf("%d requests reached the provider, %d messages: the unknown address must add none", got, len(rig.inbox.letters()))
			}
		})
	}
}

// failureCases are the provider answers the neutral reply must hide, with the outcome each must be counted as.
var failureCases = []struct {
	name    string
	rig     func(*testing.T) *providerRig
	outcome string
}{
	{"postmark 422 inactive recipient", func(t *testing.T) *providerRig {
		return newPostmarkRig(t, mailtest.PostmarkReply{Status: 422, Body: `{"ErrorCode":406,"Message":"` + word("provider-text") + `"}`}, 5*time.Second)
	}, "rejected"},
	{"postmark 500", func(t *testing.T) *providerRig {
		return newPostmarkRig(t, mailtest.PostmarkReply{Status: 500, Body: `{"Message":"` + word("provider-text") + `"}`}, 5*time.Second)
	}, "unavailable"},
	{"postmark 401", func(t *testing.T) *providerRig {
		return newPostmarkRig(t, mailtest.PostmarkReply{Status: 401, Body: `{"ErrorCode":10,"Message":"` + word("provider-text") + `"}`}, 5*time.Second)
	}, "unauthorized"},
	{"postmark timeout", func(t *testing.T) *providerRig {
		return newPostmarkRig(t, mailtest.PostmarkReply{Stall: true}, 400*time.Millisecond)
	}, "unavailable"},
	{"smtp 554 at RCPT", func(t *testing.T) *providerRig {
		return newSMTPRig(t, func(o *mailtest.SMTPOptions) { o.RcptReply = "554 5.7.1 " + word("provider-text") }, 5*time.Second)
	}, "rejected"},
	{"smtp 451 after DATA", func(t *testing.T) *providerRig {
		return newSMTPRig(t, func(o *mailtest.SMTPOptions) { o.DataReply = "451 4.3.0 " + word("provider-text") }, 5*time.Second)
	}, "unavailable"},
	{"smtp 535 at AUTH", func(t *testing.T) *providerRig {
		return newSMTPRig(t, func(o *mailtest.SMTPOptions) { o.AuthReply = "535 5.7.8 " + word("provider-text") }, 5*time.Second)
	}, "unauthorized"},
	{"smtp timeout", func(t *testing.T) *providerRig {
		return newSMTPRig(t, func(o *mailtest.SMTPOptions) { o.StallAfterGreeting = true }, 400*time.Millisecond)
	}, "unavailable"},
}

// TestAProviderFailureNeverReachesTheReplyAndIsCountedByClass: N7. For every failure class of both adapters the caller gets the
// reply of an unknown address (same shape, no error), the counter carries the closed class, and the log holds neither the
// recipient, a credential nor the provider's own text. MOCKED.
func TestAProviderFailureNeverReachesTheReplyAndIsCountedByClass(t *testing.T) {
	for _, c := range failureCases {
		t.Run(c.name, func(t *testing.T) {
			rig := c.rig(t)
			h := newHarness(t, rig.settings(loosePolicy, false))
			known, unknown := "failing@example.org", "nobody@example.org"
			who := h.seedAccount(1, known)
			h.remember(known, unknown)
			flows := map[string]*foundationv1.Id{}
			for _, address := range []string{known, unknown} {
				flows[address] = h.beginEmail(address, caller{}).GetValue().GetChallenge().GetFlowId()
			}
			ask := func(flow *foundationv1.Id, address string) (*publicapiv1.IdentityServiceRequestEmailCodeResponse, reply) {
				return rpcWithReply(h, requestCodePath, &publicapiv1.IdentityServiceRequestEmailCodeRequest{Meta: meta(), FlowId: flow, Email: proto.String(address),
					Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_AUTHENTICATE.Enum()}, caller{}, &publicapiv1.IdentityServiceRequestEmailCodeResponse{})
			}
			failed, failedReply := ask(flows[known], known)
			quiet, quietReply := ask(flows[unknown], unknown)
			if failed.GetError() != nil || quiet.GetError() != nil {
				t.Fatalf("a reply failed: %v %v", failed.GetError(), quiet.GetError())
			}
			if !proto.Equal(blank(failed), blank(quiet)) {
				t.Fatalf("the reply of a failed delivery differs from the reply of an unknown address:\n%v\n%v", failed, quiet)
			}
			if failedReply.http != quietReply.http || failedReply.status != quietReply.status ||
				!reflect.DeepEqual(comparableHeaders(failedReply), comparableHeaders(quietReply)) {
				t.Fatalf("a failed delivery shows in the HTTP code or a header: %d %v and %d %v", failedReply.http, comparableHeaders(failedReply), quietReply.http, comparableHeaders(quietReply))
			}
			// The step-up by e-mail is another caller of the same delivery: a failing provider changes nothing of its reply either.
			step := h.beginEmailStepUp(bearer(h.signIn(who, newClaim(t), caller{}).GetAccessToken()), who, identity.ClassRevokeAllSessions)
			if step.GetError() != nil || step.GetValue().GetChallenge().GetMethod() != publicapiv1.AuthMethod_AUTH_METHOD_EMAIL {
				t.Fatalf("a failed step-up delivery changed the reply: %v", step)
			}
			if got := h.emailSends(); !maps.Equal(got, map[string]int{c.outcome: 2}) {
				t.Fatalf("email_send reads %v, want two %s", got, c.outcome)
			}
			if rig.reached() != 2 {
				t.Fatalf("%d requests reached the provider", rig.reached())
			}
			logs := h.logs.String()
			for _, line := range []string{"an e-mail code could not be delivered", "a step-up code could not be delivered"} {
				if strings.Count(logs, line) != 1 {
					t.Fatalf("the log must hold %q once: %s", line, logs)
				}
			}
			if strings.Count(logs, "outcome="+c.outcome)+strings.Count(logs, `"outcome":"`+c.outcome+`"`) != 2 {
				t.Fatalf("the failures were not logged with their class: %s", logs)
			}
			for _, leak := range append(append([]string{known, unknown, word("provider-text")}, rig.secrets...), "ErrorCode") {
				if strings.Contains(logs, leak) {
					t.Errorf("the log holds %q", leak)
				}
			}
		})
	}
}

// gatedSender holds every Send until the test opens the gate; it records the sends that returned.
type gatedSender struct {
	fake     *mail.Fake
	started  chan struct{}
	finished atomic.Int64
	mu       sync.Mutex
	release  chan struct{}
}

func newGatedSender() *gatedSender {
	g := &gatedSender{fake: mail.NewFake(), started: make(chan struct{}, 16)}
	g.arm()
	return g
}

// arm closes the gate for the next sends.
func (g *gatedSender) arm() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.release = make(chan struct{})
}

// open lets every held send go; it may be called more than once.
func (g *gatedSender) open() {
	g.mu.Lock()
	defer g.mu.Unlock()
	select {
	case <-g.release:
	default:
		close(g.release)
	}
}

func (g *gatedSender) Enabled() bool { return true }

func (g *gatedSender) Send(ctx context.Context, message mail.Message) error {
	g.mu.Lock()
	release := g.release
	g.mu.Unlock()
	g.started <- struct{}{}
	select {
	case <-release:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer g.finished.Add(1)
	return g.fake.Send(ctx, message)
}

// within runs a call and fails the test when it does not return: the call is an RPC whose reply must not wait for a blocked send.
func within(t *testing.T, what string, call func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		call()
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatalf("%s did not return while the provider call was blocked", what)
	}
}

// TestTheReplyNeverWaitsForTheProvider: N1, with the production goroutine path. The sender is held on a channel; the RPC returns
// while Send is still blocked (a reply that waited would deadlock here, so the test needs no wall-clock threshold), and the replies
// of a known and an unknown address are equal. The same for the e-mail step-up. MOCKED sender, real PostgreSQL.
func TestTheReplyNeverWaitsForTheProvider(t *testing.T) {
	gate := newGatedSender()
	h := newHarness(t, settings{policy: loosePolicy, sender: gate, inbox: fakeInbox{gate.fake}, asyncMail: true})
	t.Cleanup(gate.open)
	known, unknown := "held@example.org", "absent@example.org"
	who := h.seedAccount(1, known)
	h.remember(known, unknown)
	flows := map[string]*foundationv1.Id{}
	for _, address := range []string{known, unknown} {
		flows[address] = h.beginEmail(address, caller{}).GetValue().GetChallenge().GetFlowId()
	}
	var replies [2]*publicapiv1.IdentityServiceRequestEmailCodeResponse
	for index, address := range []string{known, unknown} {
		within(t, "RequestEmailCode", func() { replies[index] = h.requestCode(flows[address], address, caller{}) })
		if replies[index].GetError() != nil {
			t.Fatalf("a reply failed: %s", failure(replies[index].GetError()))
		}
	}
	select {
	case <-gate.started:
	case <-time.After(15 * time.Second):
		t.Fatal("the provider call of the known address never started")
	}
	if gate.finished.Load() != 0 || len(gate.started) != 0 {
		t.Fatalf("the provider call finished before the gate opened, or the unknown address started one (%d finished, %d more started)", gate.finished.Load(), len(gate.started))
	}
	if !proto.Equal(blank(replies[0]), blank(replies[1])) {
		t.Fatalf("the replies differ:\n%v\n%v", replies[0], replies[1])
	}
	gate.open()
	h.awaitSends(map[string]int{"sent": 1})

	// The step-up by e-mail is held the same way.
	native := h.signIn(who, newClaim(t), caller{})
	gate.arm()
	var step *publicapiv1.IdentityServiceBeginStepUpResponse
	within(t, "BeginStepUp", func() {
		step = h.beginEmailStepUp(bearer(native.GetAccessToken()), who, identity.ClassRevokeAllSessions)
	})
	if step.GetError() != nil {
		t.Fatalf("begin the step-up: %s", failure(step.GetError()))
	}
	select {
	case <-gate.started:
	case <-time.After(15 * time.Second):
		t.Fatal("the provider call of the step-up never started")
	}
	if gate.finished.Load() != 1 {
		t.Fatalf("%d provider calls finished while the step-up's was held", gate.finished.Load())
	}
	gate.open()
	h.awaitSends(map[string]int{"sent": 2})
}

// TestAFailedDeliveryNeverRefundsASend: N5. A flow accepts three sends and refuses the fourth with the same limit whether the
// address is known and the provider works, the address is known and the provider fails, or the address is unknown. A refund after
// a failure would let a caller who asks four times tell a known address from an unknown one. MOCKED sender, real PostgreSQL.
func TestAFailedDeliveryNeverRefundsASend(t *testing.T) {
	h := newHarness(t, settings{policy: loosePolicy, asyncMail: true})
	working, failing, unknown := "works@example.org", "fails@example.org", "nobody@example.org"
	h.seedAccount(1, working)
	h.seedAccount(1, failing)
	h.remember(working, failing, unknown)
	type outcome struct {
		accepted int
		refusal  *foundationv1.ArcError
	}
	ask := func(address string) outcome {
		flow := h.beginEmail(address, caller{}).GetValue().GetChallenge().GetFlowId()
		var result outcome
		for range 4 {
			reply := h.requestCode(flow, address, caller{})
			if reply.GetError() != nil {
				result.refusal = reply.GetError()
				break
			}
			result.accepted++
		}
		return result
	}
	results := map[string]outcome{}
	results["working"] = ask(working)
	h.awaitSends(map[string]int{"sent": 3})
	h.mail.SetError(&mail.Error{Class: mail.ErrUnavailable, Provider: "smtp", Stage: "data", Code: 451})
	results["failing"] = ask(failing)
	h.awaitSends(map[string]int{"sent": 3, "unavailable": 3})
	h.mail.SetError(nil)
	results["unknown"] = ask(unknown)

	for name, result := range results {
		if result.accepted != 3 || result.refusal == nil || failure(result.refusal) != "RESOURCE/rate_limited" ||
			result.refusal.GetDetails().GetLimit().GetLimitName() != "email_code_sends" {
			t.Fatalf("%s: %d requests accepted, then %v", name, result.accepted, result.refusal)
		}
	}
	if !proto.Equal(results["working"].refusal.GetDetails(), results["failing"].refusal.GetDetails()) ||
		!proto.Equal(results["working"].refusal.GetDetails(), results["unknown"].refusal.GetDetails()) {
		t.Fatalf("the fourth refusals differ:\n%v\n%v\n%v", results["working"].refusal, results["failing"].refusal, results["unknown"].refusal)
	}
	// The unknown address changed no counter: three deliveries worked, three failed, none was started for the unknown one.
	if got := h.emailSends(); !maps.Equal(got, map[string]int{"sent": 3, "unavailable": 3}) {
		t.Fatalf("email_send reads %v", got)
	}
}

// operatorTexts are the documents an operator reads: the metrics text, the readiness document and the health document.
func (h *harness) operatorTexts() map[string]string {
	h.t.Helper()
	texts := map[string]string{}
	for where, request := range map[string]struct {
		handler http.Handler
		path    string
	}{
		"the metrics text":       {h.center.Admin(), "/metrics"},
		"the readiness document": {h.center.Admin(), "/readyz"},
		"the health document":    {h.center.Public(), "/healthz"},
	} {
		recorder := httptest.NewRecorder()
		request.handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, request.path, nil))
		if recorder.Body.Len() == 0 {
			h.t.Fatalf("%s is empty, so scanning it proves nothing", where)
		}
		texts[where] = recorder.Body.String()
	}
	return texts
}

// TestNoSecretReachesTheStoreOrTheLogsWithAnAdapter runs the secrets scan with each real adapter holding synthetic credentials:
// the token, the user name and the password, the provider's own text of a failed delivery, the codes and the addresses appear in no
// row, statement record, log line, metrics text, readiness document or health document. MOCKED provider, real PostgreSQL.
func TestNoSecretReachesTheStoreOrTheLogsWithAnAdapter(t *testing.T) {
	policy := `{"emailPerAddressLimit": 100}`
	t.Run("postmark", func(t *testing.T) {
		rig := newPostmarkRig(t, mailtest.PostmarkReply{}, 5*time.Second)
		noSecretReachesTheStoreOrTheLogs(t, rig.settings(policy, false), append(rig.secrets, word("provider-text")), func(h *harness) []string {
			// A failing delivery whose answer carries a marker: it must reach no log line.
			rig.postmark.Set(mailtest.PostmarkReply{Status: 422, Body: `{"ErrorCode":406,"Message":"` + word("provider-text") + `"}`})
			victim := h.seedAccount(1, "bounce.person@example.org")
			flow := h.beginEmail(victim.email, caller{}).GetValue().GetChallenge().GetFlowId()
			if reply := h.requestCode(flow, victim.email, caller{}); reply.GetError() != nil {
				t.Fatalf("a failed delivery changed the reply: %s", failure(reply.GetError()))
			}
			if h.emailSends()["rejected"] != 1 {
				t.Fatalf("the failed delivery was not counted: %v", h.emailSends())
			}
			return []string{victim.email}
		})
	})
	t.Run("smtp", func(t *testing.T) {
		rig := newSMTPRig(t, nil, 5*time.Second)
		noSecretReachesTheStoreOrTheLogs(t, rig.settings(policy, false), rig.secrets, nil)
	})
}

// comparableHeaders are the response headers of a reply without the ones that differ between two requests by nature (the date and the
// correlation id).
func comparableHeaders(r reply) http.Header {
	headers := r.header.Clone()
	for name := range headers {
		if lower := strings.ToLower(name); lower == "date" || strings.Contains(lower, "correlation") || strings.Contains(lower, "request-id") {
			delete(headers, name)
		}
	}
	return headers
}

// bucketPolicy leaves the e-mail limits at their defaults (5 per hour per address, 10 per hour per /24) and raises the others, so
// that the sign-in and step-up buckets do not refuse first.
const bucketPolicy = `{"signInPerPrefixLimit": 1000, "signInFailuresAccountLimit": 1000, "stepUpPerAccountLimit": 1000}`

// TestAFailedDeliveryNeverRefundsABucketUnderTheDefaultLimits: the per-flow count is not the only state a request leaves. Under the
// default limits a working provider, a failing provider and an unknown address are given exactly the same sequence of replies, six
// requests for one address (the sixth is refused by the address bucket after five) and thirteen more addresses of the same /24 (the
// prefix bucket refuses from the eleventh count of the hour on; the first part used six of the ten counts it accepts). A bucket given back after a failed delivery would let the sixth request through for a
// failing known address only, which tells known from unknown one request later than the flow count would. MOCKED sender, real
// PostgreSQL; each case has a /24 of its own.
func TestAFailedDeliveryNeverRefundsABucketUnderTheDefaultLimits(t *testing.T) {
	h := newHarness(t, settings{policy: bucketPolicy})
	type result struct{ addressSequence, prefixSequence []string }
	run := func(label, prefix string, address func(index int) string, failing bool) result {
		t.Helper()
		if failing {
			h.mail.SetError(&mail.Error{Class: mail.ErrUnavailable, Provider: "smtp", Stage: "data", Code: 451})
		} else {
			h.mail.SetError(nil)
		}
		var out result
		ask := func(flow *foundationv1.Id, mailbox string, client string) string {
			reply := h.requestCode(flow, mailbox, caller{ip: client})
			if reply.GetError() == nil {
				return "ok"
			}
			return failure(reply.GetError()) + ":" + reply.GetError().GetDetails().GetLimit().GetLimitName()
		}
		// Six requests for one address: a new flow after three (a flow allows three sends).
		var flow *foundationv1.Id
		for request := range 6 {
			if request%3 == 0 {
				flow = h.beginEmail(address(0), caller{ip: prefix + ".1"}).GetValue().GetChallenge().GetFlowId()
			}
			out.addressSequence = append(out.addressSequence, ask(flow, address(0), prefix+".1"))
		}
		// Thirteen addresses of the same /24, one request each.
		for index := 1; index <= 13; index++ {
			mailbox := address(index)
			flow = h.beginEmail(mailbox, caller{ip: prefix + ".2"}).GetValue().GetChallenge().GetFlowId()
			out.prefixSequence = append(out.prefixSequence, ask(flow, mailbox, prefix+".2"))
		}
		t.Logf("%s: %v / %v", label, out.addressSequence, out.prefixSequence)
		return out
	}
	known := func(tag string) func(int) string {
		return func(index int) string { return fmt.Sprintf("%s%d@example.org", tag, index) }
	}
	// Known accounts exist for the working and the failing cases; the unknown case has none.
	for _, tag := range []string{"w", "f"} {
		for index := range 14 {
			h.seedAccount(1, known(tag)(index))
		}
	}
	working := run("working", "198.51.100", known("w"), false)
	failing := run("failing", "198.51.101", known("f"), true)
	unknown := run("unknown", "198.51.102", known("u"), false)
	wantAddress := []string{"ok", "ok", "ok", "ok", "ok", "RESOURCE/rate_limited:email_address"}
	// The six requests of the first part were counted by the prefix bucket too (the sixth, refused by the address bucket, included), so
	// four of the thirteen are accepted: the tenth count of the hour is the last one accepted.
	wantPrefix := append(slices.Repeat([]string{"ok"}, 4), slices.Repeat([]string{"RESOURCE/rate_limited:email_prefix"}, 9)...)
	for label, got := range map[string]result{"working": working, "failing": failing, "unknown": unknown} {
		// The address bucket accepted five of its six requests and the prefix bucket four of the thirteen (ten counts with the first
		// part's six), whatever the provider did.
		if !slices.Equal(got.addressSequence, wantAddress) || !slices.Equal(got.prefixSequence, wantPrefix) {
			t.Errorf("%s: address %v, prefix %v; want %v and %v", label, got.addressSequence, got.prefixSequence, wantAddress, wantPrefix)
		}
	}
}

// TestTheCodeIsSentAfterTheCommitAndOutsideTheTransaction: with the inline background the send runs on the request's goroutine, so a
// sender that looks at the database through another connection sees whether the transaction has committed. The flow's send count
// and the step-up challenge must be visible when Send runs (a send inside the closure would run before the commit, and again at
// every retry of the closure, and would mail a code for a flow that a rollback removes).
func TestTheCodeIsSentAfterTheCommitAndOutsideTheTransaction(t *testing.T) {
	probe := &visibilityProbe{fake: mail.NewFake()}
	h := newHarness(t, settings{policy: loosePolicy, sender: probe, inbox: fakeInbox{probe.fake}})
	probe.sends = func() int { return h.count("SELECT coalesce(sum(sends), 0) FROM identity.auth_flow") }
	probe.challenges = func() int { return h.count("SELECT count(*) FROM identity.step_up_challenge") }
	address := "visible@example.org"
	who := h.seedAccount(1, address)
	h.remember(address)
	flow := h.beginEmail(address, caller{}).GetValue().GetChallenge().GetFlowId()
	if reply := h.requestCode(flow, address, caller{}); reply.GetError() != nil {
		t.Fatalf("send: %s", failure(reply.GetError()))
	}
	if got := probe.seen(); len(got) != 1 || got[0] != [2]int{1, 0} {
		t.Fatalf("at the first Send the flow's send count and the step-up challenges visible to another connection were %v, want [1 0]", got)
	}
	native := h.signIn(who, newClaim(t), caller{})
	if step := h.beginEmailStepUp(bearer(native.GetAccessToken()), who, identity.ClassRevokeAllSessions); step.GetError() != nil {
		t.Fatalf("begin the step-up: %s", failure(step.GetError()))
	}
	if got := probe.seen(); len(got) != 2 || got[1] != [2]int{1, 1} {
		t.Fatalf("at the step-up Send the visible state was %v, want the committed challenge: [1 1]", got)
	}
}

// visibilityProbe is a sender that records what another connection sees of the database at the moment of each Send.
type visibilityProbe struct {
	fake       *mail.Fake
	sends      func() int
	challenges func() int
	mu         sync.Mutex
	observed   [][2]int
}

func (v *visibilityProbe) Enabled() bool { return true }

func (v *visibilityProbe) Send(ctx context.Context, message mail.Message) error {
	seen := [2]int{v.sends(), v.challenges()}
	v.mu.Lock()
	v.observed = append(v.observed, seen)
	v.mu.Unlock()
	return v.fake.Send(ctx, message)
}

func (v *visibilityProbe) seen() [][2]int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([][2]int(nil), v.observed...)
}
