// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	connectv2 "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey/virtual"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
	foundation "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	v2 "github.com/ArcForges/Contracts/go/arcforges/sandbox/v2"
	"github.com/ArcForges/Contracts/go/arcforges/sandbox/v2/sandboxv2connect"
	"google.golang.org/protobuf/proto"
)

const (
	host03InspectRun     = sandboxv2connect.RunServiceInspectProcedure
	host03InspectSandbox = sandboxv2connect.SandboxServiceInspectProcedure
	host03UserAgent      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"
)

type host03Browser struct {
	f             *host03Fixture
	account       platform.ID
	installation  string
	csrf, cookie  string
	authenticator *virtual.Authenticator
	key           *virtual.Key
}

func (f *host03Fixture) browser() *host03Browser {
	return &host03Browser{f: f, installation: platform.NewID().String(), authenticator: virtual.New("localhost", f.origin)}
}

func (b *host03Browser) fresh() *host03Browser {
	return &host03Browser{f: b.f, installation: platform.NewID().String(), authenticator: b.authenticator, key: b.key, account: b.account}
}

type host03Challenge struct {
	FlowID    string `json:"flowId"`
	Challenge string `json:"challenge"`
	Options   struct {
		UserHandle string `json:"userHandle"`
	} `json:"options"`
}

type host03SessionView struct {
	CSRFToken     string `json:"csrfToken"`
	Authenticated bool   `json:"authenticated"`
	Session       struct {
		UserID string `json:"userId"`
	} `json:"session"`
}

func (b *host03Browser) state() host03SessionView {
	b.f.t.Helper()
	_, body := b.send(http.MethodGet, "/session/v1/web/bootstrap", "", "")
	state := host03Document[host03SessionView](b.f.t, body)
	b.csrf = state.CSRFToken
	if b.csrf == "" {
		b.f.t.Fatal("the owner's exact same-origin CSRF token was absent")
	}
	return state
}

func (b *host03Browser) claim() map[string]string {
	return map[string]string{"installationId": b.installation, "product": "arcforges-web", "platform": "web", "appVersion": "pages-1"}
}

func (b *host03Browser) enroll(token string) {
	b.f.t.Helper()
	if b.state().Authenticated {
		b.f.t.Fatal("the clean self-host already has an authenticated owner")
	}
	_, body := b.json("/session/v1/web/authentication/begin", map[string]any{"method": "passkey", "purpose": "enroll", "installation": b.claim()})
	challenge := host03Document[host03Challenge](b.f.t, body)
	creation, key := b.authenticator.Create(host03Decode(b.f.t, challenge.Challenge), host03Decode(b.f.t, challenge.Options.UserHandle))
	b.key = key
	transports := creation.Transports
	if transports == nil {
		transports = []string{}
	}
	credentials := map[string]any{"credentialId": host03Base64(creation.CredentialID), "clientDataJson": host03Base64(creation.ClientDataJSON),
		"attestationObject": host03Base64(creation.AttestationObject), "transports": transports}
	reply, _ := b.json("/session/v1/web/enrollment/complete", map[string]any{"flowId": challenge.FlowID,
		"proof": map[string]any{"localCode": token}, "credential": map[string]any{"passkey": credentials},
		"profile": map[string]string{"displayName": "Self-host operator"}})
	b.acceptSession(reply)
}

func (b *host03Browser) signIn() {
	b.f.t.Helper()
	previous := b.account
	if b.state().Authenticated {
		b.f.t.Fatal("the fresh browser unexpectedly already has restored account authority")
	}
	_, body := b.json("/session/v1/web/authentication/begin", map[string]any{"method": "passkey", "purpose": "authenticate", "installation": b.claim()})
	challenge := host03Document[host03Challenge](b.f.t, body)
	reply, _ := b.json("/session/v1/web/authentication/complete", map[string]any{"flowId": challenge.FlowID, "proof": b.proof(challenge.Challenge)})
	b.acceptSession(reply)
	if b.account != previous {
		b.f.t.Fatal("fresh passkey authentication did not recover the original account from the restored store")
	}
}

func (b *host03Browser) acceptSession(reply *http.Response) {
	b.f.t.Helper()
	for _, cookie := range reply.Cookies() {
		if cookie.Name == routes.PageCookieName && cookie.Secure && cookie.HttpOnly && cookie.Value != "" {
			b.cookie = cookie.Value
		}
	}
	if b.cookie == "" {
		b.f.t.Fatal("the browser did not receive the Center's secure session cookie")
	}
	state := b.state()
	if !state.Authenticated {
		b.f.t.Fatal("the issued browser session was not authenticated by the running Center")
	}
	b.account = host03UUID(b.f.t, state.Session.UserID)
}

func (b *host03Browser) requireRevoked() {
	b.f.t.Helper()
	if b.cookie == "" || b.state().Authenticated {
		b.f.t.Fatal("the source browser cookie remained active after logical restore")
	}
}

func (b *host03Browser) proof(challenge string) map[string]any {
	value := b.authenticator.Assert(b.key, host03Decode(b.f.t, challenge))
	return map[string]any{"passkey": map[string]string{"credentialId": host03Base64(value.CredentialID),
		"clientDataJson": host03Base64(value.ClientDataJSON), "authenticatorData": host03Base64(value.AuthenticatorData),
		"signature": host03Base64(value.Signature), "userHandle": host03Base64(value.UserHandle)}}
}

var host03ReturnLink = regexp.MustCompile(`id="return-link" href="([^"]+)"`)

func (b *host03Browser) approve(raw string) {
	b.f.t.Helper()
	verification, err := url.Parse(raw)
	if err != nil || verification.Scheme+"://"+verification.Host != b.f.origin || verification.Path != "/api/connect" ||
		verification.RawQuery != "" || verification.User != nil {
		b.f.t.Fatal("the native approval offered an unexpected external authority or path")
	}
	fragment, err := url.ParseQuery(verification.Fragment)
	if err != nil || len(fragment) != 1 || len(fragment["flow"]) != 1 {
		b.f.t.Fatal("the real Node did not offer one exact approval flow")
	}
	flow := host03UUID(b.f.t, fragment.Get("flow"))
	_, review := b.form("/connect/review", url.Values{"flow_id": {flow.String()}})
	if !strings.Contains(string(review), `id="node-fingerprint"`) {
		b.f.t.Fatal("the Center approval did not show the actual Node's credential review")
	}
	class := fleet.ClassApproveNodeSignIn
	_, begin := b.json("/session/v1/web/step-up/begin", map[string]any{"operationClass": class, "method": "passkey",
		"targetHash": identity.TargetHash(class, b.account, flow)})
	challenge := host03Document[host03Challenge](b.f.t, begin)
	b.json("/session/v1/web/step-up/complete", map[string]any{"flowId": challenge.FlowID, "proof": b.proof(challenge.Challenge)})
	_, approved := b.form("/connect/decision", url.Values{"flow_id": {flow.String()}, "decision": {"approve"}})
	link := host03ReturnLink.FindSubmatch(approved)
	if len(link) != 2 {
		b.f.t.Fatal("the exact approved PKCE browser flow did not return a callback")
	}
	callback, err := url.Parse(html.UnescapeString(string(link[1])))
	if err != nil || callback.Scheme != "http" || callback.User != nil || callback.Path != "/callback" || callback.Port() == "" ||
		net.ParseIP(callback.Hostname()) == nil || !net.ParseIP(callback.Hostname()).IsLoopback() {
		b.f.t.Fatal("the approved PKCE callback did not name the held Node loopback receiver")
	}
	client := &http.Client{Timeout: 6 * time.Second, Transport: &http.Transport{}, CheckRedirect: host03NoRedirect}
	defer client.CloseIdleConnections()
	if host03HTTPStatus(client, callback.String()) != http.StatusOK {
		b.f.t.Fatal("the installed Node's held loopback listener refused the exact PKCE response")
	}
}

func (b *host03Browser) json(path string, value any) (*http.Response, []byte) {
	b.f.t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		b.f.t.Fatal("encode a scoped browser request")
	}
	return b.send(http.MethodPost, path, "application/json", string(body))
}

func (b *host03Browser) form(path string, value url.Values) (*http.Response, []byte) {
	value.Set("csrf", b.csrf)
	return b.send(http.MethodPost, path, "application/x-www-form-urlencoded", value.Encode())
}

func (b *host03Browser) send(method, path, contentType, body string) (*http.Response, []byte) {
	b.f.t.Helper()
	request, err := http.NewRequestWithContext(b.f.t.Context(), method, b.f.origin+"/api"+path, strings.NewReader(body))
	if err != nil {
		b.f.t.Fatal("build a loopback TLS browser request")
	}
	b.headers(request)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	reply, err := b.f.client.Do(request)
	if err != nil {
		b.f.t.Fatalf("receive the real Center browser response for %s: %T", path, err)
	}
	defer reply.Body.Close()
	data, err := io.ReadAll(io.LimitReader(reply.Body, 128*1024+1))
	if err != nil || len(data) > 128*1024 || reply.StatusCode != http.StatusOK {
		b.f.t.Fatalf("real Center browser route %s: status %d or invalid bounded reply", path, reply.StatusCode)
	}
	return reply, data
}

func (b *host03Browser) headers(request *http.Request) {
	request.Header.Set("Origin", b.f.origin)
	request.Header.Set("User-Agent", host03UserAgent)
	if b.csrf != "" {
		request.Header.Set(ingress.CSRFHeader, b.csrf)
	}
	if b.cookie != "" {
		request.AddCookie(&http.Cookie{Name: routes.PageCookieName, Value: b.cookie})
	}
}

type host03BrowserTransport struct {
	b     *host03Browser
	scope host03Scope
}

func (p host03BrowserTransport) Do(request *http.Request) (*http.Response, error) {
	p.b.headers(request)
	request.Header.Set(ingress.RemoteNodeHeader, p.scope.node.String())
	request.Header.Set(ingress.RemoteEnrollmentHeader, p.scope.enrollment.String())
	request.Header.Set(ingress.RemoteGrantHeader, p.scope.grant.String())
	request.Header.Set(ingress.RemoteGrantRevisionHeader, strconv.FormatInt(p.scope.revision, 10))
	return p.b.f.client.Do(request)
}

func (b *host03Browser) remote(scope host03Scope, method string, request, response proto.Message) error {
	ctx, cancel := context.WithTimeout(b.f.t.Context(), 12*time.Second)
	defer cancel()
	transport := connecthttp.NewTransport(host03BrowserTransport{b, scope}, b.f.origin+"/api", connecthttp.WithGRPCWeb())
	return connectv2.NewClient(transport).CallUnary(ctx, connectv2.Spec{Procedure: method, StreamType: connectv2.StreamTypeUnary}, request, response)
}

func (b *host03Browser) inspect(scope host03Scope, sandbox, run string) {
	b.f.t.Helper()
	sandboxID, runID := host03LocalID(b.f.t, sandbox), host03LocalID(b.f.t, run)
	var box v2.SandboxServiceInspectResponse
	if err := b.remote(scope, host03InspectSandbox, &v2.SandboxServiceInspectRequest{Meta: host03RequestMeta(), SandboxId: host03ProtoID(sandboxID)}, &box); err != nil ||
		box.GetError() != nil || !proto.Equal(box.GetValue().GetSandbox().GetSandboxId(), host03ProtoID(sandboxID)) {
		b.f.t.Fatalf("real typed Sandbox Inspect did not return the original authorized sandbox: transport=%s code=%s", connectv2.CodeOf(err), box.GetError().GetCode())
	}
	var reply v2.RunServiceInspectResponse
	err := b.remote(scope, host03InspectRun, &v2.RunServiceInspectRequest{Meta: host03RequestMeta(), RunId: host03ProtoID(runID)}, &reply)
	runInfo := reply.GetValue().GetRun()
	if err != nil || reply.GetError() != nil || !proto.Equal(runInfo.GetRunId(), host03ProtoID(runID)) ||
		!proto.Equal(runInfo.GetSandboxId(), host03ProtoID(sandboxID)) || runInfo.GetState() != v2.RunState_RUN_STATE_RUNNING {
		b.f.t.Fatalf("real typed Run Inspect did not return the same authorized native Run: transport=%s code=%s state=%s",
			connectv2.CodeOf(err), reply.GetError().GetCode(), runInfo.GetState())
	}
}

func (b *host03Browser) rejectRun(scope host03Scope, run string, codes ...string) {
	b.f.t.Helper()
	var reply v2.RunServiceInspectResponse
	err := b.remote(scope, host03InspectRun,
		&v2.RunServiceInspectRequest{Meta: host03RequestMeta(), RunId: host03ProtoID(host03LocalID(b.f.t, run))}, &reply)
	if err != nil {
		if connectv2.CodeOf(err) == connectv2.CodeUnauthenticated && slices.Contains(codes, "unauthenticated") {
			return
		}
		b.f.t.Fatalf("expected a typed old-authority refusal or authenticated denial, got transport=%s", connectv2.CodeOf(err))
	}
	refusal := reply.GetError()
	if reply.GetValue() != nil || !slices.Contains(codes, refusal.GetCode()) ||
		refusal.GetEffect() != foundation.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN {
		b.f.t.Fatalf("expected old authority refusal with no effect: actual=%s/%s", refusal.GetCode(), refusal.GetEffect())
	}
}

func host03RequestMeta() *foundation.RequestMeta {
	return &foundation.RequestMeta{CorrelationId: host03ProtoID(platform.NewID())}
}

func host03Document[T any](t *testing.T, body []byte) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal("the real Center returned an invalid browser JSON document")
	}
	return value
}

func host03UUID(t *testing.T, text string) platform.ID {
	t.Helper()
	value, err := hex.DecodeString(strings.ReplaceAll(text, "-", ""))
	if err != nil || len(value) != 16 {
		t.Fatal("the Center did not supply a canonical exact UUID")
	}
	id := platform.ID(value)
	if id == (platform.ID{}) || id.String() != text {
		t.Fatal("the Center did not supply a canonical exact UUID")
	}
	return id
}

func host03Base64(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

func host03Decode(t *testing.T, value string) []byte {
	t.Helper()
	body, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(body) == 0 {
		t.Fatal("the scoped browser received malformed WebAuthn challenge bytes")
	}
	return body
}
