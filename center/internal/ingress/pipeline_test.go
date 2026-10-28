// SPDX-License-Identifier: AGPL-3.0-only

package ingress

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/correlation"
)

const (
	helloMethod     = "/arcforges.hello.v1.HelloService/SayHello"
	accountMethod   = "/arcforges.test.v1.Probe/Account"
	workspaceMethod = "/arcforges.test.v1.Probe/Workspace"
	origin          = "https://center.example"
	bearer          = "Bearer abcdefghijklmnop.qrstuvwxyz"
	cookie          = "__Host-af_session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	csrf            = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	workerTrace     = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
)

func must(t testing.TB) func(Policy, error) Policy {
	return func(policy Policy, err error) Policy {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return policy
	}
}

func testRoutes(t testing.TB) *Routes {
	t.Helper()
	registry, err := NewRegistry(
		must(t)(NewUnary(helloMethod, Anonymous, NoScope, 4096, false)),
		must(t)(NewUnary(accountMethod, Session, NoScope, 4096, true)),
		must(t)(NewServerStream(workspaceMethod, Session, Workspace, 4096, false)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return NewRoutes(registry, []string{"/healthz"}, nil)
}

type fakeBearer struct {
	caller *Caller
	err    error
}

func (f fakeBearer) Verify(context.Context, string) (*Caller, error) { return f.caller, f.err }

type fakeBrowser struct {
	credential *BrowserCredential
	err        error
}

func (fakeBrowser) AllowedOrigin() string { return origin }

func (f fakeBrowser) Resolve(context.Context, string) (*BrowserCredential, error) {
	return f.credential, f.err
}

var owner = Caller{
	Credential: CredentialNativeBearer, SessionID: "s", UserID: "u", DeviceID: "d",
	WorkspaceIDs: []string{correlation.FormatID(workspaceBytes)}, RecoveryGeneration: 7,
}

type rig struct {
	t        *testing.T
	pipeline http.Handler
	calls    []*Call
	outcomes []Outcome
}

func newRig(t *testing.T, options Options) *rig {
	r := &rig{t: t}
	options.Routes = testRoutes(t)
	options.Observe = func(_ *http.Request, outcome Outcome) { r.outcomes = append(r.outcomes, outcome) }
	r.pipeline = NewPipeline(options, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		call, _ := CallFrom(request.Context())
		r.calls = append(r.calls, call)
		writer.WriteHeader(http.StatusTeapot)
	}))
	return r
}

func (r *rig) do(method, target string, body []byte, header map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/grpc-web+proto")
	}
	for name, value := range header {
		if value == "" {
			request.Header.Del(name)
		} else {
			request.Header.Set(name, value)
		}
	}
	recorder := httptest.NewRecorder()
	r.pipeline.ServeHTTP(recorder, request)
	return recorder
}

func expectRefusal(t *testing.T, recorder *httptest.ResponseRecorder, reason Reason) {
	t.Helper()
	want := TrailerFrame(reason.Status, reason.Code, true)
	if recorder.Code != http.StatusOK || !bytes.Equal(recorder.Body.Bytes(), want) ||
		recorder.Header().Get("Content-Type") != "application/grpc-web+proto" ||
		recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("X-Content-Type-Options") != "nosniff" ||
		recorder.Header().Get("Content-Length") != strconv.Itoa(len(want)) {
		t.Fatalf("want trailers-only %d %s, got HTTP %d %q %v", reason.Status, reason.Code, recorder.Code, recorder.Body.Bytes(), recorder.Header())
	}
}

func expectPlain(t *testing.T, recorder *httptest.ResponseRecorder, status int) {
	t.Helper()
	if recorder.Code != status || recorder.Body.Len() != 0 || recorder.Header().Get("Cache-Control") != "no-store" ||
		recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("want plain %d, got %d %q", status, recorder.Code, recorder.Body.Bytes())
	}
}

func metaBody(t testing.TB, meta *foundationv1.RequestMeta) []byte {
	return Frame(request(marshal(t, meta)))
}

func TestPoliciesAreDeclaredAndDuplicatesRefused(t *testing.T) {
	for _, invalid := range []func() (Policy, error){
		func() (Policy, error) {
			return NewUnary("/arcforges.test.v1.Probe/ping", Anonymous, NoScope, 4096, false)
		},
		func() (Policy, error) {
			return NewUnary("arcforges.test.v1.Probe/Ping", Anonymous, NoScope, 4096, false)
		},
		func() (Policy, error) {
			return NewUnary("/Arcforges.test.v1.Probe/Ping", Anonymous, NoScope, 4096, false)
		},
		func() (Policy, error) { return NewUnary("/probe/Ping", Anonymous, NoScope, 4096, false) },
		func() (Policy, error) {
			return NewUnary("/arcforges.test.v1.Probe/Ping\n", Anonymous, NoScope, 4096, false)
		},
		func() (Policy, error) { return NewUnary(helloMethod, Anonymous, NoScope, 0, false) },
		func() (Policy, error) {
			return NewUnary(helloMethod, Anonymous, NoScope, AbsoluteMaxRequestBytes+1, false)
		},
		func() (Policy, error) { return NewUnary(helloMethod, Anonymous, Workspace, 4096, false) },
		func() (Policy, error) { return NewServerStream(helloMethod, Authentication(9), NoScope, 4096, false) },
		func() (Policy, error) { return NewServerStream(helloMethod, Session, Scope(9), 4096, false) },
	} {
		if _, err := invalid(); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("an invalid policy was declared: %v", err)
		}
	}
	hello := must(t)(NewUnary(helloMethod, Anonymous, NoScope, 4096, false))
	if _, err := NewRegistry(hello, hello); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("a duplicate policy was composed")
	}
	if _, err := NewRegistry(Policy{}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("an undeclared policy was composed")
	}
	registry, err := NewRegistry(hello)
	if err != nil || len(registry.All()) != 1 || hello.ReadsRequestMeta() {
		t.Fatal("registry")
	}
	if !must(t)(NewServerStream(workspaceMethod, Session, Workspace, 4096, false)).ReadsRequestMeta() {
		t.Fatal("a workspace method reads its meta")
	}
	routes := NewRoutes(registry, []string{"/healthz"}, []string{"/internal/"})
	for path, want := range map[string]bool{"/healthz": true, "/healthz/x": false, "/internal/": false, "/internal/x": true, "/Healthz": false} {
		if routes.IsPlain(path) != want {
			t.Fatalf("IsPlain(%q)", path)
		}
	}
}

func TestOnlyCanonicalTargetsAreServed(t *testing.T) {
	r := newRig(t, Options{})
	for _, target := range []string{
		"/healthz/", "//healthz", "/a/./healthz", "/a/../healthz", "/%68ealthz", "/arcforges.hello.v1.HelloService/SayHello/",
		"/arcforges.hello.v1.HelloService%2FSayHello", "/x\\y", "http://center.example/healthz",
	} {
		expectPlain(t, r.do(http.MethodGet, target, nil, nil), http.StatusNotFound)
	}
	if recorder := r.do(http.MethodGet, "/healthz?probe=1", nil, nil); recorder.Code != http.StatusTeapot {
		t.Fatalf("a query does not change the path: %d", recorder.Code)
	}
	expectPlain(t, r.do(http.MethodGet, "/unknown", nil, nil), http.StatusNotFound)
	expectPlain(t, r.do(http.MethodGet, "/a.b/c/d", nil, nil), http.StatusNotFound)
	if len(r.calls) != 1 || r.calls[0] != nil {
		t.Fatal("a plain route carries no call")
	}
}

func TestMethodShapedPaths(t *testing.T) {
	for path, want := range map[string]bool{
		helloMethod: true, "/a.B/C": true, "/a/B": false, "/a.b/": false, "/a.b": false, "/a.b/c/d": false, "/.": false, "/x/y": false, "/./x": true,
	} {
		if LooksLikeRPC(path) != want {
			t.Fatalf("LooksLikeRPC(%q)", path)
		}
	}
}

func TestUnregisteredMethodsAreUnimplementedAndOnlyPostIsServed(t *testing.T) {
	r := newRig(t, Options{})
	recorder := r.do(http.MethodPost, "/arcforges.hello.v1.HelloService/Unknown", Frame(nil), nil)
	expectRefusal(t, recorder, ReasonUnimplemented)
	if !bytes.Equal(recorder.Body.Bytes(), []byte("\x80\x00\x00\x00\x2egrpc-status: 12\r\ngrpc-message: unimplemented\r\n")) {
		t.Fatalf("the refusal is not the C# host's frame: %q", recorder.Body.Bytes())
	}
	expectPlain(t, r.do(http.MethodGet, helloMethod, nil, nil), http.StatusMethodNotAllowed)
	native := r.do(http.MethodPost, "/arcforges.hello.v1.HelloService/Unknown", nil, map[string]string{"Content-Type": "application/grpc"})
	if native.Code != http.StatusOK || native.Header().Get("Grpc-Status") != "12" || native.Header().Get("Grpc-Message") != "unimplemented" ||
		native.Header().Get("Content-Type") != "application/grpc" || native.Body.Len() != 0 {
		t.Fatalf("native gRPC refusal: %d %v", native.Code, native.Header())
	}
	if len(r.calls) != 0 || r.outcomes[0].Method != "unregistered" || r.outcomes[0].Refusal.Code != "unimplemented" {
		t.Fatalf("no handler runs for an unregistered method: %+v", r.outcomes)
	}
}

func TestOnlyUncompressedBinaryGrpcIsAdmitted(t *testing.T) {
	r := newRig(t, Options{})
	for _, header := range []map[string]string{
		{"Content-Type": "application/json"},
		{"Content-Type": "application/grpc-web-text+proto"},
		{"Content-Type": "application/grpc-web+json"},
		{"Content-Type": "application/proto"},
		{"Content-Type": "application/connect+proto"},
		{"Content-Type": ""},
		{"Content-Encoding": "gzip"},
		{"Grpc-Encoding": "gzip"},
	} {
		expectPlain(t, r.do(http.MethodPost, helloMethod, Frame(nil), header), http.StatusUnsupportedMediaType)
	}
	for _, header := range []map[string]string{
		{"Content-Type": "application/grpc-web"},
		{"Content-Type": "Application/GRPC-Web+Proto; charset=utf-8"},
		{"Content-Type": "application/grpc"},
		{"Content-Type": "application/grpc+proto"},
		{"Grpc-Encoding": "Identity"},
	} {
		if recorder := r.do(http.MethodPost, helloMethod, Frame(nil), header); recorder.Code != http.StatusTeapot {
			t.Fatalf("refused %v: %d", header, recorder.Code)
		}
	}
}

func TestAnAnonymousCallIsAdmittedWithTheWorkerCorrelation(t *testing.T) {
	r := newRig(t, Options{})
	recorder := r.do(http.MethodPost, helloMethod, Frame([]byte{0x0a, 0x01, 'x'}), map[string]string{"Traceparent": workerTrace, "Authorization": "ignored"})
	if recorder.Code != http.StatusTeapot || len(r.calls) != 1 {
		t.Fatalf("not admitted: %d", recorder.Code)
	}
	call := r.calls[0]
	if call.Policy.FullName != helloMethod || call.Caller.IsAuthenticated() || call.Owner != nil ||
		call.Correlation.CorrelationID != "4bf92f35-77b3-4da6-a3ce-929d0e0e4736" || call.Correlation.ParentSpanID != "00f067aa0ba902b7" {
		t.Fatalf("call: %+v", call)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("an admitted call is not cacheable")
	}
	fresh := r.do(http.MethodPost, helloMethod, Frame(nil), map[string]string{"Traceparent": strings.ToUpper(workerTrace)})
	if fresh.Code != http.StatusTeapot || !correlation.IsValidID(r.calls[1].Correlation.CorrelationID) || r.calls[1].Correlation.ParentSpanID != "" {
		t.Fatal("a malformed traceparent must give a fresh identity")
	}
}

func TestTheRequestBoundIsAppliedBeforeAnyHandler(t *testing.T) {
	r := newRig(t, Options{Bearer: fakeBearer{caller: &owner}})
	expectRefusal(t, r.do(http.MethodPost, helloMethod, make([]byte, 4097), nil), ReasonRequestTooLarge)
	tooLarge := metaBody(t, &foundationv1.RequestMeta{CorrelationId: &foundationv1.Id{Value: correlationBytes}})
	tooLarge = append(tooLarge, make([]byte, 4096)...)
	expectRefusal(t, r.do(http.MethodPost, accountMethod, tooLarge, map[string]string{"Authorization": bearer}), ReasonRequestTooLarge)
	if len(r.calls) != 0 {
		t.Fatal("an oversized request reached a handler")
	}
	// Without a declared length the bound applies while the handler reads.
	request := httptest.NewRequest(http.MethodPost, helloMethod, bytes.NewReader(make([]byte, 5000)))
	request.ContentLength = -1
	request.Header.Set("Content-Type", "application/grpc-web")
	var readErr error
	handler := NewPipeline(Options{Routes: testRoutes(t)}, http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		_, readErr = bytes.NewBuffer(nil).ReadFrom(request.Body)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), request)
	var tooBig *http.MaxBytesError
	if !errors.As(readErr, &tooBig) {
		t.Fatalf("the handler read past the bound: %v", readErr)
	}
}

func TestTheEnvelopeAndItsCorrelationAreValidated(t *testing.T) {
	r := newRig(t, Options{Bearer: fakeBearer{caller: &owner}})
	auth := map[string]string{"Authorization": bearer, "Traceparent": workerTrace}
	stated := metaBody(t, &foundationv1.RequestMeta{CorrelationId: &foundationv1.Id{Value: correlationBytes[:]}})
	if recorder := r.do(http.MethodPost, accountMethod, stated, auth); recorder.Code != http.StatusTeapot {
		t.Fatalf("a valid envelope was refused: %d %q", recorder.Code, recorder.Body.Bytes())
	}
	if got := r.calls[0].Correlation; got.CorrelationID != "4bf92f35-77b3-4da6-a3ce-929d0e0e4736" || got.ParentSpanID != "00f067aa0ba902b7" {
		t.Fatalf("stated correlation: %+v", got)
	}
	other := append([]byte(nil), correlationBytes...)
	other[0] = 0x11
	if recorder := r.do(http.MethodPost, accountMethod, metaBody(t, &foundationv1.RequestMeta{CorrelationId: &foundationv1.Id{Value: other}}), auth); recorder.Code != http.StatusTeapot {
		t.Fatal("refused")
	}
	if got := r.calls[1].Correlation; got.CorrelationID != correlation.FormatID(other) || got.ParentSpanID != "" {
		t.Fatalf("the envelope wins and a different trace is no parent: %+v", got)
	}
	for name, body := range map[string][]byte{
		"no frame":           nil,
		"compressed flag":    append([]byte{1}, stated[1:]...),
		"length mismatch":    append(append([]byte(nil), stated...), 0),
		"second frame":       append(append([]byte(nil), stated...), stated...),
		"short correlation":  metaBody(t, &foundationv1.RequestMeta{CorrelationId: &foundationv1.Id{Value: correlationBytes[:8]}}),
		"nil correlation":    metaBody(t, &foundationv1.RequestMeta{CorrelationId: &foundationv1.Id{Value: make([]byte, 16)}}),
		"repeated meta":      Frame(append(request(marshal(t, &foundationv1.RequestMeta{})), request(nil)...)),
		"trailer flag frame": append([]byte{TrailerFlag}, stated[1:]...),
	} {
		expectRefusal(t, r.do(http.MethodPost, accountMethod, body, auth), ReasonInvalidRequest)
		if len(r.calls) != 2 {
			t.Fatalf("%s reached a handler", name)
		}
	}
}

func TestCredentialsFollowTheHostRules(t *testing.T) {
	validCSRF := func(token string, present bool) bool { return present && token == csrf }
	browserCaller := owner
	browserCaller.Credential = CredentialBrowserSession
	session := &BrowserCredential{Caller: browserCaller, VerifyCSRF: validCSRF}
	body := metaBody(t, &foundationv1.RequestMeta{})
	cases := []struct {
		name    string
		options Options
		header  map[string]string
		want    *Reason
	}{
		{"no credential", Options{Bearer: fakeBearer{caller: &owner}}, nil, &ReasonUnauthenticated},
		{"no bearer verifier", Options{}, map[string]string{"Authorization": bearer}, &ReasonUnauthenticated},
		{"both credentials", Options{Bearer: fakeBearer{caller: &owner}}, map[string]string{"Authorization": bearer, "Cookie": cookie}, &ReasonUnauthenticated},
		{"malformed bearer", Options{Bearer: fakeBearer{caller: &owner}}, map[string]string{"Authorization": "Bearer short"}, &ReasonUnauthenticated},
		{"unknown bearer", Options{Bearer: fakeBearer{}}, map[string]string{"Authorization": bearer}, &ReasonUnauthenticated},
		{"wrong credential kind", Options{Bearer: fakeBearer{caller: &browserCaller}}, map[string]string{"Authorization": bearer}, &ReasonUnauthenticated},
		{"bearer store down", Options{Bearer: fakeBearer{err: errors.New("down")}}, map[string]string{"Authorization": bearer}, &ReasonDependencyUnavailable},
		{"bearer", Options{Bearer: fakeBearer{caller: &owner}}, map[string]string{"Authorization": "bearer abcdefghijklmnop.qrstuvwxyz"}, nil},
		{"no browser verifier", Options{}, map[string]string{"Cookie": cookie}, &ReasonUnauthenticated},
		{"wrong origin", Options{Browser: fakeBrowser{credential: session}}, map[string]string{"Cookie": cookie, "Origin": "https://other.example", "X-AF-CSRF": csrf}, &ReasonPermissionDenied},
		{"no origin", Options{Browser: fakeBrowser{credential: session}}, map[string]string{"Cookie": cookie, "X-AF-CSRF": csrf}, &ReasonPermissionDenied},
		{"unknown session", Options{Browser: fakeBrowser{}}, map[string]string{"Cookie": cookie, "Origin": origin, "X-AF-CSRF": csrf}, &ReasonUnauthenticated},
		{"session store down", Options{Browser: fakeBrowser{err: errors.New("down")}}, map[string]string{"Cookie": cookie, "Origin": origin, "X-AF-CSRF": csrf}, &ReasonDependencyUnavailable},
		{"no csrf", Options{Browser: fakeBrowser{credential: session}}, map[string]string{"Cookie": cookie, "Origin": origin}, &ReasonPermissionDenied},
		{"wrong csrf", Options{Browser: fakeBrowser{credential: session}}, map[string]string{"Cookie": cookie, "Origin": origin, "X-AF-CSRF": "x"}, &ReasonPermissionDenied},
		{"browser session", Options{Browser: fakeBrowser{credential: session}}, map[string]string{"Cookie": cookie, "Origin": origin, "X-AF-CSRF": csrf}, nil},
	}
	for _, test := range cases {
		r := newRig(t, test.options)
		recorder := r.do(http.MethodPost, accountMethod, body, test.header)
		if test.want != nil {
			expectRefusal(t, recorder, *test.want)
			if len(r.calls) != 0 {
				t.Fatalf("%s reached a handler", test.name)
			}
			continue
		}
		if recorder.Code != http.StatusTeapot || len(r.calls) != 1 || !r.calls[0].Caller.IsAuthenticated() {
			t.Fatalf("%s was refused: %d %q", test.name, recorder.Code, recorder.Body.Bytes())
		}
	}
}

func TestTheOwnerGateOfAWorkspaceMethod(t *testing.T) {
	generation := uint64(7)
	stale := uint64(6)
	workspace := &foundationv1.Id{Value: workspaceBytes}
	foreign := &foundationv1.Id{Value: correlationBytes}
	auth := map[string]string{"Authorization": bearer}
	r := newRig(t, Options{Bearer: fakeBearer{caller: &owner}})
	expectRefusal(t, r.do(http.MethodPost, workspaceMethod, metaBody(t, &foundationv1.RequestMeta{}), auth), ReasonInvalidRequest)
	expectRefusal(t, r.do(http.MethodPost, workspaceMethod, metaBody(t, &foundationv1.RequestMeta{WorkspaceId: foreign}), auth), ReasonPermissionDenied)
	expectRefusal(t, r.do(http.MethodPost, workspaceMethod, metaBody(t, &foundationv1.RequestMeta{WorkspaceId: workspace, RecoveryGeneration: &stale}), auth), ReasonStaleGeneration)
	noUser := owner
	noUser.UserID = ""
	expectRefusal(t, newRig(t, Options{Bearer: fakeBearer{caller: &noUser}}).do(http.MethodPost, workspaceMethod, metaBody(t, &foundationv1.RequestMeta{WorkspaceId: workspace}), auth), ReasonPermissionDenied)
	for _, meta := range []*foundationv1.RequestMeta{{WorkspaceId: workspace, RecoveryGeneration: &generation}, {WorkspaceId: workspace}} {
		if recorder := r.do(http.MethodPost, workspaceMethod, metaBody(t, meta), auth); recorder.Code != http.StatusTeapot {
			t.Fatalf("the owner was refused: %q", recorder.Body.Bytes())
		}
	}
	if len(r.calls) != 2 || r.calls[0].Owner == nil || *r.calls[0].Owner != (Owner{WorkspaceID: correlation.FormatID(workspaceBytes), UserID: "u", DeviceID: "d", RecoveryGeneration: 7}) {
		t.Fatalf("owner: %+v", r.calls)
	}
}

func TestCredentialShapes(t *testing.T) {
	header := http.Header{}
	header.Add("Cookie", "a=b; __Host-af_session=one")
	if value, ok := SessionCookie(header); !ok || value != "one" {
		t.Fatal("cookie")
	}
	header.Add("Cookie", "__Host-af_session=two")
	if _, ok := SessionCookie(header); ok {
		t.Fatal("a repeated cookie is no credential")
	}
	for _, line := range []string{"__Host-af_session=", "__host-af_session=one", "=one", "__Host-af_session"} {
		if _, ok := SessionCookie(http.Header{"Cookie": {line}}); ok {
			t.Fatalf("cookie %q", line)
		}
	}
	for value, want := range map[string]bool{
		bearer: true, "BEARER abcdefghijklmnop": true, "Bearer abcdefghijklmno": false, "Bearer " + strings.Repeat("a", 4097): false,
		"Bearer " + strings.Repeat("a", 4096): true, "Bearer abcdefghijklmnop!": false, "Basic abcdefghijklmnop": false, "Bearer": false,
	} {
		if _, ok := BearerToken(http.Header{"Authorization": {value}}); ok != want {
			t.Fatalf("bearer %q", value)
		}
	}
	if _, ok := BearerToken(http.Header{"Authorization": {bearer, bearer}}); ok {
		t.Fatal("two authorization values are no credential")
	}
}

func TestTheRefusalTableIsTheHostTable(t *testing.T) {
	want := map[string]Status{}
	for _, reason := range Reasons() {
		want[reason.Code+"/"+strconv.Itoa(int(reason.Status))] = reason.Status
		connectError := reason.ConnectError()
		if int(connectError.Code()) != int(reason.Status) || connectError.Message() != reason.Code {
			t.Fatalf("connect error of %s", reason.Code)
		}
	}
	for key, status := range map[string]Status{
		"unimplemented/12": 12, "auth.unauthenticated/16": 16, "perm.resource_denied/7": 7, "validation.invalid_request/3": 3,
		"validation.invalid_request/8": 8, "state.stale_generation/9": 9, "dependency.unavailable/14": 14,
		"auth.token_expired/16": 16, "auth.credential_revoked/16": 16,
	} {
		if want[key] != status {
			t.Fatalf("missing %s", key)
		}
	}
	if len(want) != 9 || connect.Code(StatusUnauthenticated) != connect.CodeUnauthenticated || connect.Code(StatusResourceExhausted) != connect.CodeResourceExhausted {
		t.Fatal("status numbering")
	}
	if got := TrailerFrame(StatusOK, "", false, [2]string{"x-af-probe", "done"}); string(got[5:]) != "grpc-status: 0\r\nx-af-probe: done\r\n" || got[0] != TrailerFlag {
		t.Fatalf("trailer frame %q", got)
	}
	if got := EscapeDataString("Name must not be empty. \u00e9~_-%/"); got != "Name%20must%20not%20be%20empty.%20%C3%A9~_-%25%2F" {
		t.Fatalf("escape %q", got)
	}
}

func TestDomainRepliesCarryTheCorrelation(t *testing.T) {
	call := correlation.ForRequest([]string{workerTrace}, "")
	meta := marshal(t, ResponseMeta(call))
	if meta[0] != byte(protowire.EncodeTag(4, protowire.BytesType)) {
		t.Fatal("ResponseMeta.correlation_id is tag 4")
	}
	arcError := DomainError(call, "state.not_found", foundationv1.ErrorCategory_ERROR_CATEGORY_STATE, "error.state.not_found")
	var decoded foundationv1.ArcError
	if err := proto.Unmarshal(marshal(t, arcError), &decoded); err != nil {
		t.Fatal(err)
	}
	if correlation.FormatID(decoded.GetCorrelationId().GetValue()) != call.CorrelationID || decoded.GetCode() != "state.not_found" ||
		decoded.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_NEVER || decoded.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN ||
		decoded.GetCategory() != foundationv1.ErrorCategory_ERROR_CATEGORY_STATE {
		t.Fatalf("arc error: %v", &decoded)
	}
	if !bytes.Contains(marshal(t, arcError), protowire.AppendTag(nil, 6, protowire.BytesType)) {
		t.Fatal("ArcError.correlation_id is tag 6")
	}
}
