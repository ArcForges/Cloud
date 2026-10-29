// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	hellov1 "github.com/ArcForges/Contracts/go/arcforges/hello/v1"
	"github.com/ArcForges/Contracts/go/arcforges/hello/v1/hellov1connect"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/buildinfo"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/hello"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/observe"
)

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func testConfig(mode config.Mode) config.Config {
	return config.Config{Mode: mode, PublicBaseURL: "https://center.example/api", MaxConnections: 8}
}

type harness struct {
	center *Center
	server *httptest.Server
	logs   *lockedBuffer
	calls  *int
	mu     *sync.Mutex
}

func start(t *testing.T, greeting hello.Greeting) *harness {
	t.Helper()
	logs := &lockedBuffer{}
	calls, mu := 0, &sync.Mutex{}
	counted := func(ctx context.Context, name string) (string, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return greeting(ctx, name)
	}
	center, err := New(testConfig(config.OfficialHosted), observe.NewLogger(logs, slog.LevelDebug), Options{Greeting: counted})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(center.Close)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	server := httptest.NewUnstartedServer(center.Public())
	server.Config.Protocols = protocols
	server.Start()
	t.Cleanup(server.Close)
	return &harness{center: center, server: server, logs: logs, calls: &calls, mu: mu}
}

func (h *harness) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return *h.calls
}

func TestGRPCAndGRPCWebPreserveThePublishedHello(t *testing.T) {
	for _, wire := range []string{"grpc", "grpcweb"} {
		t.Run(wire, func(t *testing.T) {
			h := start(t, hello.Stateless)
			protocols := new(http.Protocols)
			protocols.SetHTTP1(true)
			protocols.SetUnencryptedHTTP2(true)
			transport := &http.Transport{Protocols: protocols}
			defer transport.CloseIdleConnections()
			option := connecthttp.WithGRPC()
			if wire == "grpcweb" {
				option = connecthttp.WithGRPCWeb()
			}
			client := hellov1connect.NewHelloServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{Transport: transport}, h.server.URL, option)))
			for _, name := range []string{"ArcForges", "\u4e16\u754c \U0001f44b", "NUL\x00check", " ", strings.Repeat("x", 256), strings.Repeat("\U0001f44b", 128)} {
				reply, err := client.SayHello(t.Context(), &hellov1.SayHelloRequest{Name: name})
				if err != nil {
					t.Fatal(err)
				}
				if reply.GetMessage() != "Hello, "+name+"!" {
					t.Fatal("wire greeting changed")
				}
			}
			for _, row := range []struct {
				name string
				code connect.Code
			}{
				{"", connect.CodeInvalidArgument},
				{strings.Repeat("x", 257), connect.CodeResourceExhausted},
				{strings.Repeat("\U0001f44b", 129), connect.CodeResourceExhausted},
			} {
				_, err := client.SayHello(t.Context(), &hellov1.SayHelloRequest{Name: row.name})
				if connect.CodeOf(err) != row.code {
					t.Fatalf("unexpected status: %v", err)
				}
			}
			if h.count() != 6 {
				t.Fatalf("invalid input reached the greeting: calls=%d", h.count())
			}
			if strings.Contains(h.logs.String(), "ArcForges\"") || strings.Contains(h.logs.String(), "NUL") {
				t.Fatal("a request body reached the log")
			}
		})
	}
}

// grpcWeb is one binary gRPC-Web exchange over HTTP/1.1 exactly as the published C# probe makes it (tools/ArcForges.Cloud.Generation
// HelloProbe): a length-prefixed data frame out with content type application/grpc-web+proto and a grpc-timeout, then data and
// trailer frames back.
type grpcWebReply struct {
	httpStatus int
	header     http.Header
	messages   [][]byte
	trailers   map[string]string
}

func grpcWeb(t *testing.T, baseURL, path string, body []byte, header map[string]string) grpcWebReply {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/grpc-web+proto")
	request.Header.Set("Grpc-Timeout", "20000m")
	for name, value := range header {
		request.Header.Set(name, value)
	}
	return send(t, request)
}

// send posts a gRPC-Web request and reads its reply frames.
func send(t *testing.T, request *http.Request) grpcWebReply {
	t.Helper()
	response, err := (&http.Client{Transport: &http.Transport{}}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	reply := grpcWebReply{httpStatus: response.StatusCode, header: response.Header, trailers: map[string]string{}}
	for len(data) >= ingress.HeaderLength {
		flag, length := data[0], int(binary.BigEndian.Uint32(data[1:5]))
		content := data[ingress.HeaderLength : ingress.HeaderLength+length]
		data = data[ingress.HeaderLength+length:]
		if flag&ingress.TrailerFlag == 0 {
			reply.messages = append(reply.messages, content)
			continue
		}
		for line := range strings.SplitSeq(string(content), "\r\n") {
			if key, value, found := strings.Cut(line, ":"); found {
				reply.trailers[strings.TrimSpace(strings.ToLower(key))] = strings.TrimSpace(value)
			}
		}
	}
	if len(data) != 0 {
		t.Fatalf("a partial frame: %q", data)
	}
	if len(reply.trailers) == 0 && len(reply.messages) == 0 {
		// A trailers-only reply carries the status in its headers, which the published client and the Worker read.
		for _, name := range []string{"Grpc-Status", "Grpc-Message"} {
			if value := response.Header.Get(name); value != "" {
				reply.trailers[strings.ToLower(name)] = value
			}
		}
	}
	return reply
}

func helloRequest(t *testing.T, name string) []byte {
	t.Helper()
	message, err := proto.Marshal(&hellov1.SayHelloRequest{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	return ingress.Frame(message)
}

func TestTheBinaryGrpcWebExchangeOfThePublishedClient(t *testing.T) {
	h := start(t, hello.Stateless)
	for _, name := range []string{"NUL\x00check", "ArcForges", "\u4e16\u754c \U0001f44b"} {
		reply := grpcWeb(t, h.server.URL, "/arcforges.hello.v1.HelloService/SayHello", helloRequest(t, name), nil)
		if reply.httpStatus != http.StatusOK || reply.trailers["grpc-status"] != "0" || len(reply.messages) != 1 ||
			!strings.HasPrefix(reply.header.Get("Content-Type"), "application/grpc-web") {
			t.Fatalf("%q: %+v", name, reply)
		}
		var decoded hellov1.SayHelloResponse
		if err := proto.Unmarshal(reply.messages[0], &decoded); err != nil || decoded.GetMessage() != "Hello, "+name+"!" {
			t.Fatalf("%q: %v", name, err)
		}
	}
	for name, want := range map[string][2]string{
		"":                       {"3", "Name must not be empty."},
		strings.Repeat("x", 257): {"8", "Name exceeds 256 UTF-16 code units."},
	} {
		reply := grpcWeb(t, h.server.URL, "/arcforges.hello.v1.HelloService/SayHello", helloRequest(t, name), nil)
		message, err := urlUnescape(reply.trailers["grpc-message"])
		if reply.httpStatus != http.StatusOK || reply.trailers["grpc-status"] != want[0] || err != nil || message != want[1] || len(reply.messages) != 0 {
			t.Fatalf("%q: %+v", name, reply)
		}
	}
	// The ingress refusals the Worker never forwards still answer as the C# host did.
	unregistered := grpcWeb(t, h.server.URL, "/arcforges.hello.v1.HelloService/Unknown", helloRequest(t, "x"), nil)
	if unregistered.trailers["grpc-status"] != "12" || unregistered.trailers["grpc-message"] != "unimplemented" {
		t.Fatalf("unregistered: %+v", unregistered)
	}
	oversized := grpcWeb(t, h.server.URL, "/arcforges.hello.v1.HelloService/SayHello", make([]byte, 4097), nil)
	if oversized.trailers["grpc-status"] != "8" || oversized.trailers["grpc-message"] != "validation.invalid_request" {
		t.Fatalf("oversized: %+v", oversized)
	}
	for path, want := range map[string]int{"/unknown": 404, "/healthz/": 404, "/api/arcforges.hello.v1.HelloService/SayHello": 404} {
		response, err := http.Get(h.server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("%s: %d", path, response.StatusCode)
		}
	}
	unsupported, err := http.Post(h.server.URL+"/arcforges.hello.v1.HelloService/SayHello", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = unsupported.Body.Close()
	if unsupported.StatusCode != http.StatusUnsupportedMediaType || h.count() != 3 {
		t.Fatalf("json: %d calls=%d", unsupported.StatusCode, h.count())
	}
}

func urlUnescape(value string) (string, error) {
	var text strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '%' {
			text.WriteByte(value[index])
			continue
		}
		if index+2 >= len(value) {
			return "", errors.New("truncated escape")
		}
		var b byte
		for _, c := range value[index+1 : index+3] {
			b <<= 4
			switch {
			case c >= '0' && c <= '9':
				b |= byte(c - '0')
			case c >= 'A' && c <= 'F':
				b |= byte(c - 'A' + 10)
			case c >= 'a' && c <= 'f':
				b |= byte(c - 'a' + 10)
			default:
				return "", errors.New("bad escape")
			}
		}
		text.WriteByte(b)
		index += 2
	}
	return text.String(), nil
}

func TestRequestsAreLoggedWithTheirCorrelationAndCounted(t *testing.T) {
	h := start(t, hello.Stateless)
	grpcWeb(t, h.server.URL, "/arcforges.hello.v1.HelloService/SayHello", helloRequest(t, "secret-name"), map[string]string{
		"Traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "Authorization": "Bearer secret-token-value-123456",
	})
	grpcWeb(t, h.server.URL, "/arcforges.hello.v1.HelloService/SayHello", helloRequest(t, ""), nil)
	grpcWeb(t, h.server.URL, "/arcforges.hello.v1.HelloService/Unknown", helloRequest(t, "secret-name"), nil)
	logs := h.logs.String()
	for _, secret := range []string{"secret-name", "secret-token", "Bearer", "Unknown"} {
		if strings.Contains(logs, secret) {
			t.Fatalf("the log holds request content %q:\n%s", secret, logs)
		}
	}
	var lines []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(logs), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("not a JSON line: %q", line)
		}
		lines = append(lines, entry)
	}
	if len(lines) != 3 || lines[0]["correlationId"] != "4bf92f35-77b3-4da6-a3ce-929d0e0e4736" || lines[0]["code"] != "ok" ||
		lines[1]["code"] != "invalid_argument" || lines[2]["method"] != "unregistered" || lines[2]["code"] != "unimplemented" ||
		lines[2]["refusal"] != "unimplemented" {
		t.Fatalf("log lines: %v", lines)
	}
	var metrics bytes.Buffer
	if err := h.center.Metrics.WritePrometheus(&metrics); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		`arcforges_center_requests_total{method="/arcforges.hello.v1.HelloService/SayHello",code="ok"} 1`,
		`arcforges_center_requests_total{method="/arcforges.hello.v1.HelloService/SayHello",code="invalid_argument"} 1`,
		`arcforges_center_refusals_total{code="unimplemented",category="none"} 1`,
	} {
		if !strings.Contains(metrics.String(), line) {
			t.Fatalf("missing %s", line)
		}
	}
}

func TestHealthIdentifiesTheCenterAndTouchesNoDatabase(t *testing.T) {
	h := start(t, func(context.Context, string) (string, error) { return "", errors.New("health queried the greeting") })
	response, err := http.Get(h.server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var health buildinfo.Health
	if err = json.NewDecoder(response.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || health.NativeAOT ||
		health.Runtime != "go" || health.HelloBackend != BackendStateless || health.Service != "arcforges-cloud" ||
		health.Center != (buildinfo.Center{Binary: "arcforges-center", Mode: "official-hosted", PublicBaseURL: "https://center.example/api"}) {
		t.Fatalf("health: %d %+v", response.StatusCode, health)
	}
	post, err := http.Post(h.server.URL+"/healthz", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = post.Body.Close()
	if post.StatusCode != http.StatusMethodNotAllowed || h.count() != 0 {
		t.Fatalf("POST /healthz: %d", post.StatusCode)
	}
}

func TestReadinessAndMetricsAreOnTheAdminListenerOnly(t *testing.T) {
	h := start(t, hello.Stateless)
	for _, path := range []string{"/readyz", "/metrics"} {
		response, err := http.Get(h.server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("the public listener serves %s", path)
		}
	}
	admin := httptest.NewServer(h.center.Admin())
	defer admin.Close()
	response, err := http.Get(admin.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	var readiness Readiness
	if err = json.NewDecoder(response.Body).Decode(&readiness); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || readiness.Status != "ready" || len(readiness.Components) != 0 {
		t.Fatalf("readiness: %+v", readiness)
	}
	h.center.ready = append(h.center.ready, component{"database", func(context.Context) error { return errors.New("down") }})
	if got := h.center.Ready(t.Context()); got.Status != "unavailable" || got.Components["database"] != "unavailable" {
		t.Fatalf("readiness with a failing dependency: %+v", got)
	}
	metrics, err := http.Get(admin.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(metrics.Body)
	_ = metrics.Body.Close()
	if !strings.HasPrefix(metrics.Header.Get("Content-Type"), "text/plain; version=0.0.4") || !strings.Contains(string(body), "# TYPE arcforges_center_requests_total counter") {
		t.Fatalf("metrics: %s", body)
	}
}

func TestTheModeSelectsTheFeatureGate(t *testing.T) {
	for mode, available := range map[config.Mode]bool{config.OfficialHosted: false, config.SelfHosted: true} {
		center, err := New(testConfig(mode), observe.NewLogger(io.Discard, slog.LevelInfo), Options{})
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range feature.Gated() {
			if center.Features.Availability(t.Context(), key).Available != available {
				t.Fatalf("%s %s", mode, key)
			}
		}
		center.Close()
	}
}

func TestServeStartsAndStopsOnEphemeralPorts(t *testing.T) {
	logs := &lockedBuffer{}
	cfg := testConfig(config.SelfHosted)
	cfg.HTTPAddress, cfg.GRPCAddress, cfg.AdminAddress = "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0"
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, observe.NewLogger(logs, slog.LevelInfo)) }()
	var address string
	for address == "" {
		select {
		case err := <-done:
			t.Fatalf("serve stopped: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
		for line := range strings.SplitSeq(logs.String(), "\n") {
			var entry struct {
				Msg       string            `json:"msg"`
				Listeners map[string]string `json:"listeners"`
			}
			if json.Unmarshal([]byte(line), &entry) == nil && entry.Msg == "center started" {
				address = entry.Listeners["http"]
			}
		}
	}
	response, err := http.Get("http://" + address + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health: %d", response.StatusCode)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), `"msg":"center stopped"`) || !strings.Contains(logs.String(), `"mode":"self-hosted"`) {
		t.Fatalf("logs: %s", logs.String())
	}
}

// TestAnExpiredBootstrapStillServesHello (E2): a configuration whose owner bootstrap expired (its variables left set after the
// bootstrap) loads, the center starts and serves Hello and health, and the start-up log says the variables can be removed.
func TestAnExpiredBootstrapStillServesHello(t *testing.T) {
	values := map[string]string{
		config.EnvMode: string(config.SelfHosted), config.EnvPublicBaseURL: "https://center.example/api", config.EnvSurfaces: "none",
		config.EnvHTTPAddress: "127.0.0.1:0", config.EnvGRPCAddress: "127.0.0.1:0",
		config.EnvBootstrapSHA256:    strings.Repeat("ab", 32),
		config.EnvBootstrapExpiresAt: time.Now().Add(-72 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	cfg, err := config.Load(func(name string) (string, bool) { value, ok := values[name]; return value, ok })
	if err != nil || cfg.Identity.Bootstrap == nil {
		t.Fatalf("an expired bootstrap does not load: %v", err)
	}
	logs := &lockedBuffer{}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, observe.NewLogger(logs, slog.LevelInfo)) }()
	var address string
	for address == "" {
		select {
		case err := <-done:
			t.Fatalf("serve stopped: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
		for line := range strings.SplitSeq(logs.String(), "\n") {
			var entry struct {
				Msg       string            `json:"msg"`
				Listeners map[string]string `json:"listeners"`
			}
			if json.Unmarshal([]byte(line), &entry) == nil && entry.Msg == "center started" {
				address = entry.Listeners["http"]
			}
		}
	}
	reply := grpcWeb(t, "http://"+address, "/arcforges.hello.v1.HelloService/SayHello", helloRequest(t, "owner"), nil)
	if reply.trailers["grpc-status"] != "0" || len(reply.messages) != 1 {
		t.Fatalf("Hello with an expired bootstrap: %+v", reply)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), `"msg":"the owner bootstrap has expired; remove its variables"`) {
		t.Fatalf("no start-up warning: %s", logs.String())
	}
}

// TestANotActivatedReplyIsLoggedWithItsCorrelation (F18): a center whose identity surface is off answers an identity call itself
// with STATE/not_activated; the request is logged and counted as the OK reply it is, with the reply's correlation id.
func TestANotActivatedReplyIsLoggedWithItsCorrelation(t *testing.T) {
	h := start(t, hello.Stateless)
	message, err := proto.Marshal(&publicapiv1.IdentityServiceGetProfileRequest{Meta: &foundationv1.RequestMeta{}})
	if err != nil {
		t.Fatal(err)
	}
	reply := grpcWeb(t, h.server.URL, "/arcforges.publicapi.v1.IdentityService/GetProfile", ingress.Frame(message),
		map[string]string{"Traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"})
	if reply.trailers["grpc-status"] != "0" || len(reply.messages) != 1 {
		t.Fatalf("not activated: %+v", reply)
	}
	var line map[string]any
	if err = json.Unmarshal([]byte(strings.TrimSpace(h.logs.String())), &line); err != nil {
		t.Fatalf("one log line: %q", h.logs.String())
	}
	if line["method"] != "/arcforges.publicapi.v1.IdentityService/GetProfile" || line["code"] != "ok" ||
		line["correlationId"] != "4bf92f35-77b3-4da6-a3ce-929d0e0e4736" {
		t.Fatalf("log line %v", line)
	}
	var metrics bytes.Buffer
	if err = h.center.Metrics.WritePrometheus(&metrics); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(metrics.String(), `arcforges_center_requests_total{method="/arcforges.publicapi.v1.IdentityService/GetProfile",code="ok"} 1`) ||
		strings.Contains(metrics.String(), `code="unknown"`) {
		t.Fatalf("metrics %s", metrics.String())
	}
}
