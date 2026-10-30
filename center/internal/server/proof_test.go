// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/workertables"
)

// proofEnvironment is the center's environment in the acceptance environment, as the proof Container receives it: the proof vars of
// wrangler.json, the enabled surfaces the Worker forwards from FLAGSHIP_SURFACES and the header it always names
// (worker/foundation/cloud-container.ts), and a store that no test reaches (a closed loopback port, connected lazily).
func proofEnvironment(t *testing.T) map[string]string {
	t.Helper()
	root, err := workertables.RepositoryRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "wrangler.json"))
	if err != nil {
		t.Fatal(err)
	}
	var wrangler struct {
		Env struct {
			Proof struct {
				Vars map[string]string `json:"vars"`
			} `json:"proof"`
		} `json:"env"`
	}
	if err = json.Unmarshal(data, &wrangler); err != nil {
		t.Fatal(err)
	}
	vars := wrangler.Env.Proof.Vars
	values := map[string]string{config.EnvDatabaseURL: "postgres://center@127.0.0.1:1/center?sslmode=require&channel_binding=require",
		config.EnvSurfaces: vars["FLAGSHIP_SURFACES"], config.EnvClientIPHeader: strings.ToLower(config.ClientIPHeader)}
	for name, value := range vars {
		if strings.HasPrefix(name, "ARCFORGES_CENTER_") {
			values[name] = value
		}
	}
	return values
}

// TestTheProofCompositionRequiresTheWorkersClientAddress composes the acceptance environment's exact configuration (N3, G2):
// official-hosted with the identity surface, the Worker's client-address header and no trusted proxies, under the proof host's
// public base URL, with its anonymous-flow ceiling (C1). Its relying party is the proof host, and a surface call that does not carry
// exactly one client address is refused validation.invalid_request before the store is touched; with one address the call reaches
// the store.
func TestTheProofCompositionRequiresTheWorkersClientAddress(t *testing.T) {
	values := proofEnvironment(t)
	cfg, err := config.Load(func(name string) (string, bool) { value, ok := values[name]; return value, ok })
	if err != nil {
		t.Fatalf("the proof configuration does not load: %v", err)
	}
	if cfg.Mode != config.OfficialHosted || !cfg.Identity.Enabled(config.SurfaceIdentity) || cfg.Identity.ClientIPHeader != config.ClientIPHeader ||
		len(cfg.Identity.TrustedProxies) != 0 || cfg.PublicBaseURL != "https://proof.arcforges.com/api" ||
		config.RelyingPartyID(cfg.PublicBaseURL) != "proof.arcforges.com" || config.Origin(cfg.PublicBaseURL) != "https://proof.arcforges.com" ||
		cfg.Identity.Policy.AnonymousFlows != (config.Window{Limit: 600, Window: time.Hour}) {
		t.Fatalf("the proof configuration: %+v", cfg)
	}
	center, err := New(cfg, observe.NewLogger(&lockedBuffer{}, slog.LevelDebug), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(center.Close)
	listener := httptest.NewServer(center.Public())
	t.Cleanup(listener.Close)
	message, err := proto.Marshal(&publicapiv1.IdentityServiceBeginAuthenticationRequest{Meta: &foundationv1.RequestMeta{},
		Method: publicapiv1.AuthMethod_AUTH_METHOD_PASSKEY.Enum(), Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_AUTHENTICATE.Enum(),
		Installation: &publicapiv1.InstallationClaim{InstallationId: &foundationv1.Id{Value: bytes.Repeat([]byte{7}, 16)},
			Product: proto.String("arcforges-mobile"), Platform: proto.String("android-15"), AppVersion: proto.String("1.0.0")}})
	if err != nil {
		t.Fatal(err)
	}
	call := func(addresses ...string) grpcWebReply {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, listener.URL+"/arcforges.publicapi.v1.IdentityService/BeginAuthentication",
			bytes.NewReader(ingress.Frame(message)))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/grpc-web+proto")
		for _, address := range addresses {
			request.Header.Add(config.ClientIPHeader, address)
		}
		return send(t, request)
	}
	for name, addresses := range map[string][]string{"no client address": nil, "two client addresses": {"203.0.113.7", "203.0.113.8"},
		"a malformed client address": {"203.0.113.7:443"}} {
		reply := call(addresses...)
		if stat := center.Store.Pool().Stat(); reply.trailers["grpc-status"] != "3" || reply.trailers["grpc-message"] != "validation.invalid_request" ||
			len(reply.messages) != 0 || stat.NewConnsCount()+stat.AcquireCount() != 0 {
			t.Fatalf("%s: %+v", name, reply)
		}
	}
	// The pages that are on in this composition meet the same rule (TestThePagesOfTheProofCompositionRequireTheWorkersClientAddress).
	if status, body := pageGet(t, listener.URL, "/account/sign-in"); status != http.StatusBadRequest || connectionsMade(center) != 0 {
		t.Fatalf("the sign-in page without a client address: %d %.200s", status, body)
	}
	// One address passes the check: the call goes on to the store, which is unreachable here.
	reply := call("203.0.113.7")
	if reply.trailers["grpc-status"] != "0" || len(reply.messages) != 1 || !bytes.Contains(reply.messages[0], []byte("error.resource.overloaded")) ||
		center.Store.Pool().Stat().NewConnsCount() == 0 {
		t.Fatalf("one client address: %+v", reply)
	}
}

// TestThePagesOfTheProofCompositionRequireTheWorkersClientAddress (C-F1): the pages are on in the proof composition, and there the
// Worker always names the client, so a page or a JSON route of the browser protocol that arrives without exactly one valid client
// address is refused INVALID_ARGUMENT client/unknown (400) before anything is read or counted: no store connection is made, so no
// rate-limit bucket is touched and address-less callers can never share the one bucket of "unknown". With one address the pages are
// served (the sign-in page and the pre-session routes need no store).
func TestThePagesOfTheProofCompositionRequireTheWorkersClientAddress(t *testing.T) {
	values := proofEnvironment(t)
	cfg, err := config.Load(func(name string) (string, bool) { value, ok := values[name]; return value, ok })
	if err != nil {
		t.Fatalf("the proof configuration does not load: %v", err)
	}
	if !cfg.Identity.Enabled(config.SurfacePages) || config.Origin(cfg.PublicBaseURL) != "https://proof.arcforges.com" {
		t.Fatalf("the proof composition has no pages: %+v", cfg.Identity)
	}
	center, err := New(cfg, observe.NewLogger(&lockedBuffer{}, slog.LevelDebug), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(center.Close)
	listener := httptest.NewServer(center.Public())
	t.Cleanup(listener.Close)
	origin := config.Origin(cfg.PublicBaseURL)
	begin := `{"method":"passkey","purpose":"authenticate","installation":{"installationId":"01234567-89ab-4def-8123-456789abcdef",` +
		`"product":"arcforges-web","platform":"web","appVersion":"pages-1"}}`
	get := func(path string, addresses ...string) (int, string) {
		t.Helper()
		return pageGet(t, listener.URL, path, addresses...)
	}
	post := func(addresses ...string) (int, string) {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, listener.URL+"/session/v1/web/authentication/begin", strings.NewReader(begin))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		request.Header.Set(ingress.CSRFHeader, session.PreSessionCSRF(origin))
		for _, address := range addresses {
			request.Header.Add(config.ClientIPHeader, address)
		}
		return answer(t, request)
	}
	unknown := map[string][]string{"no client address": nil, "two client addresses": {"203.0.113.7", "203.0.113.8"}, "a malformed client address": {"203.0.113.7:443"}}
	for name, addresses := range unknown {
		for route, call := range map[string]func() (int, string){
			"the sign-in page":   func() (int, string) { return get("/account/sign-in", addresses...) },
			"a protected page":   func() (int, string) { return get("/account/passkeys", addresses...) },
			"the bootstrap read": func() (int, string) { return get("/session/v1/web/bootstrap", addresses...) },
			"a JSON route":       func() (int, string) { return post(addresses...) },
		} {
			status, body := call()
			if status != http.StatusBadRequest || connectionsMade(center) != 0 {
				t.Errorf("%s of %s: %d %.200s", name, route, status, body)
			}
			if route == "a JSON route" && (!strings.Contains(body, `"category":"validation","code":"invalid_argument"`) || !strings.Contains(body, `"reason":"client: unknown"`)) {
				t.Errorf("%s of %s: %.300s", name, route, body)
			}
		}
	}
	// One address passes the check: the pages that need no store are served.
	if status, body := get("/account/sign-in", "203.0.113.7"); status != http.StatusOK || !strings.Contains(body, "<html") {
		t.Errorf("the sign-in page with one address: %d %.200s", status, body)
	}
	if status, body := get("/session/v1/web/bootstrap", "203.0.113.7"); status != http.StatusOK || !strings.Contains(body, `"authenticated":false`) {
		t.Errorf("the bootstrap read with one address: %d %.200s", status, body)
	}
}

// connectionsMade is the number of store connections the center has opened or acquired: zero while no request has reached the store.
func connectionsMade(center *Center) int64 {
	stat := center.Store.Pool().Stat()
	return stat.NewConnsCount() + stat.AcquireCount()
}

// pageGet reads a path of a page with the given client-address headers and returns the status and the body of the reply.
func pageGet(t *testing.T, baseURL, path string, addresses ...string) (int, string) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		request.Header.Add(config.ClientIPHeader, address)
	}
	return answer(t, request)
}

// answer sends a request and returns the status and the body of its reply.
func answer(t *testing.T, request *http.Request) (int, string) {
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
	return response.StatusCode, string(data)
}
