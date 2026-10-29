// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/observe"
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
// public base URL. Its relying party is the proof host, and a surface call that does not carry exactly one client address is
// refused validation.invalid_request before the store is touched; with one address the call reaches the store.
func TestTheProofCompositionRequiresTheWorkersClientAddress(t *testing.T) {
	values := proofEnvironment(t)
	cfg, err := config.Load(func(name string) (string, bool) { value, ok := values[name]; return value, ok })
	if err != nil {
		t.Fatalf("the proof configuration does not load: %v", err)
	}
	if cfg.Mode != config.OfficialHosted || !cfg.Identity.Enabled(config.SurfaceIdentity) || cfg.Identity.ClientIPHeader != config.ClientIPHeader ||
		len(cfg.Identity.TrustedProxies) != 0 || cfg.PublicBaseURL != "https://proof.arcforges.com/api" ||
		config.RelyingPartyID(cfg.PublicBaseURL) != "proof.arcforges.com" || config.Origin(cfg.PublicBaseURL) != "https://proof.arcforges.com" {
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
	// One address passes the check: the call goes on to the store, which is unreachable here.
	reply := call("203.0.113.7")
	if reply.trailers["grpc-status"] != "0" || len(reply.messages) != 1 || !bytes.Contains(reply.messages[0], []byte("error.resource.overloaded")) ||
		center.Store.Pool().Stat().NewConnsCount() == 0 {
		t.Fatalf("one client address: %+v", reply)
	}
}
