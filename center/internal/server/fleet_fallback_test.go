// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/observe"
)

// TestASelfHostedCenterOnAnAddressServesNoSurface (cloud-6, F4): a self-hosted center with the default surfaces whose base URL is
// an IP address cannot be a relying party, so it starts with every surface off (health states none), and a fleet method is answered
// STATE/not_activated (state.reason fleet), like every surface method, by the center itself.
func TestASelfHostedCenterOnAnAddressServesNoSurface(t *testing.T) {
	values := map[string]string{config.EnvMode: string(config.SelfHosted), config.EnvPublicBaseURL: "https://192.168.1.10:8443"}
	cfg, err := config.Load(func(name string) (string, bool) { value, ok := values[name]; return value, ok })
	if err != nil || len(cfg.Identity.Surfaces) != 0 {
		t.Fatalf("the configuration: %+v %v", cfg.Identity, err)
	}
	center, err := New(cfg, observe.NewLogger(&lockedBuffer{}, slog.LevelDebug), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(center.Close)
	listener := httptest.NewServer(center.Public())
	t.Cleanup(listener.Close)
	response, err := http.Get(listener.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	health, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if !strings.Contains(string(health), `"surfaces":"none"`) {
		t.Fatalf("health: %s", health)
	}
	message, err := proto.Marshal(&fleetv1.NodeEnrollmentServiceRefreshNodeSessionRequest{Meta: &foundationv1.RequestMeta{}, RefreshToken: proto.String("afr1.x")})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, listener.URL+"/arcforges.fleet.v1.NodeEnrollmentService/RefreshNodeSession",
		bytes.NewReader(ingress.Frame(message)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/grpc-web+proto")
	reply := send(t, request)
	if reply.trailers["grpc-status"] != "0" || len(reply.messages) != 1 || !bytes.Contains(reply.messages[0], []byte("error.state.not_activated")) ||
		!bytes.Contains(reply.messages[0], []byte("fleet")) {
		t.Fatalf("a fleet method on a center without surfaces: %+v", reply)
	}
}
