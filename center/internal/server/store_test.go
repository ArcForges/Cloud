// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	hellov1 "github.com/ArcForges/Contracts/go/arcforges/hello/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/provision"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/ArcForges/Cloud/center/internal/store/migrate"
)

// selfHosted starts a self-hosted center against a real PostgreSQL with the runtime credential that a rotation issued; the
// database is migrated first unless migrated is false.
func selfHosted(t *testing.T, migrated bool) (*Center, *httptest.Server) {
	t.Helper()
	url, name := pgtest.Database(t)
	group := name + "_runtime"
	build, err := migrate.Load(schema.Migrations())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = migrate.Apply(context.Background(), pgtest.Connect(t, url), build, migrate.Options{Runner: "test", RuntimeRole: group}); err != nil {
		t.Fatal(err)
	}
	rotation, err := provision.Rotate(context.Background(), pgtest.Connect(t, url), provision.Options{Group: group, DirectURL: url, PooledHost: pgtest.Host(t), Runner: "test", ProbeTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !migrated {
		// A database that lost its last migration record stands for one the deploy has not migrated yet.
		if _, err = pgtest.Connect(t, url).Exec(context.Background(), "DELETE FROM platform.schema_migration WHERE version = (SELECT max(version) FROM platform.schema_migration)"); err != nil {
			t.Fatal(err)
		}
	}
	values := map[string]string{
		config.EnvMode: string(config.SelfHosted), config.EnvPublicBaseURL: "http://127.0.0.1:8080/api",
		config.EnvDatabaseURL: rotation.RuntimeURL, config.EnvNeonHello: "enabled",
	}
	cfg, err := config.Load(func(name string) (string, bool) { value, found := values[name]; return value, found })
	if err != nil {
		t.Fatal(err)
	}
	center, err := New(cfg, observe.NewLogger(io.Discard, slog.LevelInfo), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(center.Close)
	server := httptest.NewServer(center.Public())
	t.Cleanup(server.Close)
	return center, server
}

func TestASelfHostedCenterServesHelloThroughTheRuntimeRole(t *testing.T) {
	center, server := selfHosted(t, true)
	if center.Health.HelloBackend != BackendRuntime || center.Store == nil {
		t.Fatalf("backend %s", center.Health.HelloBackend)
	}
	readiness := center.Ready(t.Context())
	if readiness.Status != "ready" || readiness.Components["database"] != "ready" || readiness.Components["databaseSchema"] != "ready" {
		t.Fatalf("readiness %+v", readiness)
	}
	reply := grpcWeb(t, server.URL, "/arcforges.hello.v1.HelloService/SayHello", helloRequest(t, "NUL\x00 W\u00f6rld"), nil)
	if reply.trailers["grpc-status"] != "0" || len(reply.messages) != 1 {
		t.Fatalf("hello %+v", reply)
	}
	var response hellov1.SayHelloResponse
	if err := proto.Unmarshal(reply.messages[0], &response); err != nil || response.GetMessage() != "Hello, NUL\x00 W\u00f6rld!" {
		t.Fatalf("greeting %q %v", response.GetMessage(), err)
	}
	var metrics bytes.Buffer
	if err := center.writeDatabaseMetrics(&metrics); err != nil {
		t.Fatal(err)
	}
	lines := []string{`arcforges_center_db_pool_connections{pool="runtime",state="max"} 4`,
		fmt.Sprintf(`arcforges_center_db_schema_version{source="database"} %d`, center.buildVersion),
		fmt.Sprintf(`arcforges_center_db_schema_version{source="build"} %d`, center.buildVersion)}
	for _, line := range lines {
		if !strings.Contains(metrics.String(), line) {
			t.Fatalf("metrics lack %s:\n%s", line, metrics.String())
		}
	}
}

func TestAnUnmigratedDatabaseIsNotReady(t *testing.T) {
	center, _ := selfHosted(t, false)
	readiness := center.Ready(t.Context())
	if readiness.Status != "unavailable" || readiness.Components["database"] != "ready" || readiness.Components["databaseSchema"] != "unavailable" {
		t.Fatalf("readiness %+v", readiness)
	}
}
