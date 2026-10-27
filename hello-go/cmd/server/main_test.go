// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	hellov1 "github.com/ArcForges/Cloud/hello-go/internal/gen/arcforges/hello/v1"
	"github.com/ArcForges/Cloud/hello-go/internal/gen/arcforges/hello/v1/hellov1connect"
)

const validURL = "postgresql://owner:fixture%40%3A%3B%26%2B%25@ep-fixture-pooler.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require"

func TestNeonConfigurationRequiresVerifiedTLSAndBoundedPool(t *testing.T) {
	config, err := neonConfig(validURL)
	if err != nil {
		t.Fatal(err)
	}
	if config.ConnConfig.Password != "fixture@:;&+%" {
		t.Fatal("encoded password changed")
	}
	if config.ConnConfig.TLSConfig == nil || config.ConnConfig.TLSConfig.InsecureSkipVerify ||
		config.ConnConfig.ChannelBinding != "require" || len(config.ConnConfig.Fallbacks) != 0 ||
		config.MaxConns != 2 || config.MinConns != 0 {
		t.Fatal("unsafe connection configuration")
	}
}
func TestUnsafeURLsAreRefusedWithoutLeakingValues(t *testing.T) {
	replacements := [][2]string{
		{"sslmode=require", "sslmode=disable"},
		{"channel_binding=require", "channel_binding=disable"},
		{"fixture%40%3A%3B%26%2B%25", "********"},
		{".neon.tech/", ".neon.tech.attacker.invalid/"},
		{"-pooler.", "."},
		{"/neondb?", ":80/neondb?"},
		{"postgresql://", "https://"},
	}
	for _, item := range replacements {
		_, err := neonConfig(strings.ReplaceAll(validURL, item[0], item[1]))
		if err == nil {
			t.Fatalf("accepted invalid %s", item[0])
		}
		if strings.Contains(err.Error(), "fixture") {
			t.Fatal("configuration error leaked credential")
		}
	}
	if _, err := neonConfig(validURL + "&sslmode=require"); err == nil {
		t.Fatal("duplicate option accepted")
	}
}
func TestGRPCAndGRPCWebPreservePublishedHello(t *testing.T) {
	for _, wire := range []string{"grpc", "grpcweb"} {
		t.Run(wire, func(t *testing.T) {
			calls := 0
			source := func(_ context.Context, name string) (string, error) { calls++; return "Hello, " + name + "!", nil }
			protocols := new(http.Protocols)
			protocols.SetHTTP1(true)
			protocols.SetUnencryptedHTTP2(true)
			server := httptest.NewUnstartedServer(handler(source, healthDocument{Runtime: "go", HelloBackend: "stateless"}))
			server.Config.Protocols = protocols
			server.Start()
			defer server.Close()
			transport := &http.Transport{Protocols: protocols}
			defer transport.CloseIdleConnections()
			clientHTTP := &http.Client{Transport: transport}
			option := connecthttp.WithGRPC()
			if wire == "grpcweb" {
				option = connecthttp.WithGRPCWeb()
			}
			client := hellov1connect.NewHelloServiceClient(connect.NewClient(connecthttp.NewTransport(clientHTTP, server.URL, option)))
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
			if calls != 6 {
				t.Fatalf("invalid input reached database source: calls=%d", calls)
			}
		})
	}
}
func TestDatabaseFailureHasNoFallbackOrPrivateDetail(t *testing.T) {
	server := &helloServer{greeting: func(context.Context, string) (string, error) { return "", errors.New("synthetic-private-credential") }}
	reply, err := server.SayHello(t.Context(), &hellov1.SayHelloRequest{Name: "ArcForges"})
	if reply != nil || connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatal("database failure became a success")
	}
	if strings.Contains(err.Error(), "synthetic-private") {
		t.Fatal("database error leaked")
	}
}
func TestCancellationRemainsCancellation(t *testing.T) {
	server := &helloServer{greeting: func(ctx context.Context, _ string) (string, error) { return "", ctx.Err() }}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := server.SayHello(ctx, &hellov1.SayHelloRequest{Name: "ArcForges"})
	if connect.CodeOf(err) != connect.CodeCanceled {
		t.Fatalf("unexpected cancellation: %v", err)
	}
}
func TestHealthIdentifiesGoWithoutClaimingDotNetAOT(t *testing.T) {
	document, err := metadata("neon-postgresql")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler(func(context.Context, string) (string, error) { t.Fatal("health queried database"); return "", nil }, document))
	defer server.Close()
	response, err := server.Client().Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var health healthDocument
	if err = json.Unmarshal(body, &health); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || health.NativeAOT || health.Runtime != "go" || health.HelloBackend != "neon-postgresql" {
		t.Fatal("incorrect runtime identity")
	}
}
