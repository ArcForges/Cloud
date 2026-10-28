// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"errors"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	neonURL    = "postgresql://owner:fixture%40%3A%3B%26%2B%25@ep-fixture-pooler.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require"
	runtimeURL = "postgres://center_runtime:fixture-secret@db.internal.example:5432/center?sslmode=verify-full&channel_binding=require"
)

func environment(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func minimal(mode Mode) map[string]string {
	return map[string]string{EnvMode: string(mode), EnvPublicBaseURL: "https://center.example/api"}
}

func TestTheCenterRefusesToStartWithoutAnExplicitValidMode(t *testing.T) {
	for _, mode := range []string{"", "official", "self", "OFFICIAL-HOSTED", " self-hosted", "official-hosted\n"} {
		values := minimal("")
		if mode != "" {
			values[EnvMode] = mode
		} else {
			delete(values, EnvMode)
		}
		_, err := Load(environment(values))
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), EnvMode) {
			t.Fatalf("mode %q: %v", mode, err)
		}
	}
	for _, mode := range []Mode{OfficialHosted, SelfHosted} {
		config, err := Load(environment(minimal(mode)))
		if err != nil {
			t.Fatal(err)
		}
		if config.Mode != mode || config.PublicBaseURL != "https://center.example/api" || config.HTTPAddress != DefaultHTTPAddress ||
			config.GRPCAddress != DefaultGRPCAddress || config.AdminAddress != "" || config.MaxConnections != DefaultMaxConnections ||
			config.LogLevel != slog.LevelInfo || config.MetricsLogInterval != time.Minute || config.NeonHello != nil || config.Database != nil {
			t.Fatalf("defaults: %+v", config)
		}
	}
}

func TestThePublicBaseURLIsRequiredAndCanonical(t *testing.T) {
	for _, valid := range []string{
		"https://center.example", "https://center.example/api", "https://center.example:8443/a/b-c_d.e~f", "https://[2001:db8::1]/api",
		"https://127.0.0.1:9443",
	} {
		if got, err := ParsePublicBaseURL(valid, OfficialHosted); err != nil || got != valid {
			t.Fatalf("refused %q: %v", valid, err)
		}
	}
	for _, valid := range []string{"http://localhost:8080", "http://127.0.0.1:8080/api", "http://[::1]:8080"} {
		if _, err := ParsePublicBaseURL(valid, SelfHosted); err != nil {
			t.Fatalf("self-hosted refused %q: %v", valid, err)
		}
		if _, err := ParsePublicBaseURL(valid, OfficialHosted); err == nil {
			t.Fatalf("official-hosted accepted %q", valid)
		}
	}
	for _, invalid := range []string{
		"", "center.example", "//center.example", "https://", "https:///api", "HTTPS://center.example", "https://Center.example",
		"https://center.example/", "https://center.example/api/", "https://center.example//api", "https://center.example/./api",
		"https://center.example/a/../b", "https://center.example/a%2fb", "https://center.example/a b", "https://center.example?x=1",
		"https://center.example#x", "https://user@center.example", "https://user:pass@center.example", "https://center.example:0",
		"https://center.example:65536", "https://center.example:", "https://center.example:080", "http://center.example",
		"http://10.0.0.1:8080", "ftp://center.example", "https://center.example.", "https://center.example/\u00e9",
		" https://center.example", "https://center.example\n", "https://center.example/a\\b", "mailto:x@center.example",
		"https://center.example/" + strings.Repeat("a", MaxPublicBaseURLLength),
	} {
		for _, mode := range []Mode{OfficialHosted, SelfHosted} {
			if _, err := ParsePublicBaseURL(invalid, mode); err == nil {
				t.Fatalf("%s accepted %q", mode, invalid)
			}
		}
	}
	values := minimal(SelfHosted)
	delete(values, EnvPublicBaseURL)
	if _, err := Load(environment(values)); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), EnvPublicBaseURL) {
		t.Fatalf("a missing base URL started: %v", err)
	}
}

func TestListenersAndLimits(t *testing.T) {
	values := minimal(SelfHosted)
	values[EnvHTTPAddress] = "127.0.0.1:0"
	values[EnvGRPCAddress] = "off"
	values[EnvAdminAddress] = "0.0.0.0:9090"
	values[EnvMaxConnections] = "8"
	values[EnvLogLevel] = "debug"
	values[EnvMetricsLogInterval] = "0"
	config, err := Load(environment(values))
	if err != nil {
		t.Fatal(err)
	}
	if config.HTTPAddress != "127.0.0.1:0" || config.GRPCAddress != "" || config.AdminAddress != "0.0.0.0:9090" ||
		config.MaxConnections != 8 || config.LogLevel != slog.LevelDebug || config.MetricsLogInterval != 0 {
		t.Fatalf("config: %+v", config)
	}
	official := minimal(OfficialHosted)
	official[EnvAdminAddress] = "127.0.0.1:9090"
	if _, err := Load(environment(official)); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		EnvHTTPAddress: "off", EnvGRPCAddress: "8081", EnvAdminAddress: "center.example:9090", EnvMaxConnections: "0",
		EnvLogLevel: "trace", EnvMetricsLogInterval: "1s", EnvNeonHello: "on", EnvDatabaseMaxConns: "33",
	} {
		values := minimal(SelfHosted)
		values[name] = value
		if _, err := Load(environment(values)); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), name) {
			t.Fatalf("%s=%q: %v", name, value, err)
		}
	}
	for _, value := range []string{"0.0.0.0:9090", ":9090", "10.0.0.2:9090"} {
		values := minimal(OfficialHosted)
		values[EnvAdminAddress] = value
		if _, err := Load(environment(values)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("official-hosted exposed the admin listener on %q", value)
		}
	}
	shared := minimal(SelfHosted)
	shared[EnvGRPCAddress] = DefaultHTTPAddress
	if _, err := Load(environment(shared)); !errors.Is(err, ErrInvalid) {
		t.Fatal("two listeners on one address")
	}
}

func TestTheNeonHelloRequiresVerifiedTLSAndABoundedPool(t *testing.T) {
	config, err := NeonHelloPool(neonURL)
	if err != nil {
		t.Fatal(err)
	}
	if config.ConnConfig.Password != "fixture@:;&+%" || config.ConnConfig.TLSConfig == nil || config.ConnConfig.TLSConfig.InsecureSkipVerify ||
		config.ConnConfig.ChannelBinding != "require" || len(config.ConnConfig.Fallbacks) != 0 || config.MaxConns != 2 || config.MinConns != 0 {
		t.Fatal("unsafe connection configuration")
	}
	for _, item := range [][2]string{
		{"sslmode=require", "sslmode=disable"}, {"channel_binding=require", "channel_binding=disable"},
		{"fixture%40%3A%3B%26%2B%25", "********"}, {".neon.tech/", ".neon.tech.attacker.invalid/"}, {"-pooler.", "."},
		{"/neondb?", ":80/neondb?"}, {"postgresql://", "https://"},
	} {
		_, err := NeonHelloPool(strings.ReplaceAll(neonURL, item[0], item[1]))
		if err == nil || strings.Contains(err.Error(), "fixture") {
			t.Fatalf("%s: %v", item[0], err)
		}
	}
	if _, err := NeonHelloPool(neonURL + "&sslmode=require"); err == nil {
		t.Fatal("duplicate option accepted")
	}
	values := minimal(OfficialHosted)
	values[EnvNeonHello] = "enabled"
	if _, err := Load(environment(values)); !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "fixture") {
		t.Fatalf("enabled Hello without a URL: %v", err)
	}
	values[EnvNeonDatabaseURL] = neonURL
	if config, err := Load(environment(values)); err != nil || config.NeonHello == nil {
		t.Fatalf("enabled Hello: %v", err)
	}
}

func TestTheRuntimeDatabaseNeverLeaksAndKeepsNoSessionState(t *testing.T) {
	config, err := RuntimeDatabasePool(runtimeURL, OfficialHosted, 4)
	if err != nil {
		t.Fatal(err)
	}
	if config.MaxConns != 4 || config.ConnConfig.TLSConfig == nil || config.ConnConfig.ChannelBinding != "require" ||
		config.ConnConfig.DefaultQueryExecMode != pgx.QueryExecModeExec {
		t.Fatalf("runtime pool: %+v", config.ConnConfig)
	}
	local := "postgres://center:secret@127.0.0.1:5432/center?sslmode=disable"
	if _, err := RuntimeDatabasePool(local, SelfHosted, 4); err != nil {
		t.Fatalf("self-hosted loopback: %v", err)
	}
	for _, refused := range []struct {
		value string
		mode  Mode
	}{
		{local, OfficialHosted},
		{strings.Replace(local, "127.0.0.1", "db.internal.example", 1), SelfHosted},
		{strings.Replace(runtimeURL, "channel_binding=require", "channel_binding=prefer", 1), SelfHosted},
		{strings.Replace(runtimeURL, "sslmode=verify-full", "sslmode=prefer", 1), SelfHosted},
		{strings.Replace(runtimeURL, "&channel_binding=require", "&channel_binding=require&target_session_attrs=any", 1), SelfHosted},
		{"postgres://db.internal.example/center?sslmode=verify-full&channel_binding=require", SelfHosted},
		{"mysql://u:p@db.internal.example/center", SelfHosted},
		{"postgres://u:fixture-secret@a.example,b.example/center?sslmode=verify-full&channel_binding=require", SelfHosted},
		{local + "&channel_binding=require", SelfHosted},
	} {
		_, err := RuntimeDatabasePool(refused.value, refused.mode, 4)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("%s %q: %v", refused.mode, refused.value, err)
		}
	}
	values := minimal(OfficialHosted)
	values[EnvDatabaseURL] = runtimeURL
	values[EnvDatabaseMaxConns] = "8"
	if config, err := Load(environment(values)); err != nil || config.Database == nil || config.Database.MaxConns != 8 {
		t.Fatalf("runtime database: %v", err)
	}
}

// TestNoOfficialEndpointIsCompiledIn checks AD-0021 section 4: no production code path of the center names the official
// host; the endpoint is configuration.
func TestNoOfficialEndpointIsCompiledIn(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == "testdata" || entry.Name() == "tools") {
			return filepath.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(strings.ToLower(string(data)), "arcforges.com") {
			t.Errorf("%s names the official endpoint", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// FuzzPublicBaseURL checks that an accepted base URL is canonical, idempotent and safe to derive URLs from.
func FuzzPublicBaseURL(f *testing.F) {
	for _, seed := range []string{"https://center.example/api", "http://localhost:8080", "https://[::1]:1/a", "https://a.b/c/../d", "https://a.b?c", " "} {
		f.Add(seed, true)
	}
	f.Fuzz(func(t *testing.T, value string, selfHosted bool) {
		mode := OfficialHosted
		if selfHosted {
			mode = SelfHosted
		}
		canonical, err := ParsePublicBaseURL(value, mode)
		if err != nil {
			return
		}
		if canonical != value {
			t.Fatalf("accepted a non-canonical %q", value)
		}
		again, err := ParsePublicBaseURL(canonical, mode)
		if err != nil || again != canonical {
			t.Fatalf("not idempotent: %q", value)
		}
		uri, err := url.Parse(canonical)
		if err != nil || uri.User != nil || uri.RawQuery != "" || uri.Fragment != "" || uri.Host == "" || strings.HasSuffix(canonical, "/") {
			t.Fatalf("unsafe base %q", value)
		}
		if uri.Scheme != "https" && (uri.Scheme != "http" || !selfHosted || !isLoopbackHost(uri.Hostname())) {
			t.Fatalf("insecure base %q", value)
		}
		derived, err := url.Parse(canonical + "/arcforges.hello.v1.HelloService/SayHello")
		if err != nil || derived.Host != uri.Host || !strings.HasPrefix(derived.Path, uri.Path+"/") {
			t.Fatalf("a derived URL escapes the base %q", value)
		}
	})
}
