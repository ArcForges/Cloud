// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func environment(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func TestServeRefusesToStartWithoutAnExplicitMode(t *testing.T) {
	for _, values := range []map[string]string{
		{},
		{"ARCFORGES_CENTER_PUBLIC_BASE_URL": "https://center.example"},
		{"ARCFORGES_CENTER_MODE": "hosted", "ARCFORGES_CENTER_PUBLIC_BASE_URL": "https://center.example"},
		{"ARCFORGES_CENTER_MODE": "official-hosted"},
		{"ARCFORGES_CENTER_MODE": "official-hosted", "ARCFORGES_CENTER_PUBLIC_BASE_URL": "https://center.example",
			"ARCFORGES_NEON_HELLO": "enabled", "NEON_DATABASE_URL": "postgresql://u:leaked-secret@db.example/x"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(nil, environment(values), &stdout, &stderr); code != 1 {
			t.Fatalf("%v started: %d", values, code)
		}
		var line map[string]any
		if err := json.Unmarshal(stderr.Bytes(), &line); err != nil || line["msg"] != "the center refused to start" {
			t.Fatalf("refusal is not one JSON log line: %q", stderr.String())
		}
		if strings.Contains(stderr.String(), "leaked-secret") || stdout.Len() != 0 {
			t.Fatal("a configuration value reached the output")
		}
	}
}

func TestVersionMigrationRefusalsAndUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--build-info"}, environment(nil), &stdout, &stderr); code != 0 {
		t.Fatalf("version: %d %s", code, stderr.String())
	}
	var document map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil || document["runtime"] != "go" || document["nativeAot"] != false ||
		document["helloBackend"] != "not-probed" {
		t.Fatalf("version: %s", stdout.String())
	}
	stdout.Reset()
	if code := run([]string{"version"}, environment(nil), &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), `"binary":"arcforges-center"`) {
		t.Fatalf("version: %s", stdout.String())
	}
	stderr.Reset()
	secret := map[string]string{"ARCFORGES_CENTER_MODE": "official-hosted",
		"ARCFORGES_CENTER_MIGRATION_DATABASE_URL": "postgresql://owner:leaked-secret@db.example/center?sslmode=disable"}
	for _, arguments := range [][]string{{"migrate"}, {"migrate", "status"}, {"admin", "rotate-runtime-credential"}, {"admin", "confirm-runtime-credential", "--slot", "a"}, {"admin", "rotate-runtime-credential", "--live-slot=a"}} {
		stdout.Reset()
		stderr.Reset()
		if code := run(arguments, environment(secret), &stdout, &stderr); code != 1 || strings.Contains(stderr.String(), "leaked-secret") ||
			!strings.Contains(stderr.String(), "refused to start") || stdout.Len() != 0 {
			t.Fatalf("%v: %d %s", arguments, code, stderr.String())
		}
	}
	for _, arguments := range [][]string{{"unknown"}, {"serve", "extra"}, {"migrate", "drop"}, {"migrate", "apply", "x"}, {"admin"}, {"admin", "drop"}, {"version", "x"},
		{"admin", "confirm-runtime-credential"}, {"admin", "confirm-runtime-credential", "--slot"}, {"admin", "confirm-runtime-credential", "--slot", "c"},
		{"admin", "confirm-runtime-credential", "--slot=", "a"}, {"admin", "rotate-runtime-credential", "--slot", "a"},
		{"admin", "rotate-runtime-credential", "--live-slot", "c"}, {"admin", "rotate-runtime-credential", "--live-slot"}} {
		if code := run(arguments, environment(nil), &stdout, &stderr); code != 2 {
			t.Fatalf("%v: %d", arguments, code)
		}
	}
	stdout.Reset()
	if code := run([]string{"help"}, environment(nil), &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "usage: arcforges-center") {
		t.Fatal("help")
	}
}

func TestCTR06Phase1CommandEntriesRefuseBeforeCredentialLookup(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		args   []string
		values map[string]string
	}{
		{"local bridge", []string{"migrate", "apply"}, map[string]string{"ARCFORGES_CENTER_CTR06_BRIDGE_EXECUTABLE": "/sensitive/old-bridge"}},
		{"hosted proof", []string{"migrate", "apply"}, map[string]string{"ARCFORGES_CENTER_CTR06_PROOF_FILE": "/sensitive/old-proof"}},
		{"prepare", []string{"admin", "prepare-ctr06-bridge"}, nil},
		{"legacy restore", []string{"admin", "restore-legacy-logical-backup"}, nil},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			lookup := func(key string) (string, bool) {
				if key != "ARCFORGES_CENTER_CTR06_BRIDGE_EXECUTABLE" && key != "ARCFORGES_CENTER_CTR06_PROOF_FILE" {
					t.Fatalf("read credential or configuration %q before the phase-1 refusal", key)
				}
				value, ok := scenario.values[key]
				return value, ok
			}
			if code := run(scenario.args, lookup, &stdout, &stderr); code != exitFailure || stdout.Len() != 0 ||
				!strings.Contains(stderr.String(), "security bridge successor is not yet bound") || strings.Contains(stderr.String(), "/sensitive/") {
				t.Fatalf("refusal: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestCTR06Phase1ActualCLIRefusesBeforeConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	binary := filepath.Join(t.TempDir(), "current-center")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-trimpath", "-o", binary, "./cmd/arcforges-center")
	build.Dir = filepath.Join("..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build current CLI: %s", output)
	}
	base := []string{"ARCFORGES_CENTER_MODE=self-hosted", "ARCFORGES_CENTER_MIGRATION_DATABASE_URL=postgresql://owner:synthetic-private@" + listener.Addr().String() + "/center?sslmode=disable"}
	if root := os.Getenv("SystemRoot"); root != "" {
		base = append(base, "SystemRoot="+root)
	}
	for _, test := range []struct{ args, extra []string }{
		{[]string{"migrate", "apply"}, []string{"ARCFORGES_CENTER_CTR06_BRIDGE_EXECUTABLE=/old-bridge"}},
		{[]string{"migrate", "apply"}, []string{"ARCFORGES_CENTER_CTR06_PROOF_FILE=/old-proof"}},
		{[]string{"admin", "prepare-ctr06-bridge"}, nil},
		{[]string{"admin", "restore-legacy-logical-backup"}, nil},
	} {
		cmd := exec.Command(binary, test.args...)
		cmd.Env = append(append([]string(nil), base...), test.extra...)
		output, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "security bridge successor is not yet bound") || strings.Contains(string(output), "synthetic-private") {
			t.Fatalf("actual CLI failed to refuse %v: %v %s", test.args, err, output)
		}
	}
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.Accept()
	if err == nil {
		connection.Close()
		t.Fatal("phase-1 CLI opened a database connection")
	}
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("connection observation: %v", err)
	}
}
