// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
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
	for _, arguments := range [][]string{{"migrate"}, {"migrate", "status"}, {"admin", "rotate-runtime-credential"}, {"admin", "confirm-runtime-credential", "--slot", "a"}} {
		stdout.Reset()
		stderr.Reset()
		if code := run(arguments, environment(secret), &stdout, &stderr); code != 1 || strings.Contains(stderr.String(), "leaked-secret") ||
			!strings.Contains(stderr.String(), "refused to start") || stdout.Len() != 0 {
			t.Fatalf("%v: %d %s", arguments, code, stderr.String())
		}
	}
	for _, arguments := range [][]string{{"unknown"}, {"serve", "extra"}, {"migrate", "drop"}, {"migrate", "apply", "x"}, {"admin"}, {"admin", "drop"}, {"version", "x"},
		{"admin", "confirm-runtime-credential"}, {"admin", "confirm-runtime-credential", "--slot"}, {"admin", "confirm-runtime-credential", "--slot", "c"},
		{"admin", "confirm-runtime-credential", "--slot=", "a"}, {"admin", "rotate-runtime-credential", "--slot", "a"}} {
		if code := run(arguments, environment(nil), &stdout, &stderr); code != 2 {
			t.Fatalf("%v: %d", arguments, code)
		}
	}
	stdout.Reset()
	if code := run([]string{"help"}, environment(nil), &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "usage: arcforges-center") {
		t.Fatal("help")
	}
}
