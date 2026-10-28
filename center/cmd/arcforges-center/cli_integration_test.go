// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
)

func TestTheMigrationAndAdministrationCommands(t *testing.T) {
	url, name := pgtest.Database(t)
	directory := t.TempDir()
	secretFile := filepath.Join(directory, "runtime.json")
	password := strings.Split(strings.Split(url, ":")[2], "@")[0]
	values := map[string]string{
		"ARCFORGES_CENTER_MODE":                   "self-hosted",
		"ARCFORGES_CENTER_MIGRATION_DATABASE_URL": url,
		"ARCFORGES_CENTER_DATABASE_NAME":          name + "_center",
		"ARCFORGES_CENTER_RUNTIME_ROLE":           name + "_runtime",
		"ARCFORGES_CENTER_RUNTIME_SECRET_FILE":    secretFile,
		"ARCFORGES_CENTER_RUNTIME_POOLED_HOST":    pgtest.Host(t),
	}
	t.Cleanup(func() { pgtest.Drop(t, name+"_center") })
	command := func(expected int, arguments ...string) map[string]any {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if code := run(arguments, environment(values), &stdout, &stderr); code != expected {
			t.Fatalf("%v: exit %d, expected %d: %s", arguments, code, expected, stderr.String())
		}
		if strings.Contains(stdout.String()+stderr.String(), password) {
			t.Fatalf("%v printed a credential", arguments)
		}
		var document map[string]any
		if stdout.Len() > 0 {
			if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
				t.Fatalf("%v: %v %s", arguments, err, stdout.String())
			}
		}
		return document
	}
	if document := command(0, "admin", "ensure-database"); document["created"] != true {
		t.Fatalf("ensure-database: %v", document)
	}
	if document := command(0, "admin", "ensure-database"); document["created"] != false {
		t.Fatalf("ensure-database again: %v", document)
	}
	if document := command(0, "migrate", "status"); document["state"] != "uninitialized" {
		t.Fatalf("status before: %v", document)
	}
	if document := command(0, "migrate", "plan"); len(document["pending"].([]any)) == 0 {
		t.Fatalf("plan: %v", document)
	}
	if document := command(0, "migrate"); document["state"] != "current" || document["grants"] != "reconciled" || len(document["ran"].([]any)) == 0 ||
		number(document["serverVersionNum"]) < 160000 {
		t.Fatalf("apply: %v", document)
	}
	if document := command(0, "migrate", "apply"); document["state"] != "current" || document["ran"] != nil {
		t.Fatalf("apply again: %v", document)
	}
	rotation := command(0, "admin", "rotate-runtime-credential")
	if rotation["slot"] != "a" || rotation["loginRole"] != name+"_runtime_a" || rotation["passwordForm"] != "scram-sha-256-verifier" {
		t.Fatalf("rotation: %v", rotation)
	}
	info, err := os.Stat(secretFile)
	// Windows has no POSIX permission bits (Go reports 0666 for a writable file); the mode is checked where it exists.
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("secret file: %v %v", info, err)
	}
	content, _ := os.ReadFile(secretFile)
	var secrets map[string]string
	if err = json.Unmarshal(content, &secrets); err != nil || len(secrets) != 1 || !strings.Contains(secrets["ARCFORGES_CENTER_DATABASE_URL"], name+"_runtime_a:") {
		t.Fatal("the secret file does not hold exactly the runtime URL")
	}
	runtimePassword := strings.Split(strings.Split(secrets["ARCFORGES_CENTER_DATABASE_URL"], ":")[2], "@")[0]
	if len(runtimePassword) != 40 || strings.Contains(fmt.Sprint(rotation), runtimePassword) {
		t.Fatal("the rotation printed the runtime credential")
	}
	// The promotion of slot a is recorded once; slot b was never rotated.
	command(1, "admin", "confirm-runtime-credential", "--slot", "b")
	confirmed := command(0, "admin", "confirm-runtime-credential", "--slot", "a")
	if confirmed["slot"] != "a" || confirmed["loginRole"] != name+"_runtime_a" || confirmed["alreadyConfirmed"] != false || confirmed["promotedAt"] == "" {
		t.Fatalf("confirm: %v", confirmed)
	}
	if again := command(0, "admin", "confirm-runtime-credential", "--slot=a"); again["alreadyConfirmed"] != true || again["promotedAt"] != confirmed["promotedAt"] {
		t.Fatalf("confirm again: %v", again)
	}
	// The file is never overwritten.
	command(1, "admin", "rotate-runtime-credential")
	// An edited applied migration refuses with status 3.
	if _, err = pgtest.Connect(t, pgtest.WithDatabase(t, url, name+"_center")).Exec(t.Context(), "UPDATE platform.schema_migration SET sha256 = repeat('0', 64) WHERE version = 1"); err != nil {
		t.Fatal(err)
	}
	if document := command(3, "migrate"); document["state"] != "refused" {
		t.Fatalf("refused: %v", document)
	}
	command(3, "migrate", "status")
}

// number reads a JSON number, or -1 when the value is not one.
func number(value any) float64 {
	if number, ok := value.(float64); ok {
		return number
	}
	return -1
}
