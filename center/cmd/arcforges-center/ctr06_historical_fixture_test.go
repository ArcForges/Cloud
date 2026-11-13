// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Historical bridge exercises use the immutable pre-phase-1 implementation,
// never the current public entry points. They require an explicitly supplied
// isolated loopback PostgreSQL and the already verified 615.1 fixture. Their
// result is compatibility research, not current upgrade or rollback acceptance.
func runCTR06HistoricalFixture(t *testing.T, pattern string) {
	t.Helper()
	address := os.Getenv("ARCFORGES_TEST_POSTGRES_URL")
	if address == "" {
		t.Skip("historical fixture requires an explicitly supplied isolated PostgreSQL")
	}
	parsed, err := url.Parse(address)
	if err != nil || net.ParseIP(parsed.Hostname()) == nil || !net.ParseIP(parsed.Hostname()).IsLoopback() {
		t.Fatal("historical fixture requires a loopback PostgreSQL address")
	}
	root := filepath.Join("..", "..", "..")
	archive, err := exec.Command("git", "-C", root, "archive", "--format=tar", "ffc5b481badbfc0108a1673c8aa24e122404eb13").Output()
	if err != nil {
		t.Fatal("the fixed historical source archive is unavailable")
	}
	digest := sha256.Sum256(archive)
	if hex.EncodeToString(digest[:]) != "90ddbfa11a9f941a140837633db6b32fbb775ee29af49becf1460fef56f54674" {
		t.Fatal("the fixed historical source archive differs")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "source.tar")
	if err := os.WriteFile(file, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	unpack := exec.Command("tar", "-xf", file, "-C", dir)
	if err := unpack.Run(); err != nil {
		t.Fatal("the historical source archive could not be unpacked")
	}
	if err := os.Mkdir(filepath.Join(dir, "artifacts"), 0o700); err != nil {
		t.Fatal("the private historical artifact directory could not be created")
	}
	cmd := exec.Command("go", "test", "-count=1", "-timeout=5m", "-v", "./cmd/arcforges-center", "-run", pattern)
	cmd.Dir = filepath.Join(dir, "center")
	cmd.Env = []string{}
	for _, key := range []string{"PATH", "HOME", "USERPROFILE", "LOCALAPPDATA", "SystemRoot", "TMP", "TEMP", "TMPDIR", "GOCACHE", "GOPATH", "ARCFORGES_TEST_POSTGRES_URL", "ARCFORGES_TEST_POSTGRES_REQUIRED", "ARCFORGES_TEST_POSTGRES_CONTAINER", "ARCFORGES_TEST_CTR06_BRIDGE_BINARY", "CTR06_TEST_BRIDGE_BIN", "CTR06_TEST_BRIDGE_ARCHIVE", "CTR06_TEST_OUTPUT_DIR"} {
		if value, ok := os.LookupEnv(key); ok {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
	cmd.Env = append(cmd.Env, "GOTOOLCHAIN=local", "GOWORK=off", "GOFLAGS=-mod=readonly", "GOTELEMETRY=off", "GOPROXY=off", "GOSUMDB=off")
	output, err := cmd.CombinedOutput()
	logDigest := sha256.Sum256(output)
	if err != nil {
		t.Fatalf("isolated historical bridge fixture failed: %v (output SHA-256 %x)", err, logDigest)
	}
	t.Logf("isolated historical fixture passed; no current phase-1 bridge entry was enabled (output SHA-256 %x)", logDigest)
}
