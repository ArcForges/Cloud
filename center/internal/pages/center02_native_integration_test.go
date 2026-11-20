// SPDX-License-Identifier: AGPL-3.0-only

package pages_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

const (
	center02Required = "ARCFORGES_CENTER02_E2E_REQUIRED"
	center02Project  = "ARCFORGES_CENTER02_NODE_PROJECT"
	center02Cert     = "ARCFORGES_CENTER02_TLS_CERT"
	center02Key      = "ARCFORGES_CENTER02_TLS_KEY"
	center02URL      = "ARCFORGES_CENTER02_URL"
	center02Evidence = "ARCFORGES_CENTER02_COORDINATION_DIR"
)

type center02Approval struct {
	VerificationURI string `json:"verificationUri"`
}

type center02Owner struct {
	OwnerEpoch string `json:"ownerEpoch"`
	NodeEpoch  string `json:"nodeEpoch"`
}

// TestCenter02InstalledNode uses a real composed Go Center, an isolated PostgreSQL store, ordinary HTTPS certificate
// validation and the installed product. The browser's input uses the existing virtual passkey helper.
func TestCenter02InstalledNode(t *testing.T) {
	if os.Getenv(center02Required) != "1" {
		t.Skip("the installed Node supplement requires a scoped native fixture")
	}
	project := center02File(t, center02Project)
	center02File(t, "ARCFORGES_HOST_PATH")
	center02File(t, "ARCFORGES_TESTLOAD_PATH")
	if os.Getenv("ARCFORGES_TEST_POSTGRES_REQUIRED") != "1" || os.Getenv("ARCFORGES_MXC_PACKAGE_TESTS") != "1" {
		t.Fatal("the native fixture requires both real PostgreSQL and the verified MXC extraction")
	}
	certificate, err := tls.LoadX509KeyPair(center02File(t, center02Cert), center02File(t, center02Key))
	if err != nil {
		t.Fatal("the scoped localhost TLS certificate and key could not be loaded")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || leaf.VerifyHostname("localhost") != nil {
		t.Fatal("the scoped TLS identity must name localhost")
	}

	h := newHarness(t, settings{surfaces: "identity,pages,fleet,relay", policy: writePolicy, relay: true, nativeCertificate: &certificate})
	owner := h.seedAccount(1)
	ownerBrowser := h.newBrowser()
	ownerBrowser.mustSignIn(owner)
	coordination := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	processContext, cancelProcess := context.WithTimeout(context.Background(), 6*time.Minute)
	t.Cleanup(cancelProcess)
	command := exec.CommandContext(processContext, "dotnet", "test", "--project", project, "-c", "Release", "--no-build",
		"--filter-class", "ArcForges.ClosedLoop.Tests.CloudLinkCenterControlTests", "--minimum-expected-tests", "1", "--fail-skips", "on")
	command.Dir = filepath.Dir(project)
	command.WaitDelay = 5 * time.Second
	command.Env = center02NodeEnvironment(command.Environ())
	command.Env = append(command.Env, center02URL+"="+h.origin, center02Evidence+"="+coordination)
	var output lockedBuffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatalf("launch the installed Node test: %v", err)
	}
	done := make(chan struct{})
	var exit error
	go func() {
		exit = command.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		center02DrainChild(t, coordination, done, cancelProcess)
		if t.Failed() {
			t.Log(output.String())
		}
	})

	var approval center02Approval
	if err := json.Unmarshal(center02WaitFile(t, ctx, coordination, "approval.json", done), &approval); err != nil {
		t.Fatal("the installed Node sign-in fixture did not publish a valid approval input")
	}
	center02ApproveBrowserFlow(t, ctx, h, ownerBrowser, owner, approval.VerificationURI)
	var reported center02Owner
	if err := json.Unmarshal(center02WaitFile(t, ctx, coordination, "connected.json", done), &reported); err != nil {
		t.Fatal("the installed Node did not publish its observed owner and Node epochs")
	}
	first := center02QualifiedConnection(t, ctx, h, owner, reported)
	if err := os.WriteFile(filepath.Join(coordination, "connected-confirmed"), nil, 0600); err != nil {
		t.Fatal("the exact V2 connection observation could not be recorded")
	}
	center02WaitFile(t, ctx, coordination, "outage-request", done)
	reconnected := center02QualifiedConnection(t, ctx, h, owner, reported)
	if reconnected == first {
		t.Fatal("explicit reconnect did not establish a new V2 channel generation")
	}
	rotationDeadline := time.NewTimer(40 * time.Second)
	defer rotationDeadline.Stop()
	rotationPoll := time.NewTicker(250 * time.Millisecond)
	defer rotationPoll.Stop()
	for h.count(`SELECT count(*) FROM identity.spent_refresh AS spent
		JOIN identity.session AS s ON s.session_id = spent.session_id
		JOIN fleet.node AS node ON node.installation_id = s.installation_id WHERE node.user_id = $1`, owner.id) == 0 {
		select {
		case <-rotationPoll.C:
		case <-done:
			t.Fatal("the Node test exited before credential rotation")
		case <-rotationDeadline.C:
			t.Fatal("the real Node credential family did not rotate")
		}
	}
	h.stopHub()
	h.native.Close()
	if err := os.WriteFile(filepath.Join(coordination, "outage-ready"), nil, 0600); err != nil {
		t.Fatal("the native outage marker could not be written")
	}
	select {
	case <-done:
		if exit != nil {
			t.Fatalf("the installed Node test failed: %v", exit)
		}
	case <-ctx.Done():
		t.Fatal("the installed Node test exceeded its time bound")
	}
	t.Log(output.String())
}

func center02DrainChild(t *testing.T, directory string, done <-chan struct{}, cancel context.CancelFunc) {
	t.Helper()
	select {
	case <-done:
		return
	default:
	}
	if err := os.WriteFile(filepath.Join(directory, "fixture-abort"), nil, 0600); err != nil {
		t.Error("the Node test could not be notified to drain after fixture failure")
	}
	select {
	case <-done:
		return
	case <-time.After(38 * time.Second):
		t.Error("the Node test did not drain after the fixture abort signal")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Error("the installed Node test process did not exit after cancellation")
	}
}

func center02QualifiedConnection(t *testing.T, ctx context.Context, h *harness, owner account, reported center02Owner) platform.ID {
	t.Helper()
	var enrollment, node, protocol platform.ID
	if err := h.migration.QueryRow(ctx, `SELECT enrollment_id, node_id, protocol_epoch FROM management.node_protocol
		WHERE account_id = $1 AND protocol_major = 2 AND revoked_at IS NULL`, owner.id).Scan(&enrollment, &node, &protocol); err != nil {
		t.Fatal("no exact active V2 enrollment was recorded for the fixture account")
	}
	if count := h.count(`SELECT count(*) FROM management.node_protocol
		WHERE account_id = $1 AND protocol_major = 2 AND revoked_at IS NULL`, owner.id); count != 1 {
		t.Fatalf("the Center retained %d active V2 protocol records for the fixture account", count)
	}
	qualified := "linux-bubblewrap-sdk-v1"
	if runtime.GOOS == "windows" {
		qualified = "win-wrapper-local-v1"
	}
	current, online := h.center.Hub.V2Presence(owner.id, enrollment, node, protocol)
	if !online || current.Platform != runtime.GOOS || !slices.Equal(current.Capabilities, []string{qualified}) ||
		hex.EncodeToString(current.NodeOwnerEpoch[:]) != reported.OwnerEpoch || current.NodeEpoch != reported.NodeEpoch {
		t.Fatal("the real Center did not observe the installed Node's exact owner epoch and qualified platform profile")
	}
	return current.ConnectionID
}

func center02File(t *testing.T, name string) string {
	t.Helper()
	path := os.Getenv(name)
	if !filepath.IsAbs(path) {
		t.Fatalf("%s must name an absolute fixture file", name)
	}
	entry, err := os.Stat(path)
	if err != nil || !entry.Mode().IsRegular() {
		t.Fatalf("%s must name an existing fixture file", name)
	}
	return path
}

func center02NodeEnvironment(inherited []string) []string {
	filtered := make([]string, 0, len(inherited))
	for _, entry := range inherited {
		name, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(name) {
		case "ARCFORGES_TEST_POSTGRES_URL", "ARCFORGES_TEST_POSTGRES_CONTAINER", center02Cert, center02Key, center02URL, center02Evidence:
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func center02WaitFile(t *testing.T, ctx context.Context, directory, name string, done <-chan struct{}) []byte {
	t.Helper()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err == nil && len(data) <= 4096 {
			return data
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("could not read the bounded native fixture marker %s", name)
		}
		select {
		case <-ticker.C:
		case <-done:
			t.Fatalf("the installed Node test exited before %s", name)
		case <-ctx.Done():
			t.Fatalf("the native fixture marker %s did not arrive", name)
		}
	}
}

func center02ApproveBrowserFlow(t *testing.T, ctx context.Context, h *harness, b *browser, owner account, verification string) {
	t.Helper()
	uri, err := url.Parse(verification)
	if err != nil || uri.Scheme+"://"+uri.Host != h.origin || uri.Path != "/connect" || uri.RawQuery != "" || uri.User != nil {
		t.Fatal("the installed Node did not name this exact Center for approval")
	}
	fragment, err := url.ParseQuery(uri.Fragment)
	if err != nil || len(fragment) != 1 || len(fragment["flow"]) != 1 {
		t.Fatal("the installed Node did not publish one browser approval flow")
	}
	flow := fragment.Get("flow")
	var flowID platform.ID
	decoded, err := hex.DecodeString(strings.ReplaceAll(flow, "-", ""))
	if err != nil || len(decoded) != len(flowID) {
		t.Fatal("the installed Node did not publish a canonical remote flow ID")
	}
	copy(flowID[:], decoded)
	if flowID == (platform.ID{}) || flowID.String() != flow {
		t.Fatal("the installed Node did not publish a canonical remote flow ID")
	}
	review := b.postForm("/connect/review", url.Values{"flow_id": {flow}})
	if review.status != http.StatusOK || !strings.Contains(review.text(), `id="node-fingerprint"`) {
		t.Fatalf("the real Center did not show the Node's enrollment review: %d", review.status)
	}
	b.mustStepUp(owner, fleet.ClassApproveNodeSignIn, flowID)
	approved := b.postForm("/connect/decision", url.Values{"flow_id": {flow}, "decision": {"approve"}})
	if approved.status != http.StatusOK || !hrefPattern.MatchString(approved.text()) {
		t.Fatalf("the real Center did not issue an approved PKCE callback: %d", approved.status)
	}
	redirect, err := url.Parse(field(t, approved, hrefPattern))
	if err != nil || redirect.Scheme != "http" || redirect.User != nil || redirect.Path != "/callback" || redirect.Port() == "" ||
		net.ParseIP(redirect.Hostname()) == nil || !net.ParseIP(redirect.Hostname()).IsLoopback() {
		t.Fatal("the real Center did not return the Node's held loopback receiver")
	}
	h.remember(redirect.Query().Get("code"))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, redirect.String(), nil)
	if err != nil {
		t.Fatal("the PKCE callback request could not be prepared")
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	reply, err := client.Do(request)
	if err != nil {
		t.Fatal("the Node's loopback receiver did not accept the browser callback")
	}
	defer func() { _ = reply.Body.Close() }()
	_, err = io.Copy(io.Discard, io.LimitReader(reply.Body, 4096))
	if err != nil || reply.StatusCode != http.StatusOK {
		t.Fatalf("the Node's loopback receiver refused the browser callback: %d", reply.StatusCode)
	}
}
