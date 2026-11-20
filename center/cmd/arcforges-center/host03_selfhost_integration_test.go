// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/session"
)

const (
	host03Surfaces   = "identity,pages,fleet,relay,nodes"
	host03KeyBinding = "ARCFORGES_CENTER_KEY_HOST03_COMMAND"
)

// A scoped native supplement uses the original installed Node, the candidate's
// Go executable, native PostgreSQL tools, and an operator-style /api TLS proxy.
func TestHost03InstalledSelfHost(t *testing.T) {
	if os.Getenv("ARCFORGES_HOST03_REQUIRED") != "1" {
		t.Skip("requires the scoped HOST-03 Node, native PostgreSQL and localhost certificate")
	}
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		t.Fatal("HOST-03 requires native Windows or Linux")
	}
	if os.Getenv(pgtest.EnvRequired) != "1" {
		t.Fatal("HOST-03 requires an isolated real PostgreSQL server")
	}
	var completed *host03Receipt
	t.Cleanup(func() {
		if completed != nil && !t.Failed() {
			host03WriteReceipt(t, *completed)
		}
	})
	testURL, err := url.Parse(pgtest.ServerURL(t))
	if err != nil || net.ParseIP(testURL.Hostname()) == nil || !net.ParseIP(testURL.Hostname()).IsLoopback() {
		t.Fatal("the selected fixture PostgreSQL server must bind to loopback")
	}
	for _, tool := range []string{"pg_dump", "pg_restore"} {
		if runtime.GOOS == "linux" {
			if _, err := exec.LookPath(tool); err != nil {
				t.Fatalf("the scoped native PostgreSQL %s executable is unavailable", tool)
			}
		}
	}

	root := t.TempDir()
	centerBinary := host03Build(t, root)
	centerSHA := host03FileDigest(t, centerBinary)
	nodeBinary := host03InputFile(t, "ARCFORGES_HOST03_NODE")
	nodeSHA := host03FileDigest(t, nodeBinary)
	nodeSource := os.Getenv("ARCFORGES_HOST03_NODE_SOURCE")
	if nodeSHA != os.Getenv("ARCFORGES_HOST03_NODE_SHA256") || !host03Hex(nodeSource, 20) {
		t.Fatal("the original installed Node hash and exact source commit are required")
	}
	fixture := host03Center(t, root, centerBinary)
	source := fixture.install()
	center := fixture.serve(source, true)
	owner := fixture.browser()
	owner.enroll(fixture.bootstrap)
	t.Log("clean self-host Go/PostgreSQL installation and one-time owner bootstrap passed")

	node := startHost03Node(t, root, nodeBinary, fixture.origin)
	first := node.enroll(owner)
	sourceProtocol := fixture.protocol(source, &first)
	sandbox := node.createSandbox("Host03 native continuity")
	run := node.startRun(sandbox)
	sourceScope := node.setGrant(sandbox, first)
	owner.inspect(sourceScope, sandbox.id, run)
	node.assertLocalRun(sandbox, run)
	originalData := node.privateDigest(sandbox)

	center.stop(t, false)
	fixture.awaitOutage()
	node.requireOffline(first)
	node.assertLocalRun(sandbox, run)
	if node.privateDigest(sandbox) != originalData {
		t.Fatal("the outage changed the original private Sandbox data")
	}
	offlineSandbox := node.createSandbox("Host03 local during outage")
	node.runOffline(offlineSandbox)
	t.Log("the same Node-owned Run and private data survived the real Center listener outage")

	receipt := host03Receipt{Platform: runtime.GOOS, CenterSHA256: centerSHA, NodeSHA256: nodeSHA, NodeSource: nodeSource,
		Recovery: "source_restart", OldProtocol: sourceProtocol.String(), NodeID: first.node.String(),
		SandboxID: sandbox.id, RunID: run, PrivateDataSHA256: originalData}
	if runtime.GOOS == "linux" {
		restored := fixture.restore(source, first)
		fixture.serve(restored, false)
		owner.requireRevoked()
		owner.rejectRun(sourceScope, run, "unauthenticated")
		fresh := owner.fresh()
		fresh.signIn()
		fresh.rejectRun(sourceScope, run, "permission_denied", "not_found", "node_offline", "node_unreachable")
		node.endEnrollment()
		// Restore retained the old enrollment for audit but permanently revoked
		// its protocol. Retire that obsolete fleet row before a fresh approval.
		if fixture.command(restored, "admin", "revoke-device", "--node", first.node.String())["account"] != fresh.account.String() {
			t.Fatal("the operator did not retire the restored obsolete enrollment for the exact account")
		}
		next := node.enroll(fresh)
		protocol := fixture.protocol(restored, &next)
		if next.node != first.node || next.ownerEpoch != first.ownerEpoch || next.enrollment == first.enrollment {
			t.Fatal("restore reapproval changed the native Node or durable owner identity")
		}
		newScope := node.setGrant(sandbox, next)
		staleGrant := newScope
		staleGrant.grant, staleGrant.revision = sourceScope.grant, sourceScope.revision
		fresh.rejectRun(staleGrant, run, "permission_denied")
		if protocol == sourceProtocol || sourceScope.grant == newScope.grant {
			t.Fatal("restore reapproval must create a fresh protocol epoch and local grant")
		}
		fresh.inspect(newScope, sandbox.id, run)
		receipt.NewProtocol, receipt.Recovery = protocol.String(), "isolated_logical_restore_and_reapproval"
		receipt.ArchiveSHA256, receipt.MetadataSHA256, receipt.RestoreReceipt = restored.archiveSHA, restored.metadataSHA, restored.restoreReceipt
		t.Log("fresh PostgreSQL logical restore refused old authority and served the original Run after passkey reapproval under a new local grant")
	} else {
		fixture.serve(source, false)
		node.rejoin(first)
		owner.inspect(sourceScope, sandbox.id, run)
		if fixture.protocol(source, &first) != sourceProtocol {
			t.Fatal("ordinary Center restart changed the durable protocol epoch")
		}
		receipt.NewProtocol = sourceProtocol.String()
		t.Log("the same Windows enrollment and local Run rejoined the restarted Center")
	}
	node.assertLocalRun(sandbox, run)
	if receipt.PrivateDataSHA256 != node.privateDigest(sandbox) {
		t.Fatal("recovery changed private Sandbox data")
	}
	node.verifyNoOfficialCall()
	node.drain(sandbox, run)
	fixture.shutdown()
	completed = &receipt
}

type host03Receipt struct {
	Platform          string `json:"platform"`
	CenterSHA256      string `json:"centerSha256"`
	NodeSHA256        string `json:"nodeSha256"`
	NodeSource        string `json:"nodeSource"`
	Recovery          string `json:"recovery"`
	OldProtocol       string `json:"oldProtocol"`
	NewProtocol       string `json:"newProtocol"`
	NodeID            string `json:"nodeId"`
	SandboxID         string `json:"sandboxId"`
	RunID             string `json:"runId"`
	PrivateDataSHA256 string `json:"privateDataSha256"`
	ArchiveSHA256     string `json:"archiveSha256,omitempty"`
	MetadataSHA256    string `json:"metadataSha256,omitempty"`
	RestoreReceipt    string `json:"restoreReceipt,omitempty"`
}

type host03Fixture struct {
	t         *testing.T
	root      string
	binary    string
	bootstrap string
	private   string
	public    string
	origin    string
	backend   string
	admin     string
	client    *http.Client
	server    *httptest.Server
	child     *host03Child
}

type host03Database struct {
	name, migrationURL, runtimeRole, runtimeURL, runtimeSlot string
	archiveSHA, metadataSHA, restoreReceipt                  string
}

func host03Center(t *testing.T, root, binary string) *host03Fixture {
	t.Helper()
	f := &host03Fixture{t: t, root: root, binary: binary, bootstrap: session.NewSecret().Token(session.BootstrapPrefix),
		backend: host03Loopback(t), admin: host03Loopback(t)}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("create the scoped command signing key")
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal("marshal the scoped public signing key")
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("marshal the scoped private signing key")
	}
	f.private = base64.StdEncoding.EncodeToString(private)
	f.public = filepath.Join(root, "command-public.der")
	if err := os.WriteFile(f.public, public, 0600); err != nil {
		t.Fatal("write the scoped public signing key")
	}

	cert, err := tls.LoadX509KeyPair(host03InputFile(t, "ARCFORGES_HOST03_TLS_CERT"), host03InputFile(t, "ARCFORGES_HOST03_TLS_KEY"))
	if err != nil || len(cert.Certificate) != 1 {
		t.Fatal("the original trusted localhost TLS key pair is required")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || leaf.VerifyHostname("localhost") != nil || time.Now().Before(leaf.NotBefore) || time.Now().After(leaf.NotAfter) {
		t.Fatal("the scoped TLS certificate is not currently valid for localhost")
	}
	certs := x509.NewCertPool()
	certs.AddCert(leaf)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certs, MinVersion: tls.VersionTLS12}}
	t.Cleanup(transport.CloseIdleConnections)
	f.client = &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: host03NoRedirect}
	backend, _ := url.Parse("http://" + f.backend)
	upstream := &http.Transport{ResponseHeaderTimeout: 15 * time.Second}
	t.Cleanup(upstream.CloseIdleConnections)
	proxy := &httputil.ReverseProxy{Transport: upstream, Rewrite: func(request *httputil.ProxyRequest) {
		request.SetURL(backend)
		request.Out.Header.Del(config.ClientIPHeader)
		peer, _, err := net.SplitHostPort(request.In.RemoteAddr)
		if err == nil {
			request.Out.Header.Set(config.ClientIPHeader, peer)
		}
	}, ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
		w.WriteHeader(http.StatusBadGateway)
	}}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") || r.URL.EscapedPath() != r.URL.Path {
			http.NotFound(w, r)
			return
		}
		http.StripPrefix("/api", proxy).ServeHTTP(w, r)
	}))
	f.server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	_, port, _ := net.SplitHostPort(f.server.Listener.Addr().String())
	f.origin = "https://localhost:" + port
	return f
}

func (f *host03Fixture) env(db host03Database) map[string]string {
	return map[string]string{config.EnvMode: string(config.SelfHosted), config.EnvMigrationDatabaseURL: db.migrationURL,
		config.EnvDatabaseName: db.name, config.EnvRuntimeRole: db.runtimeRole, config.EnvRuntimePooledHost: pgtest.Host(f.t),
		config.EnvRuntimeSecretFile: filepath.Join(f.root, db.name+"-runtime.json")}
}

func (f *host03Fixture) install() host03Database {
	migrationURL, name := pgtest.Database(f.t)
	db := host03Database{name: name + "_source", migrationURL: migrationURL, runtimeRole: name + "_source_runtime"}
	f.t.Cleanup(func() { pgtest.Drop(f.t, db.name) })
	if f.command(db, "admin", "ensure-database")["created"] != true {
		f.t.Fatal("the documented self-host install did not create a clean database")
	}
	if f.command(db, "migrate", "status")["state"] != "uninitialized" {
		f.t.Fatal("the self-host install did not start from clean schema state")
	}
	if state := f.command(db, "migrate", "apply"); state["state"] != "current" || state["grants"] != "reconciled" || state["ran"] == nil {
		f.t.Fatal("the self-host migration did not admit the clean target and restricted runtime role")
	}
	now := time.Now().UTC().Truncate(time.Second)
	f.command(db, "admin", "register-signing-key", "--purpose", "command", "--kid", "host03-command-01",
		"--public-key-file", f.public, "--secret-binding", host03KeyBinding, "--not-before", now.Add(-30*time.Second).Format(time.RFC3339),
		"--not-after", now.Add(24*time.Hour).Format(time.RFC3339))
	return f.rotate(db)
}

func (f *host03Fixture) rotate(db host03Database) host03Database {
	result := f.command(db, "admin", "rotate-runtime-credential")
	slot, ok := result["slot"].(string)
	if !ok || slot != "a" && slot != "b" || result["loginRole"] != db.runtimeRole+"_"+slot {
		f.t.Fatal("the rotation did not issue the selected target runtime login")
	}
	filename := f.env(db)[config.EnvRuntimeSecretFile]
	body, err := os.ReadFile(filename)
	var contents map[string]string
	if err != nil || json.Unmarshal(body, &contents) != nil || len(contents) != 1 || contents[config.EnvDatabaseURL] == "" {
		f.t.Fatal("the rotation did not write the exact runtime credential handoff")
	}
	if err = os.Remove(filename); err != nil {
		f.t.Fatal("the private runtime handoff could not be removed")
	}
	db.runtimeURL = contents[config.EnvDatabaseURL]
	db.runtimeSlot = slot
	return db
}

func (f *host03Fixture) command(db host03Database, arguments ...string) map[string]any {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(f.t.Context(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, f.binary, arguments...)
	cmd.Env = host03Environment(f.env(db))
	var output bytes.Buffer
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil {
		f.t.Fatalf("the self-host Center %s command failed: %T (%v)", strings.Join(arguments[:min(2, len(arguments))], " "), err, host03Exit(err))
	}
	var report map[string]any
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		f.t.Fatal("the scoped Center command did not emit its JSON receipt")
	}
	return report
}

func (f *host03Fixture) serve(db host03Database, bootstrap bool) *host03Child {
	f.t.Helper()
	env := map[string]string{config.EnvMode: string(config.SelfHosted), config.EnvDatabaseURL: db.runtimeURL,
		config.EnvSurfaces: host03Surfaces, config.EnvPublicBaseURL: f.origin + "/api", config.EnvHTTPAddress: f.backend,
		config.EnvGRPCAddress: "off", config.EnvAdminAddress: f.admin, config.EnvClientIPHeader: config.ClientIPHeader,
		config.EnvTrustedProxies: "127.0.0.1/32", host03KeyBinding: f.private}
	if bootstrap {
		env[config.EnvBootstrapSHA256] = host03Digest([]byte(f.bootstrap))
		env[config.EnvBootstrapExpiresAt] = time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	}
	process := host03Start(f.t, f.binary, env, "serve")
	f.child = process
	f.t.Cleanup(func() { process.stop(f.t, false) })
	private := &http.Client{Timeout: time.Second, Transport: &http.Transport{}, CheckRedirect: host03NoRedirect}
	defer private.CloseIdleConnections()
	host03Wait(f.t, 20*time.Second, "private Center readiness", func() bool {
		f.child.requireRunning(f.t)
		return host03HTTPStatus(private, "http://"+f.admin+"/readyz") == http.StatusOK
	})
	if host03HTTPStatus(f.client, f.origin+"/api/healthz") != http.StatusOK || host03HTTPStatus(f.client, f.origin+"/readyz") != http.StatusNotFound ||
		host03HTTPStatus(f.client, f.origin+"/api/metrics") == http.StatusOK {
		f.t.Fatal("the scoped proxy did not separate public HTTP and private administration")
	}
	f.requireRestrictedRuntime(db)
	if f.command(db, "admin", "confirm-runtime-credential", "--slot", db.runtimeSlot)["slot"] != db.runtimeSlot {
		f.t.Fatal("the running Center's observed runtime slot was not confirmed")
	}
	return f.child
}

func (f *host03Fixture) requireRestrictedRuntime(db host03Database) {
	f.t.Helper()
	conn := pgtest.Connect(f.t, db.runtimeURL)
	defer conn.Close(context.Background())
	ctx, cancel := context.WithTimeout(f.t.Context(), 5*time.Second)
	defer cancel()
	tx, err := conn.Begin(ctx)
	if err != nil {
		f.t.Fatal("could not verify the real runtime role's database privilege boundary")
	}
	defer tx.Rollback(context.Background())
	var login, database string
	if err = tx.QueryRow(ctx, "SELECT session_user,current_database()").Scan(&login, &database); err != nil ||
		login != db.runtimeRole+"_"+db.runtimeSlot || database != db.name {
		f.t.Fatal("the process's generated PostgreSQL credential did not bind the expected runtime login and target")
	}
	_, err = tx.Exec(ctx, "CREATE TABLE management.host03_role_check (probe integer)")
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		f.t.Fatal("the runtime login was not explicitly denied migration-owned DDL")
	}
}

func (f *host03Fixture) awaitOutage() {
	host03Wait(f.t, 10*time.Second, "Center listener outage through the public TLS origin", func() bool {
		return host03HTTPStatus(f.client, f.origin+"/api/healthz") == http.StatusBadGateway
	})
}

func (f *host03Fixture) shutdown() {
	f.child.stop(f.t, false)
	f.awaitOutage()
}

func host03HTTPStatus(client *http.Client, endpoint string) int {
	response, err := client.Get(endpoint)
	if err != nil {
		return 0
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return response.StatusCode
}

func host03NoRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func host03WriteReceipt(t *testing.T, receipt host03Receipt) {
	t.Helper()
	t.Logf("HOST-03 paired receipt: %+v", receipt)
	filename := os.Getenv("ARCFORGES_HOST03_RECEIPT")
	if filename == "" {
		return
	}
	if !filepath.IsAbs(filename) {
		t.Fatal("the scoped acceptance receipt path must be absolute")
	}
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("the acceptance receipt must use a new file in the private report location")
	}
	writeErr := json.NewEncoder(file).Encode(receipt)
	if err = errors.Join(writeErr, file.Close()); err != nil {
		t.Fatal("the acceptance receipt could not be saved")
	}
}

func host03Build(t *testing.T, root string) string {
	t.Helper()
	name := "arcforges-center"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	filename := filepath.Join(root, name)
	cmd := exec.CommandContext(t.Context(), "go", "build", "-trimpath", "-o", filename, ".")
	cmd.Env = host03Environment(map[string]string{"GOTOOLCHAIN": "local", "GOFLAGS": "-mod=readonly"})
	if result, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build the exact native Center executable: %v\n%s", err, result)
	}
	return filename
}

func host03Environment(values map[string]string) []string {
	env := make([]string, 0, len(os.Environ())+len(values))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(name)
		if _, replaced := values[upper]; replaced || strings.HasPrefix(upper, "ARCFORGES_") || strings.HasPrefix(upper, "NEON_") ||
			strings.HasSuffix(upper, "_PROXY") || strings.HasPrefix(upper, "CLOUDFLARE_") || strings.HasPrefix(upper, "PADDLE_") {
			continue
		}
		env = append(env, entry)
	}
	for name, value := range values {
		env = append(env, name+"="+value)
	}
	return env
}

func host03InputFile(t *testing.T, variable string) string {
	t.Helper()
	name := os.Getenv(variable)
	info, err := os.Stat(name)
	if !filepath.IsAbs(name) || err != nil || !info.Mode().IsRegular() {
		t.Fatalf("%s must be an absolute path to the scoped fixture file", variable)
	}
	return name
}

func host03FileDigest(t *testing.T, name string) string {
	t.Helper()
	file, err := os.Open(name)
	if err != nil {
		t.Fatal("could not read a scoped fixture artifact for hashing")
	}
	defer file.Close()
	digest := sha256.New()
	if _, err = io.Copy(digest, file); err != nil {
		t.Fatal("could not hash a scoped fixture artifact")
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func host03Digest(contents []byte) string {
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}

func host03Hex(value string, bytes int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes && hex.EncodeToString(decoded) == value
}

func host03Loopback(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("could not allocate an isolated loopback listener")
	}
	address := listener.Addr().String()
	if listener.Close() != nil {
		t.Fatal("could not release the loopback listener")
	}
	return address
}

func host03Wait(t *testing.T, timeout time.Duration, reason string, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !predicate() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", reason)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

type host03Child struct {
	command *exec.Cmd
	done    chan struct{}
	err     error
}

func host03Start(t *testing.T, binary string, env map[string]string, arguments ...string) *host03Child {
	t.Helper()
	command := exec.Command(binary, arguments...)
	command.Env = host03Environment(env)
	if err := command.Start(); err != nil {
		t.Fatalf("could not start the scoped %s process: %v", filepath.Base(binary), err)
	}
	child := &host03Child{command: command, done: make(chan struct{})}
	go func() {
		child.err = command.Wait()
		close(child.done)
	}()
	return child
}

func (p *host03Child) requireRunning(t *testing.T) {
	t.Helper()
	select {
	case <-p.done:
		t.Fatalf("the scoped %s process exited early (%v)", filepath.Base(p.command.Path), host03Exit(p.err))
	default:
	}
}

func (p *host03Child) stop(t *testing.T, graceful bool) {
	t.Helper()
	select {
	case <-p.done:
		return
	default:
	}
	if graceful {
		select {
		case <-p.done:
			return
		case <-time.After(6 * time.Second):
			t.Error("scoped process did not exit after the documented stop command")
		}
	}
	if err := p.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Error("could not terminate an owned fixture process")
	}
	select {
	case <-p.done:
	case <-time.After(6 * time.Second):
		t.Error("could not reap an owned fixture process")
	}
}

func host03Exit(err error) any {
	var status *exec.ExitError
	if errors.As(err, &status) {
		return status.ExitCode()
	}
	if err == nil {
		return 0
	}
	return fmt.Sprintf("%T", err)
}
