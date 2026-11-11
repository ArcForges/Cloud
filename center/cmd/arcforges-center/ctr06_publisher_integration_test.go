// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/bridgeproof"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/provision"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/ArcForges/Cloud/center/internal/store/migrate"
	"github.com/jackc/pgx/v5"
)

type testJWKSRoundTripper struct {
	base http.RoundTripper
	jwks []byte
}

func (r testJWKSRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.String() == "https://token.actions.githubusercontent.com/.well-known/jwks" {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(r.jwks))), Request: request}, nil
	}
	return r.base.RoundTrip(request)
}

// This private loopback driver is compiled only into this test. The only
// substituted components are provider/OIDC transport and credentials; actual
// JS orchestration, RSA verification, Go provision/migration and PG are real.
func TestCTR06ProtectedPublisherIntegration(t *testing.T) {
	binary, archive, outDir := os.Getenv("CTR06_TEST_BRIDGE_BIN"), os.Getenv("CTR06_TEST_BRIDGE_ARCHIVE"), os.Getenv("CTR06_TEST_OUTPUT_DIR")
	if binary == "" || archive == "" || outDir == "" {
		t.Skip("requires the independently verified bridge release fixture")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("verified bridge binary unavailable")
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "028223a3dcbcbd6d7724558de02409e1e8874d876049f03fed38f47998773ba4" {
		t.Fatal("bridge binary digest differs")
	}
	ctx := context.Background()
	url, name := pgtest.Database(t)
	owner := pgtest.Connect(t, url)
	build, err := migrate.Load(schema.Migrations())
	if err != nil {
		t.Fatal(err)
	}
	var grants []schema.Grant
	for _, g := range schema.RuntimeGrants {
		if g.Schema == "fleet" && (g.Table == "routed_file_call" || g.Table == "routed_command_id" || g.Table == "routed_file_target") {
			continue
		}
		grants = append(grants, g)
	}
	legacy := name + "_runtime"
	if _, err := migrate.Apply(ctx, owner, build[:10], migrate.Options{RuntimeRole: legacy, Schemas: schema.Schemas, Grants: grants}); err != nil {
		t.Fatal(err)
	}
	old, err := provision.Rotate(ctx, owner, provision.Options{Group: legacy, DirectURL: url, Runner: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provision.Confirm(ctx, owner, legacy, old.Slot); err != nil {
		t.Fatal(err)
	}
	oldConnection := pgtest.Connect(t, old.RuntimeURL)
	holder := platform.NewID()
	if _, err := oldConnection.Exec(ctx, `INSERT INTO fleet.hub_lease(singleton,holder,fence,acquired_at,renewed_at,expires_at)
VALUES(true,$1,1,clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '1 hour')`, holder); err != nil {
		t.Fatal(err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	jwks, _ := json.Marshal(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test-issuer",
		"n": b64(key.N.Bytes()), "e": b64([]byte{1, 0, 1})}}})
	previousTransport := http.DefaultTransport
	http.DefaultTransport = testJWKSRoundTripper{base: previousTransport, jwks: jwks}
	defer func() { http.DefaultTransport = previousTransport }()

	var authBytes [32]byte
	if _, err := rand.Read(authBytes[:]); err != nil {
		t.Fatal(err)
	}
	auth := hex.EncodeToString(authBytes[:])
	revision := strings.Repeat("b", 40)
	// Build the current source executable once for a real candidate-to-bridge
	// server rollback. The launcher records this test's complete source hashes.
	currentBinary := filepath.Join(outDir, "current-arcforges-center")
	buildLog, err := os.Create(filepath.Join(outDir, "current-build.log"))
	if err != nil {
		t.Fatal(err)
	}
	compile := exec.Command("go", "build", "-trimpath", "-o", currentBinary, "./cmd/arcforges-center")
	compile.Dir = filepath.Join("..", "..")
	compile.Stdout, compile.Stderr = buildLog, buildLog
	buildErr := compile.Run()
	_ = buildLog.Close()
	if buildErr != nil {
		t.Fatal("current source executable did not build")
	}
	currentBytes, err := os.ReadFile(currentBinary)
	if err != nil {
		t.Fatal("current source executable unavailable")
	}
	currentHash := sha256.Sum256(currentBytes)
	t.Logf("current source executable sha256=%x", currentHash)
	var mu sync.Mutex
	var prepared provision.BridgePreparation
	var proc *exec.Cmd
	var done chan error
	var serviceURL string
	var bridgeLog *os.File
	stopService := func() error {
		if proc == nil || proc.Process == nil {
			return nil
		}
		_ = proc.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			_ = proc.Process.Kill()
			<-done
			return errors.New("owned service did not stop")
		}
		if bridgeLog != nil {
			_ = bridgeLog.Close()
		}
		proc = nil
		done = nil
		bridgeLog = nil
		return nil
	}
	defer func() {
		if err := stopService(); err != nil {
			t.Error(err)
		}
	}()
	startService := func(executable, logName string) error {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		address := listener.Addr().String()
		_ = listener.Close()
		bridgeLog, err = os.Create(filepath.Join(outDir, logName))
		if err != nil {
			return err
		}
		proc = exec.Command(executable, "serve")
		proc.Env = []string{"PATH=/usr/bin:/bin", config.EnvMode + "=self-hosted", config.EnvPublicBaseURL + "=https://center.example.test/api",
			config.EnvDatabaseURL + "=" + prepared.RuntimeURL, config.EnvHTTPAddress + "=" + address, config.EnvGRPCAddress + "=off",
			config.EnvSurfaces + "=none", config.EnvMetricsLogInterval + "=0"}
		proc.Stdout, proc.Stderr = bridgeLog, bridgeLog
		if err := proc.Start(); err != nil {
			return err
		}
		t.Logf("owned service %s pid=%d", logName, proc.Process.Pid)
		done = make(chan error, 1)
		started, completed := proc, done
		go func() { completed <- started.Wait() }()
		serviceURL = "http://" + address
		client := &http.Client{Timeout: 500 * time.Millisecond}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			response, e := client.Get(serviceURL + "/healthz")
			if e == nil {
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					return nil
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		return errors.New("owned service did not become ready")
	}
	healthRevision := func() (string, error) {
		response, err := (&http.Client{Timeout: time.Second}).Get(serviceURL + "/healthz")
		if err != nil {
			return "", err
		}
		defer response.Body.Close()
		var health struct {
			Revision string `json:"revision"`
		}
		if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&health) != nil {
			return "", errors.New("invalid health")
		}
		return health.Revision, nil
	}
	type request struct {
		CandidateImage string            `json:"candidateImage"`
		Variables      map[string]string `json:"variables"`
		Command        []string          `json:"command"`
		Directory      string            `json:"directory"`
		SecretFile     string            `json:"secretFile"`
		Audience       string            `json:"audience"`
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer "+auth {
			http.Error(w, "refused", http.StatusForbidden)
			return
		}
		var req request
		if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req) != nil {
			http.Error(w, "request", http.StatusBadRequest)
			return
		}
		fail := func(stage string) {
			t.Log("driver refused " + stage)
			http.Error(w, "fixture stage failed", http.StatusConflict)
		}
		write := func(value any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(value)
		}
		switch r.URL.Path {
		case "/center":
			if len(req.Command) == 2 && req.Command[0] == "admin" && req.Command[1] == "prepare-ctr06-bridge" {
				if !filepath.IsAbs(req.Directory) || filepath.Dir(req.Directory) != os.TempDir() || !strings.HasPrefix(filepath.Base(req.Directory), "arcforges-ctr06-bridge-") {
					fail("private directory")
					return
				}
				var prepErr error
				prepared, prepErr = provision.PrepareCTR06Bridge(ctx, owner, build, provision.Options{Group: legacy, DirectURL: url, Runner: revision})
				if prepErr != nil {
					fail("credential issuance")
					return
				}
				if writeSecret(filepath.Join(req.Directory, "runtime.json"), map[string]string{config.EnvDatabaseURL: prepared.RuntimeURL}) != nil {
					fail("runtime secret")
					return
				}
				write(prepared)
				return
			}
			if len(req.Command) == 1 && req.Command[0] == "migrate" {
				if req.Variables[config.EnvRuntimeRole] != prepared.BridgeRole || req.Variables[config.EnvCTR06ProofFile] != "/secrets/proof.json" {
					fail("bound migration inputs")
					return
				}
				proof, proofErr := readCTR06Proof(ctx, filepath.Join(req.Directory, "proof.json"))
				if proofErr != nil {
					fail("OIDC verification")
					return
				}
				result, migrationErr := migrate.Apply(ctx, owner, build, migrate.Options{Runner: revision, RuntimeRole: prepared.BridgeRole, BridgeProof: proof})
				if migrationErr != nil {
					t.Logf("migration failure class: %T", migrationErr)
					fail("database migration")
					return
				}
				write(result)
				return
			}
			fail("unexpected center command")
		case "/start-bridge":
			if proc != nil || req.SecretFile == "" {
				fail("bridge launch")
				return
			}
			data, readErr := os.ReadFile(req.SecretFile)
			var values map[string]string
			if readErr != nil || json.Unmarshal(data, &values) != nil || values[config.EnvDatabaseURL] != prepared.RuntimeURL {
				fail("published credential binding")
				return
			}
			if err := startService(binary, "bridge-615-service.log"); err != nil {
				fail("bridge startup")
				return
			}
			write(map[string]bool{"started": true})
		case "/oidc":
			if !strings.HasPrefix(req.Audience, "urn:arcforges:ctr06:") {
				fail("OIDC audience")
				return
			}
			now := time.Now()
			header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "test-issuer", "typ": "JWT"})
			claims, _ := json.Marshal(map[string]any{"iss": "https://token.actions.githubusercontent.com", "sub": "repo:ArcForges/Cloud:environment:cloudflare",
				"aud": req.Audience, "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
				"repository": "ArcForges/Cloud", "ref": "refs/heads/main", "sha": revision, "environment": "cloudflare", "event_name": "push",
				"workflow_ref": "ArcForges/Cloud/.github/workflows/ci.yml@refs/heads/main", "workflow_sha": revision})
			message := b64(header) + "." + b64(claims)
			hash := sha256.Sum256([]byte(message))
			sig, signErr := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
			if signErr != nil {
				fail("issuer transport")
				return
			}
			write(map[string]string{"token": message + "." + b64(sig)})
		case "/assert":
			if _, err := oldConnection.Exec(ctx, "UPDATE fleet.hub_lease SET expires_at=clock_timestamp()+interval '1 hour' WHERE singleton"); err == nil {
				fail("old open lease writer")
				return
			}
			bridge, connectErr := pgx.Connect(ctx, prepared.RuntimeURL)
			if connectErr != nil {
				fail("new runtime login")
				return
			}
			defer func() { _ = bridge.Close(ctx) }()
			tag, updateErr := bridge.Exec(ctx, `UPDATE fleet.hub_lease SET holder=$1,fence=fence+1,acquired_at=clock_timestamp(),
renewed_at=clock_timestamp(),expires_at=clock_timestamp()+interval '1 minute' WHERE singleton AND expires_at<=clock_timestamp()`, platform.NewID())
			if updateErr != nil || tag.RowsAffected() != 1 {
				fail("bridge lease handoff")
				return
			}
			if _, rotateErr := provision.Rotate(ctx, owner, provision.Options{Group: legacy, DirectURL: url}); !errors.Is(rotateErr, migrate.ErrCTR06RetirementUnproven) {
				fail("legacy rotation floor")
				return
			}
			if current, healthErr := healthRevision(); healthErr != nil || current != bridgeproof.BridgeRevision {
				fail("bridge identity after migration")
				return
			}
			if stopService() != nil || startService(currentBinary, "current-source-service.log") != nil {
				fail("current source server")
				return
			}
			if current, healthErr := healthRevision(); healthErr != nil || current != "local-dirty" {
				fail("current source identity")
				return
			}
			// Supported rollback is the exact bridge service on the same new
			// credential, with the current protected administration floor.
			if stopService() != nil || startService(binary, "bridge-615-rollback.log") != nil {
				fail("bridge rollback")
				return
			}
			if current, healthErr := healthRevision(); healthErr != nil || current != bridgeproof.BridgeRevision {
				fail("bridge rollback identity")
				return
			}
			if _, rotateErr := provision.Rotate(ctx, owner, provision.Options{Group: legacy, DirectURL: url}); !errors.Is(rotateErr, migrate.ErrCTR06RetirementUnproven) {
				fail("rollback legacy floor")
				return
			}
			if _, err := oldConnection.Exec(ctx, "UPDATE fleet.hub_lease SET expires_at=clock_timestamp()+interval '1 hour' WHERE singleton"); err == nil {
				fail("rollback revived old connection")
				return
			}
			write(map[string]bool{"verified": true})
		default:
			http.Error(w, "unknown fixture route", http.StatusNotFound)
		}
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	// The explicit local script runs only with the private Go driver below;
	// ordinary npm test and CI do not start the PG/provider component test.
	npm := "npm"
	if runtime.GOOS == "windows" {
		npm = "npm.cmd"
	}
	node := exec.Command(npm, "run", "test:ctr06:publisher:driver")
	node.Dir = filepath.Join("..", "..", "..")
	node.Env = append(os.Environ(), "CTR06_TEST_DRIVER_URL="+server.URL, "CTR06_TEST_DRIVER_TOKEN="+auth,
		"CTR06_TEST_BRIDGE_ARCHIVE="+archive, "CTR06_TEST_DATABASE_URL="+url, "CTR06_TEST_LEGACY_ROLE="+legacy)
	log, err := os.Create(filepath.Join(outDir, "publisher-node.log"))
	if err != nil {
		t.Fatal(err)
	}
	node.Stdout, node.Stderr = log, log
	err = node.Run()
	_ = log.Close()
	if err != nil {
		t.Fatalf("protected publisher component failed; see publisher-node.log (%T)", err)
	}
	mu.Lock()
	started := proc != nil
	mu.Unlock()
	if !started {
		t.Fatal("the verified bridge service was not started")
	}
}
