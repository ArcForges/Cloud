// SPDX-License-Identifier: AGPL-3.0-only

package identityapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey/virtual"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/mail"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/provision"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/ArcForges/Cloud/center/internal/server"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store/migrate"
)

// The identity surface's integration tests drive a composed center (the real ingress pipeline, Connect handlers and verifiers)
// over binary gRPC-Web, against a real PostgreSQL with the runtime credential a rotation issued, exactly as the hosted Worker
// forwards a call. They need ARCFORGES_TEST_POSTGRES_URL (the Linux leg sets it and ARCFORGES_TEST_POSTGRES_REQUIRED=1).

const (
	publicBaseURL = "https://center.example.test/api"
	origin        = "https://center.example.test"
	rpID          = "center.example.test"
)

// clock is the center's adjustable clock; it starts at the real time and only moves forward (go-webauthn checks a ceremony's
// expiry against the real time as well).
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(by time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(by)
}

// harness is one composed center over its own database.
type harness struct {
	t         *testing.T
	center    *server.Center
	url       string
	migration *pgx.Conn
	database  string
	mail      *mail.Fake
	clock     *clock
	logs      *lockedBuffer
	// bootstrap is the owner bootstrap token of the configuration (generated at run time; only its digest is configuration).
	bootstrap string
	// secrets collects every credential the test saw, for the scans of F12.
	secrets *[]string
}

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

type settings struct {
	surfaces    string
	policy      string
	noBootstrap bool
	mailOff     bool
}

func newHarness(t *testing.T, options settings) *harness {
	t.Helper()
	url, name := pgtest.Database(t)
	group := name + "_runtime"
	build, err := migrate.Load(schema.Migrations())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	migration := pgtest.Connect(t, url)
	if _, err = migrate.Apply(ctx, migration, build, migrate.Options{Runner: "test", RuntimeRole: group}); err != nil {
		t.Fatal(err)
	}
	rotation, err := provision.Rotate(ctx, pgtest.Connect(t, url), provision.Options{Group: group, DirectURL: url, PooledHost: pgtest.Host(t), Runner: "test",
		ProbeTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, migration: migration, database: name, mail: mail.NewFake(), clock: &clock{now: time.Now().UTC()}, logs: &lockedBuffer{},
		secrets: &[]string{}}
	// A self-hosted center (the test database is a loopback server without TLS, which only self-hosted mode admits) behind a
	// trusted proxy on the loopback network, so each request states its client address in the Worker's header exactly as the
	// hosted Worker does.
	values := map[string]string{
		config.EnvMode: string(config.SelfHosted), config.EnvPublicBaseURL: publicBaseURL, config.EnvDatabaseURL: rotation.RuntimeURL,
		config.EnvSurfaces: "identity", config.EnvIdentityPolicy: options.policy, config.EnvClientIPHeader: config.ClientIPHeader,
		config.EnvTrustedProxies: "127.0.0.0/8,::1/128",
	}
	if options.surfaces != "" {
		values[config.EnvSurfaces] = options.surfaces
	}
	if !options.noBootstrap {
		secret := session.NewSecret()
		h.bootstrap = secret.Token(session.BootstrapPrefix)
		h.remember(h.bootstrap)
		digest := session.BootstrapDigest(h.bootstrap)
		values[config.EnvBootstrapSHA256] = hex.EncodeToString(digest[:])
		values[config.EnvBootstrapExpiresAt] = time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	}
	cfg, err := config.Load(func(key string) (string, bool) { value, ok := values[key]; return value, ok })
	if err != nil {
		t.Fatal(err)
	}
	var sender mail.Sender = h.mail
	if options.mailOff {
		sender = mail.Disabled{}
	}
	center, err := server.New(cfg, observe.NewLogger(h.logs, slog.LevelDebug), server.Options{Mail: sender, Clock: h.clock.Now,
		Background: func(work func()) { work() }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(center.Close)
	t.Cleanup(func() {
		if t.Failed() {
			for _, line := range strings.Split(h.logs.String(), "\n") {
				if strings.Contains(line, `"level":"ERROR"`) || strings.Contains(line, `"level":"WARN"`) {
					t.Log(line)
				}
			}
		}
	})
	listener := httptest.NewServer(center.Public())
	t.Cleanup(listener.Close)
	h.center, h.url = center, listener.URL
	return h
}

func (h *harness) remember(values ...string) {
	*h.secrets = append(*h.secrets, values...)
}

// reply is one gRPC-Web answer: the status trailer and the reply message, if any.
type reply struct {
	status  string
	message string
	body    []byte
	http    int
}

// caller is how a request authenticates and where it comes from.
type caller struct {
	ip      string
	bearer  string
	cookie  string
	csrf    string
	origin  string
	headers map[string]string
}

func (h *harness) post(path string, request proto.Message, from caller) reply {
	h.t.Helper()
	data, err := proto.Marshal(request)
	if err != nil {
		h.t.Fatal(err)
	}
	httpRequest, err := http.NewRequest(http.MethodPost, h.url+path, bytes.NewReader(ingress.Frame(data)))
	if err != nil {
		h.t.Fatal(err)
	}
	httpRequest.Header.Set("Content-Type", "application/grpc-web+proto")
	if from.ip == "" {
		from.ip = "203.0.113.10"
	}
	if from.ip != "none" {
		httpRequest.Header.Set(config.ClientIPHeader, from.ip)
	}
	if from.bearer != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+from.bearer)
	}
	if from.cookie != "" {
		httpRequest.Header.Set("Cookie", ingress.SessionCookieName+"="+from.cookie)
	}
	if from.csrf != "" {
		httpRequest.Header.Set(ingress.CSRFHeader, from.csrf)
	}
	if from.origin != "" {
		httpRequest.Header.Set("Origin", from.origin)
	}
	for name, value := range from.headers {
		httpRequest.Header.Set(name, value)
	}
	response, err := http.DefaultClient.Do(httpRequest)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	result := reply{http: response.StatusCode}
	for position := 0; position+5 <= len(body); {
		flag, length := body[position], int(binary.BigEndian.Uint32(body[position+1:position+5]))
		payload := body[position+5 : position+5+length]
		position += 5 + length
		if flag&0x80 != 0 {
			for _, line := range strings.Split(string(payload), "\r\n") {
				name, value, _ := strings.Cut(line, ":")
				switch strings.ToLower(strings.TrimSpace(name)) {
				case "grpc-status":
					result.status = strings.TrimSpace(value)
				case "grpc-message":
					result.message = strings.TrimSpace(value)
				}
			}
			continue
		}
		result.body = payload
	}
	return result
}

// rpc posts a request and decodes the reply message; the call must complete (grpc-status 0).
func rpc[Response proto.Message](h *harness, path string, request proto.Message, from caller, response Response) Response {
	h.t.Helper()
	answer := h.post(path, request, from)
	if answer.status != "0" || answer.body == nil {
		h.t.Fatalf("%s: grpc-status %q %q (HTTP %d)", path, answer.status, answer.message, answer.http)
	}
	if err := proto.Unmarshal(answer.body, response); err != nil {
		h.t.Fatal(err)
	}
	return response
}

// failure is the ArcError a reply carries, as CATEGORY/code.
func failure(value *foundationv1.ArcError) string {
	if value == nil {
		return ""
	}
	return strings.TrimPrefix(value.GetCategory().String(), "ERROR_CATEGORY_") + "/" + value.GetCode()
}

func meta() *foundationv1.RequestMeta { return &foundationv1.RequestMeta{} }

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return data
}

func newClaim(t *testing.T) *publicapiv1.InstallationClaim {
	return &publicapiv1.InstallationClaim{InstallationId: &foundationv1.Id{Value: randomBytes(t, 16)}, Product: proto.String("arcforges-mobile"),
		Platform: proto.String("android-15"), AppVersion: proto.String("1.0.0")}
}

// account is a seeded account and its virtual passkey.
type account struct {
	id            platform.ID
	handle        []byte
	authenticator *virtual.Authenticator
	key           *virtual.Key
	email         string
}

// seedAccount creates an account by the store (n1: accounts are never created from the API in A1a except by the bootstrap), with
// a passkey made by a virtual authenticator and verified by the relying party, and optionally an e-mail identity.
func (h *harness) seedAccount(state int16, email string) account {
	h.t.Helper()
	rp, err := passkey.New(rpID, origin)
	if err != nil {
		h.t.Fatal(err)
	}
	result := account{id: platform.NewID(), handle: randomBytes(h.t, 32), authenticator: virtual.New(rpID, origin), email: email}
	challenge := randomBytes(h.t, 32)
	creation, key := result.authenticator.Create(challenge, result.handle)
	credential, err := rp.VerifyCreation(challenge, result.handle, creation, time.Now().Add(time.Minute))
	if err != nil {
		h.t.Fatal(err)
	}
	result.key = key
	ctx := context.Background()
	// The account and its passkey are a second older than its address, so listings in creation order never fall back to the
	// random IDs.
	now := h.clock.Now()
	registered := now.Add(-time.Second)
	if _, err = h.migration.Exec(ctx, `INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev)
VALUES ($1, 'Seeded', $2, $3, $4, 1)`, result.id, state, result.handle, registered); err != nil {
		h.t.Fatal(err)
	}
	if _, err = h.migration.Exec(ctx, `INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, public_key, user_handle,
    sign_count, backup_eligible, backup_state, transports, aaguid, attestation_format, created_at, rev)
VALUES ($1, $2, 1, 'passkey', $3, $4, $5, 0, false, false, '{}', $6, 'none', $7, 1)`, platform.NewID(), result.id,
		base64.RawURLEncoding.EncodeToString(credential.ID), credential.PublicKey, result.handle, credential.AAGUID, registered); err != nil {
		h.t.Fatal(err)
	}
	if email != "" {
		if _, err = h.migration.Exec(ctx, `INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, created_at, rev)
VALUES ($1, $2, 2, 'email', $3, $4, 1)`, platform.NewID(), result.id, email, now); err != nil {
			h.t.Fatal(err)
		}
	}
	return result
}

// signIn signs an account in with its passkey through the API and returns the native session.
func (h *harness) signIn(who account, claim *publicapiv1.InstallationClaim, from caller) *publicapiv1.NativeSession {
	h.t.Helper()
	challenge := h.beginPasskey(claim, from)
	completed := rpc(h, "/arcforges.publicapi.v1.IdentityService/CompleteAuthentication", &publicapiv1.IdentityServiceCompleteAuthenticationRequest{
		Meta: meta(), FlowId: challenge.GetFlowId(), Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_Passkey{
			Passkey: assertionOf(who.authenticator.Assert(who.key, challenge.GetChallenge()))}},
	}, from, &publicapiv1.IdentityServiceCompleteAuthenticationResponse{})
	if completed.GetError() != nil {
		h.t.Fatalf("sign-in: %s", failure(completed.GetError()))
	}
	native := completed.GetValue().GetSession()
	h.remember(native.GetAccessToken(), native.GetRefreshToken())
	return native
}

func (h *harness) beginPasskey(claim *publicapiv1.InstallationClaim, from caller) *publicapiv1.AuthChallenge {
	h.t.Helper()
	begun := rpc(h, "/arcforges.publicapi.v1.IdentityService/BeginAuthentication", &publicapiv1.IdentityServiceBeginAuthenticationRequest{
		Meta: meta(), Method: publicapiv1.AuthMethod_AUTH_METHOD_PASSKEY.Enum(), Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_AUTHENTICATE.Enum(),
		Installation: claim,
	}, from, &publicapiv1.IdentityServiceBeginAuthenticationResponse{})
	if begun.GetError() != nil {
		h.t.Fatalf("begin: %s", failure(begun.GetError()))
	}
	return begun.GetValue().GetChallenge()
}

func assertionOf(value passkey.Assertion) *publicapiv1.WebAuthnAssertion {
	return &publicapiv1.WebAuthnAssertion{CredentialId: value.CredentialID, ClientDataJson: value.ClientDataJSON, AuthenticatorData: value.AuthenticatorData,
		Signature: value.Signature, UserHandle: value.UserHandle}
}

func creationOf(value passkey.Creation) *publicapiv1.WebAuthnCreation {
	return &publicapiv1.WebAuthnCreation{CredentialId: value.CredentialID, ClientDataJson: value.ClientDataJSON, AttestationObject: value.AttestationObject,
		Transports: value.Transports}
}

// count is the number of rows of a query, read as the migration role.
func (h *harness) count(query string, arguments ...any) int {
	h.t.Helper()
	var value int
	if err := h.migration.QueryRow(context.Background(), query, arguments...).Scan(&value); err != nil {
		h.t.Fatal(err)
	}
	return value
}

func (h *harness) audits(eventType string) int {
	return h.count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1", eventType)
}

func (h *harness) verifyAudit() {
	h.t.Helper()
	if _, err := platform.VerifyAudit(context.Background(), h.migration); err != nil {
		h.t.Fatal(err)
	}
}

func page(limit int32) *foundationv1.PageRequest {
	return &foundationv1.PageRequest{Limit: proto.Int32(limit)}
}
