// SPDX-License-Identifier: AGPL-3.0-only

package pages_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey/virtual"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/mail"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/provision"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/ArcForges/Cloud/center/internal/server"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store/migrate"
)

// The pages' integration tests drive a composed center (the real ingress pipeline, the page handler and the identity surface) over
// plain HTTP, against a real PostgreSQL, as the hosted Worker forwards a browser's request: the center sees the paths below the
// public base URL's /api prefix, and the request's client address in the Worker's header. They need ARCFORGES_TEST_POSTGRES_URL
// (the Linux leg sets it and ARCFORGES_TEST_POSTGRES_REQUIRED=1).

const (
	publicBaseURL = "https://center.example.test/api"
	origin        = "https://center.example.test"
	rpID          = "center.example.test"
	basePath      = "/api"
)

// clock is the center's adjustable clock; it starts at the real time and only moves forward.
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

// harness is one composed center over its own database.
type harness struct {
	t         *testing.T
	center    *server.Center
	url       string
	migration *pgx.Conn
	clock     *clock
	logs      *lockedBuffer
	mail      *mail.Fake
	// bootstrap is the owner bootstrap token of the configuration (generated at run time; only its digest is configuration).
	bootstrap string
	// secrets collects every credential the test saw, for the scans; setCookies every Set-Cookie header the center sent.
	secrets    []string
	setCookies []string
	// database is the test database's name; bodies are every reply body the center sent.
	database string
	bodies   [][]byte
}

// proved records the routes the package's tests have proved to succeed (a 2xx or 3xx reply to a POST of the route); TestMain fails a
// full run in which one POST route of the registration was never proved.
var (
	provedMu sync.Mutex
	proved   = map[string]bool{}
)

func recordProved(method, path string, status int) {
	if status >= 200 && status < 400 {
		provedMu.Lock()
		proved[method+" "+path] = true
		provedMu.Unlock()
	}
}

type settings struct {
	surfaces    string
	policy      string
	noBootstrap bool
}

const writePolicy = `{"stepUpPerAccountLimit": 1000, "signInFailuresAccountLimit": 1000, "signInPerPrefixLimit": 1000}`

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
	h := &harness{t: t, migration: migration, mail: mail.NewFake(), clock: &clock{now: time.Now().UTC()}, logs: &lockedBuffer{}, database: name}
	values := map[string]string{
		config.EnvMode: string(config.SelfHosted), config.EnvPublicBaseURL: publicBaseURL, config.EnvDatabaseURL: rotation.RuntimeURL,
		config.EnvSurfaces: "identity,pages", config.EnvIdentityPolicy: options.policy, config.EnvClientIPHeader: config.ClientIPHeader,
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
	center, err := server.New(cfg, observe.NewLogger(h.logs, slog.LevelDebug), server.Options{Mail: h.mail, Clock: h.clock.Now, Background: func(work func()) { work() }})
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

func (h *harness) remember(values ...string) { h.secrets = append(h.secrets, values...) }

// response is one reply of the center.
type response struct {
	status int
	header http.Header
	body   []byte
}

func (r response) text() string { return string(r.body) }

// cookie is the session cookie value a reply sets ("" when it sets none or removes it).
func (r response) cookie() string {
	for _, line := range r.header.Values("Set-Cookie") {
		if value, ok := strings.CutPrefix(line, routes.PageCookieName+"="); ok {
			handle, _, _ := strings.Cut(value, ";")
			return handle
		}
	}
	return ""
}

// json decodes the reply's body.
func (r response) json(t *testing.T, into any) {
	t.Helper()
	if err := json.Unmarshal(r.body, into); err != nil {
		t.Fatalf("not JSON (%d): %v: %.200s", r.status, err, r.body)
	}
}

// refusal is the {"error": ...} body of a refused JSON route: its category/code key.
func (r response) refusal(t *testing.T) string {
	t.Helper()
	var body struct {
		Error struct {
			Category string `json:"category"`
			Code     string `json:"code"`
		} `json:"error"`
	}
	r.json(t, &body)
	return body.Error.Category + "/" + body.Error.Code
}

// request is a request to the center.
type request struct {
	method      string
	path        string
	contentType string
	body        []byte
	cookie      string
	csrf        string
	origin      string
	ip          string
	headers     http.Header
	// noOrigin and noIP leave the header out.
	noOrigin bool
}

func (h *harness) do(r request) response {
	h.t.Helper()
	var reader io.Reader
	if r.body != nil {
		reader = bytes.NewReader(r.body)
	}
	httpRequest, err := http.NewRequest(r.method, h.url+r.path, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	if r.contentType != "" {
		httpRequest.Header.Set("Content-Type", r.contentType)
	}
	if r.cookie != "" {
		httpRequest.Header.Set("Cookie", routes.PageCookieName+"="+r.cookie)
	}
	if r.csrf != "" {
		httpRequest.Header.Set(ingress.CSRFHeader, r.csrf)
	}
	if r.method == http.MethodPost && !r.noOrigin {
		if r.origin == "" {
			r.origin = origin
		}
		httpRequest.Header.Set("Origin", r.origin)
	}
	if r.ip != "none" {
		if r.ip == "" {
			r.ip = "203.0.113.10"
		}
		httpRequest.Header.Set(config.ClientIPHeader, r.ip)
	}
	for name, values := range r.headers {
		httpRequest.Header[name] = values
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	reply, err := client.Do(httpRequest)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = reply.Body.Close() }()
	body, err := io.ReadAll(reply.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	result := response{status: reply.StatusCode, header: reply.Header, body: body}
	recordProved(r.method, r.path, reply.StatusCode)
	if pagePath(r.path) {
		requireSecurityHeaders(h.t, r.method+" "+r.path, result)
	}
	h.setCookies = append(h.setCookies, reply.Header.Values("Set-Cookie")...)
	h.bodies = append(h.bodies, body)
	if handle := result.cookie(); handle != "" {
		h.remember(handle, session.CSRF(mustHandle(h.t, handle)))
	}
	return result
}

func mustHandle(t *testing.T, text string) session.Secret {
	t.Helper()
	handle, ok := session.ParseHandle(text)
	if !ok {
		t.Fatalf("not a cookie handle: %q", text)
	}
	return handle
}

// browser is a browser's state: its cookie, the CSRF token it learned and its installation claim.
type browser struct {
	h            *harness
	cookie       string
	csrf         string
	installation string
	userAgent    string
	ip           string
}

func (h *harness) newBrowser() *browser {
	id := platform.NewID()
	return &browser{h: h, installation: uuid(id), userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"}
}

func uuid(id platform.ID) string {
	text := hex.EncodeToString(id[:])
	return text[:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:]
}

func (b *browser) headers() http.Header {
	return http.Header{"User-Agent": {b.userAgent}}
}

// get is a GET with the browser's cookie.
func (b *browser) get(path string) response {
	b.h.t.Helper()
	return b.h.do(request{method: http.MethodGet, path: path, cookie: b.cookie, ip: b.ip, headers: b.headers()})
}

// postJSON is a JSON POST with the browser's cookie and CSRF token.
func (b *browser) postJSON(path string, body any) response {
	b.h.t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		b.h.t.Fatal(err)
	}
	return b.h.do(request{method: http.MethodPost, path: path, contentType: "application/json", body: data, cookie: b.cookie, csrf: b.csrf, ip: b.ip, headers: b.headers()})
}

// postEmpty is a POST without a body (the sign-out).
func (b *browser) postEmpty(path string) response {
	b.h.t.Helper()
	return b.h.do(request{method: http.MethodPost, path: path, cookie: b.cookie, csrf: b.csrf, ip: b.ip, headers: b.headers()})
}

// postForm is a form POST with the browser's cookie and the csrf field.
func (b *browser) postForm(path string, fields url.Values) response {
	b.h.t.Helper()
	if fields.Get("csrf") == "" {
		fields.Set("csrf", b.csrf)
	}
	return b.h.do(request{method: http.MethodPost, path: path, contentType: "application/x-www-form-urlencoded", body: []byte(fields.Encode()), cookie: b.cookie,
		ip: b.ip, headers: b.headers()})
}

// bootstrapState reads the bootstrap route and keeps its CSRF token.
func (b *browser) bootstrapState() bootstrapReply {
	b.h.t.Helper()
	reply := b.get("/session/v1/web/bootstrap")
	if reply.status != 200 {
		b.h.t.Fatalf("bootstrap: %d %s", reply.status, reply.text())
	}
	var state bootstrapReply
	reply.json(b.h.t, &state)
	b.csrf = state.CSRFToken
	b.h.remember(state.CSRFToken)
	return state
}

type bootstrapReply struct {
	CSRFToken     string `json:"csrfToken"`
	Authenticated bool   `json:"authenticated"`
	Session       *struct {
		SessionID          string   `json:"sessionId"`
		ExpiresAt          string   `json:"expiresAt"`
		IdleExpiresAt      string   `json:"idleExpiresAt"`
		UserID             string   `json:"userId"`
		DeviceID           string   `json:"deviceId"`
		WorkspaceIDs       []string `json:"workspaceIds"`
		RecoveryGeneration string   `json:"recoveryGeneration"`
		Purpose            string   `json:"purpose"`
	} `json:"session"`
	Profile *struct {
		DisplayName string `json:"displayName"`
		Locale      string `json:"locale"`
		Timezone    string `json:"timezone"`
		Revision    string `json:"revision"`
	} `json:"profile"`
}

type challengeReply struct {
	FlowID    string `json:"flowId"`
	Method    string `json:"method"`
	Challenge string `json:"challenge"`
	RPID      string `json:"rpId"`
	ExpiresAt string `json:"expiresAt"`
	Options   *struct {
		RPID                string   `json:"rpId"`
		UserHandle          string   `json:"userHandle"`
		AllowedCredentials  []string `json:"allowedCredentials"`
		ExcludedCredentials []string `json:"excludedCredentials"`
		UserVerification    string   `json:"userVerification"`
		Algorithms          []int    `json:"algorithms"`
	} `json:"options"`
	ProviderID string `json:"providerId"`
	Purpose    string `json:"purpose"`
}

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func unb64(t *testing.T, text string) []byte {
	t.Helper()
	data, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// claim is the browser's WebBrowserInstallationClaim.
func (b *browser) claim() map[string]any {
	return map[string]any{"installationId": b.installation, "product": "arcforges-web", "platform": "web", "appVersion": "pages-1"}
}

func assertionJSON(value passkey.Assertion) map[string]any {
	return map[string]any{"credentialId": b64(value.CredentialID), "clientDataJson": b64(value.ClientDataJSON), "authenticatorData": b64(value.AuthenticatorData),
		"signature": b64(value.Signature), "userHandle": b64(value.UserHandle)}
}

func creationJSON(value passkey.Creation) map[string]any {
	transports := value.Transports
	if transports == nil {
		transports = []string{}
	}
	return map[string]any{"credentialId": b64(value.CredentialID), "clientDataJson": b64(value.ClientDataJSON), "attestationObject": b64(value.AttestationObject),
		"transports": transports}
}

// account is a seeded account and its virtual passkey.
type account struct {
	id            platform.ID
	handle        []byte
	authenticator *virtual.Authenticator
	key           *virtual.Key
}

// seedAccount creates an account by the store, with a passkey made by a virtual authenticator and verified by the relying party.
func (h *harness) seedAccount(state int16) account {
	h.t.Helper()
	rp, err := passkey.New(rpID, origin)
	if err != nil {
		h.t.Fatal(err)
	}
	result := account{id: platform.NewID(), handle: randomBytes(h.t, 32), authenticator: virtual.New(rpID, origin)}
	challenge := randomBytes(h.t, 32)
	creation, key := result.authenticator.Create(challenge, result.handle)
	credential, err := rp.VerifyCreation(challenge, result.handle, creation, time.Now().Add(time.Minute))
	if err != nil {
		h.t.Fatal(err)
	}
	result.key = key
	ctx := context.Background()
	registered := h.clock.Now().Add(-time.Second)
	if _, err = h.migration.Exec(ctx, `INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev)
VALUES ($1, 'Seeded', $2, $3, $4, 1)`, result.id, state, result.handle, registered); err != nil {
		h.t.Fatal(err)
	}
	if _, err = h.migration.Exec(ctx, `INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, label, public_key, user_handle,
    sign_count, backup_eligible, backup_state, transports, aaguid, attestation_format, created_at, rev)
VALUES ($1, $2, 1, 'passkey', $3, 'Seeded key', $4, $5, 0, false, false, '{}', $6, 'none', $7, 1)`, platform.NewID(), result.id,
		base64.RawURLEncoding.EncodeToString(credential.ID), credential.PublicKey, result.handle, credential.AAGUID, registered); err != nil {
		h.t.Fatal(err)
	}
	return result
}

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return data
}

// signIn signs an account in through the pages' routes and returns the reply of the completion; the browser keeps the cookie and
// the session's CSRF token on success.
func (b *browser) signIn(who account) response {
	b.h.t.Helper()
	b.bootstrapState()
	begun := b.postJSON("/session/v1/web/authentication/begin", map[string]any{"method": "passkey", "purpose": "authenticate", "installation": b.claim()})
	if begun.status != 200 {
		return begun
	}
	var challenge challengeReply
	begun.json(b.h.t, &challenge)
	completed := b.postJSON("/session/v1/web/authentication/complete", map[string]any{"flowId": challenge.FlowID,
		"proof": map[string]any{"passkey": assertionJSON(who.authenticator.Assert(who.key, unb64(b.h.t, challenge.Challenge)))}})
	if completed.status == 200 {
		b.cookie = completed.cookie()
		b.bootstrapState()
	}
	return completed
}

// mustSignIn signs in and fails the test unless it succeeds.
func (b *browser) mustSignIn(who account) {
	b.h.t.Helper()
	if reply := b.signIn(who); reply.status != 200 {
		b.h.t.Fatalf("sign-in: %d %s", reply.status, reply.text())
	}
}

// stepUp proves a passkey step-up for a class and target through the pages' routes.
func (b *browser) stepUp(who account, class string, target platform.ID) response {
	b.h.t.Helper()
	begun := b.postJSON("/session/v1/web/step-up/begin", map[string]any{"operationClass": class, "method": "passkey",
		"targetHash": hashOf(class, who.id, target)})
	if begun.status != 200 {
		return begun
	}
	var challenge challengeReply
	begun.json(b.h.t, &challenge)
	return b.postJSON("/session/v1/web/step-up/complete", map[string]any{"flowId": challenge.FlowID,
		"proof": map[string]any{"passkey": assertionJSON(who.authenticator.Assert(who.key, unb64(b.h.t, challenge.Challenge)))}})
}

func (b *browser) mustStepUp(who account, class string, target platform.ID) {
	b.h.t.Helper()
	if reply := b.stepUp(who, class, target); reply.status != 200 {
		b.h.t.Fatalf("step-up of %s: %d %s", class, reply.status, reply.text())
	}
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

// sessionIDs are the sessions of an account, newest first, live or not.
func (h *harness) sessionRows(userID platform.ID) []platform.ID {
	h.t.Helper()
	rows, err := h.migration.Query(context.Background(), "SELECT session_id FROM identity.session WHERE user_id = $1 ORDER BY issued_at DESC, session_id", userID)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	var ids []platform.ID
	for rows.Next() {
		var id platform.ID
		if err = rows.Scan(&id); err != nil {
			h.t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return ids
}

// live reports whether a session is live (not revoked).
func (h *harness) live(sessionID platform.ID) bool {
	return h.count("SELECT count(*) FROM identity.session WHERE session_id = $1 AND revoked_at IS NULL", sessionID) == 1
}

var cookiePattern = regexp.MustCompile(`^__Host-af_session=[A-Za-z0-9_-]{43}; Path=/; Max-Age=[1-9][0-9]*; Secure; HttpOnly; SameSite=Strict$`)

func itoa(value int) string { return strconv.Itoa(value) }

// hashOf is the step-up target hash of a class, an account and a target object.
func hashOf(class string, accountID, target platform.ID) string {
	return identity.TargetHash(class, accountID, target)
}

// The API side: a binary gRPC-Web call to the same center, as a native client makes it, for the tests that show the pages and the
// API share a rule (the rate-limit buckets, the flows' channels).

// apiReply is a gRPC-Web reply: the trailers' status and the data frame.
type apiReply struct {
	status  string
	message string
	body    []byte
}

func (h *harness) api(path string, message proto.Message, ip string) apiReply {
	h.t.Helper()
	data, err := proto.Marshal(message)
	if err != nil {
		h.t.Fatal(err)
	}
	if ip == "" {
		ip = "203.0.113.10"
	}
	reply := h.do(request{method: http.MethodPost, path: path, contentType: "application/grpc-web+proto", body: ingress.Frame(data), ip: ip, noOrigin: true})
	result := apiReply{}
	body := reply.body
	for len(body) >= 5 {
		length := int(binary.BigEndian.Uint32(body[1:5]))
		if len(body) < 5+length {
			break
		}
		payload := body[5 : 5+length]
		if body[0]&0x80 != 0 {
			for _, line := range strings.Split(string(payload), "\r\n") {
				name, value, _ := strings.Cut(line, ":")
				switch strings.ToLower(strings.TrimSpace(name)) {
				case "grpc-status":
					result.status = strings.TrimSpace(value)
				case "grpc-message":
					result.message = strings.TrimSpace(value)
				}
			}
		} else {
			result.body = payload
		}
		body = body[5+length:]
	}
	return result
}

// apiBegin begins a native passkey authentication; the reply's refusal key is "" on success.
func (h *harness) apiBegin(ip string) (*publicapiv1.AuthChallenge, string) {
	h.t.Helper()
	id := platform.NewID()
	reply := h.api("/arcforges.publicapi.v1.IdentityService/BeginAuthentication", &publicapiv1.IdentityServiceBeginAuthenticationRequest{
		Meta: &foundationv1.RequestMeta{}, Method: publicapiv1.AuthMethod_AUTH_METHOD_PASSKEY.Enum(), Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_AUTHENTICATE.Enum(),
		Installation: &publicapiv1.InstallationClaim{InstallationId: &foundationv1.Id{Value: id[:]}, Product: proto.String("arcforges-mobile"),
			Platform: proto.String("android-15"), AppVersion: proto.String("1.0.0")}}, ip)
	if reply.status != "0" || reply.body == nil {
		h.t.Fatalf("the API begin: %q %q", reply.status, reply.message)
	}
	var response publicapiv1.IdentityServiceBeginAuthenticationResponse
	if err := proto.Unmarshal(reply.body, &response); err != nil {
		h.t.Fatal(err)
	}
	if failure := response.GetError(); failure != nil {
		return nil, strings.TrimPrefix(failure.GetCategory().String(), "ERROR_CATEGORY_") + "/" + failure.GetCode()
	}
	return response.GetValue().GetChallenge(), ""
}
