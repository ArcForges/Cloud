// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/hub"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/server"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The node channel's integration harness (EVIDENCE: REAL PostgreSQL, the composed center with its real ingress, session verifier,
// authorizer, controls and gate, the real WebSocket server; MOCKED: the node, nodetest's channel client with a software key).

const publicBaseURL = "https://center.example.test/api"

type lockedBuffer struct {
	mu   sync.Mutex
	text bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.text.Write(data)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.text.String()
}

type harness struct {
	t       *testing.T
	db      *dbtest.Database
	policy  config.IdentityPolicy
	center  *server.Center
	url     string
	logs    *lockedBuffer
	secrets []string
	// kid is the test's command key.
	kid string
}

type settings struct {
	mode     config.Mode
	plan     config.PlanConfiguration
	surfaces string
	policy   string
	disabled string
	tune     func(*hub.Settings)
}

// testSettings are short intervals for the tests.
func testSettings() hub.Settings {
	return hub.Settings{HelloDeadline: time.Second, Heartbeat: 100 * time.Millisecond, HeartbeatDeadline: 600 * time.Millisecond, PresenceInterval: time.Hour,
		SessionRecheck: time.Hour, LapseRecheck: time.Hour, TokenGrace: 300 * time.Millisecond, MaxFrameBytes: 1 << 20, InboundFramesPerSecond: 200,
		MaxInFlightCalls: 8, MaxRelayNonces: 8, TokenRefreshInterval: 30 * time.Second, SendQueueFrames: 64, SendQueueBytes: 4 << 20, WriteTimeout: time.Second, LeaseTTL: 30 * time.Second,
		LeaseRenew: time.Second, ReconnectMin: time.Second, ReconnectMax: 2 * time.Second}
}

func newHarness(t *testing.T, options settings) *harness {
	t.Helper()
	db := dbtest.New(t)
	values := map[string]string{
		config.EnvMode: string(config.SelfHosted), config.EnvPublicBaseURL: publicBaseURL, config.EnvDatabaseURL: db.RuntimeURL,
		config.EnvSurfaces: "identity,pages,fleet,relay", config.EnvIdentityPolicy: options.policy, config.EnvClientIPHeader: config.ClientIPHeader,
	}
	if options.disabled != "" {
		values[config.EnvDisabledFeatures] = options.disabled
	}
	values[config.EnvTrustedProxies] = "127.0.0.0/8,::1/128"
	if options.surfaces != "" {
		values[config.EnvSurfaces] = options.surfaces
	}
	cfg, err := config.Load(func(key string) (string, bool) { value, ok := values[key]; return value, ok })
	if err != nil {
		t.Fatal(err)
	}
	if options.mode == config.OfficialHosted {
		// The official hosted center requires a verified TLS connection to its database, which the test server does not offer: the
		// configuration is loaded as a self-hosted one and then made the hosted center's (as the pages' harness does).
		cfg.Mode, cfg.Plan, cfg.DisabledFeatures = config.OfficialHosted, options.plan, nil
	}
	// A throwaway command key per test (AF-CTR-05 E1a: the relay surface needs one whose private half is loaded).
	key, kid := db.CommandKey("ARCFORGES_CENTER_KEY_TEST")
	if err := cfg.ApplyCommandKeys([]config.CommandKey{key}); err != nil {
		t.Fatal(err)
	}
	tuned := testSettings()
	if options.tune != nil {
		options.tune(&tuned)
	}
	h := &harness{t: t, db: db, policy: cfg.Identity.Policy, logs: &lockedBuffer{}}
	center, err := server.New(cfg, observe.NewLogger(h.logs, slog.LevelDebug), server.Options{Hub: &tuned, Background: func(work func()) { work() }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(center.Close)
	h.center = center
	h.kid = kid
	if center.Hub != nil {
		if err := center.CheckCommandKeys(context.Background()); err != nil {
			t.Fatal(err)
		}
		center.Hub.Start(context.Background())
		t.Cleanup(func() {
			stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			center.Hub.Stop(stop)
		})
	}
	listener := httptest.NewServer(center.Public())
	t.Cleanup(listener.Close)
	h.url = listener.URL
	t.Cleanup(func() {
		// No log line carries a token (the center logs no credential, AGENTS.md).
		for _, secret := range h.secrets {
			if strings.Contains(h.logs.String(), secret) {
				t.Error("a log line carries a credential")
			}
		}
		if unlisted := center.Metrics.Summary()["channel "+observe.Unlisted+" "+observe.Unlisted]; unlisted != 0 {
			t.Errorf("the center counted %d channel events outside the closed list", unlisted)
		}
	})
	return h
}

// enrolled is a node with its credentials.
type enrolled struct {
	node   *nodetest.Node
	user   platform.ID
	result fleet.Enrolled
	access string
}

// enroll seeds an account and enrolls a new node through fleet.Enroll.
func (h *harness) enroll() *enrolled {
	h.t.Helper()
	user := h.db.Account(1)
	return h.enrollIn(user)
}

func (h *harness) enrollIn(user platform.ID) *enrolled {
	h.t.Helper()
	approver := h.db.Session(user, 1)
	node, err := nodetest.New()
	if err != nil {
		h.t.Fatal(err)
	}
	info, err := fleet.ParseNodeInfo(node.Info())
	if err != nil {
		h.t.Fatal(err)
	}
	var result fleet.Enrolled
	if err = h.db.Runtime.InTx(context.Background(), "enroll", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		result, err = fleet.Enroll(ctx, tx, h.policy, fleet.EnrollRequest{UserID: user, Approver: fleet.Approver{SessionID: approver.ID, AuthMethod: 1,
			AuthenticatedAt: time.Now().Add(-time.Minute)}, NodeID: node.ID, Node: info, PublicKey: node.PublicKey, Flow: fleet.FlowDevice}, time.Now())
		return err
	}); err != nil {
		h.t.Fatal(err)
	}
	h.secrets = append(h.secrets, result.Session.AccessToken, result.Session.RefreshToken)
	return &enrolled{node: node, user: user, result: result, access: result.Session.AccessToken}
}

// dial opens a channel with a bearer and the Worker's client address header.
func (h *harness) dial(bearer string, extra http.Header) (*nodetest.Channel, error) {
	header := http.Header{config.ClientIPHeader: {"198.51.100.7"}}
	for name, values := range extra {
		header[name] = values
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return nodetest.Dial(ctx, h.url, nodetest.DialOptions{Bearer: bearer, Header: header})
}

// connect opens a channel for a node and proves its hello; the channel is accepted.
func (h *harness) connect(node *enrolled) *nodetest.Channel {
	h.t.Helper()
	channel, err := h.dial(node.access, nil)
	if err != nil {
		h.t.Fatalf("dial: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := channel.Hello(ctx, node.node, node.result.InstallationID, publicBaseURL); err != nil {
		h.t.Fatal(err)
	}
	if _, err := channel.Accept(ctx); err != nil {
		h.t.Fatalf("accept: %v", err)
	}
	h.t.Cleanup(func() { _ = channel.WS.CloseNow() })
	return channel
}

// answer keeps a channel alive in the background (answers every heartbeat) until it closes, and returns how it closed.
func answer(channel *nodetest.Channel) <-chan nodetest.Closed {
	done := make(chan nodetest.Closed, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		done <- channel.AwaitClose(ctx, true)
	}()
	return done
}

// closedWithin waits for a channel's close.
func closedWithin(t *testing.T, closed <-chan nodetest.Closed, within time.Duration) nodetest.Closed {
	t.Helper()
	select {
	case result := <-closed:
		return result
	case <-time.After(within):
		t.Fatal("the channel did not close")
	}
	return nodetest.Closed{}
}

// open reports whether a channel stays open for a while.
func stillOpen(closed <-chan nodetest.Closed, during time.Duration) bool {
	select {
	case <-closed:
		return false
	case <-time.After(during):
		return true
	}
}

// refusal reads a refused upgrade's status, reason header and JSON error.
type refusal struct {
	status int
	reason string
	retry  string
	body   map[string]any
}

func refusalOf(t *testing.T, channel *nodetest.Channel, err error) refusal {
	t.Helper()
	if err == nil || channel == nil || channel.Response == nil {
		t.Fatalf("the upgrade was not refused: %v", err)
	}
	result := refusal{status: channel.Response.StatusCode, reason: channel.Response.Header.Get("ArcForges-Refusal"), retry: channel.Response.Header.Get("Retry-After")}
	data, _ := io.ReadAll(channel.Response.Body)
	var body struct {
		Error map[string]any `json:"error"`
	}
	if json.Unmarshal(data, &body) == nil {
		result.body = body.Error
	}
	return result
}

func (h *harness) count(query string, arguments ...any) int { return h.db.Count(query, arguments...) }

func (h *harness) audits(eventType string) int {
	return h.count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1", eventType)
}

// eventually polls a condition.
func eventually(t *testing.T, within time.Duration, condition func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return condition()
}
