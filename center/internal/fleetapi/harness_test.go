// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/mail"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/server"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// EVIDENCE: REAL PostgreSQL (the pinned image of the Linux leg), the real center (server.New: the ingress pipeline, the session
// verifier, the operation table, the fleet handlers) behind an httptest listener, gRPC-Web over HTTP; the node is MOCKED
// (center/internal/nodetest, a software ES256 key). Enrollment is SEEDED: fleet.Enroll is called directly in a transaction, because
// E1a serves no sign-in method (E1b and E2 do).

const publicBaseURL = "https://center.example.test/api"

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

type harness struct {
	t       *testing.T
	db      *dbtest.Database
	policy  config.IdentityPolicy
	client  nodetest.Client
	logs    *lockedBuffer
	metrics *server.Center
	secrets []string
	// inbox holds the messages the center sent (the e-mail step-up's code; MOCKED mail).
	inbox *inbox
}

// inbox is the MOCKED mail sender: it keeps every message the center sends.
type inbox struct {
	mu      sync.Mutex
	letters []mail.Message
}

func (i *inbox) Enabled() bool { return true }

func (i *inbox) Send(_ context.Context, message mail.Message) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.letters = append(i.letters, message)
	return nil
}

func (i *inbox) last() mail.Message {
	i.mu.Lock()
	defer i.mu.Unlock()
	if len(i.letters) == 0 {
		return mail.Message{}
	}
	return i.letters[len(i.letters)-1]
}

type settings struct {
	surfaces string
	policy   string
	disabled string
}

func newHarness(t *testing.T, options settings) *harness {
	t.Helper()
	db := dbtest.New(t)
	values := map[string]string{
		config.EnvMode: string(config.SelfHosted), config.EnvPublicBaseURL: publicBaseURL, config.EnvDatabaseURL: db.RuntimeURL,
		config.EnvSurfaces: "identity,pages,fleet", config.EnvIdentityPolicy: options.policy, config.EnvClientIPHeader: config.ClientIPHeader,
		config.EnvTrustedProxies: "127.0.0.0/8,::1/128", config.EnvDisabledFeatures: options.disabled,
	}
	if options.surfaces != "" {
		values[config.EnvSurfaces] = options.surfaces
	}
	cfg, err := config.Load(func(key string) (string, bool) { value, ok := values[key]; return value, ok })
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, db: db, policy: cfg.Identity.Policy, logs: &lockedBuffer{}, inbox: &inbox{}}
	center, err := server.New(cfg, observe.NewLogger(h.logs, slog.LevelDebug), server.Options{Mail: h.inbox, Background: func(work func()) { work() }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(center.Close)
	// F1: every fleet event the composed center counted during the test is a listed pair (observe.FleetOutcomes).
	t.Cleanup(func() {
		if unlisted := center.Metrics.Summary()["fleet "+observe.Unlisted+" "+observe.Unlisted]; unlisted != 0 {
			t.Errorf("the center counted %d fleet events outside the closed list", unlisted)
		}
	})
	listener := httptest.NewServer(center.Public())
	t.Cleanup(listener.Close)
	h.metrics = center
	h.client = nodetest.Client{URL: listener.URL, ClientIPHeader: config.ClientIPHeader}
	return h
}

// enrolled is a node with its credentials.
type enrolled struct {
	node     *nodetest.Node
	user     platform.ID
	approver dbtest.Session
	result   fleet.Enrolled
	access   string
	refresh  string
}

// enroll seeds an account (in the state given) and its approving browser session, and enrolls a new node through fleet.Enroll.
func (h *harness) enroll(state int16) *enrolled {
	h.t.Helper()
	user := h.db.Account(state)
	return h.enrollIn(user, h.db.Session(user, 1))
}

func (h *harness) enrollIn(user platform.ID, approver dbtest.Session) *enrolled {
	h.t.Helper()
	node, err := nodetest.New()
	if err != nil {
		h.t.Fatal(err)
	}
	result := h.enrollNode(user, approver, node)
	return &enrolled{node: node, user: user, approver: approver, result: result, access: result.Session.AccessToken, refresh: result.Session.RefreshToken}
}

func (h *harness) enrollNode(user platform.ID, approver dbtest.Session, node *nodetest.Node) fleet.Enrolled {
	h.t.Helper()
	info, err := fleet.ParseNodeInfo(node.Info())
	if err != nil {
		h.t.Fatal(err)
	}
	var result fleet.Enrolled
	if err = h.db.Runtime.InTx(context.Background(), "enroll", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		// The account must be Active to enroll; a restricted account's node is enrolled while Active and restricted afterwards.
		var err error
		result, err = fleet.Enroll(ctx, tx, h.policy, fleet.EnrollRequest{UserID: user, Approver: fleet.Approver{SessionID: approver.ID, AuthMethod: 1,
			AuthenticatedAt: time.Now().Add(-time.Minute)}, NodeID: node.ID, Node: info, PublicKey: node.PublicKey, Flow: fleet.FlowDevice}, time.Now())
		return err
	}); err != nil {
		h.t.Fatal(err)
	}
	h.secrets = append(h.secrets, result.Session.AccessToken, result.Session.RefreshToken)
	return result
}

func meta() *foundationv1.RequestMeta { return &foundationv1.RequestMeta{} }

func command() *foundationv1.RequestMeta {
	id := platform.NewID()
	return &foundationv1.RequestMeta{CommandId: &foundationv1.Id{Value: id[:]}}
}

const (
	refreshPath = "/arcforges.fleet.v1.NodeEnrollmentService/RefreshNodeSession"
	reportPath  = "/arcforges.fleet.v1.NodeEnrollmentService/ReportNodeInfo"
	signOutPath = "/arcforges.fleet.v1.NodeEnrollmentService/SignOutNode"
)

func (h *harness) post(path string, request proto.Message, bearer string) nodetest.Reply {
	h.t.Helper()
	reply, err := h.client.Post(path, request, bearer)
	if err != nil {
		h.t.Fatal(err)
	}
	return reply
}

// refresh posts RefreshNodeSession and returns the value or the refusal.
func (h *harness) refresh(token string) (*fleetv1.NodeEnrollmentServiceRefreshNodeSessionValue, *foundationv1.ArcError) {
	h.t.Helper()
	response, err := nodetest.Decode(h.post(refreshPath, &fleetv1.NodeEnrollmentServiceRefreshNodeSessionRequest{Meta: meta(), RefreshToken: proto.String(token)}, ""),
		&fleetv1.NodeEnrollmentServiceRefreshNodeSessionResponse{})
	if err != nil {
		h.t.Fatal(err)
	}
	if value := response.GetValue(); value != nil {
		h.secrets = append(h.secrets, value.GetAccessToken(), value.GetRefreshToken())
	}
	return response.GetValue(), response.GetError()
}

func (h *harness) report(bearer string, metaValue *foundationv1.RequestMeta, info *fleetv1.EnrollingNodeInfo) (*fleetv1.NodeEnrollmentServiceReportNodeInfoValue, *foundationv1.ArcError) {
	h.t.Helper()
	response, err := nodetest.Decode(h.post(reportPath, &fleetv1.NodeEnrollmentServiceReportNodeInfoRequest{Meta: metaValue, Node: info}, bearer),
		&fleetv1.NodeEnrollmentServiceReportNodeInfoResponse{})
	if err != nil {
		h.t.Fatal(err)
	}
	return response.GetValue(), response.GetError()
}

func (h *harness) signOut(bearer string, metaValue *foundationv1.RequestMeta) (*fleetv1.NodeEnrollmentServiceSignOutNodeValue, *foundationv1.ArcError) {
	h.t.Helper()
	response, err := nodetest.Decode(h.post(signOutPath, &fleetv1.NodeEnrollmentServiceSignOutNodeRequest{Meta: metaValue}, bearer),
		&fleetv1.NodeEnrollmentServiceSignOutNodeResponse{})
	if err != nil {
		h.t.Fatal(err)
	}
	return response.GetValue(), response.GetError()
}

// failure is a refusal as CATEGORY/code.
func failure(value *foundationv1.ArcError) string {
	if value == nil {
		return ""
	}
	return strings.TrimPrefix(value.GetCategory().String(), "ERROR_CATEGORY_") + "/" + value.GetCode()
}

func (h *harness) count(query string, arguments ...any) int { return h.db.Count(query, arguments...) }

func (h *harness) audits(eventType string) int {
	return h.count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1", eventType)
}

// payload is the JSON payload of the last audit event of a type.
func (h *harness) payload(eventType string) map[string]any {
	h.t.Helper()
	var data []byte
	if err := h.db.Migration.QueryRow(context.Background(), "SELECT payload FROM audit.audit_event WHERE event_type = $1 ORDER BY sequence DESC LIMIT 1", eventType).
		Scan(&data); err != nil {
		h.t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		h.t.Fatal(err)
	}
	return fields
}

// issue issues a native session of a scope for an account on a new device (the other credential kinds of the scope matrix).
func (h *harness) issue(user platform.ID, scope session.Scope) session.Native {
	h.t.Helper()
	device, installation := platform.NewID(), platform.NewID()
	h.db.Exec("INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev) VALUES ('" +
		device.String() + "', '" + user.String() + "', 'phone', 4, 1, false, now(), now(), 1)")
	h.db.Exec("INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, installed_at, last_active_at, rev) VALUES ('" +
		installation.String() + "', '" + device.String() + "', '" + user.String() + "', 'arcforges-mobile', '1.0.0', 'android', now(), now(), 1)")
	var issued session.Native
	if err := h.db.Runtime.InTx(context.Background(), "issue", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		issued, err = session.IssueNative(ctx, tx, h.policy, session.Grant{UserID: user, DeviceID: device, InstallationID: installation, Scope: scope,
			Product: "arcforges-mobile", Purpose: session.PurposeAuthenticate, AuthMethod: 1, AuthenticatedAt: time.Now()}, time.Now())
		return err
	}); err != nil {
		h.t.Fatal(err)
	}
	h.secrets = append(h.secrets, issued.AccessToken, issued.RefreshToken)
	return issued
}

// trackStatements creates pg_stat_statements in the test's database (the test server preloads the library, as the Linux leg's does)
// and returns a reader of the statements it recorded since; a read error fails the test, so a statement check can never pass because
// nothing was recorded.
func (h *harness) trackStatements() func() string {
	h.t.Helper()
	admin := pgtest.Connect(h.t, pgtest.WithDatabase(h.t, pgtest.ServerURL(h.t), h.db.Name))
	if _, err := admin.Exec(context.Background(), "CREATE EXTENSION IF NOT EXISTS pg_stat_statements"); err != nil {
		h.t.Fatalf("the test server must preload pg_stat_statements: %v", err)
	}
	return func() string {
		h.t.Helper()
		var statements string
		if err := admin.QueryRow(context.Background(), "SELECT coalesce(string_agg(query, E'\\n'), '') FROM pg_stat_statements").Scan(&statements); err != nil {
			h.t.Fatalf("read pg_stat_statements: %v", err)
		}
		if statements == "" {
			h.t.Fatal("pg_stat_statements recorded nothing")
		}
		return statements
	}
}
