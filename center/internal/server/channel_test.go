// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
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
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The node channel on the composed server (AF-CTR-05 E1a, Plan PN-1, CTR5-HUB-12; EVIDENCE: REAL composed center, REAL http.Server
// with the center's own timeouts and connection bounds, REAL PostgreSQL; MOCKED: the node, nodetest's channel client).

// channelCenter composes a self-hosted center with the relay surface and serves it on a real listener with the center's server and
// bounds; requests and nodes are the slot counts.
func channelCenter(t *testing.T, requests, nodes int, settings hub.Settings) (*Center, *dbtest.Database, string) {
	t.Helper()
	db := dbtest.New(t)
	values := map[string]string{
		config.EnvMode: string(config.SelfHosted), config.EnvPublicBaseURL: "https://center.example.test/api", config.EnvDatabaseURL: db.RuntimeURL,
		config.EnvSurfaces: "identity,pages,fleet,relay",
	}
	cfg, err := config.Load(func(key string) (string, bool) { value, found := values[key]; return value, found })
	if err != nil {
		t.Fatal(err)
	}
	key, _ := db.CommandKey("ARCFORGES_CENTER_KEY_TEST")
	if err := cfg.ApplyCommandKeys([]config.CommandKey{key}); err != nil {
		t.Fatal(err)
	}
	logger := observe.NewLogger(io.Discard, slog.LevelInfo)
	center, err := New(cfg, logger, Options{Hub: &settings})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(center.Close)
	if center.Hub == nil {
		t.Fatal("the relay surface composed no hub")
	}
	if err := center.CheckCommandKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	center.Hub.Start(context.Background())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := newPublicServer(center.Public(), true, logger)
	go func() { _ = server.Serve(listen(listener, requests, nodes)) }()
	t.Cleanup(func() { center.stopServing([]*http.Server{server}, 5*time.Second) })
	return center, db, "http://" + listener.Addr().String()
}

// enrollNode enrolls a node through fleet.Enroll and returns it with its access token and installation.
func enrollNode(t *testing.T, db *dbtest.Database) (*nodetest.Node, string, fleet.Enrolled) {
	t.Helper()
	user := db.Account(1)
	approver := db.Session(user, 1)
	node, err := nodetest.New()
	if err != nil {
		t.Fatal(err)
	}
	info, err := fleet.ParseNodeInfo(node.Info())
	if err != nil {
		t.Fatal(err)
	}
	var result fleet.Enrolled
	if err = db.Runtime.InTx(context.Background(), "enroll", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		result, err = fleet.Enroll(ctx, tx, config.DefaultIdentityPolicy(), fleet.EnrollRequest{UserID: user, Approver: fleet.Approver{SessionID: approver.ID,
			AuthMethod: 1, AuthenticatedAt: time.Now().Add(-time.Minute)}, NodeID: node.ID, Node: info, PublicKey: node.PublicKey, Flow: fleet.FlowDevice}, time.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return node, result.Session.AccessToken, result
}

func channelSettings() hub.Settings {
	settings := hub.SettingsOf(config.DefaultIdentityPolicy())
	settings.Heartbeat, settings.HeartbeatDeadline = time.Second, 3*time.Second
	return settings
}

// TestTheServersDeadlinesNeverCutAnUpgradedChannel is PN-1 (mutation "the server write deadline cutting an upgraded connection"): on the
// composed server with its real 20-second read and write timeouts, a node channel lives past both, its heartbeats flowing in both
// directions, because the upgrade clears the deadlines the server set before the hijack.
func TestTheServersDeadlinesNeverCutAnUpgradedChannel(t *testing.T) {
	if testing.Short() {
		t.Skip("a 24-second channel")
	}
	t.Parallel()
	_, db, url := channelCenter(t, 64, 256, channelSettings())
	node, access, enrolled := enrollNode(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	channel, err := nodetest.Dial(ctx, url, nodetest.DialOptions{Bearer: access})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = channel.WS.CloseNow() }()
	if err := channel.Hello(ctx, node, enrolled.InstallationID, "https://center.example.test/api"); err != nil {
		t.Fatal(err)
	}
	if _, err := channel.Accept(ctx); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(readTimeout + 4*time.Second)
	beats := 0
	for time.Now().Before(until) {
		frame, err := channel.Next(ctx)
		if err != nil {
			t.Fatalf("the channel ended after %d heartbeats: %v", beats, err)
		}
		if beat := frame.GetHeartbeat(); beat != nil {
			beats++
			if err := channel.Heartbeat(ctx, beat.GetSeq()); err != nil {
				t.Fatalf("the node's heartbeat after %d: %v", beats, err)
			}
		}
		if frame.GetClose() != nil {
			t.Fatalf("closed after %d heartbeats: %v", beats, frame.GetClose())
		}
	}
	// A heartbeat about every second (the supervisor's tick adds a little), so more than fifteen in the 24 seconds.
	if beats < 15 {
		t.Fatalf("%d heartbeats in %s", beats, readTimeout+4*time.Second)
	}
}

// TestAnUpgradedChannelLeavesTheRequestBound (PN-1, CTR5-HUB-12): with one request slot, an open channel gives its slot back once
// admitted, so requests are still served; with every node slot held, the next upgrade is refused 503 before it is upgraded.
func TestAnUpgradedChannelLeavesTheRequestBound(t *testing.T) {
	_, db, url := channelCenter(t, 1, 1, channelSettings())
	node, access, enrolled := enrollNode(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	channel, err := nodetest.Dial(ctx, url, nodetest.DialOptions{Bearer: access})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = channel.WS.CloseNow() }()
	if err := channel.Hello(ctx, node, enrolled.InstallationID, "https://center.example.test/api"); err != nil {
		t.Fatal(err)
	}
	if _, err := channel.Accept(ctx); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	for range 3 {
		response, err := client.Get(url + routes.HealthPath)
		if err != nil {
			t.Fatalf("a request while a channel holds the only node slot: %v", err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("health: %d", response.StatusCode)
		}
	}
	_, secondAccess, _ := enrollNode(t, db)
	refused, err := nodetest.Dial(ctx, url, nodetest.DialOptions{Bearer: secondAccess})
	if err == nil || refused.Response == nil || refused.Response.StatusCode != http.StatusServiceUnavailable ||
		!strings.HasPrefix(refused.Response.Header.Get(routes.RefusalHeader), "RESOURCE/") {
		t.Fatalf("an upgrade with every node slot held: %v", err)
	}
}

// relayCenter composes (without serving) a self-hosted center with the relay surface and the command keys given.
func relayCenter(t *testing.T, db *dbtest.Database, logs io.Writer, keys ...config.CommandKey) *Center {
	t.Helper()
	values := map[string]string{
		config.EnvMode: string(config.SelfHosted), config.EnvPublicBaseURL: "https://center.example.test/api", config.EnvDatabaseURL: db.RuntimeURL,
		config.EnvSurfaces: "identity,pages,fleet,relay",
	}
	cfg, err := config.Load(func(key string) (string, bool) { value, found := values[key]; return value, found })
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.ApplyCommandKeys(keys); err != nil {
		t.Fatal(err)
	}
	center, err := New(cfg, observe.NewLogger(logs, slog.LevelDebug), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(center.Close)
	return center
}

// TestAFailedHandshakeGivesTheNodeSlotBack is review B N-6: the node slot is taken before websocket.Accept, so an upgrade whose
// handshake fails there (here: a browser Origin the library refuses) moves its connection back to a request slot; its HTTP/1.1
// connection stays open, and the one node slot is free for a node's channel.
func TestAFailedHandshakeGivesTheNodeSlotBack(t *testing.T) {
	center, db, url := channelCenter(t, 4, 1, channelSettings())
	_, access, _ := enrollNode(t, db)
	connection, err := net.Dial("tcp", strings.TrimPrefix(url, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	request := "GET /fleet/v1/node HTTP/1.1\r\nHost: " + strings.TrimPrefix(url, "http://") + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + base64.StdEncoding.EncodeToString([]byte("the sample nonce")) + "\r\nSec-WebSocket-Protocol: arcforges.relay.v1\r\n" +
		"Origin: https://elsewhere.example\r\nAuthorization: Bearer " + access + "\r\n\r\n"
	if _, err := connection.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode == http.StatusSwitchingProtocols || response.Close {
		t.Fatalf("the handshake with a foreign Origin: %d (close %v)", response.StatusCode, response.Close)
	}
	if center.Metrics.ChannelCount("refused", "handshake") != 1 {
		t.Fatal("the failed handshake was not counted")
	}
	node, second, enrolled := enrollNode(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	channel, err := nodetest.Dial(ctx, url, nodetest.DialOptions{Bearer: second})
	if err != nil {
		t.Fatalf("a channel while a failed handshake's connection is still open: %v", err)
	}
	defer func() { _ = channel.WS.CloseNow() }()
	if err := channel.Hello(ctx, node, enrolled.InstallationID, "https://center.example.test/api"); err != nil {
		t.Fatal(err)
	}
	if _, err := channel.Accept(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestStartRefusesAMismatchedOrMissingCommandKey is E1-15 (CTR5-SIG-02, CTR5-KEY-01, moved into E1a): a center that serves the relay
// surface starts only with a valid command key whose private half it loaded. A loaded key that no valid row names refuses the start, as
// does a loaded key whose row registers another public half (the error names the binding and the kid, never the key); with its row
// matching, the start passes and ChannelAccepted will list the kid.
func TestStartRefusesAMismatchedOrMissingCommandKey(t *testing.T) {
	db := dbtest.New(t)
	// A key that no row names.
	stray, _ := dbtest.RegisterCommandKey(t, db.Migration, "ARCFORGES_CENTER_KEY_STRAY")
	db.Exec("DELETE FROM fleet.signing_key WHERE secret_binding = 'ARCFORGES_CENTER_KEY_STRAY'")
	if err := relayCenter(t, db, io.Discard, stray).CheckCommandKeys(t.Context()); err == nil || !strings.Contains(err.Error(), "ARCFORGES_CENTER_KEY_STRAY") {
		t.Fatalf("a key no row names: %v", err)
	}
	// A row whose public half is another key's.
	registered, kid := dbtest.RegisterCommandKey(t, db.Migration, "ARCFORGES_CENTER_KEY_MAIN")
	other, _ := dbtest.RegisterCommandKey(t, db.Migration, "ARCFORGES_CENTER_KEY_OTHER")
	mismatched, err := config.NewCommandKey("ARCFORGES_CENTER_KEY_MAIN", other.Signer())
	if err != nil {
		t.Fatal(err)
	}
	err = relayCenter(t, db, io.Discard, mismatched).CheckCommandKeys(t.Context())
	if err == nil || !strings.Contains(err.Error(), "ARCFORGES_CENTER_KEY_MAIN") || !strings.Contains(err.Error(), kid) || strings.Contains(err.Error(), scalarHex(t, other)) {
		t.Fatalf("a key whose row registers another public half: %v", err)
	}
	// The matching key.
	center := relayCenter(t, db, io.Discard, registered)
	if err := center.CheckCommandKeys(t.Context()); err != nil {
		t.Fatalf("the matching key: %v", err)
	}
	// A successor row of the same binding whose not_before lies ahead and whose public half is another key's (review A N-6): the
	// loaded key is not that row's, so the start refuses before a rotation could adopt it.
	now := time.Now()
	successor := "test-" + platform.NewID().String()[:12]
	tx, err := db.Migration.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.RegisterKey(t.Context(), tx, platform.SigningKey{KID: successor, Purpose: platform.CommandSigning, Algorithm: "ES256",
		PublicKey: other.PublicKey(), SecretBinding: "ARCFORGES_CENTER_KEY_MAIN", NotBefore: now.Add(time.Hour), NotAfter: now.Add(60 * 24 * time.Hour)}, now); err != nil {
		_ = tx.Rollback(t.Context())
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	err = relayCenter(t, db, io.Discard, registered).CheckCommandKeys(t.Context())
	if err == nil || !strings.Contains(err.Error(), "ARCFORGES_CENTER_KEY_MAIN") || !strings.Contains(err.Error(), successor) {
		t.Fatalf("a future row of the binding with another public half: %v", err)
	}
}

// TestTheCommandKeyNeverAppearsInLogsOrHealth is E1-16 (SEC-19): the start's log lines and the health document name the kid and the
// binding at most, never the private half or its encoding.
func TestTheCommandKeyNeverAppearsInLogsOrHealth(t *testing.T) {
	db := dbtest.New(t)
	key, _ := dbtest.RegisterCommandKey(t, db.Migration, "ARCFORGES_CENTER_KEY_MAIN")
	logs := &strings.Builder{}
	center := relayCenter(t, db, logs, key)
	if err := center.CheckCommandKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key.Signer())
	if err != nil {
		t.Fatal(err)
	}
	health, _ := json.Marshal(center.Health)
	for _, text := range []string{logs.String(), string(health), fmt.Sprintf("%+v", center.Config)} {
		for _, secret := range []string{scalarHex(t, key), base64.StdEncoding.EncodeToString(der), hex.EncodeToString(der)} {
			if strings.Contains(text, secret) {
				t.Fatal("the command key's private half appears in a log line, the health document or the configuration's formatting")
			}
		}
	}
	if !strings.Contains(logs.String(), "command keys loaded") {
		t.Fatalf("the start does not say which kids it holds: %s", logs.String())
	}
}

// scalarHex is the hex of a command key's private scalar, a form the private half must never appear in.
func scalarHex(t *testing.T, key config.CommandKey) string {
	t.Helper()
	raw, err := key.Signer().Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}
