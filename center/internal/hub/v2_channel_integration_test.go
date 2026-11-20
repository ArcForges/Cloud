// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"github.com/coder/websocket"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/hub"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

type v2TestChallenge struct {
	socket                                 *websocket.Conn
	connection, enrollment, epoch, account platform.ID
	fence                                  int64
	payload                                []byte
}

func (h *harness) dialV2(ctx context.Context, bearer string) *v2TestChallenge {
	h.t.Helper()
	ws, response, err := dialV2Channel(ctx, h.url, bearer)
	if err != nil {
		status := 0
		if response != nil {
			status = response.StatusCode
		}
		h.t.Fatalf("open V2 channel: HTTP %d: %v", status, err)
	}
	h.t.Cleanup(func() { _ = ws.CloseNow() })
	if ws.Subprotocol() != "arcforges.relay.v2" {
		h.t.Fatal("V2 did not negotiate its exact subprotocol")
	}
	body := readV2TestFrame(h.t, ctx, ws, 1, 1)
	if len(body) != 112 {
		h.t.Fatalf("challenge size %d", len(body))
	}
	c := &v2TestChallenge{socket: ws, payload: body, fence: int64(binary.BigEndian.Uint64(body[96:104]))}
	copy(c.connection[:], body[32:48])
	copy(c.enrollment[:], body[48:64])
	copy(c.epoch[:], body[64:80])
	copy(c.account[:], body[80:96])
	if c.fence <= 0 || c.epoch == (platform.ID{}) || c.connection == (platform.ID{}) {
		h.t.Fatal("challenge was missing live binding IDs or lease fence")
	}
	return c
}

func dialV2Channel(ctx context.Context, url, bearer string) (*websocket.Conn, *http.Response, error) {
	return websocket.Dial(ctx, "ws"+strings.TrimPrefix(url, "http")+"/fleet/v2/node", &websocket.DialOptions{
		Subprotocols: []string{"arcforges.relay.v2"}, HTTPHeader: http.Header{
			"Authorization": {"Bearer " + bearer}, config.ClientIPHeader: {"198.51.100.7"}},
	})
}

func (c *v2TestChallenge) sendHello(t *testing.T, ctx context.Context, node *enrolled, ownerEpoch platform.ID, nodeEpoch string, capabilities ...string) {
	t.Helper()
	intent := append([]byte{}, node.node.ID[:]...)
	intent = append(intent, node.result.InstallationID[:]...)
	intent = append(intent, ownerEpoch[:]...)
	intent = append(intent, byte(len(nodeEpoch)))
	intent = append(intent, nodeEpoch...)
	intent = append(intent, 2, byte(len(capabilities)))
	for _, capability := range capabilities {
		intent = append(intent, byte(len(capability)))
		intent = append(intent, capability...)
	}
	audience := sha256.Sum256([]byte(publicBaseURL))
	proof := slices.Concat([]byte("ArcForges relay-hello v2\n"), c.payload, audience[:], intent)
	signature := node.node.SignMessage(proof, true)
	writeV2TestFrame(t, ctx, c.socket, 2, 1, append(intent, signature...))
}

func (c *v2TestChallenge) accept(t *testing.T, ctx context.Context) {
	t.Helper()
	body := readV2TestFrame(t, ctx, c.socket, 3, 2)
	if len(body) != 68 || !slices.Equal(body[:16], c.connection[:]) || !slices.Equal(body[16:32], c.enrollment[:]) ||
		!slices.Equal(body[32:48], c.epoch[:]) || int64(binary.BigEndian.Uint64(body[48:56])) != c.fence ||
		binary.BigEndian.Uint32(body[56:60]) != 1<<20 {
		t.Fatal("accepted channel did not echo the exact challenge binding and negotiated frame bound")
	}
}

func readV2TestFrame(t *testing.T, ctx context.Context, socket *websocket.Conn, tag byte, sequence uint64) []byte {
	t.Helper()
	kind, data, err := socket.Read(ctx)
	if err != nil {
		t.Fatalf("read frame kind %d: %v", tag, err)
	}
	if kind != websocket.MessageBinary || len(data) < 10 || data[0] != 2 || data[1] != tag || binary.BigEndian.Uint64(data[2:10]) != sequence {
		t.Fatalf("expected V2 frame kind %d, sequence %d", tag, sequence)
	}
	return data[10:]
}

func writeV2TestFrame(t *testing.T, ctx context.Context, socket *websocket.Conn, tag byte, sequence uint64, body []byte) {
	t.Helper()
	raw := append(binary.BigEndian.AppendUint64([]byte{2, tag}, sequence), body...)
	if err := socket.Write(ctx, websocket.MessageBinary, raw); err != nil {
		t.Fatalf("write frame kind %d: %v", tag, err)
	}
}

func readV2TestClose(t *testing.T, ctx context.Context, socket *websocket.Conn, sequence uint64, code uint32, reason string) {
	t.Helper()
	body := readV2TestFrame(t, ctx, socket, 6, sequence)
	if len(body) < 8 || binary.BigEndian.Uint32(body[:4]) != code || string(body[8:]) != reason {
		t.Fatalf("expected V2 close %d/%s", code, reason)
	}
	_ = socket.CloseNow()
}

// Exercise two authorized peers at different protocol generations against the
// actual migrated database, retained account enrollment, and Go hub.
func TestV2BindingRotationReplacementAndDeviceRevocation(t *testing.T) {
	h := newHarness(t, settings{tune: func(settings *hub.Settings) {
		settings.HelloDeadline = 4 * time.Second
		settings.Heartbeat = 3 * time.Second
		settings.HeartbeatDeadline = 15 * time.Second
	}})
	ctx, cancel := background()
	defer cancel()
	node := h.enroll()
	ownerEpoch := platform.NewID()

	pendingLegacy, err := h.dial(node.access, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pendingLegacy.WS.CloseNow() })
	unknown := h.dialV2(ctx, node.access)
	unknown.sendHello(t, ctx, node, ownerEpoch, "1", "cohort-ci.481.1", "required.future")
	readV2TestClose(t, ctx, unknown.socket, 2, hub.CloseRefused, "upgrade_required")
	var bindings int
	if err = h.db.Runtime.Pool().QueryRow(ctx, "SELECT count(*) FROM management.node_protocol WHERE enrollment_id=$1", node.result.EnrollmentID).Scan(&bindings); err != nil || bindings != 0 {
		t.Fatalf("unnegotiated enrollment bound probe: %d, %v", bindings, err)
	}

	first := h.dialV2(ctx, node.access)
	if first.account != node.user || first.enrollment != node.result.EnrollmentID {
		t.Fatal("challenge was not bound to the credential's exact enrollment and account")
	}
	first.sendHello(t, ctx, node, ownerEpoch, "1", "cohort-ci.481.1", "linux-bubblewrap-sdk-v1", "optional.future", "win-wrapper-local-v1")
	first.accept(t, ctx)
	presence, online := h.center.Hub.V2Presence(node.user, first.enrollment, node.node.ID, first.epoch)
	if !online || presence.ConnectionID != first.connection || presence.HubFence != first.fence || presence.NodeOwnerEpoch != ownerEpoch ||
		presence.NodeEpoch != "1" || presence.Platform != "linux" || !slices.Equal(presence.Capabilities, []string{"linux-bubblewrap-sdk-v1"}) {
		t.Fatalf("unexpected qualified V2 presence: %+v, online=%v", presence, online)
	}
	if _, visible := h.center.Hub.V2Presence(platform.NewID(), first.enrollment, node.node.ID, first.epoch); visible {
		t.Fatal("V2 presence was projected into an unrelated account")
	}
	if _, visible := h.center.Hub.V2Presence(node.user, first.enrollment, node.node.ID, platform.NewID()); visible {
		t.Fatal("V2 presence was projected under an unrelated protocol epoch")
	}

	if err := pendingLegacy.Hello(ctx, node.node, node.result.InstallationID, publicBaseURL); err != nil {
		t.Fatal(err)
	}
	if closed := pendingLegacy.AwaitClose(ctx, false); closed.Code != hub.CloseRefused || closed.Reason != "upgrade_required" {
		t.Fatalf("legacy generation did not refuse after V2 enrollment: %+v", closed)
	}

	client := nodetest.Client{URL: h.url, ClientIPHeader: config.ClientIPHeader}
	reply, err := client.Post("/arcforges.fleet.v1.NodeEnrollmentService/RefreshNodeSession", &fleetv1.NodeEnrollmentServiceRefreshNodeSessionRequest{
		Meta: &foundationv1.RequestMeta{}, RefreshToken: proto.String(node.result.Session.RefreshToken)}, "")
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := nodetest.Decode(reply, &fleetv1.NodeEnrollmentServiceRefreshNodeSessionResponse{})
	if err != nil || refreshed.GetValue().GetAccessToken() == "" {
		t.Fatalf("real enrollment rotation did not issue a successor token: %v", err)
	}
	rotated := refreshed.GetValue()
	h.secrets = append(h.secrets, rotated.GetAccessToken(), rotated.GetRefreshToken())
	writeV2TestFrame(t, ctx, first.socket, 5, 2, []byte(rotated.GetAccessToken()))
	heartbeat := readV2TestFrame(t, ctx, first.socket, 4, 3)
	writeV2TestFrame(t, ctx, first.socket, 4, 3, heartbeat)
	if _, response, err := dialV2Channel(ctx, h.url, node.access); err == nil || response == nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatal("rotated older access token was still admitted to a channel")
	}

	second := h.dialV2(ctx, rotated.GetAccessToken())
	if second.connection == first.connection || second.epoch != first.epoch || second.fence != first.fence {
		t.Fatal("reconnect changed protocol authority or did not replace the connection generation")
	}
	second.sendHello(t, ctx, node, ownerEpoch, "2", "cohort-ci.481.1", "linux-bubblewrap-sdk-v1")
	second.accept(t, ctx)
	readV2TestClose(t, ctx, first.socket, 4, hub.CloseReplaced, "replaced")

	participants := []device.Participant{fleet.NodeParticipant{}, h.center.Hub.Participant()}
	if err = h.db.Runtime.InTx(ctx, "revoke a V2 device", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := device.Revoke(ctx, tx, node.user, node.result.DeviceID, device.RevokedByOwner, participants, time.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	readV2TestClose(t, ctx, second.socket, 3, hub.CloseCredential, "revoked")
	var revoked bool
	var protocol platform.ID
	if err = h.db.Runtime.Pool().QueryRow(ctx, `SELECT protocol_epoch, revoked_at IS NOT NULL FROM management.node_protocol
WHERE enrollment_id=$1 AND node_id=$2 AND account_id=$3`, first.enrollment, node.node.ID, node.user).Scan(&protocol, &revoked); err != nil ||
		!revoked || protocol != first.epoch {
		t.Fatalf("protocol tombstone did not retain the exact epoch: revoked=%v err=%v", revoked, err)
	}
	if _, visible := h.center.Hub.V2Presence(node.user, second.enrollment, node.node.ID, second.epoch); visible {
		t.Fatal("revoked V2 enrollment still projected online")
	}
}
