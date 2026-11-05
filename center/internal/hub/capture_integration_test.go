// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
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

// EVIDENCE: REAL PostgreSQL, the REAL composed center and its WebSocket server; the node is nodetest's channel client (MOCKED, software
// key). E1-26 (AF-CTR-05 E1a): the node channel's exchanges, captured as the messages on the wire in both directions and normalized,
// in the format of the AF-CTR-04 FakeCenter captures (center/internal/fleetapi/testdata/exchanges, schema version 2). Part N1 copies
// the directory verbatim for the ArcForges FakeCenter's conformance test. For a channel, request.frames are the node's messages and
// reply.frames the center's, each in order, every message one binary RelayFrame in hex; reply.trailers is the WebSocket close status
// and reason the node read; a refusal before the upgrade has no frames on either side but its HTTP status, its reason headers and its
// JSON body (one frame, the body's bytes in hex). Determinism comes from normalization: only values the center or a random source
// produced are replaced, each distinct value by its own placeholder of the same shape, the same placeholder wherever it appears.

// channelExchangesDirectory holds one file per captured case.
const channelExchangesDirectory = "testdata/exchanges"

// channelCohort names the relay.v1 the captures are encoded with (the Contracts cohort the center pins).
const channelCohort = "1.0.0-ci.437.1"

var channelNormalization = []string{
	"a 16-byte ID the center or the node drew: 15 bytes of its kind (0xa1 correlation, 0xa3 installation, 0xa5 connection, 0xa6 node) and n for the n-th distinct one of the kind",
	"the hello nonce the center drew: 32 bytes of 0xb0+n",
	"a hello signature (ES256 draws a nonce): 64 bytes of 0xe0+n",
	"a command key's kid: kid-<n, 8 digits>",
	"a token: its prefix and the canonical base64url of 32 bytes of n (the n-th distinct token)",
	"every Instant: unix_seconds is the offset from the case's start, rounded to 5 seconds; nanos 0",
	"a 4500 close's reconnect hint (RelayClose.reconnect_after_ms): 1000",
	"a refusal's JSON body: correlationId the placeholder text of its ID, retryAt the case's start plus the offset, rounded to 5 seconds",
	"the authorization header carries the placeholder of its token; the client address header is recorded as sent",
}

type channelWire struct {
	ContentType string   `json:"contentType"`
	HTTPStatus  int      `json:"httpStatus,omitempty"`
	Frames      []string `json:"frames"`
	Trailers    string   `json:"trailers,omitempty"`
}

type channelExchange struct {
	SchemaVersion   int               `json:"schemaVersion"`
	Source          string            `json:"source"`
	ContractsCohort string            `json:"contractsCohort"`
	CenterCommit    string            `json:"centerCommit"`
	Method          string            `json:"method"`
	Case            string            `json:"case"`
	Outcome         string            `json:"outcome"`
	Headers         map[string]string `json:"headers"`
	Request         channelWire       `json:"request"`
	Reply           channelWire       `json:"reply"`
	Normalized      []string          `json:"normalized"`
	SHA256          string            `json:"sha256"`
}

// channelPlaceholders maps volatile values to placeholders over one case.
type channelPlaceholders struct {
	t      *testing.T
	start  time.Time
	ids    map[string][]byte
	values map[string]string
	counts map[string]int
}

func (p *channelPlaceholders) next(kind string) int { p.counts[kind]++; return p.counts[kind] }

func (p *channelPlaceholders) id(value []byte, kind byte) []byte {
	if len(value) != 16 {
		return value
	}
	key := hex.EncodeToString(value)
	if placeholder, ok := p.ids[key]; ok {
		return placeholder
	}
	placeholder := bytes.Repeat([]byte{kind}, 16)
	placeholder[15] = byte(p.next(fmt.Sprintf("id-%x", kind)))
	p.ids[key] = placeholder
	return placeholder
}

func (p *channelPlaceholders) filled(kind string, value []byte, base byte, size int) []byte {
	key := kind + hex.EncodeToString(value)
	if placeholder, ok := p.values[key]; ok {
		return []byte(placeholder)
	}
	placeholder := bytes.Repeat([]byte{base + byte(p.next(kind))}, size)
	p.values[key] = string(placeholder)
	return placeholder
}

func (p *channelPlaceholders) text(kind, value, format string) string {
	key := kind + value
	if placeholder, ok := p.values[key]; ok {
		return placeholder
	}
	placeholder := fmt.Sprintf(format, p.next(kind))
	p.values[key] = placeholder
	return placeholder
}

func (p *channelPlaceholders) token(value string) string {
	if placeholder, ok := p.values["token"+value]; ok {
		return placeholder
	}
	placeholder := "afa1." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(p.next("token"))}, 32))
	p.values["token"+value] = placeholder
	return placeholder
}

func (p *channelPlaceholders) instant(value *foundationv1.Instant) *foundationv1.Instant {
	if value == nil {
		return nil
	}
	offset := time.Unix(value.GetUnixSeconds(), int64(value.GetNanos())).Sub(p.start)
	rounded := (offset + 2500*time.Millisecond) / (5 * time.Second) * 5
	return &foundationv1.Instant{UnixSeconds: proto.Int64(int64(rounded)), Nanos: proto.Uint32(0)}
}

func (p *channelPlaceholders) idValue(value *foundationv1.Id, kind byte) *foundationv1.Id {
	if value == nil {
		return nil
	}
	return &foundationv1.Id{Value: p.id(value.GetValue(), kind)}
}

// frame normalizes one transmitted RelayFrame.
func (p *channelPlaceholders) frame(data []byte) string {
	var frame relayv1.RelayFrame
	if err := proto.Unmarshal(data, &frame); err != nil {
		p.t.Fatalf("a message that is not a RelayFrame: %v", err)
	}
	switch member := frame.GetFrame().(type) {
	case *relayv1.RelayFrame_Challenge:
		value := member.Challenge
		value.Nonce = p.filled("nonce", value.GetNonce(), 0xb0, 32)
		value.ConnectionId = p.idValue(value.GetConnectionId(), 0xa5)
		value.HelloDeadline = p.instant(value.GetHelloDeadline())
	case *relayv1.RelayFrame_Accepted:
		value := member.Accepted
		value.ConnectionId = p.idValue(value.GetConnectionId(), 0xa5)
		for index, kid := range value.GetSigningKids() {
			value.SigningKids[index] = p.text("kid", kid, "kid-%08d")
		}
	case *relayv1.RelayFrame_Heartbeat:
		member.Heartbeat.SentAt = p.instant(member.Heartbeat.GetSentAt())
	case *relayv1.RelayFrame_Close:
		if member.Close.ReconnectAfterMs != nil {
			member.Close.ReconnectAfterMs = proto.Uint32(1000)
		}
	case *relayv1.RelayFrame_NodeHello:
		value := member.NodeHello
		value.NodeId = p.idValue(value.GetNodeId(), 0xa6)
		value.InstallationId = p.idValue(value.GetInstallationId(), 0xa3)
		if len(value.GetHelloSignature()) == 64 {
			value.HelloSignature = p.filled("signature", value.GetHelloSignature(), 0xe0, 64)
		}
	case *relayv1.RelayFrame_TokenRefresh:
		member.TokenRefresh.Token = proto.String(p.token(member.TokenRefresh.GetToken()))
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(&frame)
	if err != nil {
		p.t.Fatal(err)
	}
	return hex.EncodeToString(encoded)
}

var (
	correlationPattern = regexp.MustCompile(`"correlationId":"[0-9a-f-]{36}"`)
	retryPattern       = regexp.MustCompile(`"retryAt":"[^"]*"`)
)

// recorder captures one case.
type recorder struct {
	mu     sync.Mutex
	node   [][]byte
	center [][]byte
	on     bool
}

func (r *recorder) record(fromCenter bool, data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.on {
		return
	}
	copied := append([]byte(nil), data...)
	if fromCenter {
		r.center = append(r.center, copied)
	} else {
		r.node = append(r.node, copied)
	}
}

type channelCapturer struct {
	t     *testing.T
	cases map[string]channelExchange
}

// add builds the capture of a case from its recording, its close and its headers.
func (c *channelCapturer) add(name, outcome string, start time.Time, headers map[string]string, r *recorder, closed *nodetest.Closed, refused *http.Response) {
	c.t.Helper()
	p := &channelPlaceholders{t: c.t, start: start, ids: map[string][]byte{}, values: map[string]string{}, counts: map[string]int{}}
	result := channelExchange{SchemaVersion: 2, Source: "TestChannelExchangeCapture", ContractsCohort: channelCohort, Method: "NodeChannel", Case: name, Outcome: outcome,
		Headers: map[string]string{}, Normalized: channelNormalization}
	for name, value := range headers {
		if name == "authorization" {
			value = "Bearer " + p.token(strings.TrimPrefix(value, "Bearer "))
		}
		result.Headers[name] = value
	}
	result.Request = channelWire{ContentType: "websocket " + nodetest.ChannelSubprotocol, Frames: []string{}}
	result.Reply = channelWire{ContentType: "websocket " + nodetest.ChannelSubprotocol, Frames: []string{}}
	r.mu.Lock()
	// Every message in order of each direction (the node's and the center's are each in their own order).
	for _, data := range r.center {
		result.Reply.Frames = append(result.Reply.Frames, p.frame(data))
	}
	for _, data := range r.node {
		result.Request.Frames = append(result.Request.Frames, p.frame(data))
	}
	r.mu.Unlock()
	switch {
	case refused != nil:
		body, _ := io.ReadAll(refused.Body)
		text := correlationPattern.ReplaceAllStringFunc(string(body), func(match string) string {
			raw, _ := hex.DecodeString(strings.ReplaceAll(match[len(`"correlationId":"`):len(match)-1], "-", ""))
			id := p.id(raw, 0xa1)
			return `"correlationId":"` + fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:]) + `"`
		})
		text = retryPattern.ReplaceAllStringFunc(text, func(match string) string {
			at, err := time.Parse(time.RFC3339Nano, match[len(`"retryAt":"`):len(match)-1])
			if err != nil {
				return match
			}
			offset := (at.Sub(start) + 2500*time.Millisecond) / (5 * time.Second) * 5 * time.Second
			return `"retryAt":"` + time.Unix(0, 0).UTC().Add(offset).Format(time.RFC3339) + `"`
		})
		result.Reply = channelWire{ContentType: refused.Header.Get("Content-Type"), HTTPStatus: refused.StatusCode, Frames: []string{hex.EncodeToString([]byte(text))}}
		for _, name := range []string{"ArcForges-Refusal", "Retry-After"} {
			if value := refused.Header.Get(name); value != "" {
				result.Headers["reply "+strings.ToLower(name)] = value
			}
		}
	case closed != nil:
		result.Reply.HTTPStatus = http.StatusSwitchingProtocols
		result.Reply.Trailers = fmt.Sprintf("websocket-close: %d", closed.Status)
	}
	content, _ := json.Marshal(struct {
		Method, Case, Outcome string
		Headers               map[string]string
		Request, Reply        channelWire
		Normalized            []string
	}{result.Method, result.Case, result.Outcome, result.Headers, result.Request, result.Reply, result.Normalized})
	digest := sha256.Sum256(content)
	result.SHA256 = hex.EncodeToString(digest[:])
	if _, twice := c.cases["NodeChannel-"+name]; twice {
		c.t.Fatalf("two captures named %s", name)
	}
	c.cases["NodeChannel-"+name] = result
}

// TestChannelExchangeCapture compares a fresh capture of every case with the committed directory; with ARCFORGES_UPDATE_EXCHANGES=1 it
// writes the directory instead (ARCFORGES_CENTER_COMMIT names the commit of a new or changed file).
func TestChannelExchangeCapture(t *testing.T) {
	c := &channelCapturer{t: t, cases: map[string]channelExchange{}}
	quiet := func(s *hub.Settings) {
		s.Heartbeat, s.HeartbeatDeadline, s.LapseRecheck, s.TokenGrace = time.Minute, 3*time.Minute, 300*time.Millisecond, 300*time.Millisecond
	}
	h := newHarness(t, settings{tune: quiet})
	gate := &switchedGate{}
	h.center.Hub.SetGate(gate)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	headersOf := func(bearer string) map[string]string {
		return map[string]string{"authorization": "Bearer " + bearer, "sec-websocket-protocol": nodetest.ChannelSubprotocol, "x-arcforges-client-ip": "198.51.100.7"}
	}
	open := func(node *enrolled, r *recorder) *nodetest.Channel {
		channel, err := nodetest.Dial(ctx, h.url, nodetest.DialOptions{Bearer: node.access, Header: http.Header{config.ClientIPHeader: {"198.51.100.7"}},
			Record: r.record})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = channel.WS.CloseNow() })
		return channel
	}
	closedCase := func(name string, node *enrolled, act func(*nodetest.Channel)) {
		t.Helper()
		start := time.Now()
		r := &recorder{on: true}
		channel := open(node, r)
		act(channel)
		closed := channel.AwaitClose(ctx, false)
		c.add(name, fmt.Sprintf("close %d %s", closed.Code, closed.Reason), start, headersOf(node.access),
			r, &closed, nil)
	}
	hello := func(node *enrolled) func(*nodetest.Channel) {
		return func(channel *nodetest.Channel) {
			if err := channel.Hello(ctx, node.node, node.result.InstallationID, publicBaseURL); err != nil {
				t.Fatal(err)
			}
			if _, err := channel.Accept(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	// The accepted channel, closed by the node.
	accepted := h.enroll()
	closedCase("accepted", accepted, func(channel *nodetest.Channel) {
		hello(accepted)(channel)
		if err := channel.TokenRefresh(ctx, accepted.access); err != nil {
			t.Fatal(err)
		}
		_ = channel.Send(ctx, &relayv1.RelayFrame{Frame: &relayv1.RelayFrame_Close{Close: &relayv1.RelayClose{Code: proto.Uint32(1000), Reason: proto.String("node_closed")}}})
	})
	// The hello's refusals.
	mismatch := h.enroll()
	closedCase("hello-mismatch", mismatch, func(channel *nodetest.Channel) {
		other := platform.NewID()
		_ = channel.SendHello(ctx, other, mismatch.result.InstallationID, mismatch.node.SignMessage(channel.HelloMessage(publicBaseURL, other, mismatch.result.InstallationID), true))
	})
	stranger := h.enroll()
	signature := h.enroll()
	closedCase("hello-signature", signature, func(channel *nodetest.Channel) {
		ids := [2]platform.ID{signature.node.ID, signature.result.InstallationID}
		_ = channel.SendHello(ctx, ids[0], ids[1], stranger.node.SignMessage(channel.HelloMessage(publicBaseURL, ids[0], ids[1]), true))
	})
	malformed := h.enroll()
	closedCase("hello-malformed", malformed, func(channel *nodetest.Channel) {
		_ = channel.Send(ctx, &relayv1.RelayFrame{Frame: &relayv1.RelayFrame_NodeHello{NodeHello: &relayv1.NodeHello{InstallationId: idOf(malformed.result.InstallationID[:]),
			HelloSignature: make([]byte, 64)}}})
	})
	deadline := h.enroll()
	closedCase("hello-deadline", deadline, func(*nodetest.Channel) {})
	// A replaced channel: the older connection's view.
	replaced := h.enroll()
	closedCase("replaced", replaced, func(channel *nodetest.Channel) {
		hello(replaced)(channel)
		newer := open(replaced, &recorder{})
		hello(replaced)(newer)
	})
	// Revocation, expiry, lapse.
	revoked := h.enroll()
	closedCase("revoked", revoked, func(channel *nodetest.Channel) {
		hello(revoked)(channel)
		participants := []device.Participant{fleet.NodeParticipant{}, h.center.Hub.Participant()}
		if err := h.db.Runtime.InTx(ctx, "revoke", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
			_, err := device.Revoke(ctx, tx, revoked.user, revoked.result.DeviceID, device.RevokedByOwner, participants, time.Now())
			return err
		}); err != nil {
			t.Fatal(err)
		}
	})
	expired := h.enroll()
	closedCase("token-expired", expired, func(channel *nodetest.Channel) {
		hello(expired)(channel)
		h.db.Exec("UPDATE identity.session SET access_expires_at = now() WHERE installation_id = '" + expired.result.InstallationID.String() + "'")
		_ = channel.TokenRefresh(ctx, expired.access)
	})
	lapsed := h.enroll()
	closedCase("lapsed", lapsed, func(channel *nodetest.Channel) {
		hello(lapsed)(channel)
		gate.state.Store(gateLapsed)
	})
	gate.state.Store(gateAvailable)
	// The refusals before the upgrade.
	refusedCase := func(name string, bearer string, extra http.Header) {
		t.Helper()
		start := time.Now()
		header := http.Header{config.ClientIPHeader: {"198.51.100.7"}}
		for key, values := range extra {
			header[key] = values
		}
		channel, err := nodetest.Dial(ctx, h.url, nodetest.DialOptions{Bearer: bearer, Header: header})
		if err == nil || channel.Response == nil {
			t.Fatalf("%s: the upgrade was not refused: %v", name, err)
		}
		headers := headersOf(bearer)
		if bearer == "" {
			delete(headers, "authorization")
		}
		c.add(name, channel.Response.Header.Get("ArcForges-Refusal"), start, headers, &recorder{}, nil, channel.Response)
	}
	refusedCase("refused-no-credential", "", nil)
	revokedNode := h.enroll()
	h.db.Exec("UPDATE identity.session SET revoked_at = now(), revoke_reason = 6 WHERE installation_id = '" + revokedNode.result.InstallationID.String() + "'")
	refusedCase("refused-credential-revoked", revokedNode.access, nil)
	expiredNode := h.enroll()
	h.db.Exec("UPDATE identity.session SET access_expires_at = now() - interval '1 second' WHERE installation_id = '" + expiredNode.result.InstallationID.String() + "'")
	refusedCase("refused-token-expired", expiredNode.access, nil)
	refusedCase("refused-account-session", h.issueAccount(h.db.Account(1)), nil)
	// A graceful stop.
	stopped := h.enroll()
	closedCase("shutting-down", stopped, func(channel *nodetest.Channel) {
		hello(stopped)(channel)
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		go h.center.Hub.Stop(stop)
	})
	if os.Getenv("ARCFORGES_UPDATE_EXCHANGES") == "1" {
		writeChannelExchanges(t, c.cases)
		return
	}
	committed, err := filepath.Glob(filepath.Join(channelExchangesDirectory, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(committed) != len(c.cases) {
		t.Errorf("%d committed exchanges, %d captured: run ARCFORGES_UPDATE_EXCHANGES=1 go test -run TestChannelExchangeCapture", len(committed), len(c.cases))
	}
	for _, file := range committed {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var stored channelExchange
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&stored); err != nil {
			t.Errorf("%s: %v", file, err)
			continue
		}
		captured, ok := c.cases[strings.TrimSuffix(filepath.Base(file), ".json")]
		stored.CenterCommit, captured.CenterCommit = "", ""
		left, _ := json.Marshal(stored)
		right, _ := json.Marshal(captured)
		if !ok || !bytes.Equal(left, right) {
			t.Errorf("%s differs from a fresh capture: run ARCFORGES_UPDATE_EXCHANGES=1 go test -run TestChannelExchangeCapture", file)
		}
	}
}

func writeChannelExchanges(t *testing.T, cases map[string]channelExchange) {
	t.Helper()
	if err := os.MkdirAll(channelExchangesDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	committed, _ := filepath.Glob(filepath.Join(channelExchangesDirectory, "*.json"))
	for _, file := range committed {
		if _, ok := cases[strings.TrimSuffix(filepath.Base(file), ".json")]; !ok {
			_ = os.Remove(file)
		}
	}
	names := make([]string, 0, len(cases))
	for name := range cases {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		path := filepath.Join(channelExchangesDirectory, name+".json")
		value := cases[name]
		if data, err := os.ReadFile(path); err == nil {
			var stored channelExchange
			if json.Unmarshal(data, &stored) == nil {
				commit := stored.CenterCommit
				stored.CenterCommit, value.CenterCommit = "", ""
				left, _ := json.Marshal(stored)
				right, _ := json.Marshal(value)
				if bytes.Equal(left, right) {
					continue
				}
				_ = commit
			}
		}
		value.CenterCommit = os.Getenv("ARCFORGES_CENTER_COMMIT")
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
