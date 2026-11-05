// SPDX-License-Identifier: AGPL-3.0-only

// Package hub is the center's node channel (AF-CTR-05 part E1a; ArcForges-Design AD-0021 sections 9 and 11, 11-security-privacy
// section 3 "Channel proof of possession"; Plan CTR5-HUB-01..12 as amended by PB-4, PB-5, D0-B2, PN-1..PN-4 and Q21..Q23): the one
// outbound WebSocket a signed-in node holds to the center, on GET /fleet/v1/node with the subprotocol arcforges.relay.v1.
//
// Admission (CTR5-HUB-02), before the upgrade, each refusal an HTTP answer whose closed reason is also in the ArcForges-Refusal header
// (PN-3): the method, the upgrade headers and the subprotocol; the hub lease; the node's native bearer (session.Verifier: unknown,
// expired and revoked told apart; a cookie is never read, PN-4); the operation row fleet.nodeChannel through access.Authorize (the node
// scope, the upgrade-rate buckets of package quota, access.authorized, the gate of center.nodes); a live node row for the credential's
// installation; a free node connection slot. Then the upgrade, with the server's read and write deadlines cleared (PN-1).
//
// The hello (PB-4, D0-B2): the center sends a challenge on this connection only, a 32-byte nonce and the connection ID. The node
// answers NodeHello with an ES256 signature by its node key over HelloMessage. The hub verifies it against the key registered for the
// bearer credential's installation (never a key the hello names), then that the hello names the credential's node and installation;
// either failure closes 4403. The nonce is used once, and it is void at the 10-second hello deadline (4408) or when the connection
// closes. Only then is the connection the node's: an older connection of the same node is closed 4409 (replaced), and the hub answers
// ChannelAccepted with the limits.
//
// While open (CTR5-HUB-06..10): the center sends a heartbeat every Heartbeat, and either side closes after HeartbeatDeadline without a
// frame (4408; a half-open connection is found by this deadline, never by TCP); presence is written at accept, at most once per
// presence interval and at close, fenced by the lease; TokenRefresh rebinds the connection to a new access token of the same session
// and installation, and a connection whose token expired without one for TokenGrace closes 4401; the credential is re-read every
// SessionRecheck and at every TokenRefresh (revoked: 4401; an account that may no longer sign in: 4403); the gate is asked for
// center.nodes every LapseRecheck and at every TokenRefresh (unavailable: 4403, audited access.gated once; undecidable: the connection
// stays until the next check, Q23); a frame over the bound closes 4413, a node over the frame rate 4429, a frame a node may not send
// 4403. A revocation committed in this process closes the node's connection at once (4401): the device cascade through Participant,
// the other session revocations through session.Announce, each re-checked against the store first where it is only a notice. A
// graceful stop closes every connection 4500 with a jittered reconnect hint, then releases the lease.
package hub

import (
	"context"
	"crypto/rand"
	"log/slog"
	"math/big"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The close codes of the channel (Plan CTR5-HUB-11; relay.proto RelayClose.code).
const (
	CloseCredential   = 4401 // the credential expired or was revoked
	CloseRefused      = 4403 // refused: feature, account state, node mismatch, a proof or frame the hub does not accept
	CloseDeadline     = 4408 // the hello or heartbeat deadline passed
	CloseReplaced     = 4409 // a newer connection of the node replaced this one
	CloseTooLarge     = 4413 // a frame over the bound
	CloseRateLimited  = 4429 // a node over the frame rate
	CloseShuttingDown = 4500 // the center is going away (shutdown, or this process lost the hub lease): reconnect after the hint
	CloseKillSwitch   = 4503 // reserved (AF-CLD-04)
)

// Settings are the hub's intervals and bounds (config.IdentityPolicy's channel keys; tests shorten them).
type Settings struct {
	HelloDeadline          time.Duration
	Heartbeat              time.Duration
	HeartbeatDeadline      time.Duration
	PresenceInterval       time.Duration
	SessionRecheck         time.Duration
	LapseRecheck           time.Duration
	TokenGrace             time.Duration
	MaxFrameBytes          int
	InboundFramesPerSecond int
	// MaxInFlightCalls and MaxRelayNonces are what ChannelAccepted states for the calls (E1b) and the relay nonces (E2) of a
	// connection: 8 each (Plan C.9).
	MaxInFlightCalls int
	MaxRelayNonces   int
	SendQueueFrames  int
	SendQueueBytes   int
	// WriteTimeout bounds one write to a node; a node that stops reading is closed when it passes.
	WriteTimeout time.Duration
	// LeaseTTL and LeaseRenew are the hub lease's time to live and renewal interval (PB-5: 30 s and 10 s).
	LeaseTTL   time.Duration
	LeaseRenew time.Duration
	// ReconnectMin and ReconnectMax bound the jittered reconnect hint of a 4500 close (RelayClose.reconnect_after_ms, at most 300 s).
	ReconnectMin time.Duration
	ReconnectMax time.Duration
}

// SettingsOf are the hub settings of a policy: the plan's values (C.9) unless the policy overrides them.
func SettingsOf(policy config.IdentityPolicy) Settings {
	return Settings{
		HelloDeadline: 10 * time.Second, Heartbeat: policy.ChannelHeartbeat, HeartbeatDeadline: policy.ChannelHeartbeatDeadline,
		PresenceInterval: time.Minute, SessionRecheck: policy.ChannelSessionRecheck, LapseRecheck: policy.ChannelLapseRecheck,
		TokenGrace: policy.ChannelTokenGrace, MaxFrameBytes: routes.NodeChannelMaxFrameBytes, InboundFramesPerSecond: policy.ChannelInboundFramesPerSecond,
		MaxInFlightCalls: 8, MaxRelayNonces: 8,
		SendQueueFrames: policy.ChannelSendQueueFrames, SendQueueBytes: policy.ChannelSendQueueBytes, WriteTimeout: 10 * time.Second,
		LeaseTTL: DefaultLeaseTTL, LeaseRenew: DefaultLeaseRenew, ReconnectMin: time.Second, ReconnectMax: 30 * time.Second,
	}
}

// Options compose a hub.
type Options struct {
	DB         *store.DB
	Verifier   *session.Verifier
	Authorizer *access.Authorizer
	// Gate is the feature gate the lapse re-check asks (the authorizer's).
	Gate     feature.Gate
	Codec    Codec
	Settings Settings
	// CenterURL is the center's canonical public base URL, the audience of the hello proof.
	CenterURL string
	// Surface reports whether the relay surface is enabled; a disabled surface's route answers 404.
	Surface func() bool
	// ClientIP and ClientOrigin read the client's address and coarse origin as the ingress does; RequireClientIP refuses a request
	// without an address (hosted mode).
	ClientIP        func(*http.Request) (netip.Addr, bool)
	RequireClientIP bool
	ClientOrigin    func(*http.Request) ingress.Origin
	// Slot takes a node connection slot for an upgrade (the server's count of upgraded connections, apart from its listener limit;
	// CTR5-HUB-12, PN-1) and moves the connection over to it: ok is false when every slot is held. Nil admits every upgrade.
	Slot    func(*http.Request) (release func(), ok bool)
	Clock   func() time.Time
	Logger  *slog.Logger
	Metrics *observe.Metrics
}

// Hub is the node channel of one center process.
type Hub struct {
	db         *store.DB
	verifier   *session.Verifier
	authorizer *access.Authorizer
	gate       feature.Gate
	codec      Codec
	settings   Settings
	centerURL  string
	surface    func() bool
	options    Options
	clock      func() time.Time
	logger     *slog.Logger
	metrics    *observe.Metrics
	lease      *Lease

	mu       sync.Mutex
	nodes    map[platform.ID]*conn // the accepted connection of each node
	all      map[*conn]bool        // every open connection, accepted or not
	stopping bool
	kids     []string // the held command keys' kids (UseSigningKids)
	wg       sync.WaitGroup

	stop    context.CancelFunc
	done    chan struct{}
	unlisen func()
}

// New composes a hub; Start takes the lease and starts its loops.
func New(options Options) *Hub {
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	metrics := options.Metrics
	if metrics == nil {
		metrics = observe.NewMetrics()
	}
	surface := options.Surface
	if surface == nil {
		surface = func() bool { return true }
	}
	return &Hub{
		db: options.DB, verifier: options.Verifier, authorizer: options.Authorizer, gate: options.Gate, codec: options.Codec,
		settings: options.Settings, centerURL: options.CenterURL, surface: surface, options: options, clock: clock, logger: logger,
		metrics: metrics, lease: NewLease(options.DB, platform.NewID(), options.Settings.LeaseTTL, clock),
		nodes: map[platform.ID]*conn{}, all: map[*conn]bool{},
	}
}

// Lease is the hub's claim of the hub lease.
func (h *Hub) Lease() *Lease { return h.lease }

// Start takes the hub lease when it is free (another process's live lease leaves this hub serving no channel until it can take it
// over), listens for committed revocations and starts the lease loop. It returns at once; Stop ends it.
func (h *Hub) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	h.stop = cancel
	h.done = make(chan struct{})
	h.unlisen = session.ListenRevocations(h.revoked)
	h.acquire(ctx)
	go h.leaseLoop(ctx)
}

// acquire tries to take the lease once, and clears what a previous holder left recorded.
func (h *Hub) acquire(ctx context.Context) {
	fence, err := h.lease.Acquire(ctx)
	switch {
	case err == nil:
		h.metrics.ObserveChannel("lease", "acquired")
		h.logger.Info("the node channel hub holds the hub lease", "fence", fence)
		if err := h.clearStale(ctx, fence, h.clock()); err != nil {
			h.logger.Warn("the channels a previous hub recorded could not be cleared", "error", err.Error())
		}
	case err == ErrLeaseHeld:
		h.metrics.ObserveChannel("lease", "held_elsewhere")
	default:
		h.logger.Warn("the hub lease could not be acquired; retrying", "error", err.Error())
	}
}

// leaseLoop renews the held lease, or tries to take it, every LeaseRenew. A lease lost closes every connection 4500 (the node
// reconnects, to the process that holds the lease now).
func (h *Hub) leaseLoop(ctx context.Context) {
	defer close(h.done)
	ticker := time.NewTicker(h.settings.LeaseRenew)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if _, held := h.lease.Fence(); !held {
			h.acquire(ctx)
			continue
		}
		renewed, err := h.lease.Renew(ctx)
		switch {
		case err != nil:
			h.logger.Warn("the hub lease could not be renewed; retrying", "error", err.Error())
		case !renewed:
			h.metrics.ObserveChannel("lease", "lost")
			h.logger.Warn("the node channel hub lost the hub lease; its connections close")
			h.closeAll(CloseShuttingDown, "lease_lost")
		}
	}
}

// Stop is the graceful stop (CTR5-HUB-11): no new upgrade is admitted, every connection closes 4500 with a jittered reconnect hint and
// is waited for within ctx, then the lease is released so that the next process takes it over at once.
func (h *Hub) Stop(ctx context.Context) {
	h.mu.Lock()
	h.stopping = true
	h.mu.Unlock()
	h.closeAll(CloseShuttingDown, "shutting_down")
	waited := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-ctx.Done():
	}
	if h.unlisen != nil {
		h.unlisen()
	}
	if h.stop != nil {
		h.stop()
		<-h.done
	}
	release, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := h.lease.Release(release); err != nil {
		h.logger.Warn("the hub lease could not be released; it expires on its own", "error", err.Error())
	} else {
		h.metrics.ObserveChannel("lease", "released")
	}
}

// serving reports whether the hub admits an upgrade: it holds the lease and is not stopping.
func (h *Hub) serving() (int64, bool) {
	h.mu.Lock()
	stopping := h.stopping
	h.mu.Unlock()
	fence, held := h.lease.Fence()
	return fence, held && !stopping
}

// Connected reports whether a node has an accepted connection in this process.
func (h *Hub) Connected(nodeID platform.ID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.nodes[nodeID]
	return ok
}

// Count is the number of accepted connections.
func (h *Hub) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.nodes)
}

// track adds an upgraded connection before its hello; it reports false while the hub is stopping.
func (h *Hub) track(c *conn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stopping {
		return false
	}
	h.all[c] = true
	h.wg.Add(1)
	return true
}

// accept makes a proved connection the node's (CTR5-HUB-04, PB-4): an older connection of the node is closed 4409 after the newer one
// is registered, never before its proof. It reports the connection it replaced.
func (h *Hub) accept(c *conn) (*conn, bool) {
	h.mu.Lock()
	if h.stopping || !h.all[c] || c.closing.Load() {
		h.mu.Unlock()
		return nil, false
	}
	older := h.nodes[c.nodeID]
	h.nodes[c.nodeID] = c
	count := len(h.nodes)
	h.mu.Unlock()
	h.metrics.SetChannelConnected(count)
	if older != nil {
		older.closeWith(CloseReplaced, "replaced")
	}
	return older, true
}

// release makes a closing connection no longer the node's.
func (h *Hub) release(c *conn) {
	h.mu.Lock()
	if h.nodes[c.nodeID] == c {
		delete(h.nodes, c.nodeID)
	}
	count := len(h.nodes)
	h.mu.Unlock()
	h.metrics.SetChannelConnected(count)
}

// forget removes an ended connection.
func (h *Hub) forget(c *conn) {
	h.mu.Lock()
	if h.nodes[c.nodeID] == c {
		delete(h.nodes, c.nodeID)
	}
	tracked := h.all[c]
	delete(h.all, c)
	count := len(h.nodes)
	h.mu.Unlock()
	h.metrics.SetChannelConnected(count)
	if tracked {
		h.wg.Done()
	}
}

// matching are the open connections a predicate selects.
func (h *Hub) matching(selected func(*conn) bool) []*conn {
	h.mu.Lock()
	defer h.mu.Unlock()
	var result []*conn
	for c := range h.all {
		if selected(c) {
			result = append(result, c)
		}
	}
	return result
}

// closeAll closes every open connection with a code.
func (h *Hub) closeAll(code uint32, reason string) {
	for _, c := range h.matching(func(*conn) bool { return true }) {
		c.closeWith(code, reason)
	}
}

// revoked is the listener of committed session revocations (session.Announce): each connection the notice may concern re-checks its
// credential against the store, on its own goroutine, and closes 4401 when it is revoked.
func (h *Hub) revoked(notice session.Revocation) {
	for _, c := range h.matching(func(c *conn) bool { return notice.Names(c.sessionID, c.installationID, c.userID) }) {
		go c.recheckSession(context.Background())
	}
}

// Participant is the hub's part of the device revocation cascade (DC-06, CTR5-HUB-08), registered after fleet.NodeParticipant: in the
// revocation's transaction it counts the device's open channels, and once that transaction committed it closes them 4401.
func (h *Hub) Participant() Participant { return Participant{hub: h} }

// Participant is the cascade participant of a hub.
type Participant struct{ hub *Hub }

// Name is the participant's name in the device.revoked audit counts.
func (Participant) Name() string { return "fleet.channel" }

// RevokeDevice closes the device's channels after the revocation commits and counts them.
func (p Participant) RevokeDevice(ctx context.Context, _ pgx.Tx, _, deviceID platform.ID, _ time.Time) (int64, error) {
	if p.hub == nil {
		return 0, nil
	}
	selected := p.hub.matching(func(c *conn) bool { return c.deviceID == deviceID })
	store.AfterCommit(ctx, func() {
		for _, c := range p.hub.matching(func(c *conn) bool { return c.deviceID == deviceID }) {
			c.closeWith(CloseCredential, "revoked")
		}
	})
	return int64(len(selected)), nil
}

// reconnectHint is a jittered reconnect delay of a 4500 close, between ReconnectMin and ReconnectMax.
func (h *Hub) reconnectHint() time.Duration {
	span := h.settings.ReconnectMax - h.settings.ReconnectMin
	if span <= 0 {
		return h.settings.ReconnectMin
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return h.settings.ReconnectMin
	}
	return h.settings.ReconnectMin + time.Duration(n.Int64())
}

// Bind gives the hub the identity surface's authorizer, verifier and gate, which the composition builds after the hub (the hub's
// participant must be registered with the identity service first).
func (h *Hub) Bind(authorizer *access.Authorizer, verifier *session.Verifier, gate feature.Gate) {
	h.authorizer, h.verifier, h.gate = authorizer, verifier, gate
}

// Disabled is the route's handler where the relay surface is off: 404 with its reason, before anything of the request is read.
func Disabled() http.Handler {
	h := &Hub{clock: time.Now, logger: slog.New(slog.DiscardHandler), metrics: observe.NewMetrics(), surface: func() bool { return false }}
	return h
}

// maxSigningKids is ChannelAccepted's bound of signing_kids.
const maxSigningKids = 8

// UseSigningKids sets the kids of the command keys the center holds (CheckCommandKeys at the start: valid keys whose private half is
// loaded), newest first. ChannelAccepted lists the ones still valid at each acceptance, at least one (the contract's bound).
func (h *Hub) UseSigningKids(kids []string) {
	h.mu.Lock()
	h.kids = append([]string(nil), kids...)
	h.mu.Unlock()
}

// signingKids are the held command keys valid now, newest first, at most eight: the keys a call of this connection may be signed with
// (the center signs from AF-CTR-05 E1b on). A store that does not answer leaves the held list as the start found it.
func (h *Hub) signingKids(ctx context.Context, now time.Time) []string {
	h.mu.Lock()
	held := append([]string(nil), h.kids...)
	h.mu.Unlock()
	var kids []string
	err := h.db.InTx(ctx, "read the signing keys of a channel", store.TxOptions{ReadOnly: true, Timeout: presenceTimeout}, func(ctx context.Context, tx pgx.Tx) error {
		keys, err := platform.ValidKeys(ctx, tx, platform.CommandSigning, now)
		kids = kids[:0]
		for _, key := range keys {
			if len(kids) < maxSigningKids && slices.Contains(held, key.KID) {
				kids = append(kids, key.KID)
			}
		}
		return err
	})
	if err != nil {
		h.logger.Warn("the signing keys of a channel could not be read", "error", err.Error())
		return held[:min(len(held), maxSigningKids)]
	}
	return kids
}

// SetGate replaces the gate the lapse re-check asks (the composition binds the authorizer's; the lapse tests put one that changes its
// answer in its place).
func (h *Hub) SetGate(gate feature.Gate) {
	h.mu.Lock()
	h.gate = gate
	h.mu.Unlock()
}

func (h *Hub) currentGate() feature.Gate {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.gate
}
