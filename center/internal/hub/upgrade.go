// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/jackc/pgx/v5"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/pages"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// upgradePolicy is the policy the authorizer sees for the channel's upgrade: the route's path (the row fleet.nodeChannel), a session
// route of the relay surface.
var upgradePolicy = ingress.Policy{FullName: routes.NodeChannelPath, Kind: ingress.Unary, Authentication: ingress.Session, Scope: ingress.NoScope,
	Surface: routes.SurfaceRelay}

// ServeHTTP admits and upgrades one node channel (CTR5-HUB-02). Every refusal before the upgrade is an HTTP answer with the refusal
// as a JSON ArcError and its closed reason in the ArcForges-Refusal header (PN-3); after the upgrade, a RelayClose and a close code.
func (h *Hub) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	call := correlation.ForRequest(request.Header.Values(ingress.TraceparentHeader), "")
	if !h.surface() {
		// A disabled surface: the path is not served.
		h.refuse(writer, call, http.StatusNotFound, arc.NotActivated(routes.SurfaceRelay))
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		h.refuse(writer, call, http.StatusMethodNotAllowed, arc.InvalidArgument("method", "not_admitted"))
		return
	}
	if refusal := admissible(request); refusal != nil {
		h.metrics.ObserveChannel("refused", "request")
		h.refuse(writer, call, http.StatusBadRequest, refusal)
		return
	}
	fence, serving := h.serving()
	if !serving {
		// This process does not hold the hub lease (another one does, or it is stopping): retry shortly; the node reconnects to
		// whichever process holds it (PB-5).
		h.metrics.ObserveChannel("refused", "lease")
		h.refuse(writer, call, 0, arc.Unavailable())
		return
	}
	clientIP, known := h.clientIP(request)
	if !known && h.options.RequireClientIP {
		h.refuse(writer, call, http.StatusBadRequest, arc.InvalidArgument("client", "not_admitted"))
		return
	}
	// The credential: a native bearer only. A cookie is never read on this route (PN-4: a cookie-only upgrade is unauthenticated).
	token, ok := ingress.BearerToken(request.Header)
	if !ok || h.verifier == nil {
		h.metrics.ObserveChannel("refused", "credential")
		h.refuse(writer, call, 0, arc.Unauthenticated())
		return
	}
	ctx := request.Context()
	caller, expires, err := h.verifier.VerifyNative(ctx, token)
	switch {
	case errors.Is(err, ingress.ErrTokenExpired):
		h.metrics.ObserveChannel("refused", "credential")
		h.refuse(writer, call, 0, arc.TokenExpired())
		return
	case errors.Is(err, ingress.ErrCredentialRevoked):
		h.metrics.ObserveChannel("refused", "credential")
		h.refuse(writer, call, 0, arc.CredentialRevoked())
		return
	case err != nil:
		h.refuse(writer, call, 0, arc.Unavailable())
		return
	case caller == nil:
		h.metrics.ObserveChannel("refused", "credential")
		h.refuse(writer, call, 0, arc.Unauthenticated())
		return
	}
	// The operation row: the node scope, the upgrade-rate buckets, access.authorized, the gate of center.nodes (in that order).
	admitted := &ingress.Call{Policy: upgradePolicy, Caller: *caller, Correlation: call, ClientIP: clientIP}
	if h.options.ClientOrigin != nil {
		admitted.Origin = h.options.ClientOrigin(request)
	}
	_, err = h.authorizer.Authorize(ctx, admitted)
	admitted.Finish()
	if err != nil {
		h.metrics.ObserveChannel("refused", "authorization")
		h.refuseError(writer, call, err)
		return
	}
	node, err := h.liveNode(ctx, *caller)
	switch {
	case err != nil:
		h.refuse(writer, call, 0, arc.Unavailable())
		return
	case node == nil:
		// A credential whose installation has no live node row is no node credential any more (C0 E-14).
		h.metrics.ObserveChannel("refused", "node")
		h.refuse(writer, call, 0, arc.Unauthenticated())
		return
	}
	release := func() {}
	if h.options.Slot != nil {
		var free bool
		if release, free = h.options.Slot(request); !free {
			h.metrics.ObserveChannel("refused", "connections")
			h.refuse(writer, call, 0, arc.Unavailable())
			return
		}
	}
	// PN-1: the server's read and write deadlines were set on the connection before this handler ran. Go's Hijack clears them as well
	// (net/http conn.hijackLocked), so this clear keeps the channel independent of that behaviour rather than being its only guard; the
	// channel's own deadlines are the heartbeat deadline and the write timeout, and the composed server's test holds a channel past both
	// of the server's timeouts.
	controller := http.NewResponseController(writer)
	if err := controller.SetReadDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		release()
		h.refuse(writer, call, 0, arc.Unavailable())
		return
	}
	if err := controller.SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		release()
		h.refuse(writer, call, 0, arc.Unavailable())
		return
	}
	ws, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{routes.NodeChannelSubprotocol},
		CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		release()
		h.metrics.ObserveChannel("refused", "handshake")
		return
	}
	// The hub bounds every message itself (4413), so the library's own limit is off.
	ws.SetReadLimit(-1)
	c := &conn{hub: h, ws: ws, sessionID: parseID(caller.SessionID), userID: parseID(caller.UserID), deviceID: parseID(caller.DeviceID),
		installationID: parseID(caller.InstallationID), nodeID: node.nodeID, enrollmentID: node.enrollmentID, publicKey: node.publicKey,
		connectionID: platform.NewID(), fence: fence, accessExpires: expires, queue: make(chan []byte, h.settings.SendQueueFrames),
		finished: make(chan struct{})}
	if raw := correlation.IDBytes(call.CorrelationID); len(raw) == 16 {
		var id platform.ID
		copy(id[:], raw)
		c.correlationID = &id
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	if !h.track(c) {
		release()
		c.cancel()
		_ = ws.Close(websocket.StatusCode(CloseShuttingDown), "shutting_down")
		return
	}
	h.metrics.ObserveChannel("opened", "upgraded")
	// The handler returns at once; the connection is served on its own goroutines, and its slot is released when it ends.
	go func() {
		defer release()
		c.run()
	}()
}

// admissible checks the upgrade request's shape (CTR5-HUB-02): exactly the upgrade headers of RFC 6455 version 13, the route's one
// subprotocol, no query, no body.
func admissible(request *http.Request) *arc.Refusal {
	header := request.Header
	switch {
	case request.URL.RawQuery != "" || strings.Contains(request.RequestURI, "?"):
		return arc.InvalidArgument("query", "not_admitted")
	case request.ContentLength != 0 || len(request.TransferEncoding) > 0:
		return arc.InvalidArgument("body", "not_admitted")
	case !headerHasToken(header, "Upgrade", "websocket") || !headerHasToken(header, "Connection", "upgrade"):
		return arc.InvalidArgument("upgrade", "required")
	case len(header.Values("Sec-WebSocket-Version")) != 1 || header.Get("Sec-WebSocket-Version") != "13":
		return arc.InvalidArgument("version", "not_admitted")
	case len(header.Values("Sec-WebSocket-Key")) != 1:
		return arc.InvalidArgument("key", "required")
	}
	offered := 0
	for _, line := range header.Values("Sec-WebSocket-Protocol") {
		for item := range strings.SplitSeq(line, ",") {
			if strings.TrimSpace(item) != routes.NodeChannelSubprotocol {
				return arc.InvalidArgument("subprotocol", "not_admitted")
			}
			offered++
		}
	}
	if offered != 1 {
		return arc.InvalidArgument("subprotocol", "required")
	}
	return nil
}

// headerHasToken reports whether a comma-separated header lists a token (case-insensitive).
func headerHasToken(header http.Header, name, token string) bool {
	for _, line := range header[textproto.CanonicalMIMEHeaderKey(name)] {
		for item := range strings.SplitSeq(line, ",") {
			if strings.EqualFold(strings.TrimSpace(item), token) {
				return true
			}
		}
	}
	return false
}

func (h *Hub) clientIP(request *http.Request) (netip.Addr, bool) {
	if h.options.ClientIP == nil {
		return netip.Addr{}, false
	}
	return h.options.ClientIP(request)
}

// liveNodeRow is the live node of a credential's installation and the installation's registered key.
type liveNodeRow struct {
	nodeID, enrollmentID platform.ID
	publicKey            []byte
}

// liveNode reads the live node row of the credential's installation in its account, with the key registered for that installation:
// the key the hello is verified against (D0-B2), whatever the hello names.
func (h *Hub) liveNode(ctx context.Context, caller ingress.Caller) (*liveNodeRow, error) {
	var row liveNodeRow
	found := true
	err := h.db.InTx(ctx, "read the node of a channel", store.TxOptions{ReadOnly: true, Timeout: presenceTimeout}, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT n.node_id, n.enrollment_id, i.public_key FROM fleet.node n
JOIN device.installation i ON i.installation_id = n.installation_id
WHERE n.installation_id = $1 AND n.user_id = $2 AND n.revoked_at IS NULL AND i.revoked_at IS NULL AND i.public_key IS NOT NULL`,
			parseID(caller.InstallationID), parseID(caller.UserID)).Scan(&row.nodeID, &row.enrollmentID, &row.publicKey)
		if errors.Is(err, pgx.ErrNoRows) {
			found = false
			return nil
		}
		return err
	})
	if err != nil || !found {
		return nil, err
	}
	return &row, nil
}

// parseID is the ID of a canonical UUID text the verifier produced (the zero ID for anything else, which matches no row).
func parseID(text string) platform.ID {
	var id platform.ID
	if raw := correlation.IDBytes(text); len(raw) == len(id) {
		copy(id[:], raw)
	}
	return id
}

// refuseError answers an authorizer's error: its refusal, a gate failure's overloaded, or a store failure's overloaded.
func (h *Hub) refuseError(writer http.ResponseWriter, call correlation.Context, err error) {
	var refusal *arc.Refusal
	if errors.As(err, &refusal) {
		h.refuse(writer, call, 0, refusal)
		return
	}
	h.logger.Warn("the node channel's admission could not be decided", "correlationId", call.CorrelationID, "error", err.Error())
	h.refuse(writer, call, 0, arc.Unavailable())
}

// refuse answers a refusal before the upgrade: the status of its category (or the one given), the JSON ArcError, and the closed reason
// in the ArcForges-Refusal header with Retry-After for a retry after time (PN-3).
func (h *Hub) refuse(writer http.ResponseWriter, call correlation.Context, status int, refusal *arc.Refusal) {
	now := h.clock()
	value := refusal.Dated(now).ArcError(call)
	if status == 0 {
		status = upgradeStatus(value)
	}
	header := writer.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set(routes.RefusalHeader, refusal.Key())
	if at := value.GetRetry().GetRetryAt(); at != nil && value.GetRetry().GetMode() == foundationv1.RetryMode_RETRY_MODE_AFTER_TIME {
		wait := time.Unix(at.GetUnixSeconds(), int64(at.GetNanos())).Sub(now)
		header.Set("Retry-After", strconv.FormatInt(max(1, int64((wait+time.Second-1)/time.Second)), 10))
	}
	body, err := pages.ErrorBody(value)
	if err != nil {
		writer.WriteHeader(status)
		return
	}
	header.Set("Content-Type", "application/json")
	header.Set("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}

// upgradeStatus is the HTTP status of a refused upgrade: 401 for a credential the node refreshes or replaces, 403 for authorization
// and entitlement, 400 for a request the route does not admit, 404 for a surface that is off, 429 for a rate limit, 503 for anything
// the node retries after a while (the hub lease, the connection bound, a store that did not answer).
func upgradeStatus(value *foundationv1.ArcError) int {
	switch value.GetCategory() {
	case foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHENTICATION:
		return http.StatusUnauthorized
	case foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHORIZATION, foundationv1.ErrorCategory_ERROR_CATEGORY_ENTITLEMENT:
		return http.StatusForbidden
	case foundationv1.ErrorCategory_ERROR_CATEGORY_VALIDATION:
		return http.StatusBadRequest
	case foundationv1.ErrorCategory_ERROR_CATEGORY_STATE:
		return http.StatusNotFound
	case foundationv1.ErrorCategory_ERROR_CATEGORY_RESOURCE:
		if value.GetCode() == "rate_limited" {
			return http.StatusTooManyRequests
		}
	}
	return http.StatusServiceUnavailable
}
