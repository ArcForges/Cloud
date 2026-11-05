// SPDX-License-Identifier: AGPL-3.0-only

package routes

import (
	"fmt"
	"strings"
)

// SurfaceRelay is the relay surface: the node channel (AF-CTR-05 E1a; Plan CTR5-SUR-01, Q10, Q15). Its one route is served only where
// the surface is enabled; elsewhere the Worker answers 404 before any Container wakes, and the center answers 404 too.
const SurfaceRelay = "relay"

// The node channel (Plan CTR5-HUB-01): a WebSocket on GET <center>/fleet/v1/node with the subprotocol arcforges.relay.v1, binary
// messages, one relay.v1 RelayFrame per message.
const (
	// NodeChannelPath is the channel's path below the public base URL (the Worker owns APIPrefix in front of it).
	NodeChannelPath = "/fleet/v1/node"
	// NodeChannelID is the route's name and the operation ID of its row (access.Operations, fleet.nodeChannel).
	NodeChannelID = "fleet.nodeChannel"
	// NodeChannelSubprotocol is the one subprotocol the upgrade admits and the center selects.
	NodeChannelSubprotocol = "arcforges.relay.v1"
	// NodeChannelMaxFrameBytes is the largest message either side sends on the channel (Plan CTR5-HUB-03, C.9: 1 MiB): the
	// platform's WebSocket message limit (Cloudflare Workers and Durable Objects, 32 MiB) leaves ample headroom over it.
	NodeChannelMaxFrameBytes = 1 << 20
	// NodeChannelUpgradeMilliseconds bounds the Worker's budget for the upgrade itself (the admission's few short transactions and the
	// 101); the channel's own lifetime is the connection's, never a route budget.
	NodeChannelUpgradeMilliseconds = 15_000
)

// RefusalHeader is the response header that carries the closed reason of a refusal of the upgrade (Plan PN-3): a client such as .NET's
// ClientWebSocket sees only the status and the headers of a reply that is not 101, never its body. Its value is <CATEGORY>/<code>
// as errors.md names them (for example AUTHENTICATION/token_expired or RESOURCE/rate_limited); a refusal that advises a retry after
// time also carries Retry-After in whole seconds. The body is the same refusal as a JSON ArcError ({"error": ...}).
const RefusalHeader = "ArcForges-Refusal"

// The Worker's rules for a refusal of the upgrade it forwards (Plan PN-3; the Worker's generated table states them): only these
// statuses, a JSON body of at most UpgradeRefusalBytes, and the reason headers (RefusalHeader, Retry-After) only with a value of
// visible ASCII of at most 128 characters. Any other reply becomes the Worker's own 503.
const (
	UpgradeRefusalBytes        = 16384
	UpgradeRefusalValuePattern = `^[\x21-\x7e]{1,128}$`
)

// UpgradeRefusalStatuses are the statuses of the center's refusals before an upgrade (hub.ServeHTTP answers no other).
func UpgradeRefusalStatuses() []int { return []int{400, 401, 403, 404, 405, 429, 503} }

// UpgradeRoute is one WebSocket upgrade route (AF-CTR-05 E1a): an exact GET path that the Worker passes through to the center as an
// upgrade only (Upgrade: websocket, the route's subprotocol, a native bearer of the edge's shape, no query, no body, no cookie), and
// whose 101 it returns unchanged (Plan PN-2). The Worker's generated table (upgradeRoutes) and the center's ingress both read these rows.
type UpgradeRoute struct {
	// Path is the exact path below the public base URL; ID names the route.
	Path string
	ID   string
	// Surface is the switchable surface the route belongs to.
	Surface string
	// Subprotocol is the one WebSocket subprotocol the route admits.
	Subprotocol string
	// MaxFrameBytes bounds one message on the channel (the center enforces it; the Worker states it).
	MaxFrameBytes int
	// MaxDurationMilliseconds bounds the upgrade request itself, until the 101.
	MaxDurationMilliseconds int
	// Instance is the Container instance that serves the route: the one center instance (PLT-6, Plan PN-2: the single hub).
	Instance string
}

// RelayUpgradeRoutes are the upgrade routes of the relay surface: the node channel.
func RelayUpgradeRoutes() []UpgradeRoute {
	return []UpgradeRoute{{
		Path: NodeChannelPath, ID: NodeChannelID, Surface: SurfaceRelay, Subprotocol: NodeChannelSubprotocol, MaxFrameBytes: NodeChannelMaxFrameBytes,
		MaxDurationMilliseconds: NodeChannelUpgradeMilliseconds, Instance: HealthInstance,
	}}
}

// ErrUpgradeRegistration is the error of an inconsistent upgrade route.
var ErrUpgradeRegistration = fmt.Errorf("%w: inconsistent upgrade route", ErrRegistration)

// CheckUpgrades refuses an upgrade registration the Worker or the center could not serve safely: a path that is not canonical or looks
// like a method, a duplicate, a surface other than relay, a subprotocol that is not a token, a frame bound above 1 MiB, a budget out of
// range, or an instance other than the one center instance.
func CheckUpgrades(rows []UpgradeRoute) error {
	seen := map[string]bool{}
	for _, row := range rows {
		switch {
		case row.Surface != SurfaceRelay:
			return fmt.Errorf("%w: %s belongs to the surface %q", ErrUpgradeRegistration, row.ID, row.Surface)
		case row.Path == "" || row.Path[0] != '/' || strings.ContainsAny(row.Path, "?#%\\. ") || strings.Contains(row.Path, "//") || strings.HasSuffix(row.Path, "/"):
			return fmt.Errorf("%w: %s is not canonical", ErrUpgradeRegistration, row.Path)
		case seen[row.Path] || seen[row.ID] || row.ID == "":
			return fmt.Errorf("%w: %s is registered twice or unnamed", ErrUpgradeRegistration, row.Path)
		case !subprotocolPattern(row.Subprotocol):
			return fmt.Errorf("%w: %s has the subprotocol %q", ErrUpgradeRegistration, row.ID, row.Subprotocol)
		case row.MaxFrameBytes < 1024 || row.MaxFrameBytes > NodeChannelMaxFrameBytes:
			return fmt.Errorf("%w: %s has the frame bound %d", ErrUpgradeRegistration, row.ID, row.MaxFrameBytes)
		case row.MaxDurationMilliseconds < 1 || row.MaxDurationMilliseconds > PageDurationMilliseconds:
			return fmt.Errorf("%w: %s has the budget %d", ErrUpgradeRegistration, row.ID, row.MaxDurationMilliseconds)
		case row.Instance != HealthInstance:
			return fmt.Errorf("%w: %s is not served by the %s instance", ErrUpgradeRegistration, row.ID, HealthInstance)
		}
		seen[row.Path], seen[row.ID] = true, true
	}
	return nil
}

// subprotocolPattern is a WebSocket subprotocol of lower-case letters, digits, dots and hyphens (an RFC 6455 token).
func subprotocolPattern(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// Relay is the relay surface's module.
func Relay() (Module, error) {
	rows := RelayUpgradeRoutes()
	if err := CheckUpgrades(rows); err != nil {
		return Module{}, err
	}
	return Module{Name: "relay", Surface: SurfaceRelay, Upgrades: rows, Budgets: map[string]Budget{}}, nil
}
