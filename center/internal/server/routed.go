// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/fleetapi"
	"github.com/ArcForges/Cloud/center/internal/hub"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// hubRouter is the hub as the routed API asks it (fleetapi.Router; AF-CTR-05 E2b): fleetapi does not import the hub (the hub's pages
// import the fleet server), so the composition adapts the one to the other. The relay of a relayed call is the value the authorizer's
// verifier returned (hub.VerifiedRelay); anything else is refused, never routed.
type hubRouter struct{ hub *hub.Hub }

func (r hubRouter) Routable() (int64, bool)           { return r.hub.Routable() }
func (r hubRouter) Connected(nodeID platform.ID) bool { return r.hub.Connected(nodeID) }

func (r hubRouter) Route(ctx context.Context, call fleetapi.RoutedCall) (fleetapi.RoutedResult, error) {
	routed := hub.Call{AccountID: call.AccountID, TargetNodeID: call.TargetNodeID, CommandID: call.CommandID, Method: call.Method, Payload: call.Payload,
		Deadline: call.Deadline}
	if call.Relay != nil {
		verified, ok := call.Relay.(hub.VerifiedRelay)
		if !ok || !verified.Verified() {
			return fleetapi.RoutedResult{}, arc.Unauthenticated()
		}
		routed.Relay = &verified
	} else {
		routed.Session = &hub.SessionCaller{UserID: call.UserID, SessionID: call.SessionID}
	}
	result, err := r.hub.Call(ctx, routed)
	if err != nil {
		return fleetapi.RoutedResult{}, err
	}
	return fleetapi.RoutedResult{Outcome: result.Outcome, Response: result.Response, ResponseSHA256: result.ResponseSHA256, ExecutedAt: result.ExecutedAt,
		Refusal: result.Refusal}, nil
}
