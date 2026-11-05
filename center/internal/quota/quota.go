// SPDX-License-Identifier: AGPL-3.0-only

// Package quota is the per-account resource controls of the center's gated rows (AF-CTR-05 part E0, CTR5-GATE-05; DC-07): the
// access.Control implementations the composition registers with access.WithControls. Each control stands in front of the rows of its
// groups of the routed task control table (feature.OperationKeys) and runs before the audit and the gate, so an account that exhausted
// one is refused before access.authorized is appended and before the entitlement is read (docs/center-entitlement.md, "the reason the
// control comes first").
//
//   - RoutedCalls: the routed calls of an account (submission, status and output, control), a request bucket of package ratelimit
//     (routed_calls_per_account), refused RESOURCE/rate_limited with retry_at at the end of the window.
//   - RoutedInFlight: the routed calls of an account that run at once (routed_in_flight_per_account), counted by this process and
//     released when the call ends (ingress.Call.AfterCall), refused RESOURCE/rate_limited with a short retry_at.
//   - ChannelUpgrades: the node channel's upgrade attempts of an account and of one node (channel_upgrades_per_account,
//     channel_upgrades_per_node), request buckets in front of the node channel's row (fleet.nodeChannel, AF-CTR-05 E1a).
//
// Every number is a policy key of config.IdentityPolicy whose default is an owner placeholder under H-07 (illustrative only). None is a
// plan limit: the plan catalogue carries no limit, no refusal here says plan_limit_reached, and there is no connected-node cap (Q21:
// the enrollment cap, MaxNodesPerAccount, governs how many nodes an account has).
package quota

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/ratelimit"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The names of the controls: their policy keys and the limit names of their refusals.
const (
	RoutedCallsName    = string(ratelimit.RoutedCallsAccount)
	RoutedInFlightName = "routed_in_flight_per_account"
	ChannelUpgradeName = string(ratelimit.ChannelUpgradeAccount)
)

// InFlightRetry is the retry_at of a refusal of RoutedInFlight: a slot frees when one of the account's calls ends, so the caller may
// try again shortly.
const InFlightRetry = time.Second

// routedGroups are the groups of the routed operations: submission, status and output, control (not the node channel, MCP or push).
var routedGroups = []feature.Group{feature.GroupSubmission, feature.GroupStatusAndOutput, feature.GroupControl}

// Routed reports whether an operation row is a gated row of a routed group.
func Routed(operation access.Operation) bool {
	return operation.Feature != "" && slices.Contains(routedGroups, operation.Group)
}

// Channel reports whether an operation row is the gated node channel (the node connection group).
func Channel(operation access.Operation) bool {
	return operation.Feature != "" && operation.Group == feature.GroupNodeConnection
}

// Controls are the center's resource controls, in the order Authorize runs them: the channel upgrades, then the routed calls' rate
// and in-flight bounds. The clock is the composition's.
func Controls(db *store.DB, policy config.IdentityPolicy, clock func() time.Time) []access.Control {
	if clock == nil {
		clock = time.Now
	}
	limiter := ratelimit.New(db)
	return []access.Control{
		&ChannelUpgrades{limiter: limiter, account: policy.ChannelUpgradePerAccount, node: policy.ChannelUpgradePerNode, clock: clock},
		&RoutedCalls{limiter: limiter, window: policy.RoutedCallsPerAccount, clock: clock},
		NewRoutedInFlight(policy.RoutedInFlightPerAccount, clock),
	}
}

// accountKey is the bucket key of the caller's account.
func accountKey(call *ingress.Call) string { return "account:" + call.Caller.UserID }

// RoutedCalls is the rate of an account's routed calls (routed_calls_per_account).
type RoutedCalls struct {
	limiter *ratelimit.Limiter
	window  config.Window
	clock   func() time.Time
}

// Name is the control's policy key.
func (*RoutedCalls) Name() string { return RoutedCallsName }

// Covers is every gated row of a routed group.
func (*RoutedCalls) Covers(operation access.Operation) bool { return Routed(operation) }

// Admit counts the call in the account's bucket and refuses it over the limit.
func (c *RoutedCalls) Admit(ctx context.Context, call *ingress.Call, _ access.Operation) error {
	return take(ctx, c.limiter, ratelimit.Bucket{Kind: ratelimit.RoutedCallsAccount, Key: accountKey(call), Window: c.window}, c.clock())
}

// ChannelUpgrades is the rate of the node channel's upgrade attempts, of an account and of one node.
type ChannelUpgrades struct {
	limiter       *ratelimit.Limiter
	account, node config.Window
	clock         func() time.Time
}

// Name is the control's policy key.
func (*ChannelUpgrades) Name() string { return ChannelUpgradeName }

// Covers is the gated node channel row.
func (*ChannelUpgrades) Covers(operation access.Operation) bool { return Channel(operation) }

// Admit counts the attempt in the account's bucket, then in the node's (a node credential names its installation), and refuses it
// over either limit.
func (c *ChannelUpgrades) Admit(ctx context.Context, call *ingress.Call, _ access.Operation) error {
	now := c.clock()
	if err := take(ctx, c.limiter, ratelimit.Bucket{Kind: ratelimit.ChannelUpgradeAccount, Key: accountKey(call), Window: c.account}, now); err != nil {
		return err
	}
	if call.Caller.InstallationID == "" {
		return nil
	}
	return take(ctx, c.limiter, ratelimit.Bucket{Kind: ratelimit.ChannelUpgradeNode, Key: "node:" + call.Caller.InstallationID, Window: c.node}, now)
}

// take counts one request of a bucket and answers its refusal (RESOURCE/rate_limited, the bucket's kind as the limit name, retry_at
// at the end of the window), or the store failure.
func take(ctx context.Context, limiter *ratelimit.Limiter, bucket ratelimit.Bucket, now time.Time) error {
	decision, err := limiter.Take(ctx, bucket, now)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return decision.Refusal(bucket)
	}
	return nil
}

// RoutedInFlight bounds the routed calls of an account that run at once in this process (routed_in_flight_per_account). A slot is
// taken before the audit and the gate and given back when the call ends, whatever it answered (ingress.Call.AfterCall).
type RoutedInFlight struct {
	limit int
	clock func() time.Time
	mu    sync.Mutex
	held  map[string]int
}

// NewRoutedInFlight is the in-flight control of a limit.
func NewRoutedInFlight(limit int, clock func() time.Time) *RoutedInFlight {
	if clock == nil {
		clock = time.Now
	}
	return &RoutedInFlight{limit: limit, clock: clock, held: map[string]int{}}
}

// Name is the control's policy key.
func (*RoutedInFlight) Name() string { return RoutedInFlightName }

// Covers is every gated row of a routed group.
func (*RoutedInFlight) Covers(operation access.Operation) bool { return Routed(operation) }

// Admit takes one of the account's slots, or refuses the call when every slot is held.
func (c *RoutedInFlight) Admit(_ context.Context, call *ingress.Call, _ access.Operation) error {
	account := accountKey(call)
	c.mu.Lock()
	if c.held[account] >= c.limit {
		c.mu.Unlock()
		return arc.RateLimited(RoutedInFlightName, int64(c.limit), c.clock().Add(InFlightRetry))
	}
	c.held[account]++
	c.mu.Unlock()
	released := false
	call.AfterCall(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if released {
			return
		}
		released = true
		if c.held[account]--; c.held[account] <= 0 {
			delete(c.held, account)
		}
	})
	return nil
}

// Held is the number of slots an account holds (tests and metrics).
func (c *RoutedInFlight) Held(account string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.held["account:"+account]
}
