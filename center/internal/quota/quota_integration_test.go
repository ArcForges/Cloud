// SPDX-License-Identifier: AGPL-3.0-only

package quota

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/ratelimit"
)

// The per-account resource controls (AF-CTR-05 part E0, CTR5-GATE-05; EVIDENCE: REAL controls, REAL rate-limit buckets over REAL
// PostgreSQL; MOCKED: the rows are fabricated gated rows, one per group, because no gated row is served before AF-CTR-05 E1 and E2).

// gatedRow is a fabricated gated row of a group, with the key the routed task control table names for it.
func gatedRow(group feature.Group) access.Operation {
	key, _ := feature.KeyOfGroup(group)
	return access.Operation{Path: "/arcforges.test.v1.QuotaProbe/" + string(group), ID: "probe." + string(group), Risk: "R2", Session: true, Feature: key, Group: group,
		Audit: access.AuditBeforeCall}
}

func callOf(account, installation string) *ingress.Call {
	return &ingress.Call{Caller: ingress.Caller{Credential: ingress.CredentialNativeBearer, UserID: account, InstallationID: installation, Scope: "account"}}
}

// refusedAs checks a refusal: RESOURCE/rate_limited naming the limit and its maximum, with a retry instant; never a plan limit.
func refusedAs(t *testing.T, err error, name string, maximum int64, retryAt time.Time) {
	t.Helper()
	var refusal *arc.Refusal
	if !errors.As(err, &refusal) || refusal.Key() != "RESOURCE/rate_limited" || refusal.Limit == nil || refusal.Limit.Name != name || refusal.Limit.Maximum != maximum ||
		!refusal.RetryAt.Equal(retryAt) {
		t.Fatalf("%v (%+v), want RESOURCE/rate_limited %s %d retry at %v", err, refusal, name, maximum, retryAt)
	}
	if refusal.Code == "plan_limit_reached" || refusal.Code == "quota_exceeded" {
		t.Fatalf("a control answered %s", refusal.Code)
	}
}

func TestTheCompositionsControlsCoverTheRoutedAndChannelGroupsOnly(t *testing.T) {
	controls := Controls(nil, config.DefaultIdentityPolicy(), nil)
	names := map[string]bool{}
	for _, control := range controls {
		names[control.Name()] = true
	}
	if len(names) != 3 || !names[RoutedCallsName] || !names[RoutedInFlightName] || !names[ChannelUpgradeName] {
		t.Fatalf("the controls: %v", names)
	}
	covered := []access.Operation{gatedRow(feature.GroupSubmission), gatedRow(feature.GroupStatusAndOutput), gatedRow(feature.GroupControl),
		gatedRow(feature.GroupNodeConnection)}
	if err := access.CheckControls(covered, controls); err != nil {
		t.Fatalf("the routed groups and the channel: %v", err)
	}
	// MCP (AF-CTR-07) and push (AF-CLD-06) bring their own controls: a row of theirs fails the composition until they do.
	for _, group := range []feature.Group{feature.GroupMCP, feature.GroupPush} {
		if access.CheckControls(append(covered, gatedRow(group)), controls) == nil {
			t.Errorf("a %s row was admitted without its own control", group)
		}
	}
	// No control stands in front of an essential row.
	for _, control := range controls {
		for _, operation := range access.Operations() {
			if control.Covers(operation) {
				t.Errorf("%s covers the essential row %s", control.Name(), operation.ID)
			}
		}
	}
}

// TestTheRoutedCallRateIsAnAccountBucket: the window's limit of routed calls is admitted, the next is refused RESOURCE/rate_limited
// with retry_at at the end of the window, another account is not affected, and the next window admits again.
func TestTheRoutedCallRateIsAnAccountBucket(t *testing.T) {
	db := dbtest.New(t)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	policy := config.DefaultIdentityPolicy()
	policy.RoutedCallsPerAccount = config.Window{Limit: 3, Window: time.Hour}
	control := Controls(db.Runtime, policy, func() time.Time { return now })[1]
	row := gatedRow(feature.GroupStatusAndOutput)
	account, other := platform.NewID().String(), platform.NewID().String()
	ctx := context.Background()
	for index := range 3 {
		if err := control.Admit(ctx, callOf(account, ""), row); err != nil {
			t.Fatalf("call %d: %v", index, err)
		}
	}
	refusedAs(t, control.Admit(ctx, callOf(account, ""), row), RoutedCallsName, 3, now.Add(time.Hour))
	if err := control.Admit(ctx, callOf(other, ""), row); err != nil {
		t.Fatalf("another account: %v", err)
	}
	now = now.Add(time.Hour)
	if err := control.Admit(ctx, callOf(account, ""), row); err != nil {
		t.Fatalf("the next window: %v", err)
	}
}

// TestTheInFlightControlReleasesItsSlotWhenTheCallEnds: the limit's number of calls run at once, the next is refused with a short
// retry_at, a slot comes back when its call finishes (once, however often Finish is called), and accounts do not share slots.
func TestTheInFlightControlReleasesItsSlotWhenTheCallEnds(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	control := NewRoutedInFlight(2, func() time.Time { return now })
	row := gatedRow(feature.GroupSubmission)
	ctx := context.Background()
	first, second, third := callOf("a", ""), callOf("a", ""), callOf("a", "")
	if control.Admit(ctx, first, row) != nil || control.Admit(ctx, second, row) != nil || control.Held("a") != 2 {
		t.Fatalf("two calls: %d held", control.Held("a"))
	}
	refusedAs(t, control.Admit(ctx, third, row), RoutedInFlightName, 2, now.Add(InFlightRetry))
	if err := control.Admit(ctx, callOf("b", ""), row); err != nil {
		t.Fatalf("another account: %v", err)
	}
	first.Finish()
	first.Finish()
	if control.Held("a") != 1 {
		t.Fatalf("after one call ended: %d held", control.Held("a"))
	}
	if err := control.Admit(ctx, third, row); err != nil {
		t.Fatalf("a slot that came back: %v", err)
	}
	second.Finish()
	third.Finish()
	if control.Held("a") != 0 {
		t.Fatalf("after every call ended: %d held", control.Held("a"))
	}
}

// TestTheChannelUpgradeRateIsAnAccountAndANodeBucket: the upgrade attempts of an account and of one node are each bounded (Q21: an
// upgrade rate, never a connected-node cap).
func TestTheChannelUpgradeRateIsAnAccountAndANodeBucket(t *testing.T) {
	db := dbtest.New(t)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	policy := config.DefaultIdentityPolicy()
	policy.ChannelUpgradePerAccount = config.Window{Limit: 4, Window: time.Hour}
	policy.ChannelUpgradePerNode = config.Window{Limit: 2, Window: 10 * time.Minute}
	control := Controls(db.Runtime, policy, func() time.Time { return now })[0]
	row := gatedRow(feature.GroupNodeConnection)
	ctx := context.Background()
	account := platform.NewID().String()
	for index := range 2 {
		if err := control.Admit(ctx, callOf(account, "node-1"), row); err != nil {
			t.Fatalf("attempt %d: %v", index, err)
		}
	}
	refusedAs(t, control.Admit(ctx, callOf(account, "node-1"), row), string(ratelimit.ChannelUpgradeNode), 2, now.Add(10*time.Minute))
	if err := control.Admit(ctx, callOf(account, "node-2"), row); err != nil {
		t.Fatalf("another node: %v", err)
	}
	// The account's fifth attempt (node-1's refused one counted in the account bucket too) is over the account's limit.
	refusedAs(t, control.Admit(ctx, callOf(account, "node-3"), row), ChannelUpgradeName, 4, now.Add(time.Hour))
}
