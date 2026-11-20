// SPDX-License-Identifier: AGPL-3.0-only

package entitlement

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

func TestCommerceBindsAndShortensTheOriginalPaidPeriod(t *testing.T) {
	db := newDatabase(t)
	clock := &testClock{now: at(110)}
	source := &fixedDefinitions{definitions: Definitions{Version: "hosted-commerce-test", Capabilities: []CapabilityDefinition{
		{Key: "center.nodes", RequiresPaidTerm: true}, {Key: "remote.view", RequiresPaidTerm: true}, {Key: "remote.control", RequiresPaidTerm: true},
	}}}
	service := NewService(db.runtime, source, nil, clock.Now)
	ctx := t.Context()
	account := db.account()
	grace := at(340)
	paid := CommerceTerm{SubscriptionRef: "sub_test", PeriodRef: "period_test", StartsAt: at(100), EndsAt: at(300), GraceEndsAt: &grace,
		Features: []string{"remote.control", "center.nodes", "remote.view"}}
	change := CommerceChange{AccountID: account, DefinitionsVersion: "hosted-commerce-test", EventRef: "event_paid", NewTerm: &paid}
	apply := func(change CommerceChange, afterApply error) (CommerceResult, error) {
		var result CommerceResult
		err := db.runtime.InTx(ctx, "apply test commerce facts", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
			var err error
			if result, err = service.ApplyCommerce(ctx, tx, change); err != nil {
				return err
			}
			return afterApply
		})
		return result, err
	}
	if _, err := apply(change, nil); !errors.Is(err, ErrDefinitionsSuperseded) {
		t.Fatalf("payment used unrecorded definitions: %v", err)
	}
	if recorded, err := service.RecordDefinitions(ctx, clock.Now()); err != nil || recorded != Recorded {
		t.Fatalf("record hosted definitions: %v %v", recorded, err)
	}
	badVersion := change
	badVersion.DefinitionsVersion = "unrelated"
	if _, err := apply(badVersion, nil); !errors.Is(err, ErrCommerceDefinitions) {
		t.Fatalf("payment used another catalogue's definitions: %v", err)
	}
	legacy := paid
	legacy.Features = []string{"center.nodes", "remote.view", "center.execute"}
	badFeature := change
	badFeature.NewTerm = &legacy
	if _, err := apply(badFeature, nil); !errors.Is(err, ErrCommerceFact) {
		t.Fatalf("a paid V2 offer issued a retired capability: %v", err)
	}
	rollback := errors.New("reject the caller's receipt")
	if _, err := apply(change, rollback); !errors.Is(err, rollback) {
		t.Fatalf("rolling back the caller's receipt: %v", err)
	}
	if db.count("SELECT count(*) FROM entitlement.service_term") != 0 ||
		db.count("SELECT count(*) FROM entitlement.grant") != 0 ||
		db.count("SELECT count(*) FROM entitlement.revision") != 0 ||
		db.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'entitlement.commerce.applied'") != 0 {
		t.Fatal("rolled-back payment left entitlement or audit effects")
	}
	first, err := apply(change, nil)
	if err != nil || !first.Changed || first.TermID == "" || len(first.GrantIDs) != 3 {
		t.Fatalf("verified payment: %+v %v", first, err)
	}
	checkGate := func(want bool) {
		t.Helper()
		snapshot, err := service.Read(ctx, account)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range hostedServiceKeys {
			entry, ok := snapshot.Capability(key)
			if !ok || entry.Granted != want {
				t.Fatalf("%s allowed=%t, got %+v", key, want, entry)
			}
		}
	}
	checkGate(true)
	change.EventRef = "event_other_delivery"
	again, err := apply(change, nil)
	if err != nil || again.Changed || again.TermID != first.TermID || again.Version != first.Version || !slices.Equal(again.GrantIDs, first.GrantIDs) {
		t.Fatalf("same period: %+v %v", again, err)
	}
	clock.At(180)
	autoRenew := false
	ending := CommerceTermEnd{TermID: first.TermID, GrantIDs: first.GrantIDs, EffectiveAt: at(150)}
	refund := CommerceChange{AccountID: account, DefinitionsVersion: "hosted-commerce-test", EventRef: "event_refund",
		EndTerms: []CommerceTermEnd{ending}, AutoRenew: &autoRenew}
	unmatched := ending
	unmatched.GrantIDs = slices.Clone(ending.GrantIDs)
	unmatched.GrantIDs[0] = platform.NewID().String()
	bad := refund
	bad.EndTerms = []CommerceTermEnd{unmatched}
	if _, err := apply(bad, nil); !errors.Is(err, ErrCommerceFact) {
		t.Fatalf("a refund accepted an unrelated grant: %v", err)
	}
	checkGate(true)
	if result, err := apply(refund, nil); err != nil || !result.Changed {
		t.Fatalf("verified refund: %+v %v", result, err)
	}
	checkGate(false)
	clock.At(200)
	refund.EventRef = "event_later_end"
	refund.EndTerms[0].EffectiveAt = at(170)
	if result, err := apply(refund, nil); err != nil || result.Changed {
		t.Fatalf("late weaker shortening: %+v %v", result, err)
	}
	change.EventRef = "event_late_paid"
	if result, err := apply(change, nil); err != nil || result.Changed || result.TermID != first.TermID {
		t.Fatalf("late paid event reissued the refunded period: %+v %v", result, err)
	}
	checkGate(false)
	if db.count("SELECT count(*) FROM entitlement.service_term WHERE term_id = $1::uuid AND ends_at = $2 AND grace_ends_at = $3",
		first.TermID, paid.EndsAt.Time(), grace.Time()) != 1 ||
		db.count("SELECT count(*) FROM entitlement.service_term_action WHERE term_id = $1::uuid AND effective_at = $2", first.TermID, at(150).Time()) != 1 ||
		db.count("SELECT count(*) FROM entitlement.grant WHERE effective_until = $1", paid.EndsAt.Time()) != 3 ||
		db.count("SELECT count(*) FROM entitlement.revocation WHERE effective_from = $1", at(150).Time()) != 3 ||
		db.count("SELECT count(*) FROM entitlement.account_status_fact WHERE NOT auto_renew AND status = 1") != 1 ||
		db.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'entitlement.commerce.applied'") != 2 {
		t.Fatal("original observations, narrower effects, or transactional audit were lost")
	}
	if report, err := service.VerifyRebuild(ctx, account); err != nil || report.Status != RebuildEqual {
		t.Fatalf("rebuild after payment and refund: %+v %v", report, err)
	}
}
