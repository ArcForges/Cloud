// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/store"
	"github.com/jackc/pgx/v5/pgconn"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
)

// TestTheSettledStateFollowsTheAnswer (decisions B-1, section 4 and section 5; review B N-12): the state an attempt's answer gives a
// record that is not final, for every kind of answer, the hub's not_found and invalid_argument included.
func TestTheSettledStateFollowsTheAnswer(t *testing.T) {
	dnh, unknown, happened := foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN, foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN,
		foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED
	cases := []struct {
		name      string
		answer    RoutedAnswer
		delivered bool
		state     RoutedState
		reached   bool
		final     bool
	}{
		{"the hub's not_found", RoutedAnswer{Effect: dnh, Refusal: "state/not_found"}, false, RoutedNotDelivered, false, false},
		{"the hub's invalid_argument", RoutedAnswer{Refusal: "validation/invalid_argument"}, false, RoutedNotDelivered, false, false},
		{"the hub's not_found after a delivered attempt", RoutedAnswer{Effect: dnh, Refusal: "state/not_found"}, true, RoutedUnknown, true, false},
		{"the hub's DID_NOT_HAPPEN after a delivered attempt", RoutedAnswer{Effect: dnh, Refusal: "state/node_offline"}, true, RoutedUnknown, true, false},
		{"the hub's UNKNOWN", RoutedAnswer{Effect: unknown, Refusal: "state/node_unreachable"}, false, RoutedUnknown, true, false},
		{"an executed value", RoutedAnswer{Verified: true, Outcome: 1}, false, RoutedSucceeded, true, true},
		{"a handler error that did not happen", RoutedAnswer{Verified: true, Outcome: 1, HandlerError: true, Effect: dnh, Refusal: "state/not_found"}, false, RoutedFailed, true, false},
		{"a handler error that happened", RoutedAnswer{Verified: true, Outcome: 1, HandlerError: true, Effect: happened, Refusal: "execution/operation_failed"}, false, RoutedFailed, true, true},
		{"a handler error of a resend that did not happen", RoutedAnswer{Verified: true, Outcome: 1, HandlerError: true, Effect: dnh}, true, RoutedUnknown, true, false},
		{"a handler error with an unknown effect", RoutedAnswer{Verified: true, Outcome: 1, HandlerError: true, Effect: unknown}, false, RoutedUnknown, true, false},
		{"a policy refusal that did not happen", RoutedAnswer{Verified: true, Outcome: 2, Effect: dnh}, false, RoutedRejected, true, false},
		{"a policy refusal that happened", RoutedAnswer{Verified: true, Outcome: 2, Effect: happened}, false, RoutedRejected, true, true},
		{"a verification refusal that did not happen", RoutedAnswer{Verified: true, Outcome: 3, Effect: dnh}, false, RoutedRejected, true, false},
		{"an expiry that did not happen", RoutedAnswer{Verified: true, Outcome: 4, Effect: dnh}, false, RoutedExpired, true, false},
		{"an expiry that happened", RoutedAnswer{Verified: true, Outcome: 4, Effect: happened}, false, RoutedExpired, true, true},
		{"a refusal whose effect is unknown", RoutedAnswer{Verified: true, Outcome: 2, Effect: unknown}, false, RoutedUnknown, true, false},
		// A resend (an earlier attempt may have reached the node; decisions R1): a refusal that did not happen leaves it UNKNOWN.
		{"a policy refusal of a resend that did not happen", RoutedAnswer{Verified: true, Outcome: 2, Effect: dnh}, true, RoutedUnknown, true, false},
		{"an expiry of a resend that did not happen", RoutedAnswer{Verified: true, Outcome: 4, Effect: dnh}, true, RoutedUnknown, true, false},
		{"a policy refusal of a resend that happened", RoutedAnswer{Verified: true, Outcome: 2, Effect: happened}, true, RoutedRejected, true, true},
	}
	for _, c := range cases {
		state, reached, final := settled(c.answer, c.delivered)
		if state != c.state || reached != c.reached || final != c.final {
			t.Errorf("%s: %s %v %v", c.name, state, reached, final)
		}
	}
}

func TestComparableReplayRequiresARecordedOutcome(t *testing.T) {
	cases := []struct {
		name       string
		answer     RoutedAnswer
		comparable bool
	}{
		{"unverified", RoutedAnswer{Outcome: 1}, false},
		{"node refusal", RoutedAnswer{Verified: true, Outcome: 2}, false},
		{"success", RoutedAnswer{Verified: true, Outcome: 1}, true},
		{"happened handler error", RoutedAnswer{Verified: true, Outcome: 1, HandlerError: true, Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED}, true},
		{"did not happen handler error", RoutedAnswer{Verified: true, Outcome: 1, HandlerError: true, Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN}, false},
		{"unknown handler error", RoutedAnswer{Verified: true, Outcome: 1, HandlerError: true, Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN}, false},
		{"unspecified handler error", RoutedAnswer{Verified: true, Outcome: 1, HandlerError: true, Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNSPECIFIED}, false},
	}
	for _, test := range cases {
		if got := test.answer.ComparableReplay(); got != test.comparable {
			t.Errorf("%s: comparable = %v, want %v", test.name, got, test.comparable)
		}
	}
}

// The bridge only changes the named cross-namespace violation. In particular,
// unrelated unique constraints, cancellation and unanswered commits retain
// the original store behavior.
func TestFutureRoutedNamespaceConflictIsNarrow(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"exact", &pgconn.PgError{Code: "23505", ConstraintName: "routed_command_id_namespace"}, true},
		{"wrapped exact", fmt.Errorf("wrapped: %w", &pgconn.PgError{Code: "23505", ConstraintName: "routed_command_id_namespace"}), true},
		{"different constraint", &pgconn.PgError{Code: "23505", ConstraintName: "different_unique"}, false},
		{"different SQLSTATE", &pgconn.PgError{Code: "23503", ConstraintName: "routed_command_id_namespace"}, false},
		{"unanswered commit", store.ErrCommitUnknown, false},
		{"unrelated", errors.New("unrelated"), false},
		{"nil", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := routedNamespaceConflict(tc.err); got != tc.want {
				t.Fatalf("mapped = %v, want %v", got, tc.want)
			}
		})
	}
}
