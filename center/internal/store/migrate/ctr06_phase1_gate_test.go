// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"errors"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/bridgeproof"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/jackc/pgx/v5"
)

func TestCTR06UnboundPublicBridgeEntriesRefuseBeforeEffects(t *testing.T) {
	ctx := context.Background()
	result, err := Apply(ctx, nil, nil, Options{BridgeProof: &bridgeproof.Verified{}})
	if result.State != StateRefused || !errors.Is(err, ErrCTR06SecurityBridgeUnbound) {
		t.Fatalf("old proof entry: %+v %v", result, err)
	}
	called := false
	result, err = ApplySelfHostedCTR06(ctx, nil, nil, Options{}, "/old-bridge", func(context.Context, PreparedBridgeRoles) (string, error) {
		called = true
		return "", nil
	})
	if called || result.State != StateRefused || !errors.Is(err, ErrCTR06SecurityBridgeUnbound) {
		t.Fatalf("self-hosted entry: called=%v result=%+v err=%v", called, result, err)
	}
	_, err = RestoreLegacy(ctx, config.Migration{}, "/archive", "digest", "/provenance", "digest", "runner",
		func(context.Context, *pgx.Conn, []Migration, PreparedBridgeRoles) (string, error) {
			called = true
			return "", nil
		})
	if called || !errors.Is(err, ErrCTR06SecurityBridgeUnbound) {
		t.Fatalf("legacy restore entry: called=%v err=%v", called, err)
	}
}
