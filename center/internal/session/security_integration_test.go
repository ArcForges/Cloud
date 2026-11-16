// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"context"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/dbtest"
)

// Real row locks prove account-before-session order for current refresh, spent
// refresh reuse and browser renewal. Attempts=1 makes a deadlock observable.
func TestRefreshAndRenewSerializeBehindAccountSecurityMutation(t *testing.T) {
	db := dbtest.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	policy := config.DefaultIdentityPolicy()
	for _, kind := range []string{"current_refresh", "spent_refresh", "browser_renew"} {
		t.Run(kind, func(t *testing.T) {
			user := db.Account(1)
			now := time.Now().UTC().Truncate(time.Microsecond)
			nativeSession, installation := native(t, db, user, ScopeAccount, "arcforges-mobile", now)
			token := nativeSession.RefreshToken
			if kind == "spent_refresh" {
				if _, _, err := Refresh(ctx, db.Runtime, policy, token, AccountRefresh(installation), now, nil, nil); err != nil {
					t.Fatal(err)
				}
			}
			browser := db.Session(user, 1)
			var handle Secret
			copy(handle[:], browser.Handle)
			tx, err := db.Migration.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err = tx.Exec(ctx, `SELECT 1 FROM identity.user WHERE user_id=$1 FOR UPDATE`, user); err != nil {
				t.Fatal(err)
			}
			type result struct {
				err  error
				live bool
			}
			done := make(chan result, 1)
			go func() {
				if kind == "browser_renew" {
					_, live, err := Renew(ctx, db.Runtime, policy, handle, now)
					done <- result{err, live}
					return
				}
				admission := AccountRefresh(installation)
				admission.Attempts = 1
				_, _, err := Refresh(ctx, db.Runtime, policy, token, admission, now, nil, nil)
				done <- result{err: err}
			}()
			waited := false
			for deadline := time.Now().Add(8 * time.Second); !waited && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
				select {
				case outcome := <-done:
					t.Fatalf("session operation crossed the account lock: %v", outcome.err)
				default:
				}
				var waiting int
				if err = tx.QueryRow(ctx, `SELECT count(*) FROM pg_locks l WHERE NOT l.granted AND pg_backend_pid()=ANY(pg_blocking_pids(l.pid))`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				waited = waiting > 0
			}
			if !waited {
				t.Fatal("session operation never waited behind account mutation")
			}
			if _, err = tx.Exec(ctx, `UPDATE identity.account_security_state SET auth_epoch=auth_epoch+1,recovery_generation=recovery_generation+1,
changed_at=greatest(changed_at,$2),rev=rev+1 WHERE user_id=$1`, user, now); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `UPDATE identity.session SET revoked_at=$2,revoke_reason=2,rev=rev+1 WHERE user_id=$1 AND revoked_at IS NULL`, user, now); err != nil {
				t.Fatal("reversed session/account lock order", err)
			}
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case outcome := <-done:
				if kind == "browser_renew" {
					if outcome.err != nil || outcome.live {
						t.Fatal("revoked browser was renewed", outcome.err)
					}
				} else if refusalKey(outcome.err) != "AUTHENTICATION/credential_revoked" {
					t.Fatal("refresh crossed the generation fence", outcome.err)
				}
			case <-ctx.Done():
				t.Fatal("session operation did not settle", ctx.Err())
			}
		})
	}
}
