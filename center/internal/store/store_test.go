// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
)

func TestSanitizeKeepsTheStateAndDropsTheMessage(t *testing.T) {
	cases := map[string]error{
		"23505": ErrConflict, "23514": ErrConstraint, "40001": ErrContention, "40P01": ErrContention, "42501": ErrPermission,
		"57014": ErrTimeout, "08006": ErrUnavailable, "53300": ErrUnavailable, "57P01": ErrUnavailable, "42P01": ErrInternal,
	}
	for code, kind := range cases {
		err := Sanitize("op", &pgconn.PgError{Code: code, Message: "secret value 42", Detail: "Key (token)=(secret)", ConstraintName: "c"})
		if !errors.Is(err, kind) || strings.Contains(err.Error(), "secret") || !strings.Contains(err.Error(), code) {
			t.Errorf("%s: %v", code, err)
		}
	}
	if err := Sanitize("op", context.DeadlineExceeded); !errors.Is(err, ErrTimeout) {
		t.Error(err)
	}
	domain := errors.New("a domain error")
	if err := Sanitize("op", domain); err != domain {
		t.Error("a domain error was rewritten")
	}
}

func TestSerializationFailuresAreRetried(t *testing.T) {
	url, _ := pgtest.Database(t)
	setup := pgtest.Connect(t, url)
	if _, err := setup.Exec(context.Background(), "CREATE TABLE doctor (id int PRIMARY KEY, on_call boolean NOT NULL); INSERT INTO doctor VALUES (1, true), (2, true)"); err != nil {
		t.Fatal(err)
	}
	db := New(pgtest.Pool(t, url, 4))
	var attempts atomic.Int32
	var firstAttempts sync.WaitGroup
	firstAttempts.Add(2)
	// The classic write skew: each transaction checks that another doctor stays on call and takes one off. Both first attempts
	// read before either writes, so serializable isolation aborts one of them; the retry then sees the other's commit and keeps
	// the invariant (at least one doctor on call).
	leave := func(id int) error {
		first := true
		return db.InTx(context.Background(), "leave", TxOptions{Isolation: pgx.Serializable, Attempts: 5, Timeout: 30 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
			attempts.Add(1)
			var onCall int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM doctor WHERE on_call").Scan(&onCall); err != nil {
				return err
			}
			if first {
				first = false
				firstAttempts.Done()
				firstAttempts.Wait()
			}
			if onCall < 2 {
				return nil
			}
			_, err := tx.Exec(ctx, "UPDATE doctor SET on_call = false WHERE id = $1", id)
			return err
		})
	}
	var group sync.WaitGroup
	for id := 1; id <= 2; id++ {
		group.Go(func() {
			if err := leave(id); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	var onCall int
	if err := setup.QueryRow(context.Background(), "SELECT count(*) FROM doctor WHERE on_call").Scan(&onCall); err != nil {
		t.Fatal(err)
	}
	if onCall != 1 || attempts.Load() != 3 {
		t.Fatalf("%d doctors on call after %d attempts; expected 1 after one retry", onCall, attempts.Load())
	}
}

func TestADeadlineEndsTheTransaction(t *testing.T) {
	url, _ := pgtest.Database(t)
	db := New(pgtest.Pool(t, url, 2))
	started := time.Now()
	err := db.InTx(context.Background(), "slow", TxOptions{Timeout: 300 * time.Millisecond}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "SELECT pg_sleep(10)")
		return err
	})
	if !errors.Is(err, ErrTimeout) || time.Since(started) > 5*time.Second {
		t.Fatalf("%v after %s", err, time.Since(started))
	}
}
