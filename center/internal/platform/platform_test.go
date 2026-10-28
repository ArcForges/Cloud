// SPDX-License-Identifier: AGPL-3.0-only

package platform

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/store"
)

func TestTheInboxAppliesARedeliveredMessageOnce(t *testing.T) {
	f := setup(t)
	var applied atomic.Int32
	receive := func() error {
		return f.db.InTx(context.Background(), "webhook", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
			first, err := Receive(ctx, tx, "paddle", "evt_01", 0)
			if err != nil || !first {
				return err
			}
			applied.Add(1)
			if err = increment(ctx, tx, "inbox"); err != nil {
				return err
			}
			return Processed(ctx, tx, "paddle", "evt_01", InboxApplied)
		})
	}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if err := receive(); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if applied.Load() != 1 || f.counter(t, "inbox") != 1 {
		t.Fatalf("applied %d times, counter %d", applied.Load(), f.counter(t, "inbox"))
	}
	// A message whose transaction rolled back was never received.
	failed := errors.New("failed")
	err := f.db.InTx(context.Background(), "webhook", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := Receive(ctx, tx, "paddle", "evt_02", 0); err != nil {
			return err
		}
		return failed
	})
	if !errors.Is(err, failed) {
		t.Fatal(err)
	}
	err = f.db.InTx(context.Background(), "webhook", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		first, err := Receive(ctx, tx, "paddle", "evt_02", 0)
		if err == nil && !first {
			return errors.New("a rolled-back delivery was remembered")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func scheduleJobs(t *testing.T, f fixture, count int) []ID {
	t.Helper()
	ids := make([]ID, count)
	err := f.db.InTx(context.Background(), "schedule", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		for index := range ids {
			ids[index] = NewID()
			if _, err := Schedule(ctx, tx, ids[index], "test.job", []byte(fmt.Sprint(index)), time.Now().Add(-time.Second)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func TestAnExpiredLeaseIsFencedOut(t *testing.T) {
	f := setup(t)
	scheduleJobs(t, f, 1)
	ctx := context.Background()
	stale, err := Claim(ctx, f.db, "test.job", "worker-a", time.Second)
	if err != nil || stale == nil || stale.Fence != 1 {
		t.Fatalf("claim: %+v %v", stale, err)
	}
	if again, err := Claim(ctx, f.db, "test.job", "worker-b", time.Second); err != nil || again != nil {
		t.Fatalf("a leased job was claimed twice: %+v %v", again, err)
	}
	time.Sleep(1100 * time.Millisecond)
	current, err := Claim(ctx, f.db, "test.job", "worker-b", time.Minute)
	if err != nil || current == nil || current.Fence != 2 || current.Attempts != 2 {
		t.Fatalf("reclaim: %+v %v", current, err)
	}
	// The stale holder can neither write under its fence, renew nor complete.
	err = f.db.InTx(ctx, "stale write", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		if err := stale.Fenced(ctx, tx); err != nil {
			return err
		}
		return increment(ctx, tx, "fenced")
	})
	if !errors.Is(err, ErrLeaseLost) || f.counter(t, "fenced") != 0 {
		t.Fatalf("stale write: %v counter %d", err, f.counter(t, "fenced"))
	}
	if err = stale.Renew(ctx, f.db, time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale renew: %v", err)
	}
	err = f.db.InTx(ctx, "stale completion", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error { return stale.Complete(ctx, tx) })
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale completion: %v", err)
	}
	err = f.db.InTx(ctx, "completion", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		if err := current.Fenced(ctx, tx); err != nil {
			return err
		}
		if err := increment(ctx, tx, "fenced"); err != nil {
			return err
		}
		return current.Complete(ctx, tx)
	})
	if err != nil || f.counter(t, "fenced") != 1 {
		t.Fatalf("completion: %v counter %d", err, f.counter(t, "fenced"))
	}
	if next, err := Claim(ctx, f.db, "test.job", "worker-c", time.Minute); err != nil || next != nil {
		t.Fatalf("a completed job was claimed: %+v %v", next, err)
	}
}

func TestConcurrentClaimersTakeEachJobOnce(t *testing.T) {
	f := setup(t)
	ids := scheduleJobs(t, f, 30)
	var mu sync.Mutex
	claimed := map[ID]int{}
	var group sync.WaitGroup
	for worker := range 5 {
		group.Go(func() {
			for {
				lease, err := Claim(context.Background(), f.db, "test.job", fmt.Sprintf("worker-%d", worker), time.Minute)
				if err != nil {
					t.Error(err)
					return
				}
				if lease == nil {
					return
				}
				mu.Lock()
				claimed[lease.JobID]++
				mu.Unlock()
				if err = f.db.InTx(context.Background(), "complete", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error { return lease.Complete(ctx, tx) }); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	group.Wait()
	for _, id := range ids {
		if claimed[id] != 1 {
			t.Fatalf("job %s was claimed %d times", id, claimed[id])
		}
	}
}

func TestAFailedJobRetriesThenDeadLetters(t *testing.T) {
	f := setup(t)
	scheduleJobs(t, f, 1)
	ctx := context.Background()
	for attempt := 1; attempt <= 2; attempt++ {
		lease, err := Claim(ctx, f.db, "test.job", "worker", time.Minute)
		if err != nil || lease == nil {
			t.Fatalf("attempt %d: %+v %v", attempt, lease, err)
		}
		if err = lease.Fail(ctx, f.db, time.Now().Add(-time.Second), 2, "transient"); err != nil {
			t.Fatal(err)
		}
	}
	var state int16
	if err := f.migration.QueryRow(ctx, "SELECT state FROM platform.job_lease").Scan(&state); err != nil || state != jobDeadLettered {
		t.Fatalf("state %d %v", state, err)
	}
}

func TestTheAuditChainSerializesAppendsAndDetectsTampering(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	correlation := NewID()
	var group sync.WaitGroup
	for writer := range 8 {
		group.Go(func() {
			for index := range 6 {
				err := f.db.InTx(ctx, "audit", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
					_, err := AppendAudit(ctx, tx, Event{EventID: NewID(), ActorRef: fmt.Sprintf("account:%d", writer), EventType: "node.revoked",
						CorrelationID: &correlation, TargetKind: "node", TargetID: fmt.Sprint(index), Payload: []byte(`{"sha256":"…"}`)})
					return err
				})
				if err != nil {
					t.Error(err)
				}
			}
		})
	}
	group.Wait()
	runtimeCount, err := VerifyAudit(ctx, f.db.Pool())
	if err != nil || runtimeCount != 48 {
		t.Fatalf("verify: %d %v", runtimeCount, err)
	}
	// The runtime role cannot rewrite history; the owner cannot update it either (the trigger refuses), and a deletion breaks
	// the chain.
	err = f.db.InTx(ctx, "tamper", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE audit.audit_event SET reason = 'x' WHERE sequence = 3")
		return err
	})
	if !errors.Is(err, store.ErrPermission) {
		t.Fatalf("runtime update: %v", err)
	}
	if _, err = f.migration.Exec(ctx, "UPDATE audit.audit_event SET reason = 'x' WHERE sequence = 3"); !pgtest.IsCode(err, "42501") {
		t.Fatalf("owner update: %v", err)
	}
	if _, err = f.migration.Exec(ctx, "DELETE FROM audit.audit_event WHERE sequence = 3"); err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyAudit(ctx, f.migration); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("a removed event was not detected: %v", err)
	}
}

func es256(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestSigningKeysRotateWithOverlap(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	register := func(key SigningKey) error {
		return pgx.BeginFunc(ctx, f.migration, func(tx pgx.Tx) error { return RegisterKey(ctx, tx, key, now) })
	}
	first := SigningKey{KID: "cmd-2026-10", Purpose: CommandSigning, Algorithm: "ES256", PublicKey: es256(t), SecretBinding: "CENTER_COMMAND_KEY_A",
		NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour)}
	if err := register(first); err != nil {
		t.Fatal(err)
	}
	gap := first
	gap.KID, gap.NotBefore, gap.NotAfter = "cmd-2027-gap", first.NotAfter.Add(-24*time.Hour), first.NotAfter.Add(90*24*time.Hour)
	if err := register(gap); err == nil {
		t.Fatal("a successor with less than the minimum overlap was accepted")
	}
	second := first
	second.KID, second.SecretBinding, second.NotBefore, second.NotAfter = "cmd-2027-01", "CENTER_COMMAND_KEY_B", now.Add(30*24*time.Hour), now.Add(180*24*time.Hour)
	second.PublicKey = es256(t)
	if err := register(second); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]SigningKey{
		"long":      {KID: "cmd-long-01", Purpose: CommandSigning, Algorithm: "ES256", PublicKey: es256(t), SecretBinding: "X", NotBefore: now, NotAfter: now.Add(MaxKeyValidity + time.Hour)},
		"backdated": {KID: "cmd-back-01", Purpose: RelayHMAC, Algorithm: "HS256", SecretBinding: "X", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)},
		"algorithm": {KID: "cmd-alg-001", Purpose: CommandSigning, Algorithm: "HS256", SecretBinding: "X", NotBefore: now, NotAfter: now.Add(time.Hour)},
		"no key":    {KID: "cmd-nokey-1", Purpose: EntitlementToken, Algorithm: "ES256", SecretBinding: "X", NotBefore: now, NotAfter: now.Add(time.Hour)},
		"binding":   {KID: "relay-0001", Purpose: RelayHMAC, Algorithm: "HS256", SecretBinding: "lowercase", NotBefore: now, NotAfter: now.Add(time.Hour)},
	} {
		if err := register(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The runtime role reads the verification set: the first key alone now, both once the successor is valid.
	keys, err := ValidKeys(ctx, f.db.Pool(), CommandSigning, now.Add(time.Minute))
	if err != nil || len(keys) != 1 || keys[0].KID != "cmd-2026-10" {
		t.Fatalf("now: %+v %v", keys, err)
	}
	keys, err = ValidKeys(ctx, f.db.Pool(), CommandSigning, now.Add(60*24*time.Hour))
	if err != nil || len(keys) != 2 || keys[0].KID != "cmd-2027-01" {
		t.Fatalf("overlap: %+v %v", keys, err)
	}
}
