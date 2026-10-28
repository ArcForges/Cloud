// SPDX-License-Identifier: AGPL-3.0-only

package platform

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The restore drill (docs/postgres-store.md, Recovery): `python eng/center.py check` on Linux migrates a database with the
// native executable, runs the seed phase against it with the runtime credential, dumps it with pg_dump, restores the dump into a
// second, isolated PostgreSQL server, migrates and rotates there, and runs the verify phase against the restored database. The
// phases skip outside the drill.
const (
	envDrillPhase      = "ARCFORGES_DRILL_PHASE"
	envDrillRuntimeURL = "ARCFORGES_DRILL_RUNTIME_URL"
)

var (
	drillCommand = ID{0xd1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x81, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	drillJob     = ID{0xd1, 0x22, 0x22, 0x22, 0x22, 0x22, 0x42, 0x22, 0x82, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22}
)

func TestRestoreDrill(t *testing.T) {
	phase, runtimeURL := os.Getenv(envDrillPhase), os.Getenv(envDrillRuntimeURL)
	if phase == "" || runtimeURL == "" {
		t.Skip("restore drill phase: run by python eng/center.py check on Linux")
	}
	db := store.New(pgtest.Pool(t, runtimeURL, 4))
	ctx := context.Background()
	cmd := Command{Principal: "account:drill", CommandID: drillCommand, Operation: "/arcforges.test.v1.Drill/Seed", Request: []byte("drill request")}
	switch phase {
	case "seed":
		outcome, err := Execute(ctx, db, cmd, store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) ([]byte, error) {
			if _, err := Enqueue(ctx, tx, Message{DedupKey: "drill-event", Topic: "test.drill", AggregateKind: "drill", AggregateID: drillCommand,
				AggregateRev: 1, Payload: []byte("drill payload"), CorrelationID: drillCommand}); err != nil {
				return nil, err
			}
			if _, err := Schedule(ctx, tx, drillJob, "test.drill", []byte("job"), time.Now().Add(-time.Minute)); err != nil {
				return nil, err
			}
			for index := range 3 {
				if _, err := AppendAudit(ctx, tx, Event{EventID: NewID(), ActorRef: "account:drill", EventType: "drill.seeded", TargetKind: "drill",
					TargetID: string(rune('a' + index))}); err != nil {
					return nil, err
				}
			}
			return []byte("drill reply"), nil
		})
		if err != nil || outcome.Replayed {
			t.Fatalf("seed: %+v %v", outcome, err)
		}
	case "verify":
		// The restored receipt answers the replay without running the command.
		outcome, err := Execute(ctx, db, cmd, store.TxOptions{}, func(context.Context, pgx.Tx) ([]byte, error) {
			return nil, errors.New("the restored command ran again")
		})
		if err != nil || !outcome.Replayed || !bytes.Equal(outcome.Result, []byte("drill reply")) {
			t.Fatalf("receipt replay: %+v %v", outcome, err)
		}
		// The restored outbox message is published.
		sink := &recorder{}
		if report, err := (&Publisher{DB: db, Sink: sink}).PublishOnce(ctx); err != nil || report.Dispatched != 1 || sink.count("drill-event") != 1 {
			t.Fatalf("outbox: %+v %v", report, err)
		}
		// The restored job is claimed and completed under its fence.
		lease, err := Claim(ctx, db, "test.drill", "drill", time.Minute)
		if err != nil || lease == nil || lease.JobID != drillJob {
			t.Fatalf("job: %+v %v", lease, err)
		}
		if err = db.InTx(ctx, "complete", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error { return lease.Complete(ctx, tx) }); err != nil {
			t.Fatal(err)
		}
		// The restored audit chain verifies and keeps growing.
		if count, err := VerifyAudit(ctx, db.Pool()); err != nil || count != 3 {
			t.Fatalf("audit: %d %v", count, err)
		}
		err = db.InTx(ctx, "audit", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
			_, err := AppendAudit(ctx, tx, Event{EventID: NewID(), ActorRef: "account:drill", EventType: "drill.verified"})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if count, err := VerifyAudit(ctx, db.Pool()); err != nil || count != 4 {
			t.Fatalf("audit after restore: %d %v", count, err)
		}
	default:
		t.Fatalf("unknown drill phase %q", phase)
	}
}
