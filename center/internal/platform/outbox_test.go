// SPDX-License-Identifier: AGPL-3.0-only

package platform

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/store"
)

// recorder is a sink that records every delivery; before is called first and can fail or crash the publication.
type recorder struct {
	mu         sync.Mutex
	deliveries []Delivery
	before     func(Delivery) error
}

func (r *recorder) Publish(_ context.Context, delivery Delivery) error {
	if r.before != nil {
		if err := r.before(delivery); err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deliveries = append(r.deliveries, delivery)
	return nil
}

func (r *recorder) count(key string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, delivery := range r.deliveries {
		if delivery.DedupKey == key {
			n++
		}
	}
	return n
}

func message(key string) Message {
	return Message{DedupKey: key, Topic: "test.counter.incremented", AggregateKind: "counter", AggregateID: NewID(), AggregateRev: 1,
		Payload: []byte("payload " + key), CorrelationID: NewID()}
}

// commitWithMessage commits a business change and its outbox message together.
func commitWithMessage(t *testing.T, f fixture, key string) {
	t.Helper()
	err := f.db.InTx(context.Background(), "business change", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		if err := increment(ctx, tx, "outbox"); err != nil {
			return err
		}
		_, err := Enqueue(ctx, tx, message(key))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (f fixture) outboxState(t *testing.T, key string) (state int16, attempts int) {
	t.Helper()
	if err := f.migration.QueryRow(context.Background(), "SELECT state, attempts FROM platform.outbox WHERE dedup_key = $1", key).Scan(&state, &attempts); err != nil {
		t.Fatal(err)
	}
	return state, attempts
}

func TestAMessageCommitsWithItsChangeOrNotAtAll(t *testing.T) {
	f := setup(t)
	commitWithMessage(t, f, "committed")
	rolledBack := errors.New("rolled back")
	err := f.db.InTx(context.Background(), "business change", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := Enqueue(ctx, tx, message("rolled-back")); err != nil {
			return err
		}
		return rolledBack
	})
	if !errors.Is(err, rolledBack) {
		t.Fatal(err)
	}
	var keys []string
	rows, _ := f.migration.Query(context.Background(), "SELECT dedup_key FROM platform.outbox ORDER BY sequence")
	keys, err = pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(keys) != 1 || keys[0] != "committed" {
		t.Fatalf("outbox %v %v", keys, err)
	}
	// Enqueueing the same dedup key again is a no-op.
	err = f.db.InTx(context.Background(), "enqueue again", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		enqueued, err := Enqueue(ctx, tx, message("committed"))
		if err == nil && enqueued {
			return errors.New("a duplicate dedup key was enqueued")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTheOutboxIsPublishedAfterACrashBetweenCommitAndPublish(t *testing.T) {
	f := setup(t)
	commitWithMessage(t, f, "event-1")
	// The first publisher claims the message, the sink receives it, and the process dies before the message is marked.
	sink := &recorder{}
	crashing, crash := context.WithCancel(context.Background())
	sink.before = func(Delivery) error { return nil }
	first := &Publisher{DB: f.db, Sink: crashingSink{sink, crash}, Lease: time.Second}
	if _, err := first.PublishOnce(crashing); err == nil {
		t.Fatal("the crashed pass reported success")
	}
	if state, attempts := f.outboxState(t, "event-1"); state != outboxPending || attempts != 1 || sink.count("event-1") != 1 {
		t.Fatalf("after the crash: state %d attempts %d deliveries %d", state, attempts, sink.count("event-1"))
	}
	// Before the lease ends nobody else takes it; after it, a new publisher delivers it again and marks it.
	second := &Publisher{DB: f.db, Sink: sink, Lease: time.Second}
	if report, err := second.PublishOnce(context.Background()); err != nil || report.Claimed != 0 {
		t.Fatalf("within the lease: %+v %v", report, err)
	}
	time.Sleep(1100 * time.Millisecond)
	report, err := second.PublishOnce(context.Background())
	if err != nil || report.Dispatched != 1 {
		t.Fatalf("after the lease: %+v %v", report, err)
	}
	if state, attempts := f.outboxState(t, "event-1"); state != outboxDispatched || attempts != 2 || sink.count("event-1") != 2 {
		t.Fatalf("at least once: state %d attempts %d deliveries %d", state, attempts, sink.count("event-1"))
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.deliveries[1].Attempt != 2 || sink.deliveries[0].DedupKey != sink.deliveries[1].DedupKey {
		t.Fatalf("the redelivery must carry the same dedup key and the next attempt: %+v", sink.deliveries)
	}
}

// crashingSink delivers and then kills the publishing process's context before the message can be marked.
type crashingSink struct {
	sink  *recorder
	crash context.CancelFunc
}

func (c crashingSink) Publish(ctx context.Context, delivery Delivery) error {
	err := c.sink.Publish(ctx, delivery)
	c.crash()
	return err
}

func TestConcurrentPublishersDeliverEveryMessage(t *testing.T) {
	f := setup(t)
	const messages = 60
	for index := range messages {
		commitWithMessage(t, f, fmt.Sprintf("m-%02d", index))
	}
	sink := &recorder{}
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			publisher := &Publisher{DB: f.db, Sink: sink, Batch: 7}
			for {
				report, err := publisher.PublishOnce(context.Background())
				if err != nil {
					t.Error(err)
					return
				}
				if report.Claimed == 0 {
					return
				}
			}
		})
	}
	group.Wait()
	for index := range messages {
		key := fmt.Sprintf("m-%02d", index)
		if state, _ := f.outboxState(t, key); state != outboxDispatched || sink.count(key) < 1 {
			t.Fatalf("%s: state %d deliveries %d", key, state, sink.count(key))
		}
	}
}

func TestAFailingSinkRetriesThenDeadLetters(t *testing.T) {
	f := setup(t)
	commitWithMessage(t, f, "poison")
	sink := &recorder{before: func(Delivery) error { return errors.New("the queue refused the message") }}
	publisher := &Publisher{DB: f.db, Sink: sink, MaxAttempts: 2}
	if report, err := publisher.PublishOnce(context.Background()); err != nil || report.Failed != 1 {
		t.Fatalf("first failure: %+v %v", report, err)
	}
	// Make it available now instead of waiting for the backoff.
	if _, err := f.migration.Exec(context.Background(), "UPDATE platform.outbox SET available_at = now() WHERE dedup_key = 'poison'"); err != nil {
		t.Fatal(err)
	}
	if report, err := publisher.PublishOnce(context.Background()); err != nil || report.DeadLettered != 1 {
		t.Fatalf("second failure: %+v %v", report, err)
	}
	var lastError string
	if err := f.migration.QueryRow(context.Background(), "SELECT last_error FROM platform.outbox WHERE dedup_key = 'poison'").Scan(&lastError); err != nil || lastError != "the queue refused the message" {
		t.Fatalf("last error %q %v", lastError, err)
	}
	if state, _ := f.outboxState(t, "poison"); state != outboxDeadLettered {
		t.Fatalf("state %d", state)
	}
}
