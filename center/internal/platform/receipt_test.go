// SPDX-License-Identifier: AGPL-3.0-only

package platform

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/ArcForges/Cloud/center/internal/store"
)

func command(principal string, id ID, request string) Command {
	return Command{Principal: principal, CommandID: id, Operation: "/arcforges.test.v1.TestService/Increment", Request: []byte(request)}
}

func TestAReplayReturnsTheStoredResultAndRunsOnce(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	id := NewID()
	runs := 0
	run := func(ctx context.Context, tx pgx.Tx) ([]byte, error) {
		runs++
		return []byte("reply-1"), increment(ctx, tx, "replay")
	}
	first, err := Execute(ctx, f.db, command("account:1", id, "\x0a\x03abc"), store.TxOptions{}, run)
	if err != nil || first.Replayed || !first.Succeeded || string(first.Result) != "reply-1" {
		t.Fatalf("first: %+v %v", first, err)
	}
	second, err := Execute(ctx, f.db, command("account:1", id, "\x0a\x03abc"), store.TxOptions{}, run)
	if err != nil || !second.Replayed || !second.Succeeded || string(second.Result) != "reply-1" {
		t.Fatalf("replay: %+v %v", second, err)
	}
	if runs != 1 || f.counter(t, "replay") != 1 {
		t.Fatalf("the command ran %d times and changed the counter to %d", runs, f.counter(t, "replay"))
	}
}

func TestADifferentPayloadUnderTheSameIDIsRefused(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	id := NewID()
	run := func(ctx context.Context, tx pgx.Tx) ([]byte, error) {
		return []byte("ok"), increment(ctx, tx, "mismatch")
	}
	if _, err := Execute(ctx, f.db, command("account:1", id, "first"), store.TxOptions{}, run); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, f.db, command("account:1", id, "second"), store.TxOptions{}, run); !errors.Is(err, ErrCommandIDReused) {
		t.Fatalf("a different payload: %v", err)
	}
	other := command("account:1", id, "first")
	other.Operation = "/arcforges.test.v1.TestService/Other"
	if _, err := Execute(ctx, f.db, other, store.TxOptions{}, run); !errors.Is(err, ErrCommandIDReused) {
		t.Fatalf("a different operation: %v", err)
	}
	// The same ID of another principal is another command.
	if outcome, err := Execute(ctx, f.db, command("account:2", id, "second"), store.TxOptions{}, run); err != nil || outcome.Replayed {
		t.Fatalf("another principal: %+v %v", outcome, err)
	}
	if f.counter(t, "mismatch") != 2 {
		t.Fatalf("counter %d", f.counter(t, "mismatch"))
	}
}

func TestConcurrentDuplicatesExecuteOnce(t *testing.T) {
	for _, isolation := range []pgx.TxIsoLevel{pgx.ReadCommitted, pgx.Serializable} {
		t.Run(string(isolation), func(t *testing.T) {
			f := setup(t)
			id := NewID()
			var runs atomic.Int32
			const callers = 16
			outcomes := make([]Outcome, callers)
			failures := make([]error, callers)
			start := make(chan struct{})
			var group sync.WaitGroup
			for index := range callers {
				group.Go(func() {
					<-start
					outcomes[index], failures[index] = Execute(context.Background(), f.db, command("node:7", id, "payload"),
						store.TxOptions{Isolation: isolation, Attempts: 20}, func(ctx context.Context, tx pgx.Tx) ([]byte, error) {
							runs.Add(1)
							return []byte("once"), increment(ctx, tx, "concurrent")
						})
				})
			}
			close(start)
			group.Wait()
			fresh := 0
			for index := range callers {
				if failures[index] != nil {
					t.Fatalf("caller %d: %v", index, failures[index])
				}
				if !outcomes[index].Succeeded || !bytes.Equal(outcomes[index].Result, []byte("once")) {
					t.Fatalf("caller %d: %+v", index, outcomes[index])
				}
				if !outcomes[index].Replayed {
					fresh++
				}
			}
			if fresh != 1 || f.counter(t, "concurrent") != 1 {
				t.Fatalf("%d callers executed and the counter is %d (%d attempts ran the body)", fresh, f.counter(t, "concurrent"), runs.Load())
			}
		})
	}
}

func TestARefusalIsStoredAndItsChangesRolledBack(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	id := NewID()
	runs := 0
	run := func(ctx context.Context, tx pgx.Tx) ([]byte, error) {
		runs++
		if err := increment(ctx, tx, "refused"); err != nil {
			return nil, err
		}
		return nil, &Refusal{Code: "state.precondition_failed", Result: []byte("arc-error")}
	}
	first, err := Execute(ctx, f.db, command("account:1", id, "x"), store.TxOptions{}, run)
	if err != nil || first.Succeeded || first.ErrorCode != "state.precondition_failed" || string(first.Result) != "arc-error" {
		t.Fatalf("refusal: %+v %v", first, err)
	}
	second, err := Execute(ctx, f.db, command("account:1", id, "x"), store.TxOptions{}, run)
	if err != nil || !second.Replayed || second.ErrorCode != "state.precondition_failed" {
		t.Fatalf("replayed refusal: %+v %v", second, err)
	}
	if runs != 1 || f.counter(t, "refused") != 0 {
		t.Fatalf("runs %d counter %d", runs, f.counter(t, "refused"))
	}
}

func TestAnInfrastructureFailureStoresNoReceipt(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	id := NewID()
	broken := errors.New("the node did not answer")
	if _, err := Execute(ctx, f.db, command("account:1", id, "x"), store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) ([]byte, error) {
		if err := increment(ctx, tx, "retry"); err != nil {
			return nil, err
		}
		return nil, broken
	}); !errors.Is(err, broken) {
		t.Fatalf("failure: %v", err)
	}
	outcome, err := Execute(ctx, f.db, command("account:1", id, "x"), store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) ([]byte, error) {
		return []byte("second try"), increment(ctx, tx, "retry")
	})
	if err != nil || outcome.Replayed || string(outcome.Result) != "second try" || f.counter(t, "retry") != 1 {
		t.Fatalf("retry: %+v %v counter %d", outcome, err, f.counter(t, "retry"))
	}
}

func TestReceiptInputsAreBounded(t *testing.T) {
	f := setup(t)
	run := func(context.Context, pgx.Tx) ([]byte, error) { return nil, nil }
	if _, err := Execute(context.Background(), f.db, Command{CommandID: NewID(), Operation: "x"}, store.TxOptions{}, run); err == nil {
		t.Fatal("a command without a principal was accepted")
	}
	big := func(context.Context, pgx.Tx) ([]byte, error) { return make([]byte, MaxResultBytes+1), nil }
	if _, err := Execute(context.Background(), f.db, command("account:1", NewID(), "x"), store.TxOptions{}, big); err == nil {
		t.Fatal("an oversized result was stored")
	}
}

// TestLookupAnswersAReceiptWithoutRunning pins Lookup: no receipt is no answer; a stored success or refusal is answered as Execute
// would replay it; other bytes or another operation under the ID are a reuse; nothing is written.
func TestLookupAnswersAReceiptWithoutRunning(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	id, refused := NewID(), NewID()
	if _, found, err := Lookup(ctx, f.db, command("account:1", id, "abc")); err != nil || found {
		t.Fatalf("no receipt: %v %v", found, err)
	}
	if _, err := Execute(ctx, f.db, command("account:1", id, "abc"), store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) ([]byte, error) {
		return []byte("done"), increment(ctx, tx, "lookup")
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(ctx, f.db, command("account:1", refused, "abc"), store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) ([]byte, error) {
		return nil, &Refusal{Code: "STATE/not_found", Result: []byte("stored refusal")}
	}); err != nil {
		t.Fatal(err)
	}
	outcome, found, err := Lookup(ctx, f.db, command("account:1", id, "abc"))
	if err != nil || !found || !outcome.Replayed || !outcome.Succeeded || string(outcome.Result) != "done" {
		t.Fatalf("stored success: %+v %v %v", outcome, found, err)
	}
	outcome, found, err = Lookup(ctx, f.db, command("account:1", refused, "abc"))
	if err != nil || !found || outcome.Succeeded || outcome.ErrorCode != "STATE/not_found" || string(outcome.Result) != "stored refusal" {
		t.Fatalf("stored refusal: %+v %v %v", outcome, found, err)
	}
	if _, _, err = Lookup(ctx, f.db, command("account:1", id, "abd")); !errors.Is(err, ErrCommandIDReused) {
		t.Fatalf("other bytes: %v", err)
	}
	if _, found, err = Lookup(ctx, f.db, command("account:2", id, "abc")); err != nil || found {
		t.Fatalf("another principal's ID: %v %v", found, err)
	}
	if f.counter(t, "lookup") != 1 {
		t.Fatal("a lookup ran the command")
	}
}

// TestARetryWithItsOwnCorrelationIsTheSameRequest pins the receipt digest's input (B1): the request as transmitted without
// RequestMeta.correlation_id, every kept field byte for byte in wire order, and nothing else left out.
func TestARetryWithItsOwnCorrelationIsTheSameRequest(t *testing.T) {
	// field is one encoded field; a bytes field's value is passed with its length prefix.
	field := func(number protowire.Number, kind protowire.Type, value []byte) []byte {
		return append(protowire.AppendTag(nil, number, kind), value...)
	}
	// idField is an Id message {value: 16 bytes of fill} as field number.
	idField := func(number protowire.Number, fill byte) []byte {
		id := field(1, protowire.BytesType, protowire.AppendBytes(nil, bytes.Repeat([]byte{fill}, 16)))
		return field(number, protowire.BytesType, protowire.AppendBytes(nil, id))
	}
	meta := func(parts ...[]byte) []byte {
		return field(1, protowire.BytesType, protowire.AppendBytes(nil, bytes.Join(parts, nil)))
	}
	commandID, revision := idField(1, 0x11), field(2, protowire.BytesType, protowire.AppendBytes(nil, field(1, protowire.VarintType, protowire.AppendVarint(nil, 7))))
	unknown := field(9, protowire.VarintType, protowire.AppendVarint(nil, 3))
	body := field(10, protowire.BytesType, protowire.AppendBytes(nil, []byte("target")))
	digest := func(message []byte) []byte {
		t.Helper()
		input, err := RequestDigestInput(message)
		if err != nil {
			t.Fatal(err)
		}
		return input
	}
	plain := append(meta(commandID, revision, unknown), body...)
	if !bytes.Equal(digest(plain), plain) {
		t.Fatal("a request without a correlation is not digested as transmitted")
	}
	first := append(meta(commandID, idField(3, 0x21), revision, unknown), body...)
	again := append(meta(commandID, idField(3, 0x22), revision, unknown), body...)
	twice := append(meta(idField(3, 0x23), commandID, revision, idField(3, 0x24), unknown), body...)
	for name, message := range map[string][]byte{"one correlation": first, "another correlation": again, "two correlations": twice} {
		if !bytes.Equal(digest(message), plain) {
			t.Errorf("%s: %x, want %x", name, digest(message), plain)
		}
	}
	// Everything else is the request: meta's other fields, a second meta and the body.
	for name, message := range map[string][]byte{
		"another expected revision": append(meta(commandID, idField(3, 0x21), unknown), body...),
		"another command":           append(meta(idField(1, 0x12), idField(3, 0x21), revision, unknown), body...),
		"another body":              append(meta(commandID, idField(3, 0x21), revision, unknown), field(10, protowire.BytesType, protowire.AppendBytes(nil, []byte("other")))...),
		"another field order":       append(body, meta(commandID, idField(3, 0x21), revision, unknown)...),
		"a second meta":             append(append(meta(commandID, idField(3, 0x21), revision, unknown), meta(unknown)...), body...),
	} {
		if bytes.Equal(digest(message), digest(first)) {
			t.Errorf("%s digests as the first request", name)
		}
	}
	for _, malformed := range [][]byte{first[:len(first)-1], {0x0a, 0x05, 0x1a}, {0x80}} {
		if _, err := RequestDigestInput(malformed); err == nil {
			t.Errorf("a malformed request %x was digested", malformed)
		}
	}
}
