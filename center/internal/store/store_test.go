// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

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

// TestACommitErrorIsARollbackOnlyWhenTheServerSaysSo pins the classification of a COMMIT error (F6).
func TestACommitErrorIsARollbackOnlyWhenTheServerSaysSo(t *testing.T) {
	cases := map[string]struct {
		err        error
		rolledBack bool
	}{
		"a serialization failure":         {&pgconn.PgError{Code: "40001"}, true},
		"a deadlock":                      {&pgconn.PgError{Code: "40P01"}, true},
		"a transaction integrity error":   {&pgconn.PgError{Code: "40002"}, true},
		"a deferred unique violation":     {&pgconn.PgError{Code: "23505"}, true},
		"a deferred check violation":      {&pgconn.PgError{Code: "23514"}, true},
		"a transaction that had failed":   {pgx.ErrTxCommitRollback, true},
		"statement completion unknown":    {&pgconn.PgError{Code: "40003"}, false},
		"the pooler's protocol violation": {&pgconn.PgError{Code: "08P01"}, false},
		"an administrator shutdown":       {&pgconn.PgError{Code: "57P01"}, false},
		"a lost connection":               {io.ErrUnexpectedEOF, false},
		"a closed connection":             {net.ErrClosed, false},
		"a deadline":                      {context.DeadlineExceeded, false},
		"a cancellation":                  {context.Canceled, false},
		"an unknown error":                {errors.New("conn busy"), false},
	}
	for name, item := range cases {
		if commitRolledBack(item.err) != item.rolledBack {
			t.Errorf("%s: rolled back %v", name, !item.rolledBack)
		}
	}
}

// commitProxy relays connections to the test server and acts on the first COMMIT it sees while armed. "drop" forwards the COMMIT
// and closes the connection before the server's reply reaches the client: the server commits, the client sees the connection fail.
// "lose" closes the connection without forwarding the COMMIT: nothing commits, and the client sees the same failure.
type commitProxy struct {
	listener net.Listener
	target   string
	mode     atomic.Value
	commits  atomic.Int32
}

// commitMessage is the simple-query message pgx sends to commit: 'Q', its length (11) and "commit" with its terminator.
var commitMessage = append([]byte{'Q', 0, 0, 0, 11}, "commit\x00"...)

func newCommitProxy(t *testing.T, target string) *commitProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &commitProxy{listener: listener, target: target}
	proxy.mode.Store("")
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			go proxy.relay(client)
		}
	}()
	return proxy
}

func (p *commitProxy) relay(client net.Conn) {
	server, err := net.Dial("tcp", p.target)
	if err != nil {
		_ = client.Close()
		return
	}
	var cut atomic.Bool
	closeBoth := sync.OnceFunc(func() {
		_ = client.Close()
		_ = server.Close()
	})
	defer closeBoth()
	go func() {
		defer closeBoth()
		buffer := make([]byte, 32*1024)
		for {
			n, err := server.Read(buffer)
			if n > 0 {
				if cut.Load() {
					return // the COMMIT's reply never reaches the client
				}
				if _, err := client.Write(buffer[:n]); err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	buffer := make([]byte, 32*1024)
	var tail []byte
	for {
		n, err := client.Read(buffer)
		if n > 0 {
			window := append(tail, buffer[:n]...)
			if mode, _ := p.mode.Load().(string); mode != "" && bytes.Contains(window, commitMessage) {
				p.mode.Store("")
				p.commits.Add(1)
				if mode == "lose" {
					return
				}
				cut.Store(true)
			}
			if _, err := server.Write(buffer[:n]); err != nil {
				return
			}
			tail = append([]byte(nil), window[max(0, len(window)-len(commitMessage)+1):]...)
		}
		if err != nil {
			return
		}
	}
}

// TestACommitWithoutAnAnswerIsUnknownAndNeverRetried loses the connection of a COMMIT after the server committed, and before the
// COMMIT reached the server: both are ErrCommitUnknown, fn runs once, and only the first committed (F6). An auxiliary transaction
// (D10) reports the same two cases as ErrUnavailable, and never runs fn again either.
func TestACommitWithoutAnAnswerIsUnknownAndNeverRetried(t *testing.T) {
	url, _ := pgtest.Database(t)
	setup := pgtest.Connect(t, url)
	if _, err := setup.Exec(context.Background(), "CREATE TABLE ledger (id int PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	proxy := newCommitProxy(t, pgtest.Host(t))
	proxied := strings.Replace(url, "@"+pgtest.Host(t)+"/", "@"+proxy.listener.Addr().String()+"/", 1)
	if proxied == url {
		t.Fatal("the test URL does not name the server's host")
	}
	db := New(pgtest.Pool(t, proxied, 2))
	for index, item := range []struct {
		mode      string
		auxiliary bool
	}{{"drop", false}, {"lose", false}, {"drop", true}, {"lose", true}} {
		id, mode := index+1, item.mode
		var runs atomic.Int32
		proxy.mode.Store(mode)
		err := db.InTx(context.Background(), "insert", TxOptions{Timeout: 2 * time.Second, Auxiliary: item.auxiliary}, func(ctx context.Context, tx pgx.Tx) error {
			runs.Add(1)
			_, err := tx.Exec(ctx, "INSERT INTO ledger VALUES ($1)", id)
			return err
		})
		var stored int
		if scanErr := setup.QueryRow(context.Background(), "SELECT count(*) FROM ledger WHERE id = $1", id).Scan(&stored); scanErr != nil {
			t.Fatal(scanErr)
		}
		kind, other := ErrCommitUnknown, ErrUnavailable
		if item.auxiliary {
			kind, other = ErrUnavailable, ErrCommitUnknown
		}
		if !errors.Is(err, kind) || errors.Is(err, other) || runs.Load() != 1 || proxy.commits.Load() != int32(id) {
			t.Fatalf("%s (auxiliary %v): %v after %d runs (%d commits seen)", mode, item.auxiliary, err, runs.Load(), proxy.commits.Load())
		}
		if (mode == "drop") != (stored == 1) {
			t.Fatalf("%s: %d rows", mode, stored)
		}
	}
	// The proxy is disarmed: the next transaction commits normally.
	if err := db.InTx(context.Background(), "insert", TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO ledger VALUES (5)")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// A read-only transaction has no effect: a lost COMMIT reply is an ordinary connection failure, not an unknown commit.
	proxy.mode.Store("drop")
	err := db.InTx(context.Background(), "read", TxOptions{ReadOnly: true, Attempts: 1}, func(ctx context.Context, tx pgx.Tx) error {
		var count int
		return tx.QueryRow(ctx, "SELECT count(*) FROM ledger").Scan(&count)
	})
	if errors.Is(err, ErrCommitUnknown) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a read-only commit: %v", err)
	}
}

// TestAPanicInFnRollsBackAndReleasesTheConnection (D1): a callback that panics while it holds a row lock still ends its transaction
// and gives its connection back, as pgx.BeginTxFunc did: the pool's only connection is free, no session stays idle in a transaction,
// the row is unchanged and the next transaction takes its lock at once. The pool is the test's own and is closed with a bounded
// wait, so a leaked connection fails the test instead of hanging it.
func TestAPanicInFnRollsBackAndReleasesTheConnection(t *testing.T) {
	url, _ := pgtest.Database(t)
	setup := pgtest.Connect(t, url)
	ctx := context.Background()
	if _, err := setup.Exec(ctx, "CREATE TABLE counter (id int PRIMARY KEY, value int NOT NULL); INSERT INTO counter VALUES (1, 0)"); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 1
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		closed := make(chan struct{})
		go func() {
			pool.Close()
			close(closed)
		}()
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Error("pool.Close blocked: a connection was never given back")
		}
	}()
	db := New(pool)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("the callback's panic did not reach the caller")
			}
		}()
		_ = db.InTx(ctx, "panic", TxOptions{Timeout: 2 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "UPDATE counter SET value = value + 1 WHERE id = 1"); err != nil {
				return err
			}
			panic("a defect in the callback")
		})
	}()
	if acquired := pool.Stat().AcquiredConns(); acquired != 0 {
		t.Fatalf("%d connections stay acquired after the panic", acquired)
	}
	var idle int
	if err = setup.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND state LIKE 'idle in transaction%'").
		Scan(&idle); err != nil {
		t.Fatal(err)
	}
	if idle != 0 {
		t.Fatalf("%d sessions stay idle in a transaction after the panic", idle)
	}
	if err = db.InTx(ctx, "next", TxOptions{Timeout: 2 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE counter SET value = value + 10 WHERE id = 1")
		return err
	}); err != nil {
		t.Fatalf("the next transaction on the row: %v", err)
	}
	var value int
	if err = setup.QueryRow(ctx, "SELECT value FROM counter WHERE id = 1").Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != 10 {
		t.Fatalf("the row holds %d: the panicked transaction was not rolled back", value)
	}
}
