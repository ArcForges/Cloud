// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/fleetapi"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// Test-only SQL seeds future public rows; registration uses the supported CLI or its exact transaction callback.
func TestSigningKeyAdmissionSerializesEveryPublishedPurpose(t *testing.T) {
	url, name := pgtest.Database(t)
	directory := t.TempDir()
	values := map[string]string{
		"ARCFORGES_CENTER_MODE": "self-hosted", "ARCFORGES_CENTER_MIGRATION_DATABASE_URL": url,
		"ARCFORGES_CENTER_DATABASE_NAME": name + "_center", "ARCFORGES_CENTER_RUNTIME_ROLE": name + "_runtime",
		"ARCFORGES_CENTER_RUNTIME_SECRET_FILE": filepath.Join(directory, "runtime.json"),
		"ARCFORGES_CENTER_RUNTIME_POOLED_HOST": pgtest.Host(t),
	}
	t.Cleanup(func() { pgtest.Drop(t, name+"_center") })
	command := func(args ...string) (int, string) {
		var stdout, stderr bytes.Buffer
		code := run(args, environment(values), &stdout, &stderr)
		return code, stderr.String()
	}
	for _, args := range [][]string{{"admin", "ensure-database"}, {"migrate"}} {
		if code, text := command(args...); code != 0 {
			t.Fatalf("setup %s: exit %d: %s", args[0], code, text)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dbURL := pgtest.WithDatabase(t, url, name+"_center")
	center := pgtest.Connect(t, dbURL)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicFile := writeKey(t, directory, "budget-public.der", &key.PublicKey, false)
	before := time.Now().UTC().Truncate(time.Second)
	proofKid := "proof-" + strings.Repeat("a", 32)
	proofBinding := "ARCFORGES_CENTER_KEY_PROOF_" + strings.Repeat("A", 32)
	candidate := platform.SigningKey{KID: proofKid, Purpose: platform.CommandSigning, Algorithm: "ES256", PublicKey: der,
		SecretBinding: proofBinding, NotBefore: before, NotAfter: before.Add(399 * 24 * time.Hour)}
	// Ordinary command and entitlement registration still work while the shared response has room.
	for _, purpose := range []string{"command", "entitlement"} {
		kid := "within-" + purpose
		valid := []string{"admin", "register-signing-key", "--purpose", purpose, "--kid", kid, "--public-key-file", publicFile,
			"--secret-binding", "WITHIN_" + strings.ToUpper(purpose), "--not-before", before.Format(time.RFC3339), "--not-after", before.Add(30 * 24 * time.Hour).Format(time.RFC3339)}
		if code, text := command(valid...); code != 0 {
			t.Fatalf("within-budget %s exit %d: %s", purpose, code, text)
		}
		if _, err = center.Exec(ctx, "DELETE FROM fleet.signing_key WHERE kid=$1", kid); err != nil {
			t.Fatal(err)
		}
	}
	count := 0
	for n := 1; n <= 1000; n++ {
		tx, err := center.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO fleet.signing_key
(kid, purpose, algorithm, public_key, secret_binding, not_before, not_after, created_at)
VALUES ($1, 1, 'ES256', $2, $3, $4, $5, $6)`, fmt.Sprintf("synthetic-%08d", n), der,
			fmt.Sprintf("SYNTHETIC_%d", n), before.Add(time.Hour), before.Add(300*24*time.Hour), before)
		if err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		size, limit, err := fleetapi.SigningKeyReplyBudget(ctx, tx, before, candidate)
		if err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if size > limit {
			_ = tx.Rollback(ctx)
			break
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		count = n
	}
	if count < 1 || count >= 1000 {
		t.Fatalf("could not create near-limit set, count=%d", count)
	}
	t.Logf("near-limit synthetic published keys: %d", count)
	now := time.Now().UTC().Truncate(time.Second)
	args := func(purpose, kid, binding string, end time.Time) []string {
		return []string{"admin", "register-signing-key", "--purpose", purpose, "--kid", kid, "--public-key-file", publicFile,
			"--secret-binding", binding, "--not-before", now.Format(time.RFC3339), "--not-after", end.Format(time.RFC3339)}
	}
	if code, text := command(args("command", proofKid, proofBinding, now.Add(399*24*time.Hour))...); code != 0 {
		t.Fatalf("near-limit proof registration: exit %d: %s", code, text)
	}
	fingerprint := func() string {
		var value string
		err := center.QueryRow(ctx, `SELECT coalesce(md5(string_agg(ROW(kid, purpose, algorithm, encode(public_key, 'hex'),
			secret_binding, not_before, not_after, retired_at)::text, '|' ORDER BY kid)), '') FROM fleet.signing_key`).Scan(&value)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	proofState := fingerprint()
	for _, purpose := range []string{"command", "entitlement"} {
		kid := strings.Repeat(map[string]string{"command": "c", "entitlement": "e"}[purpose], 64)
		code, text := command(args(purpose, kid, "ORDINARY_"+strings.ToUpper(purpose), now.Add(400*24*time.Hour))...)
		if code != 1 || !strings.Contains(text, "node-credential reply budget") {
			t.Errorf("ordinary %s after proof must fail for capacity: exit=%d", purpose, code)
		}
		var found bool
		if err = center.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM fleet.signing_key WHERE kid=$1)", kid).Scan(&found); err != nil {
			t.Fatal(err)
		}
		if found {
			t.Errorf("ordinary %s overflow inserted a row", purpose)
			if _, err = center.Exec(ctx, "DELETE FROM fleet.signing_key WHERE kid=$1", kid); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got := fingerprint(); got != proofState {
		t.Fatal("an over-budget attempt changed existing public metadata")
	}
	var intact int
	if err = center.QueryRow(ctx, "SELECT count(*) FROM fleet.signing_key WHERE retired_at IS NULL").Scan(&intact); err != nil || intact != count+1 {
		t.Fatalf("existing keys changed: unretired=%d expected=%d err=%v", intact, count+1, err)
	}
	// Replace only our own proof fixture, then leave a new registration uncommitted while a normal writer waits.
	if _, err = center.Exec(ctx, "DELETE FROM fleet.signing_key WHERE kid=$1", proofKid); err != nil {
		t.Fatal(err)
	}
	baseline := fingerprint()
	for index, purpose := range []string{"command", "entitlement"} {
		t.Run("concurrent_"+purpose, func(t *testing.T) {
			firstConn, secondConn := pgtest.Connect(t, dbURL), pgtest.Connect(t, dbURL)
			first, err := firstConn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = first.Rollback(context.Background()) }()
			second, err := secondConn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = second.Rollback(context.Background()) }()
			var firstPID, secondPID int
			if err = first.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&firstPID); err != nil {
				t.Fatal(err)
			}
			if err = second.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&secondPID); err != nil {
				t.Fatal(err)
			}
			letter := string(rune('b' + index))
			firstKid := "proof-" + strings.Repeat(letter, 32)
			firstArgs := args("command", firstKid, "ARCFORGES_CENTER_KEY_PROOF_"+strings.Repeat(strings.ToUpper(letter), 32), now.Add(399*24*time.Hour))
			secondArgs := args(purpose, strings.Repeat("d", 38), "ORDINARY_CONCURRENT", now.Add(400*24*time.Hour))
			firstRun, ok := registerSigningKey(firstArgs[2:])
			if !ok {
				t.Fatal("first flags")
			}
			secondRun, ok := registerSigningKey(secondArgs[2:])
			if !ok {
				t.Fatal("second flags")
			}
			if _, err = firstRun(ctx, first, now); err != nil {
				t.Fatalf("first registration: %v", err)
			}
			finished := make(chan error, 1)
			go func() { _, runErr := secondRun(ctx, second, now); finished <- runErr }()
			// Observe the specific first backend in the second backend's PostgreSQL blocker set before releasing it.
			blocked := false
			for attempt := 0; attempt < 200; attempt++ {
				var waiting bool
				if err = center.QueryRow(ctx, "SELECT $1 = ANY(pg_blocking_pids($2))", firstPID, secondPID).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					blocked = true
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !blocked {
				cancel()
				<-finished
				t.Fatal("the second writer never waited for the first transaction")
			}
			if err = first.Commit(ctx); err != nil {
				cancel()
				<-finished
				t.Fatal(err)
			}
			if err = <-finished; err == nil || !strings.Contains(err.Error(), "node-credential reply budget") {
				t.Errorf("concurrent %s writer must see the committed proof row and fail capacity: %v", purpose, err)
			}
			committed := fingerprint()
			if err = second.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if got := fingerprint(); got != committed {
				t.Fatal("refusal changed committed public metadata")
			}
			if err = center.QueryRow(ctx, "SELECT count(*) FROM fleet.signing_key WHERE retired_at IS NULL").Scan(&intact); err != nil || intact != count+1 {
				t.Fatalf("concurrent admission changed existing rows: unretired=%d expected=%d err=%v", intact, count+1, err)
			}
			if _, err = center.Exec(ctx, "DELETE FROM fleet.signing_key WHERE kid=$1", firstKid); err != nil {
				t.Fatal(err)
			}
			if got := fingerprint(); got != baseline {
				t.Fatal("concurrency test changed its original set")
			}
		})
	}
	// A caller that supplies a snapshot-isolation transaction must fail instead of reading a stale set after the lock.
	stale := pgtest.Connect(t, dbURL)
	tx, err := stale.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	callback, ok := registerSigningKey(args("entitlement", "snapshot-key", "SNAPSHOT_KEY", now.Add(400*24*time.Hour))[2:])
	if !ok {
		t.Fatal("snapshot flags")
	}
	if _, err = callback(ctx, tx, now); err == nil || !strings.Contains(err.Error(), "requires read committed") {
		t.Fatalf("stale snapshot must be refused before a write: %v", err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if got := fingerprint(); got != baseline {
		t.Fatal("snapshot refusal changed the original set")
	}
}
