// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"errors"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
)

// TestTheExpandAndContractRollbackProcedure exercises the rollback procedure of docs/postgres-store.md for one schema change
// (a new required column): expand, deploy, roll the application back while keeping the migration, roll forward, backfill and
// contract. Revision N and revision N+1 are the two applications; the database is never migrated backwards.
func TestTheExpandAndContractRollbackProcedure(t *testing.T) {
	url, _ := pgtest.Database(t)
	ctx := context.Background()
	conn := pgtest.Connect(t, url)
	directory := fstest.MapFS{
		"0001_demo.sql": {Data: []byte("CREATE SCHEMA demo; CREATE TABLE demo.note (id integer PRIMARY KEY, body text NOT NULL);")},
		// Expand: additive and nullable, so revision N keeps working on the new schema.
		"0002_note_title_expand.sql": {Data: []byte("ALTER TABLE demo.note ADD COLUMN title text;")},
		// Backfill: rows written before revision N+1, or by revision N during a rollback, get the derived value.
		"0003_note_title_backfill.sql": {Data: []byte("UPDATE demo.note SET title = left(body, 20) WHERE title IS NULL;")},
		// Contract: only once revision N is no longer a rollback target.
		"0004_note_title_contract.sql": {Data: []byte("ALTER TABLE demo.note ALTER COLUMN title SET NOT NULL;")},
	}
	all, err := Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	migrateTo := func(version int) {
		t.Helper()
		if _, err := Apply(ctx, pgtest.Connect(t, url), all[:version], Options{Runner: "test"}); err != nil {
			t.Fatalf("migrate to %d: %v", version, err)
		}
	}
	// Revision N writes and reads the body only; revision N+1 also writes the title and reads it with a fallback.
	revisionN := func(id int) error {
		if _, err := conn.Exec(ctx, "INSERT INTO demo.note (id, body) VALUES ($1, $2)", id, "note written by revision N"); err != nil {
			return err
		}
		var body string
		return conn.QueryRow(ctx, "SELECT body FROM demo.note WHERE id = $1", id).Scan(&body)
	}
	revisionN1 := func(id int) error {
		if _, err := conn.Exec(ctx, "INSERT INTO demo.note (id, body, title) VALUES ($1, $2, $3)", id, "note written by revision N+1", "N+1"); err != nil {
			return err
		}
		rows, err := conn.Query(ctx, "SELECT coalesce(title, left(body, 20)) FROM demo.note")
		if err != nil {
			return err
		}
		_, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	}
	step := func(name string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}

	migrateTo(1)
	step("revision N on the baseline", revisionN(1))
	// Deploy N+1: the deploy migrates first (expand), then promotes N+1. Until the promotion, N runs on the expanded schema.
	migrateTo(2)
	step("revision N on the expanded schema", revisionN(2))
	step("revision N+1", revisionN1(3))
	// Roll back: the application returns to N while the expand migration stays applied. Removing the migration from the build
	// is refused, so a rollback is never a down-migration.
	if _, err = Apply(ctx, pgtest.Connect(t, url), all[:1], Options{Runner: "test"}); !errors.Is(err, ErrRefused) {
		t.Fatalf("a rollback by removing the applied migration was not refused: %v", err)
	}
	if version, err := CheckCompatible(ctx, conn, all[:1]); err != nil || version != 2 {
		t.Fatalf("revision N must accept the expanded database: %d %v", version, err)
	}
	step("revision N after the rollback", revisionN(4))
	step("revision N reads rows of N+1", conn.QueryRow(ctx, "SELECT body FROM demo.note WHERE id = 3").Scan(new(string)))
	// Roll forward: N+1 reads the rows N wrote during the rollback through its fallback.
	step("revision N+1 after the roll-forward", revisionN1(5))
	migrateTo(3)
	var missing int
	step("backfill", conn.QueryRow(ctx, "SELECT count(*) FROM demo.note WHERE title IS NULL").Scan(&missing))
	if missing != 0 {
		t.Fatalf("%d rows without a title after the backfill", missing)
	}
	// Contract once N is no longer a rollback target: from now on N would fail, which is why the contract waits.
	migrateTo(4)
	step("revision N+1 after the contract", revisionN1(6))
	if err = revisionN(7); !pgtest.IsCode(err, "23502") {
		t.Fatalf("revision N must fail after the contract (not null violation), got %v", err)
	}
}
