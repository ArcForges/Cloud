// SPDX-License-Identifier: AGPL-3.0-only

package platform

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/ArcForges/Cloud/center/internal/store"
	"github.com/ArcForges/Cloud/center/internal/store/migrate"
)

// fixture is a migrated database: the runtime role's store (as the center uses it) and the migration role's connection.
type fixture struct {
	db        *store.DB
	migration *pgx.Conn
	runtime   string
}

// setup migrates an isolated database, adds a business table the runtime role may write (testbiz.counter, outside the module
// schemas) and connects a login role of the runtime group through an exec-mode pool.
func setup(t *testing.T) fixture {
	t.Helper()
	url, name := pgtest.Database(t)
	group := name + "_runtime"
	build, err := migrate.Load(schema.Migrations())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	conn := pgtest.Connect(t, url)
	if _, err = migrate.Apply(ctx, conn, build, migrate.Options{Runner: "test", RuntimeRole: group}); err != nil {
		t.Fatal(err)
	}
	login, password := group+"_a", pgtest.Secret()
	statements := []string{
		"CREATE SCHEMA testbiz",
		"CREATE TABLE testbiz.counter (key text PRIMARY KEY, value bigint NOT NULL)",
		"GRANT USAGE ON SCHEMA testbiz TO " + group,
		"GRANT SELECT, INSERT, UPDATE ON testbiz.counter TO " + group,
		"CREATE ROLE " + login + " LOGIN PASSWORD '" + password + "' IN ROLE " + group,
	}
	for _, statement := range statements {
		if _, err = conn.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	pool := pgtest.Pool(t, pgtest.WithUser(t, url, login, password), 24)
	return fixture{db: store.New(pool), migration: conn, runtime: group}
}

// increment adds one to a business counter in tx.
func increment(ctx context.Context, tx pgx.Tx, key string) error {
	_, err := tx.Exec(ctx, "INSERT INTO testbiz.counter (key, value) VALUES ($1, 1) ON CONFLICT (key) DO UPDATE SET value = testbiz.counter.value + 1", key)
	return err
}

func (f fixture) counter(t *testing.T, key string) int64 {
	t.Helper()
	var value int64
	err := f.migration.QueryRow(context.Background(), "SELECT coalesce((SELECT value FROM testbiz.counter WHERE key = $1), 0)", key).Scan(&value)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
