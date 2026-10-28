// SPDX-License-Identifier: AGPL-3.0-only

// Package migrate applies the center's versioned PostgreSQL migrations (ArcForges-Design data/cloud-store.md section 6). The
// numbered SQL files are embedded in the executable and applied in order, each in its own transaction, under an exclusive
// session advisory lock on a direct (unpooled) connection with the migration role, and recorded with their SHA-256 in
// platform.schema_migration. A repeated run applies nothing. An applied file whose bytes changed, an applied file missing from
// the build and a database ahead of the build are refused before anything runs, so a merged migration is never edited or
// removed: a change is a new migration (expand and contract, docs/postgres-store.md). After the migrations the runner reconciles
// the grants of the runtime role (grants.go).
//
// Nothing here prints or returns a credential: the result names the database, the roles, the versions and the checksums.
package migrate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArcForges/Cloud/center/internal/schema"
)

// LockKey is the session advisory lock that serializes migration runs on one database ("arcforge" in ASCII).
const LockKey int64 = 0x6172_6366_6f72_6765

// Defaults of a run.
const (
	DefaultLockTimeout      = 2 * time.Minute
	DefaultStatementTimeout = 10 * time.Minute
	// DefaultLockWait bounds how long one DDL statement waits for a table lock held by the running revision; a migration
	// that would block the service longer fails and rolls back instead.
	DefaultLockWait = 30 * time.Second
	maxFileBytes    = 1 << 20
	lockPoll        = 250 * time.Millisecond
)

// The states a status or a run reports.
const (
	StateUninitialized = "uninitialized" // platform.schema_migration does not exist yet
	StatePending       = "pending"       // migrations of this build are not applied yet
	StateCurrent       = "current"       // every migration of this build is applied, nothing else is
	StateRefused       = "refused"       // the database record differs from the build; nothing is applied
)

var namePattern = regexp.MustCompile(`^([0-9]{4})_[a-z0-9_]+\.sql$`)

// ErrRefused is returned when the database's record of applied migrations differs from the build.
var ErrRefused = errors.New("the database's applied migrations differ from this build; nothing was applied")

// ErrLocked is returned when another run holds the migration lock for longer than the lock timeout.
var ErrLocked = errors.New("another migration run holds the migration lock")

// Migration is one numbered SQL file of the build.
type Migration struct {
	Version int
	Name    string
	SQL     string
	SHA256  string
}

// Load reads the numbered migrations of a directory: every entry is a file NNNN_name.sql, the versions run 1, 2, … without a
// gap, and nothing else is in the directory. Line endings are normalized to LF before hashing and execution, so a checkout's
// line-ending conversion never changes a checksum.
func Load(directory fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(directory, ".")
	if err != nil {
		return nil, fmt.Errorf("read the migrations: %w", err)
	}
	migrations := make([]Migration, 0, len(entries))
	for index, entry := range entries {
		match := namePattern.FindStringSubmatch(entry.Name())
		if entry.IsDir() || match == nil {
			return nil, fmt.Errorf("unexpected entry %q among the migrations (expected NNNN_name.sql)", entry.Name())
		}
		version, _ := strconv.Atoi(match[1])
		if version != index+1 {
			return nil, fmt.Errorf("migration %s is out of sequence: expected version %04d", entry.Name(), index+1)
		}
		content, err := fs.ReadFile(directory, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}
		if len(content) > maxFileBytes {
			return nil, fmt.Errorf("migration %s is larger than %d bytes", entry.Name(), maxFileBytes)
		}
		content = bytes.ReplaceAll(content, []byte("\r\n"), []byte("\n"))
		if len(bytes.TrimSpace(content)) == 0 {
			return nil, fmt.Errorf("migration %s is empty", entry.Name())
		}
		digest := sha256.Sum256(content)
		migrations = append(migrations, Migration{Version: version, Name: entry.Name(), SQL: string(content), SHA256: hex.EncodeToString(digest[:])})
	}
	if len(migrations) == 0 {
		return nil, errors.New("the build has no migration")
	}
	return migrations, nil
}

// Applied is one row of platform.schema_migration.
type Applied struct {
	Version   int       `json:"version"`
	Name      string    `json:"name"`
	SHA256    string    `json:"sha256"`
	AppliedAt time.Time `json:"appliedAt"`
	AppliedBy string    `json:"appliedBy"`
}

// Comparison is the build's migrations against a database's record.
type Comparison struct {
	Pending  []Migration
	Problems []string
}

// Compare finds the pending migrations and every difference that refuses a run: an applied migration whose name or checksum
// differs from the build (an edited file), a gap in the applied versions (a removed file) and an applied version the build does
// not have (a database ahead of the build).
func Compare(build []Migration, applied []Applied) Comparison {
	var comparison Comparison
	for index, row := range applied {
		switch {
		case row.Version != index+1:
			comparison.Problems = append(comparison.Problems, fmt.Sprintf("the applied versions have a gap before %04d (%s): an applied migration was removed", row.Version, row.Name))
			return comparison
		case row.Version > len(build):
			comparison.Problems = append(comparison.Problems, fmt.Sprintf("the database has migration %04d (%s), which this build does not have: the database is ahead of this build", row.Version, row.Name))
		case build[index].Name != row.Name:
			comparison.Problems = append(comparison.Problems, fmt.Sprintf("applied migration %04d is %s, but this build's is %s: an applied migration was renamed or removed", row.Version, row.Name, build[index].Name))
		case build[index].SHA256 != row.SHA256:
			comparison.Problems = append(comparison.Problems, fmt.Sprintf("applied migration %s was edited: its checksum %s differs from this build's %s", row.Name, short(row.SHA256), short(build[index].SHA256)))
		}
	}
	if len(comparison.Problems) == 0 && len(applied) < len(build) {
		comparison.Pending = build[len(applied):]
	}
	return comparison
}

func short(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

// Querier is what reading the record needs: a connection or a transaction.
type Querier interface {
	Query(ctx context.Context, sql string, arguments ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, arguments ...any) pgx.Row
}

// ReadApplied reads platform.schema_migration; exists is false before the first run.
func ReadApplied(ctx context.Context, q Querier) (applied []Applied, exists bool, err error) {
	if err = q.QueryRow(ctx, "SELECT to_regclass('platform.schema_migration') IS NOT NULL").Scan(&exists); err != nil || !exists {
		return nil, exists, err
	}
	rows, err := q.Query(ctx, "SELECT version, name, sha256, applied_at, applied_by FROM platform.schema_migration ORDER BY version")
	if err != nil {
		return nil, true, err
	}
	applied, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Applied, error) {
		var value Applied
		err := row.Scan(&value.Version, &value.Name, &value.SHA256, &value.AppliedAt, &value.AppliedBy)
		return value, err
	})
	return applied, true, err
}

// Step is one migration applied by a run.
type Step struct {
	Version    int    `json:"version"`
	Name       string `json:"name"`
	SHA256     string `json:"sha256"`
	DurationMS int64  `json:"durationMs"`
}

// Result is the record of a status, a plan or a run. It names no credential.
type Result struct {
	Database      string    `json:"database"`
	MigrationRole string    `json:"migrationRole"`
	RuntimeRole   string    `json:"runtimeRole,omitempty"`
	State         string    `json:"state"`
	Version       int       `json:"version"`
	BuildVersion  int       `json:"buildVersion"`
	Applied       []Applied `json:"applied"`
	Pending       []string  `json:"pending"`
	Ran           []Step    `json:"ran,omitempty"`
	Problems      []string  `json:"problems,omitempty"`
	Grants        string    `json:"grants,omitempty"`
}

// Inspect reports the database against the build without changing anything and without the lock.
func Inspect(ctx context.Context, conn *pgx.Conn, build []Migration) (Result, error) {
	result := Result{BuildVersion: len(build), Applied: []Applied{}, Pending: []string{}}
	if err := conn.QueryRow(ctx, "SELECT current_database(), current_user").Scan(&result.Database, &result.MigrationRole); err != nil {
		return result, Sanitize("identify the database", err)
	}
	applied, exists, err := ReadApplied(ctx, conn)
	if err != nil {
		return result, Sanitize("read platform.schema_migration", err)
	}
	result.describe(build, applied, exists)
	return result, nil
}

func (r *Result) describe(build []Migration, applied []Applied, exists bool) Comparison {
	comparison := Compare(build, applied)
	r.Applied = append([]Applied{}, applied...)
	r.Version = len(applied)
	r.Pending = []string{}
	for _, migration := range comparison.Pending {
		r.Pending = append(r.Pending, migration.Name)
	}
	r.Problems = comparison.Problems
	switch {
	case len(comparison.Problems) > 0:
		r.State = StateRefused
	case !exists:
		r.State = StateUninitialized
	case len(comparison.Pending) > 0:
		r.State = StatePending
	default:
		r.State = StateCurrent
	}
	return comparison
}

// Options of a run.
type Options struct {
	// Runner names the build that applies the migrations (its revision); it is recorded with every applied migration.
	Runner string
	// RuntimeRole is the runtime group role whose grants are reconciled after the migrations; empty skips the reconciliation.
	RuntimeRole      string
	LockTimeout      time.Duration
	StatementTimeout time.Duration
	LockWait         time.Duration
	Logger           *slog.Logger
	// Grants and Schemas default to the center's (package schema); tests replace them.
	Grants  []schema.Grant
	Schemas []string
}

func (o *Options) defaults() {
	if o.LockTimeout <= 0 {
		o.LockTimeout = DefaultLockTimeout
	}
	if o.StatementTimeout <= 0 {
		o.StatementTimeout = DefaultStatementTimeout
	}
	if o.LockWait <= 0 {
		o.LockWait = DefaultLockWait
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Grants == nil {
		o.Grants = schema.RuntimeGrants
	}
	if o.Schemas == nil {
		o.Schemas = schema.Schemas
	}
	if o.Runner == "" {
		o.Runner = "unknown"
	}
}

// Failure is a migration that failed and was rolled back. It carries the SQLSTATE and the server's primary message (never the
// detail, which can quote row values).
type Failure struct {
	Version  int
	Name     string
	SQLState string
	Message  string
}

func (f *Failure) Error() string {
	return fmt.Sprintf("migration %s failed and was rolled back: %s (SQLSTATE %s)", f.Name, f.Message, f.SQLState)
}

// Apply runs the pending migrations of the build under the migration lock and reconciles the runtime role's grants. The
// connection must be a direct session (not a transaction pooler): the advisory lock is a session lock.
func Apply(ctx context.Context, conn *pgx.Conn, build []Migration, options Options) (Result, error) {
	options.defaults()
	result := Result{BuildVersion: len(build), RuntimeRole: options.RuntimeRole, Applied: []Applied{}, Pending: []string{}}
	if err := conn.QueryRow(ctx, "SELECT current_database(), current_user").Scan(&result.Database, &result.MigrationRole); err != nil {
		return result, Sanitize("identify the database", err)
	}
	if options.RuntimeRole != "" {
		if err := ValidRoleName(options.RuntimeRole); err != nil {
			return result, err
		}
		if options.RuntimeRole == result.MigrationRole {
			return result, errors.New("the runtime role must not be the migration role")
		}
	}
	if err := lock(ctx, conn, options); err != nil {
		return result, err
	}
	defer unlock(conn)
	if err := bootstrap(ctx, conn); err != nil {
		return result, Sanitize("create platform.schema_migration", err)
	}
	applied, exists, err := ReadApplied(ctx, conn)
	if err != nil {
		return result, Sanitize("read platform.schema_migration", err)
	}
	comparison := result.describe(build, applied, exists)
	if len(comparison.Problems) > 0 {
		for _, problem := range comparison.Problems {
			options.Logger.Error("migration refused", "problem", problem)
		}
		return result, ErrRefused
	}
	for _, migration := range comparison.Pending {
		step, err := applyOne(ctx, conn, migration, options)
		if err != nil {
			options.Logger.Error("migration failed", "migration", migration.Name, "error", err.Error())
			return result, err
		}
		options.Logger.Info("migration applied", "migration", migration.Name, "sha256", migration.SHA256, "durationMs", step.DurationMS)
		result.Ran = append(result.Ran, step)
	}
	if applied, _, err = ReadApplied(ctx, conn); err != nil {
		return result, Sanitize("read platform.schema_migration", err)
	}
	result.describe(build, applied, true)
	if options.RuntimeRole != "" {
		if err = reconcile(ctx, conn, options); err != nil {
			return result, err
		}
		result.Grants = "reconciled"
	}
	return result, nil
}

func lock(ctx context.Context, conn *pgx.Conn, options Options) error {
	deadline := time.Now().Add(options.LockTimeout)
	waiting := false
	for {
		var acquired bool
		if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", LockKey).Scan(&acquired); err != nil {
			return Sanitize("take the migration lock", err)
		}
		if acquired {
			return nil
		}
		if !waiting {
			options.Logger.Info("waiting for another migration run to release the migration lock")
			waiting = true
		}
		if time.Now().After(deadline) {
			return ErrLocked
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(lockPoll):
		}
	}
}

func unlock(conn *pgx.Conn) {
	// Ending the session releases the lock too; an explicit unlock keeps a reused connection clean.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", LockKey)
}

// bootstrapSQL creates the schema and the record table. It never changes: a later change of platform.schema_migration is an
// ordinary migration.
const bootstrapSQL = `
CREATE SCHEMA IF NOT EXISTS platform;
CREATE TABLE IF NOT EXISTS platform.schema_migration (
    version     integer     NOT NULL,
    name        text        NOT NULL,
    sha256      text        NOT NULL,
    applied_at  timestamptz NOT NULL DEFAULT now(),
    applied_by  text        NOT NULL DEFAULT current_user,
    duration_ms bigint      NOT NULL,
    runner      text        NOT NULL,
    CONSTRAINT schema_migration_pkey PRIMARY KEY (version),
    CONSTRAINT schema_migration_name UNIQUE (name),
    CONSTRAINT schema_migration_version CHECK (version >= 1),
    CONSTRAINT schema_migration_name_shape CHECK (name ~ '^[0-9]{4}_[a-z0-9_]+[.]sql$'),
    CONSTRAINT schema_migration_sha256 CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT schema_migration_duration CHECK (duration_ms >= 0),
    CONSTRAINT schema_migration_runner CHECK (length(runner) BETWEEN 1 AND 128)
);`

func bootstrap(ctx context.Context, conn *pgx.Conn) error {
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, bootstrapSQL)
		return err
	})
}

func applyOne(ctx context.Context, conn *pgx.Conn, migration Migration, options Options) (Step, error) {
	started := time.Now()
	err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		settings := fmt.Sprintf("SET LOCAL statement_timeout = %d; SET LOCAL lock_timeout = %d",
			options.StatementTimeout.Milliseconds(), options.LockWait.Milliseconds())
		if _, err := tx.Exec(ctx, settings); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, migration.SQL); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "INSERT INTO platform.schema_migration (version, name, sha256, duration_ms, runner) VALUES ($1, $2, $3, $4, $5)",
			migration.Version, migration.Name, migration.SHA256, time.Since(started).Milliseconds(), runnerName(options.Runner))
		return err
	})
	if err != nil {
		failure := &Failure{Version: migration.Version, Name: migration.Name, SQLState: "unknown", Message: "the migration did not complete"}
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) {
			failure.SQLState, failure.Message = pgError.Code, pgError.Message
		} else if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			failure.SQLState, failure.Message = "57014", "the run was cancelled or timed out"
		}
		return Step{}, failure
	}
	return Step{Version: migration.Version, Name: migration.Name, SHA256: migration.SHA256, DurationMS: time.Since(started).Milliseconds()}, nil
}

func runnerName(runner string) string {
	if len(runner) > 128 {
		return runner[:128]
	}
	return runner
}

// Sanitize keeps the SQLSTATE and the operation of a database error and drops the server message, which can quote values.
func Sanitize(operation string, err error) error {
	if err == nil {
		return nil
	}
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		if pgError.ConstraintName != "" {
			return fmt.Errorf("%s: SQLSTATE %s (constraint %s)", operation, pgError.Code, pgError.ConstraintName)
		}
		return fmt.Errorf("%s: SQLSTATE %s", operation, pgError.Code)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: timed out", operation)
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("%s: cancelled", operation)
	}
	if pgconn.Timeout(err) {
		return fmt.Errorf("%s: timed out", operation)
	}
	return fmt.Errorf("%s: the database is unreachable or refused the connection", operation)
}

var rolePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{2,40}$`)

// ValidRoleName accepts a lowercase role name of 3 to 41 characters that is not reserved, so its rotation login roles
// (name_a, name_b) are valid identifiers too.
func ValidRoleName(name string) error {
	if !rolePattern.MatchString(name) || strings.HasPrefix(name, "pg_") || strings.HasPrefix(name, "neon") ||
		name == "postgres" || name == "public" || name == "cloud_admin" {
		return fmt.Errorf("the runtime role name must match %s and must not be reserved", rolePattern)
	}
	return nil
}

// ErrIncompatible reports a database the running build cannot use: a migration of the build is not applied, or an applied one
// differs from the build's.
var ErrIncompatible = errors.New("the database schema does not match this build")

// CheckCompatible is the runtime's schema check (it needs only SELECT on platform.schema_migration): every migration of the
// build must be applied exactly. Migrations beyond the build are allowed, because expand-and-contract keeps the previous
// revision working while the next one is migrated and deployed. It returns the database's version.
func CheckCompatible(ctx context.Context, q Querier, build []Migration) (int, error) {
	applied, exists, err := ReadApplied(ctx, q)
	if err != nil {
		return 0, Sanitize("read platform.schema_migration", err)
	}
	if !exists || len(applied) < len(build) {
		return len(applied), fmt.Errorf("%w: %d of its %d migrations are applied", ErrIncompatible, len(applied), len(build))
	}
	for index, migration := range build {
		if applied[index].Version != migration.Version || applied[index].Name != migration.Name || applied[index].SHA256 != migration.SHA256 {
			return len(applied), fmt.Errorf("%w: applied migration %04d differs", ErrIncompatible, migration.Version)
		}
	}
	return len(applied), nil
}
