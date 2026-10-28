// SPDX-License-Identifier: AGPL-3.0-only

// Package provision creates the center's database and rotates the runtime credential with the migration role over the direct
// connection. The runtime credential is a password of one of two login roles (<group>_a, <group>_b) that are members of the
// runtime group role and hold no grant of their own. Each rotation sets a new password on the slot that was rotated less
// recently, so the revision still running keeps its working credential while the next revision deploys with the new one. The
// password is generated here, sent only inside the statement over the verified TLS connection (Neon accepts no pre-hashed
// password), returned only inside the pooled runtime URL and never printed or logged.
package provision

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArcForges/Cloud/center/internal/store/migrate"
)

// DefaultConnectionLimit bounds each login role's server connections (the center's pool is four per instance; the pooler and a
// rotation overlap need a few more).
const DefaultConnectionLimit = 16

var databaseName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// EnsureDatabase creates the database if it does not exist (owned by the migration role) and reports whether it created it.
func EnsureDatabase(ctx context.Context, conn *pgx.Conn, name string) (bool, error) {
	if !databaseName.MatchString(name) || name == "postgres" || strings.HasPrefix(name, "template") {
		return false, errors.New("the database name must be a lowercase identifier")
	}
	var exists bool
	if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)", name).Scan(&exists); err != nil {
		return false, migrate.Sanitize("look up the database", err)
	}
	if exists {
		return false, nil
	}
	_, err := conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) && pgError.Code == "42P04" {
		return false, nil // created concurrently
	}
	if err != nil {
		return false, migrate.Sanitize("create the database", err)
	}
	return true, nil
}

// Options of a rotation.
type Options struct {
	// Group is the runtime group role (it must exist: `migrate` creates it and reconciles its grants).
	Group string
	// DirectURL is the migration role's direct URL of the center's database; the pooled URL is derived from it.
	DirectURL string
	// PooledHost is host[:port] of the pooled endpoint; empty derives the Neon -pooler host, or keeps the direct host.
	PooledHost string
	// Runner names the build that rotates (its revision).
	Runner          string
	ConnectionLimit int
	// ProbeTimeout bounds the pooled-connection probe, which retries while a new password propagates to the pooler.
	ProbeTimeout time.Duration
}

// Rotation is the result of a rotation. RuntimeURL is the credential; every other field may be printed.
type Rotation struct {
	Database   string `json:"database"`
	Group      string `json:"runtimeRole"`
	LoginRole  string `json:"loginRole"`
	Slot       string `json:"slot"`
	RotatedAt  string `json:"rotatedAt"`
	Probe      Probe  `json:"probe"`
	RuntimeURL string `json:"-"`
}

// Probe is what the new credential proved through the pooled endpoint.
type Probe struct {
	Pooled              bool `json:"pooledEndpoint"`
	ConnectedAsLogin    bool `json:"connectedAsLoginRole"`
	ReadsGrantedTable   bool `json:"readsGrantedTable"`
	CannotCreate        bool `json:"cannotCreateTables"`
	CannotReadUngranted bool `json:"cannotReadUngrantedTables"`
}

// Rotate sets a new password on the less recently rotated login role of the runtime group, records the rotation, composes the
// pooled runtime URL and proves through it that the credential connects as that login role, reads a granted table, and can
// neither create a table nor read an ungranted one. conn is the migration role's direct connection to the center's database.
func Rotate(ctx context.Context, conn *pgx.Conn, options Options) (Rotation, error) {
	if err := migrate.ValidRoleName(options.Group); err != nil {
		return Rotation{}, err
	}
	if options.ConnectionLimit <= 0 {
		options.ConnectionLimit = DefaultConnectionLimit
	}
	if options.ProbeTimeout <= 0 {
		options.ProbeTimeout = time.Minute
	}
	runner := options.Runner
	if runner == "" || len(runner) > 128 {
		runner = "unknown"
	}
	password, err := Password()
	if err != nil {
		return Rotation{}, err
	}
	rotation := Rotation{Group: options.Group}
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		// The migration lock serializes a rotation with migrations and with another rotation.
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", migrate.LockKey); err != nil {
			return migrate.Sanitize("take the migration lock", err)
		}
		if err := tx.QueryRow(ctx, "SELECT current_database()").Scan(&rotation.Database); err != nil {
			return migrate.Sanitize("identify the database", err)
		}
		var ready bool
		if err := tx.QueryRow(ctx, "SELECT to_regclass('platform.runtime_credential') IS NOT NULL AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)", options.Group).Scan(&ready); err != nil {
			return migrate.Sanitize("check the migrations", err)
		}
		if !ready {
			return errors.New("the database is not migrated or the runtime role does not exist; run arcforges-center migrate first")
		}
		if err := migrate.RequirePlainRole(ctx, tx, options.Group, false); err != nil {
			return err
		}
		slot, err := nextSlot(ctx, tx)
		if err != nil {
			return err
		}
		rotation.Slot, rotation.LoginRole = slot, options.Group+"_"+slot
		login := pgx.Identifier{rotation.LoginRole}.Sanitize()
		var exists bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)", rotation.LoginRole).Scan(&exists); err != nil {
			return migrate.Sanitize("look up the login role", err)
		}
		// Only LOGIN, INHERIT, the connection limit and the password are set: a CREATEROLE role (the Neon owner) may not name the
		// superuser, replication or BYPASSRLS attributes at all, and RequirePlainRole below refuses a role that has one.
		attributes := fmt.Sprintf("LOGIN INHERIT CONNECTION LIMIT %d PASSWORD %s", options.ConnectionLimit, literal(password))
		statement := "ALTER ROLE " + login + " WITH " + attributes
		if !exists {
			statement = "CREATE ROLE " + login + " WITH " + attributes
		}
		if _, err = tx.Exec(ctx, statement); err != nil {
			// The statement holds the password: only the SQLSTATE is reported.
			return migrate.Sanitize("set the runtime credential of "+rotation.LoginRole, err)
		}
		if err = membership(ctx, tx, rotation.LoginRole, options.Group); err != nil {
			return err
		}
		if err = migrate.RequirePlainRole(ctx, tx, rotation.LoginRole, true); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO platform.runtime_credential (slot, login_role, rotated_at, rotated_by) VALUES ($1, $2, now(), $3)
ON CONFLICT (slot) DO UPDATE SET login_role = excluded.login_role, rotated_at = excluded.rotated_at, rotated_by = excluded.rotated_by
RETURNING to_char(rotated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`, slot, rotation.LoginRole, runner).Scan(&rotation.RotatedAt)
	})
	if err != nil {
		return Rotation{}, err
	}
	rotation.RuntimeURL, err = RuntimeURL(options.DirectURL, rotation.LoginRole, password, options.PooledHost)
	if err != nil {
		return Rotation{}, err
	}
	rotation.Probe, err = probe(ctx, rotation, options)
	if err != nil {
		return Rotation{}, err
	}
	return rotation, nil
}

func nextSlot(ctx context.Context, tx pgx.Tx) (string, error) {
	rows, err := tx.Query(ctx, "SELECT slot FROM platform.runtime_credential ORDER BY rotated_at, slot")
	if err != nil {
		return "", migrate.Sanitize("read the runtime credentials", err)
	}
	slots, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return "", migrate.Sanitize("read the runtime credentials", err)
	}
	for _, candidate := range []string{"a", "b"} {
		found := false
		for _, slot := range slots {
			found = found || slot == candidate
		}
		if !found {
			return candidate, nil
		}
	}
	return slots[0], nil // the less recently rotated slot
}

// membership makes the login role a member of exactly the runtime group, inheriting its grants.
func membership(ctx context.Context, tx pgx.Tx, login, group string) error {
	rows, err := tx.Query(ctx, `SELECT g.rolname FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles r ON r.oid = m.member
WHERE r.rolname = $1`, login)
	if err != nil {
		return migrate.Sanitize("read the login role's memberships", err)
	}
	groups, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return migrate.Sanitize("read the login role's memberships", err)
	}
	member := false
	for _, name := range groups {
		if name != group {
			return fmt.Errorf("the login role %s is a member of %s; it must be a member of the runtime role only", login, name)
		}
		member = true
	}
	if !member {
		if _, err = tx.Exec(ctx, "GRANT "+pgx.Identifier{group}.Sanitize()+" TO "+pgx.Identifier{login}.Sanitize()); err != nil {
			return migrate.Sanitize("add the login role to the runtime role", err)
		}
	}
	return nil
}

// Password returns 40 characters of base64url (240 random bits; Neon requires at least 60 bits of entropy) with lowercase,
// uppercase, a digit and a symbol and no character three times in a row.
func Password() (string, error) {
	for range 64 {
		var random [30]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", err
		}
		candidate := base64.RawURLEncoding.EncodeToString(random[:])
		if strings.ContainsAny(candidate, "abcdefghijklmnopqrstuvwxyz") && strings.ContainsAny(candidate, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") &&
			strings.ContainsAny(candidate, "0123456789") && strings.ContainsAny(candidate, "-_") && !tripled(candidate) {
			return candidate, nil
		}
	}
	return "", errors.New("could not generate a password")
}

func tripled(value string) bool {
	for index := 2; index < len(value); index++ {
		if value[index] == value[index-1] && value[index] == value[index-2] {
			return true
		}
	}
	return false
}

// literal quotes a generated password (base64url: no quote or backslash can occur).
func literal(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// PooledHost derives the pooled endpoint of a Neon direct host (ep-name.region.aws.neon.tech → ep-name-pooler.region…); any
// other host is kept.
func PooledHost(host string) string {
	name, rest, found := strings.Cut(host, ".")
	if found && strings.HasPrefix(name, "ep-") && !strings.HasSuffix(name, "-pooler") && strings.HasSuffix(rest, "neon.tech") {
		return name + "-pooler." + rest
	}
	return host
}

// RuntimeURL composes the runtime credential: the direct URL with the login role, its password and the pooled host.
func RuntimeURL(direct, login, password, pooledHost string) (string, error) {
	uri, err := url.Parse(direct)
	if err != nil || uri.Hostname() == "" {
		return "", errors.New("the direct URL is not a URL")
	}
	if pooledHost == "" {
		pooledHost = PooledHost(uri.Hostname())
		if port := uri.Port(); port != "" {
			pooledHost = net.JoinHostPort(pooledHost, port)
		}
	}
	uri.Host = pooledHost
	uri.User = url.UserPassword(login, password)
	return uri.String(), nil
}

func probe(ctx context.Context, rotation Rotation, options Options) (Probe, error) {
	config, err := pgx.ParseConfig(rotation.RuntimeURL)
	if err != nil {
		return Probe{}, errors.New("the runtime URL does not parse")
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeExec
	config.ConnectTimeout = 10 * time.Second
	result := Probe{Pooled: config.Host != hostOf(options.DirectURL)}
	deadline := time.Now().Add(options.ProbeTimeout)
	var conn *pgx.Conn
	for {
		conn, err = pgx.ConnectConfig(ctx, config)
		if err == nil {
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return Probe{}, migrate.Sanitize("connect with the new runtime credential through the pooled endpoint", err)
		}
		select {
		case <-ctx.Done():
			return Probe{}, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	defer func() { _ = conn.Close(context.Background()) }()
	var user, database string
	var versions int
	if err = conn.QueryRow(ctx, "SELECT current_user, current_database(), (SELECT count(*) FROM platform.schema_migration)").Scan(&user, &database, &versions); err != nil {
		return Probe{}, migrate.Sanitize("read through the pooled endpoint", err)
	}
	result.ConnectedAsLogin = user == rotation.LoginRole && database == rotation.Database
	result.ReadsGrantedTable = versions > 0
	result.CannotCreate = refused(ctx, conn, "CREATE TABLE platform.runtime_probe (x int)")
	result.CannotReadUngranted = refused(ctx, conn, "SELECT count(*) FROM platform.runtime_credential")
	if !result.ConnectedAsLogin || !result.ReadsGrantedTable || !result.CannotCreate || !result.CannotReadUngranted {
		return result, fmt.Errorf("the new runtime credential did not behave as the least-privilege runtime role: %+v", result)
	}
	return result, nil
}

// refused runs a statement in a transaction that is always rolled back and reports whether it failed for lack of privilege.
func refused(ctx context.Context, conn *pgx.Conn, statement string) bool {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return false
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, statement)
	var pgError *pgconn.PgError
	return errors.As(err, &pgError) && pgError.Code == "42501"
}

func hostOf(value string) string {
	uri, err := url.Parse(value)
	if err != nil {
		return ""
	}
	return uri.Hostname()
}
