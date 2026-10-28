// SPDX-License-Identifier: AGPL-3.0-only

// Package provision creates the center's database and rotates the runtime credential with the migration role over the direct
// connection. The runtime credential is a password of one of two login roles (<group>_a, <group>_b) that are members of the
// runtime group role and hold no grant of their own. A slot is live only once the deployment that carries its password was
// promoted and Confirm recorded it; each rotation sets a new password on the slot other than the most recently promoted one,
// so the revision still running keeps its working credential however often a deployment fails and is retried. The password is
// generated here and returned only inside the pooled runtime URL; it is never printed or logged. On a self-hosted PostgreSQL only
// a SCRAM-SHA-256 verifier of it reaches the server; on Neon, which refuses verifiers, the password itself travels inside the
// statement over the verified TLS connection (docs/postgres-store.md says who can read it there).
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
	// LiveSlot is the slot the live Worker version uses, as the deployment read it from Cloudflare ("" when unknown). When set,
	// the rotation takes the other slot whatever the record says; otherwise the record decides.
	LiveSlot string
}

// Rotation is the result of a rotation. RuntimeURL is the credential; every other field may be printed.
type Rotation struct {
	Database  string `json:"database"`
	Group     string `json:"runtimeRole"`
	LoginRole string `json:"loginRole"`
	Slot      string `json:"slot"`
	RotatedAt string `json:"rotatedAt"`
	// SlotSource says what chose the slot: "live-version" (the deployment named the live slot) or "record".
	SlotSource string `json:"slotSource"`
	// PasswordForm is FormVerifier or FormNeonPlaintext.
	PasswordForm     string `json:"passwordForm"`
	ServerVersionNum int    `json:"serverVersionNum"`
	// Logging is what the server records of statements; the rotation refuses pg_stat_statements.track = 'all'.
	Logging    migrate.Logging `json:"logging"`
	Probe      Probe           `json:"probe"`
	RuntimeURL string          `json:"-"`
}

// Probe is what the new credential proved through the pooled endpoint and, for CONNECT, through one unpooled connection.
type Probe struct {
	Pooled bool `json:"pooledEndpoint"`
	// ConnectsUnpooled shows CONNECT conclusively: a direct connection always starts a new server backend, which checks the
	// privilege, whereas the pooler may answer with a backend that started before a revocation.
	ConnectsUnpooled    bool `json:"connectsUnpooled"`
	ConnectedAsLogin    bool `json:"connectedAsLoginRole"`
	ReadsGrantedTable   bool `json:"readsGrantedTable"`
	CannotCreate        bool `json:"cannotCreateTables"`
	CannotReadUngranted bool `json:"cannotReadUngrantedTables"`
	// CannotCreateTemporary shows that PUBLIC's TEMPORARY privilege on the database is revoked.
	CannotCreateTemporary bool `json:"cannotCreateTemporaryTables"`
}

// Rotate sets a new password on the login role of the runtime group that is not the most recently promoted one (slot a when
// none was promoted), records the rotation as not yet promoted, checks that the login role inherits the runtime group and may
// connect, composes the pooled runtime URL and proves through it that the credential connects as that login role, reads a
// granted table, and can neither create a table, nor a temporary table, nor read an ungranted one; one unpooled connection
// proves CONNECT. conn is the migration role's direct connection to the center's database.
func Rotate(ctx context.Context, conn *pgx.Conn, options Options) (Rotation, error) {
	if err := migrate.ValidRoleName(options.Group); err != nil {
		return Rotation{}, err
	}
	if options.LiveSlot != "" && options.LiveSlot != "a" && options.LiveSlot != "b" {
		return Rotation{}, fmt.Errorf("%w: the live slot is a or b", ErrUnknownSlot)
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
	// One predicate decides Neon: the one that derives the pooled host.
	neon := NeonHost(hostOf(options.DirectURL))
	rotation := Rotation{Group: options.Group}
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		// The migration lock serializes a rotation with migrations and with another rotation.
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", migrate.LockKey); err != nil {
			return migrate.Sanitize("take the migration lock", err)
		}
		if err := tx.QueryRow(ctx, "SELECT current_database(), current_setting('server_version_num')::int").Scan(&rotation.Database, &rotation.ServerVersionNum); err != nil {
			return migrate.Sanitize("identify the database", err)
		}
		logging, err := migrate.ReadLogging(ctx, tx)
		if err != nil {
			return err
		}
		rotation.Logging = logging
		if logging.PgStatStatementsTrack == "all" {
			// With track = 'all', pg_stat_statements would record the nested role statement, secret included.
			return errors.New("pg_stat_statements.track is 'all', which would record the nested role statement with its secret; set it to 'top' (the default) before rotating")
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
		rotation.SlotSource = "record"
		if options.LiveSlot != "" {
			// The live version's slot is never rotated, even when the record is behind it.
			slot, rotation.SlotSource = other(options.LiveSlot), "live-version"
		}
		rotation.Slot, rotation.LoginRole = slot, options.Group+"_"+slot
		var exists bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)", rotation.LoginRole).Scan(&exists); err != nil {
			return migrate.Sanitize("look up the login role", err)
		}
		// RequirePlainRole below refuses a login role with an elevated attribute.
		secret, form, err := passwordSecret(password, neon)
		if err != nil {
			return err
		}
		rotation.PasswordForm = form
		if err = setLogin(ctx, tx, rotation.LoginRole, secret, options.ConnectionLimit, !exists); err != nil {
			return err
		}
		if err = membership(ctx, tx, rotation.LoginRole, options.Group, rotation.ServerVersionNum); err != nil {
			return err
		}
		if err = migrate.RequirePlainRole(ctx, tx, rotation.LoginRole, true); err != nil {
			return err
		}
		var inherits, connects bool
		if err = tx.QueryRow(ctx, "SELECT pg_has_role($1, $2, 'USAGE'), has_database_privilege($1, current_database(), 'CONNECT')",
			rotation.LoginRole, options.Group).Scan(&inherits, &connects); err != nil {
			return migrate.Sanitize("check the login role's privileges", err)
		}
		if !inherits || !connects {
			return fmt.Errorf("the login role %s does not inherit the runtime role's privileges or may not connect to the database (inherits %v, connect %v)",
				rotation.LoginRole, inherits, connects)
		}
		return tx.QueryRow(ctx, `INSERT INTO platform.runtime_credential (slot, login_role, rotated_at, rotated_by, promoted_at)
VALUES ($1, $2, now(), $3, NULL)
ON CONFLICT (slot) DO UPDATE SET login_role = excluded.login_role, rotated_at = excluded.rotated_at, rotated_by = excluded.rotated_by,
    promoted_at = NULL
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

// nextSlot is the slot other than the most recently promoted one, or a when no slot was promoted yet. A slot rotated by a
// deployment that was never promoted is rotated again; the most recently promoted slot, which the running revision uses, never.
func nextSlot(ctx context.Context, tx pgx.Tx) (string, error) {
	var live string
	err := tx.QueryRow(ctx, "SELECT slot FROM platform.runtime_credential WHERE promoted_at IS NOT NULL ORDER BY promoted_at DESC, slot LIMIT 1").Scan(&live)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "a", nil
	case err != nil:
		return "", migrate.Sanitize("read the runtime credentials", err)
	case live == "a":
		return "b", nil
	default:
		return "a", nil
	}
}

func other(slot string) string {
	if slot == "a" {
		return "b"
	}
	return "a"
}

// Confirmation is the result of Confirm; every field may be printed.
type Confirmation struct {
	Database   string `json:"database"`
	Group      string `json:"runtimeRole"`
	LoginRole  string `json:"loginRole"`
	Slot       string `json:"slot"`
	RotatedAt  string `json:"rotatedAt"`
	PromotedAt string `json:"promotedAt"`
	// Already is true when the slot's current password was confirmed before; nothing changed.
	Already bool `json:"alreadyConfirmed"`
}

// ErrUnknownSlot refuses a slot other than a or b, or one that was never rotated.
var ErrUnknownSlot = errors.New("unknown runtime credential slot")

// Confirm records, under the migration lock, that the deployment carrying the slot's current password was promoted, so the next
// rotation leaves that slot alone. It is idempotent: a slot whose current password was confirmed already keeps its time. It
// refuses a slot other than a or b and a slot that was never rotated.
func Confirm(ctx context.Context, conn *pgx.Conn, group, slot string) (Confirmation, error) {
	if err := migrate.ValidRoleName(group); err != nil {
		return Confirmation{}, err
	}
	if slot != "a" && slot != "b" {
		return Confirmation{}, fmt.Errorf("%w: the slot is a or b", ErrUnknownSlot)
	}
	confirmation := Confirmation{Group: group, Slot: slot}
	err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", migrate.LockKey); err != nil {
			return migrate.Sanitize("take the migration lock", err)
		}
		if err := tx.QueryRow(ctx, "SELECT current_database()").Scan(&confirmation.Database); err != nil {
			return migrate.Sanitize("identify the database", err)
		}
		var ready bool
		if err := tx.QueryRow(ctx, "SELECT to_regclass('platform.runtime_credential') IS NOT NULL").Scan(&ready); err != nil {
			return migrate.Sanitize("check the migrations", err)
		}
		if !ready {
			return errors.New("the database is not migrated; run arcforges-center migrate first")
		}
		var promoted *string
		err := tx.QueryRow(ctx, `SELECT login_role, to_char(rotated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    to_char(promoted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
FROM platform.runtime_credential WHERE slot = $1 FOR UPDATE`, slot).Scan(&confirmation.LoginRole, &confirmation.RotatedAt, &promoted)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: slot %s was never rotated", ErrUnknownSlot, slot)
		}
		if err != nil {
			return migrate.Sanitize("read the runtime credential", err)
		}
		if confirmation.LoginRole != group+"_"+slot {
			return fmt.Errorf("slot %s belongs to the login role %s, not to the runtime role %s", slot, confirmation.LoginRole, group)
		}
		if promoted != nil {
			confirmation.PromotedAt, confirmation.Already = *promoted, true
			return nil
		}
		return tx.QueryRow(ctx, `UPDATE platform.runtime_credential SET promoted_at = greatest(now(), rotated_at) WHERE slot = $1
RETURNING to_char(promoted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`, slot).Scan(&confirmation.PromotedAt)
	})
	if err != nil {
		return Confirmation{}, err
	}
	return confirmation, nil
}

// membership makes the login role a member of exactly the runtime group, inheriting its grants. From PostgreSQL 16 the inherit
// option belongs to the membership: it is granted WITH INHERIT TRUE, which also corrects an existing membership that does not
// inherit.
func membership(ctx context.Context, tx pgx.Tx, login, group string, serverVersionNum int) error {
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
	grant := "GRANT " + pgx.Identifier{group}.Sanitize() + " TO " + pgx.Identifier{login}.Sanitize()
	if serverVersionNum >= 160000 {
		grant += " WITH INHERIT TRUE"
	} else if member {
		return nil
	}
	if _, err = tx.Exec(ctx, grant); err != nil {
		return migrate.Sanitize("add the login role to the runtime role", err)
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

// NeonHost reports whether host is a Neon compute endpoint (ep-<name>.<region>.….neon.tech). It is the one predicate that
// decides Neon: the derived pooled host (PooledHost) and the password form of a rotation (Neon refuses SCRAM verifiers).
func NeonHost(host string) bool {
	name, rest, found := strings.Cut(strings.ToLower(host), ".")
	return found && strings.HasPrefix(name, "ep-") && (rest == "neon.tech" || strings.HasSuffix(rest, ".neon.tech"))
}

// PooledHost derives the pooled endpoint of a Neon direct host (ep-name.region.aws.neon.tech → ep-name-pooler.region…); any
// other host is kept.
func PooledHost(host string) string {
	if !NeonHost(host) {
		return host
	}
	name, rest, _ := strings.Cut(host, ".")
	if strings.HasSuffix(name, "-pooler") {
		return host
	}
	return name + "-pooler." + rest
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
	deadline := time.Now().Add(options.ProbeTimeout)
	result := Probe{Pooled: hostOf(rotation.RuntimeURL) != hostOf(options.DirectURL)}
	// One unpooled connection as the login role starts a new backend, which checks CONNECT on the database.
	direct, err := RuntimeURL(options.DirectURL, rotation.LoginRole, passwordOf(rotation.RuntimeURL), hostPortOf(options.DirectURL))
	if err != nil {
		return Probe{}, err
	}
	conn, err := connectRetrying(ctx, direct, deadline, "connect with the new runtime credential directly")
	if err != nil {
		return Probe{}, err
	}
	err = conn.QueryRow(ctx, "SELECT current_user = $1 AND has_database_privilege(current_user, current_database(), 'CONNECT')", rotation.LoginRole).
		Scan(&result.ConnectsUnpooled)
	_ = conn.Close(context.Background())
	if err != nil {
		return Probe{}, migrate.Sanitize("check CONNECT on a direct connection", err)
	}
	if conn, err = connectRetrying(ctx, rotation.RuntimeURL, deadline, "connect with the new runtime credential through the pooled endpoint"); err != nil {
		return Probe{}, err
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
	result.CannotCreateTemporary = refused(ctx, conn, "CREATE TEMPORARY TABLE runtime_probe (x int)")
	if !result.ConnectsUnpooled || !result.ConnectedAsLogin || !result.ReadsGrantedTable || !result.CannotCreate || !result.CannotReadUngranted ||
		!result.CannotCreateTemporary {
		return result, fmt.Errorf("the new runtime credential did not behave as the least-privilege runtime role: %+v", result)
	}
	return result, nil
}

// connectRetrying connects in exec mode, retrying until the deadline while a new password propagates (to the pooler); an error
// never repeats the URL.
func connectRetrying(ctx context.Context, value string, deadline time.Time, operation string) (*pgx.Conn, error) {
	config, err := pgx.ParseConfig(value)
	if err != nil {
		return nil, errors.New("the runtime URL does not parse")
	}
	config.DefaultQueryExecMode = pgx.QueryExecModeExec
	config.ConnectTimeout = 10 * time.Second
	for {
		conn, err := pgx.ConnectConfig(ctx, config)
		if err == nil {
			return conn, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return nil, migrate.Sanitize(operation, err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func passwordOf(value string) string {
	uri, err := url.Parse(value)
	if err != nil || uri.User == nil {
		return ""
	}
	password, _ := uri.User.Password()
	return password
}

func hostPortOf(value string) string {
	uri, err := url.Parse(value)
	if err != nil {
		return ""
	}
	return uri.Host
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
