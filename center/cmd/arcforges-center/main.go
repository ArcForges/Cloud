// SPDX-License-Identifier: AGPL-3.0-only

// Command arcforges-center is the ArcForges center: one executable that serves the public routes (serve, the default),
// applies the PostgreSQL migrations (migrate), creates the database, rotates the runtime credential and records its promotion
// (admin), revokes sessions as the operator's incident tool (admin revoke-sessions), grants and revokes the operator role (admin
// grant-operator, revoke-operator), registers and retires the center's public signing keys and releases a node ID by revoking its
// device (admin register-signing-key, retire-signing-key, revoke-device; AF-CTR-04) and reports its identity (version, --build-info).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/bridgeproof"
	"github.com/ArcForges/Cloud/center/internal/buildinfo"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/provision"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/ArcForges/Cloud/center/internal/server"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
	"github.com/ArcForges/Cloud/center/internal/store/migrate"
)

const usage = `usage: arcforges-center [command]

commands:
  serve                            serve the public routes (the default); configured by ARCFORGES_CENTER_* (docs/center.md)
  migrate [apply|status|plan]      apply the PostgreSQL migrations (apply, the default), or report them without changing
                                   anything; configured by ARCFORGES_CENTER_MIGRATION_DATABASE_URL (docs/postgres-store.md)
  admin ensure-database            create the center's database if it does not exist
  admin backup-logical --archive <new path> --metadata <new path>
                                   capture a checked full 0011 backup and its trusted snapshot metadata
  admin restore-logical-backup --archive <path> --sha256 <digest> --metadata <path> --metadata-sha256 <digest>
                                   restore a supported trusted backup to an explicitly named new, isolated database
  admin restore-legacy-logical-backup --archive <path> --sha256 <digest> --provenance <path> --provenance-sha256 <digest>
                                   restore a provenance-attested schema-10 full backup through the verified local bridge
  admin rotate-runtime-credential [--live-slot a|b]
                                   set a new runtime credential on the slot that is not the live one (named, or else the last
                                   promoted one) and write the runtime URL to ARCFORGES_CENTER_RUNTIME_SECRET_FILE
  admin confirm-runtime-credential --slot a|b
                                   record that the deployment carrying the slot's credential was promoted
  admin prepare-ctr06-bridge       issue a distinct schema-10 bridge credential into the private runtime secret file
  admin revoke-sessions --account <uuid> | --all
                                   revoke every unrevoked session of one account, or of every account, whatever its scope
                                   (audited as identity.sessions.revoked_by_operator); prints the counts per scope
  admin grant-operator --account <uuid> --reason <text> [--days N]
                                   make an active account an operator for N days (1 to 90, default 30): it may then issue operator
                                   grants of features on an official-hosted center (audited as identity.operator.granted)
  admin revoke-operator --account <uuid>
                                   end the account's operator role now (audited as identity.operator.revoked); the owner who
                                   bootstrapped the center stays an operator through the bootstrap
  admin register-signing-key --purpose command|entitlement --kid <id> --public-key-file <pem|der> --secret-binding <NAME>
                             --not-before <rfc3339> --not-after <rfc3339>
                                   record the public half of a signing key (ES256 P-256) whose private half the named platform
                                   secret holds; nodes receive it with their next sign-in or refresh (audited as
                                   fleet.signing_key.registered)
  admin inspect-signing-key --kid <id>
                                   read public key metadata, including a retired key, without changing the registry
  admin retire-signing-key --kid <id> [--at <rfc3339>]
                                   retire a signing key now or at the instant (audited as fleet.signing_key.retired); prints how
                                   many valid keys of its purpose remain
  admin revoke-device --device <uuid> | --node <uuid>
                                   revoke a device (named, or as the device of a node ID's live enrollment) with its installations,
                                   sessions and node rows, freeing the node ID (audited as device.revoked by operator:cli)
  version                          print the build identity as JSON (also --build-info)
  help                             print this help

exit status: 0 success, 1 failure, 2 usage, 3 refused (the database's migrations differ from this build),
             4 unknown slot (confirm-runtime-credential: this database's record has no row for the slot)
`

// The exit statuses.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
	exitRefused = 3
	// exitUnknownSlot lets the deployment tell a slot that this database's record lacks (a recreated, restored or new database) from
	// a failure.
	exitUnknownSlot = 4
)

func main() {
	os.Exit(run(os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr))
}

func run(arguments []string, lookup func(string) (string, bool), stdout, stderr io.Writer) int {
	command := "serve"
	if len(arguments) > 0 {
		command = arguments[0]
	}
	sub := ""
	if len(arguments) > 1 {
		sub = arguments[1]
	}
	slot := ""
	var target revokeTarget
	var role operatorFlags
	if command == "admin" && sub == "restore-logical-backup" {
		return restoreCommand(arguments[2:], lookup, stdout, stderr)
	}
	if command == "admin" && sub == "backup-logical" {
		return backupCommand(arguments[2:], lookup, stdout, stderr)
	}
	if command == "admin" && sub == "restore-legacy-logical-backup" {
		return legacyRestoreCommand(arguments[2:], lookup, stdout, stderr)
	}
	if command == "admin" && (sub == "register-signing-key" || sub == "inspect-signing-key" || sub == "retire-signing-key" || sub == "revoke-device") {
		return fleetAdmin(sub, arguments[2:], lookup, stdout, stderr)
	}
	switch {
	case command == "admin" && (sub == "grant-operator" || sub == "revoke-operator"):
		var ok bool
		if role, ok = parseOperatorFlags(arguments[2:], sub == "grant-operator"); !ok {
			_, _ = fmt.Fprint(stderr, usage)
			return exitUsage
		}
	case command == "admin" && sub == "revoke-sessions":
		var ok bool
		if target, ok = revokeFlags(arguments[2:]); !ok {
			_, _ = fmt.Fprint(stderr, usage)
			return exitUsage
		}
	case command == "admin" && sub == "confirm-runtime-credential":
		if slot = slotFlag(arguments[2:], "--slot"); slot != "a" && slot != "b" {
			_, _ = fmt.Fprint(stderr, usage)
			return exitUsage
		}
	case command == "admin" && sub == "rotate-runtime-credential" && len(arguments) > 2:
		if slot = slotFlag(arguments[2:], "--live-slot"); slot != "a" && slot != "b" {
			_, _ = fmt.Fprint(stderr, usage)
			return exitUsage
		}
	case len(arguments) > 2, len(arguments) == 2 && command != "migrate" && command != "admin":
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch command {
	case "serve":
		return serve(lookup, stderr)
	case "migrate":
		if sub == "" {
			sub = "apply"
		}
		if sub != "apply" && sub != "status" && sub != "plan" {
			_, _ = fmt.Fprint(stderr, usage)
			return exitUsage
		}
		return migration(sub, lookup, stdout, stderr)
	case "admin":
		if sub == "revoke-sessions" {
			return revokeSessions(target, lookup, stdout, stderr)
		}
		if sub == "grant-operator" || sub == "revoke-operator" {
			return operatorRole(sub, role, lookup, stdout, stderr)
		}
		if sub != "ensure-database" && sub != "rotate-runtime-credential" && sub != "confirm-runtime-credential" && sub != "prepare-ctr06-bridge" {
			_, _ = fmt.Fprint(stderr, usage)
			return exitUsage
		}
		return admin(sub, slot, lookup, stdout, stderr)
	case "version", "--build-info":
		document, err := buildinfo.Document("not-probed", buildinfo.Center{})
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return exitFailure
		}
		if err = json.NewEncoder(stdout).Encode(document); err != nil {
			return exitFailure
		}
		return exitOK
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(stdout, usage)
		return exitOK
	default:
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
}

// revokeTarget is what admin revoke-sessions revokes: one account's sessions, or every account's.
type revokeTarget struct {
	account *platform.ID
	all     bool
}

// revokeFlags reads `--account <uuid>`, `--account=<uuid>` or `--all` as the only arguments.
func revokeFlags(rest []string) (revokeTarget, bool) {
	value := ""
	switch {
	case len(rest) == 1 && rest[0] == "--all":
		return revokeTarget{all: true}, true
	case len(rest) == 2 && rest[0] == "--account":
		value = rest[1]
	case len(rest) == 1 && strings.HasPrefix(rest[0], "--account="):
		value = strings.TrimPrefix(rest[0], "--account=")
	default:
		return revokeTarget{}, false
	}
	var account platform.ID
	raw := correlation.IDBytes(value)
	if len(raw) != len(account) {
		return revokeTarget{}, false
	}
	copy(account[:], raw)
	if account.String() != value {
		return revokeTarget{}, false
	}
	return revokeTarget{account: &account}, true
}

// revokeSessions is `admin revoke-sessions` (PLT-10), the operator's incident tool: with the migration role it revokes every
// unrevoked session of one account or of every account, whatever its scope (reason: revoked by the operator), and appends the
// audit event identity.sessions.revoked_by_operator (actor operator:cli) in the same transaction, then prints the counts per scope.
// Every revoked credential is refused at its next call; a refresh answers credential_revoked.
func revokeSessions(target revokeTarget, lookup func(string) (string, bool), stdout, stderr io.Writer) int {
	logger := observe.NewLogger(stderr, slog.LevelInfo).With("command", "admin revoke-sessions")
	cfg, err := config.LoadMigration(lookup)
	if err != nil {
		logger.Error("the command refused to start", "error", err.Error())
		return exitFailure
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	conn, err := connect(ctx, cfg.URL)
	if err != nil {
		logger.Error("the command could not connect", "error", err.Error())
		return exitFailure
	}
	defer func() { _ = conn.Close(context.Background()) }()
	now := time.Now().UTC().Truncate(time.Microsecond)
	targetKind, targetID := "center", "all"
	if target.account != nil {
		targetKind, targetID = "account", target.account.String()
	}
	var counts map[string]int64
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if err := migrate.RequireOrdinaryDatabase(ctx, tx, cfg.Database); err != nil {
			return err
		}
		var err error
		if counts, err = session.RevokeByOperator(ctx, tx, target.account, now); err != nil {
			return err
		}
		payload, err := json.Marshal(map[string]any{"sessions": counts, "all": target.all})
		if err != nil {
			return err
		}
		_, err = platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: now, ActorRef: "operator:cli",
			EventType: "identity.sessions.revoked_by_operator", TargetKind: targetKind, TargetID: targetID, Payload: payload})
		return err
	})
	if err != nil {
		logger.Error("the sessions could not be revoked", "error", store.Sanitize("revoke sessions", err).Error())
		return exitFailure
	}
	_ = json.NewEncoder(stdout).Encode(map[string]any{"target": targetKind, "account": targetID, "revoked": counts})
	logger.Info("sessions revoked by the operator", "target", targetKind, "account", targetID)
	return exitOK
}

// slotFlag reads `<flag> a|b` or `<flag>=a|b` as the only arguments; anything else is "".
func slotFlag(rest []string, flag string) string {
	switch {
	case len(rest) == 2 && rest[0] == flag:
		return rest[1]
	case len(rest) == 1 && strings.HasPrefix(rest[0], flag+"="):
		return strings.TrimPrefix(rest[0], flag+"=")
	}
	return ""
}

func serve(lookup func(string) (string, bool), stderr io.Writer) int {
	cfg, err := config.Load(lookup)
	logger := observe.NewLogger(stderr, cfg.LogLevel)
	if err != nil {
		logger.Error("the center refused to start", "error", err.Error())
		return exitFailure
	}
	// The command keys (AF-CTR-05 E1a, CTR5-KEY-01): read once from the process environment and unset from it at once, whatever
	// follows, so no later os.Getenv or os.Environ and no child process sees them; an error names the variable, never its value. The
	// unset does not reach the kernel's copy of the start environment (/proc/<pid>/environ keeps the variables for the life of the
	// process, readable by the same user and root), and the Go heap copies are not zeroed, so a core dump can still contain them.
	keys, err := commandKeys()
	if err == nil {
		err = cfg.ApplyCommandKeys(keys)
	}
	if err != nil {
		logger.Error("the center refused to start", "error", err.Error())
		return exitFailure
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err = server.Run(ctx, cfg, logger); err != nil {
		logger.Error("the center stopped", "error", err.Error())
		return exitFailure
	}
	return exitOK
}

// commandKeys reads the command keys of the process environment and unsets every ARCFORGES_CENTER_KEY_ variable, whatever the outcome
// (CTR5-KEY-01: read once, never left in the process environment for a later reader; see serve for what an unset does not reach).
func commandKeys() ([]config.CommandKey, error) {
	keys, names, err := config.LoadCommandKeys(os.Environ())
	for _, name := range names {
		_ = os.Unsetenv(name)
	}
	return keys, err
}

// revision names this build in the migration record.
func revision() string {
	document, err := buildinfo.Document("not-probed", buildinfo.Center{})
	if err != nil || document.Revision == "" {
		return "unknown"
	}
	return document.Revision
}

// connect opens the migration role's direct connection; an error never repeats the URL.
func connect(ctx context.Context, value string) (*pgx.Conn, error) {
	connConfig, err := pgx.ParseConfig(value)
	if err != nil {
		return nil, errors.New("the migration database URL does not parse")
	}
	connConfig.ConnectTimeout = 30 * time.Second
	connConfig.RuntimeParams["application_name"] = "arcforges-center-migrate"
	conn, err := pgx.ConnectConfig(ctx, connConfig)
	if err != nil {
		return nil, migrate.Sanitize("connect to the database", err)
	}
	return conn, nil
}

func migration(sub string, lookup func(string) (string, bool), stdout, stderr io.Writer) int {
	if sub == "apply" {
		bridge, _ := lookup(config.EnvCTR06BridgeExecutable)
		proof, _ := lookup(config.EnvCTR06ProofFile)
		if bridge != "" || proof != "" {
			_, _ = fmt.Fprintln(stderr, migrate.ErrCTR06SecurityBridgeUnbound)
			return exitFailure
		}
	}
	logger := observe.NewLogger(stderr, slog.LevelInfo).With("command", "migrate "+sub)
	cfg, err := config.LoadMigration(lookup)
	if err != nil {
		logger.Error("the migration refused to start", "error", err.Error())
		return exitFailure
	}
	build, err := migrate.Load(schema.Migrations())
	if err != nil {
		logger.Error("the build's migrations are invalid", "error", err.Error())
		return exitFailure
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	conn, err := connect(ctx, cfg.URL)
	if err != nil {
		logger.Error("the migration could not connect", "error", err.Error())
		return exitFailure
	}
	defer func() { _ = conn.Close(context.Background()) }()
	var result migrate.Result
	if sub == "apply" {
		var proof *bridgeproof.Verified
		if cfg.CTR06ProofFile != "" {
			proof, err = readCTR06Proof(ctx, cfg.CTR06ProofFile)
			if err != nil {
				logger.Error("the protected bridge proof could not be verified")
				return exitFailure
			}
		}
		options := migrate.Options{Runner: revision(), RuntimeRole: cfg.RuntimeRole, LockTimeout: cfg.LockTimeout, Logger: logger, BridgeProof: proof}
		if cfg.CTR06BridgeExecutable != "" {
			directHost := net.JoinHostPort(conn.Config().Host, strconv.Itoa(int(conn.Config().Port)))
			result, err = migrate.ApplySelfHostedCTR06(ctx, conn, build, options, cfg.CTR06BridgeExecutable,
				func(ctx context.Context, roles migrate.PreparedBridgeRoles) (string, error) {
					prepared, e := provision.CompleteIssuedCTR06Bridge(ctx, conn, build, provision.Options{
						Group: cfg.RuntimeRole, DirectURL: cfg.URL, PooledHost: directHost, Runner: revision(),
					}, roles)
					if e != nil {
						return "", e
					}
					return prepared.RuntimeURL, nil
				})
		} else {
			result, err = migrate.Apply(ctx, conn, build, options)
		}
	} else {
		result, err = migrate.Inspect(ctx, conn, build)
		if err == nil && result.Version == 10 {
			var exists bool
			if err = conn.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", cfg.RuntimeRole).Scan(&exists); err == nil {
				result.RuntimeRoleExists = &exists
			}
		}
	}
	_ = json.NewEncoder(stdout).Encode(result)
	if sub != "apply" && result.ServerVersionNum != 0 && !result.ServerMajorMatchesTested {
		logger.Warn("the server's PostgreSQL major differs from the tested major", "serverVersionNum", result.ServerVersionNum,
			"testedMajor", migrate.TestedMajor)
	}
	switch {
	case errors.Is(err, migrate.ErrRefused), err == nil && result.State == migrate.StateRefused:
		logger.Error("the database's migrations differ from this build; nothing was applied", "problems", result.Problems)
		return exitRefused
	case err != nil:
		logger.Error("the migration failed", "error", err.Error())
		return exitFailure
	}
	logger.Info("migration "+sub+" finished", "database", result.Database, "state", result.State, "version", result.Version, "applied", len(result.Ran),
		"serverVersionNum", result.ServerVersionNum)
	return exitOK
}

func admin(sub, slot string, lookup func(string) (string, bool), stdout, stderr io.Writer) int {
	if sub == "prepare-ctr06-bridge" {
		_, _ = fmt.Fprintln(stderr, migrate.ErrCTR06SecurityBridgeUnbound)
		return exitFailure
	}
	logger := observe.NewLogger(stderr, slog.LevelInfo).With("command", "admin "+sub)
	cfg, err := config.LoadMigration(lookup)
	if err != nil {
		logger.Error("the command refused to start", "error", err.Error())
		return exitFailure
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if sub == "ensure-database" {
		conn, err := connect(ctx, cfg.Maintenance)
		if err != nil {
			logger.Error("the command could not connect", "error", err.Error())
			return exitFailure
		}
		defer func() { _ = conn.Close(context.Background()) }()
		created, err := provision.EnsureDatabase(ctx, conn, cfg.Database)
		if err != nil {
			logger.Error("the database could not be ensured", "error", err.Error())
			return exitFailure
		}
		_ = json.NewEncoder(stdout).Encode(map[string]any{"database": cfg.Database, "created": created})
		return exitOK
	}
	if sub == "confirm-runtime-credential" {
		conn, err := connect(ctx, cfg.URL)
		if err != nil {
			logger.Error("the command could not connect", "error", err.Error())
			return exitFailure
		}
		defer func() { _ = conn.Close(context.Background()) }()
		confirmation, err := provision.Confirm(ctx, conn, cfg.RuntimeRole, slot)
		if errors.Is(err, provision.ErrUnknownSlot) {
			logger.Error("this database's record has no row for the slot", "slot", slot, "error", err.Error())
			return exitUnknownSlot
		}
		if err != nil {
			logger.Error("the runtime credential's promotion could not be recorded", "slot", slot, "error", err.Error())
			return exitFailure
		}
		_ = json.NewEncoder(stdout).Encode(confirmation)
		logger.Info("runtime credential promotion recorded", "database", confirmation.Database, "loginRole", confirmation.LoginRole,
			"slot", confirmation.Slot, "alreadyConfirmed", confirmation.Already)
		return exitOK
	}
	if cfg.SecretFile == "" {
		logger.Error("set " + config.EnvRuntimeSecretFile + " to the absolute path of a new file for the runtime URL")
		return exitFailure
	}
	if _, err = os.Stat(filepath.Dir(cfg.SecretFile)); err != nil {
		logger.Error("the directory of the runtime secret file does not exist")
		return exitFailure
	}
	if _, err = os.Lstat(cfg.SecretFile); err == nil {
		logger.Error("the runtime secret file exists already; it is never overwritten")
		return exitFailure
	}
	conn, err := connect(ctx, cfg.URL)
	if err != nil {
		logger.Error("the command could not connect", "error", err.Error())
		return exitFailure
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if sub == "prepare-ctr06-bridge" {
		build, loadErr := migrate.Load(schema.Migrations())
		if loadErr != nil {
			logger.Error("the build's migrations are invalid")
			return exitFailure
		}
		prepared, prepareErr := provision.PrepareCTR06Bridge(ctx, conn, build, provision.Options{Group: cfg.RuntimeRole, DirectURL: cfg.URL, PooledHost: cfg.PooledHost, Runner: revision()})
		if prepareErr != nil {
			logger.Error("the bridge credential could not be prepared", "error", prepareErr.Error())
			return exitFailure
		}
		if err = writeSecret(cfg.SecretFile, map[string]string{config.EnvDatabaseURL: prepared.RuntimeURL}); err != nil {
			logger.Error("the bridge runtime secret file could not be written")
			return exitFailure
		}
		_ = json.NewEncoder(stdout).Encode(prepared)
		return exitOK
	}
	rotation, err := provision.Rotate(ctx, conn, provision.Options{Group: cfg.RuntimeRole, DirectURL: cfg.URL, PooledHost: cfg.PooledHost, Runner: revision(),
		LiveSlot: slot})
	if err != nil {
		logger.Error("the runtime credential could not be rotated", "error", err.Error())
		return exitFailure
	}
	if err = writeSecret(cfg.SecretFile, map[string]string{config.EnvDatabaseURL: rotation.RuntimeURL}); err != nil {
		logger.Error("the runtime secret file could not be written", "error", err.Error())
		return exitFailure
	}
	_ = json.NewEncoder(stdout).Encode(rotation)
	logger.Info("runtime credential rotated", "database", rotation.Database, "loginRole", rotation.LoginRole, "slot", rotation.Slot,
		"slotSource", rotation.SlotSource, "passwordForm", rotation.PasswordForm)
	return exitOK
}

// writeSecret creates a new file readable by its owner only and writes the secrets as one JSON object (the format of
// `wrangler deploy --secrets-file`).
func writeSecret(path string, secrets map[string]string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create the file")
	}
	if err = json.NewEncoder(file).Encode(secrets); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return errors.New("write the file")
	}
	if err = file.Close(); err != nil {
		_ = os.Remove(path)
		return errors.New("close the file")
	}
	return nil
}
