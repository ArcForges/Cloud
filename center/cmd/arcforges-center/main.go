// SPDX-License-Identifier: AGPL-3.0-only

// Command arcforges-center is the ArcForges center: one executable that serves the public routes (serve, the default),
// applies the PostgreSQL migrations (migrate), creates the database, rotates the runtime credential and records its promotion
// (admin) and reports its identity (version, --build-info).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/buildinfo"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/provision"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/ArcForges/Cloud/center/internal/server"
	"github.com/ArcForges/Cloud/center/internal/store/migrate"
)

const usage = `usage: arcforges-center [command]

commands:
  serve                            serve the public routes (the default); configured by ARCFORGES_CENTER_* (docs/center.md)
  migrate [apply|status|plan]      apply the PostgreSQL migrations (apply, the default), or report them without changing
                                   anything; configured by ARCFORGES_CENTER_MIGRATION_DATABASE_URL (docs/postgres-store.md)
  admin ensure-database            create the center's database if it does not exist
  admin rotate-runtime-credential  set a new runtime credential on the slot that is not the last promoted one and write the
                                   runtime URL to ARCFORGES_CENTER_RUNTIME_SECRET_FILE
  admin confirm-runtime-credential --slot a|b
                                   record that the deployment carrying the slot's credential was promoted
  version                          print the build identity as JSON (also --build-info)
  help                             print this help

exit status: 0 success, 1 failure, 2 usage, 3 refused (the database's migrations differ from this build)
`

// The exit statuses.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
	exitRefused = 3
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
	switch {
	case command == "admin" && sub == "confirm-runtime-credential":
		rest := arguments[2:]
		switch {
		case len(rest) == 2 && rest[0] == "--slot":
			slot = rest[1]
		case len(rest) == 1 && strings.HasPrefix(rest[0], "--slot="):
			slot = strings.TrimPrefix(rest[0], "--slot=")
		}
		if slot != "a" && slot != "b" {
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
		if sub != "ensure-database" && sub != "rotate-runtime-credential" && sub != "confirm-runtime-credential" {
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

func serve(lookup func(string) (string, bool), stderr io.Writer) int {
	cfg, err := config.Load(lookup)
	logger := observe.NewLogger(stderr, cfg.LogLevel)
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
		result, err = migrate.Apply(ctx, conn, build, migrate.Options{Runner: revision(), RuntimeRole: cfg.RuntimeRole, LockTimeout: cfg.LockTimeout, Logger: logger})
	} else {
		result, err = migrate.Inspect(ctx, conn, build)
	}
	_ = json.NewEncoder(stdout).Encode(result)
	switch {
	case errors.Is(err, migrate.ErrRefused), err == nil && result.State == migrate.StateRefused:
		logger.Error("the database's migrations differ from this build; nothing was applied", "problems", result.Problems)
		return exitRefused
	case err != nil:
		logger.Error("the migration failed", "error", err.Error())
		return exitFailure
	}
	logger.Info("migration "+sub+" finished", "database", result.Database, "state", result.State, "version", result.Version, "applied", len(result.Ran))
	return exitOK
}

func admin(sub, slot string, lookup func(string) (string, bool), stdout, stderr io.Writer) int {
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
	rotation, err := provision.Rotate(ctx, conn, provision.Options{Group: cfg.RuntimeRole, DirectURL: cfg.URL, PooledHost: cfg.PooledHost, Runner: revision()})
	if err != nil {
		logger.Error("the runtime credential could not be rotated", "error", err.Error())
		return exitFailure
	}
	if err = writeSecret(cfg.SecretFile, map[string]string{config.EnvDatabaseURL: rotation.RuntimeURL}); err != nil {
		logger.Error("the runtime secret file could not be written", "error", err.Error())
		return exitFailure
	}
	_ = json.NewEncoder(stdout).Encode(rotation)
	logger.Info("runtime credential rotated", "database", rotation.Database, "loginRole", rotation.LoginRole, "slot", rotation.Slot)
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
