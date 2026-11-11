// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/provision"
	"github.com/ArcForges/Cloud/center/internal/store/migrate"
	"github.com/jackc/pgx/v5"
)

var restoreDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func restoreFlags(args []string, capture bool) (map[string]string, bool) {
	allowed := map[string]bool{"--archive": true, "--metadata": true}
	if !capture {
		allowed["--sha256"] = true
		allowed["--metadata-sha256"] = true
	}
	if len(args) != len(allowed)*2 {
		return nil, false
	}
	values := make(map[string]string, len(allowed))
	for i := 0; i < len(args); i += 2 {
		if !allowed[args[i]] || values[args[i]] != "" || args[i+1] == "" {
			return nil, false
		}
		values[args[i]] = args[i+1]
	}
	if !filepath.IsAbs(values["--archive"]) || !filepath.IsAbs(values["--metadata"]) {
		return nil, false
	}
	if !capture && (!restoreDigest.MatchString(values["--sha256"]) || !restoreDigest.MatchString(values["--metadata-sha256"])) {
		return nil, false
	}
	return values, true
}

func restoreCommand(args []string, lookup func(string) (string, bool), stdout, stderr io.Writer) int {
	values, ok := restoreFlags(args, false)
	if !ok {
		_, _ = fmt.Fprintln(stderr, "restore requires --archive <absolute path> --sha256 <digest> --metadata <absolute path> --metadata-sha256 <digest>")
		return exitUsage
	}
	if name, _ := lookup(config.EnvDatabaseName); name == "" {
		_, _ = fmt.Fprintln(stderr, "restore requires an explicitly named new destination database")
		return exitUsage
	}
	cfg, err := config.LoadMigration(lookup)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "restore configuration was refused")
		return exitFailure
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	report, err := migrate.RestoreLogical(ctx, cfg, values["--archive"], values["--sha256"], values["--metadata"], values["--metadata-sha256"], revision())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "restore refused: %s\n", err.Error())
		return exitFailure
	}
	if err := json.NewEncoder(stdout).Encode(report); err != nil {
		return exitFailure
	}
	return exitOK
}

func backupCommand(args []string, lookup func(string) (string, bool), stdout, stderr io.Writer) int {
	values, ok := restoreFlags(args, true)
	if !ok {
		_, _ = fmt.Fprintln(stderr, "backup requires --archive <new absolute path> --metadata <new absolute path>")
		return exitUsage
	}
	cfg, err := config.LoadMigration(lookup)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "backup configuration was refused")
		return exitFailure
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	report, err := migrate.CaptureLogical(ctx, cfg, values["--archive"], values["--metadata"])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "backup refused: %s\n", err.Error())
		return exitFailure
	}
	if err := json.NewEncoder(stdout).Encode(report); err != nil {
		return exitFailure
	}
	return exitOK
}

func legacyRestoreCommand(args []string, lookup func(string) (string, bool), stdout, stderr io.Writer) int {
	if err := migrate.RequireCTR06SecurityBridge(); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return exitFailure
	}
	allowed := map[string]bool{"--archive": true, "--sha256": true, "--provenance": true, "--provenance-sha256": true}
	if len(args) != len(allowed)*2 {
		_, _ = fmt.Fprintln(stderr, "legacy restore requires --archive <path> --sha256 <digest> --provenance <path> --provenance-sha256 <digest>")
		return exitUsage
	}
	values := make(map[string]string, len(allowed))
	for i := 0; i < len(args); i += 2 {
		if !allowed[args[i]] || values[args[i]] != "" || args[i+1] == "" {
			return exitUsage
		}
		values[args[i]] = args[i+1]
	}
	if !filepath.IsAbs(values["--archive"]) || !filepath.IsAbs(values["--provenance"]) ||
		!restoreDigest.MatchString(values["--sha256"]) || !restoreDigest.MatchString(values["--provenance-sha256"]) {
		return exitUsage
	}
	if name, _ := lookup(config.EnvDatabaseName); name == "" {
		_, _ = fmt.Fprintln(stderr, "legacy restore requires an explicitly named new destination database")
		return exitUsage
	}
	cfg, err := config.LoadMigration(lookup)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "legacy restore configuration was refused")
		return exitFailure
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	report, err := migrate.RestoreLegacy(ctx, cfg, values["--archive"], values["--sha256"], values["--provenance"], values["--provenance-sha256"], revision(),
		func(ctx context.Context, conn *pgx.Conn, build []migrate.Migration, roles migrate.PreparedBridgeRoles) (string, error) {
			directHost := net.JoinHostPort(conn.Config().Host, strconv.Itoa(int(conn.Config().Port)))
			prepared, err := provision.CompleteIssuedCTR06Bridge(ctx, conn, build, provision.Options{
				Group: cfg.RuntimeRole, DirectURL: cfg.URL, PooledHost: directHost, Runner: revision(),
			}, roles)
			if err != nil {
				return "", err
			}
			return prepared.RuntimeURL, nil
		})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "legacy restore refused: %s\n", err.Error())
		return exitFailure
	}
	if err := json.NewEncoder(stdout).Encode(report); err != nil {
		return exitFailure
	}
	return exitOK
}
