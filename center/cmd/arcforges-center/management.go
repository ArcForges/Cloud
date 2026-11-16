// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/ArcForges/Cloud/center/internal/store/migrate"
)

func managementCommand(args []string, lookup func(string) (string, bool), stdout, stderr io.Writer) int {
	values, ok := restoreFlags(args, true)
	if !ok {
		_, _ = fmt.Fprintln(stderr, "management transition requires --archive <new absolute path> --metadata <new absolute path>")
		return exitUsage
	}
	cfg, err := config.LoadMigration(lookup)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "management transition configuration was refused")
		return exitFailure
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	conn, err := connect(ctx, cfg.URL)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "management transition connection was refused")
		return exitFailure
	}
	defer conn.Close(context.Background())
	build, err := migrate.Load(schema.Migrations())
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "management migration catalogue was refused")
		return exitFailure
	}
	result, err := migrate.ApplyManagement(ctx, conn, build, migrate.Options{Runner: revision(), RuntimeRole: cfg.RuntimeRole, LockTimeout: cfg.LockTimeout}, cfg, values["--archive"], values["--metadata"])
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "management transition refused:", err)
		return exitFailure
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		return exitFailure
	}
	return exitOK
}
