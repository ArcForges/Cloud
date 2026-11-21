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

func contractionCommand(args []string, lookup func(string) (string, bool), stdout, stderr io.Writer) int {
	values, ok := restoreFlagValues(args, "--archive", "--metadata", "--witness-database", "--witness-role")
	if !ok || migrate.ValidRoleName(values["--witness-role"]) != nil {
		_, _ = fmt.Fprintln(stderr, "contraction requires new absolute --archive and --metadata paths, a new --witness-database and a new --witness-role")
		return exitUsage
	}
	source, err := config.LoadMigration(lookup)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "contraction source configuration was refused")
		return exitFailure
	}
	witness, err := config.LoadMigration(func(name string) (string, bool) {
		switch name {
		case config.EnvDatabaseName:
			return values["--witness-database"], true
		case config.EnvRuntimeRole:
			return values["--witness-role"], true
		default:
			return lookup(name)
		}
	})
	if err != nil || witness.Database == source.Database || witness.RuntimeRole == source.RuntimeRole {
		_, _ = fmt.Fprintln(stderr, "contraction witness must name a separate database and runtime role")
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	conn, err := connect(ctx, source.URL)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "contraction source connection was refused")
		return exitFailure
	}
	defer conn.Close(context.Background())
	build, err := migrate.Load(schema.Migrations())
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "contraction migration catalogue was refused")
		return exitFailure
	}
	options := migrate.Options{Runner: revision(), RuntimeRole: source.RuntimeRole, LockTimeout: source.LockTimeout}
	result, err := migrate.ApplyContraction(ctx, conn, build, options, source, witness, values["--archive"], values["--metadata"])
	if err != nil {
		if result.State == migrate.StateMaintenance {
			_, _ = fmt.Fprintln(stderr, err)
		} else {
			_, _ = fmt.Fprintln(stderr, "contraction refused:", err)
		}
		return exitFailure
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		return exitFailure
	}
	return exitOK
}
