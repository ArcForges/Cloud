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
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/ArcForges/Cloud/center/internal/store/migrate"
	"github.com/jackc/pgx/v5"
)

func finishAccountDeletion(args []string, lookup func(string) (string, bool), stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "--operation" {
		_, _ = fmt.Fprintln(stderr, "account deletion cleanup requires --operation <uuid>")
		return exitUsage
	}
	var operation platform.ID
	raw := correlation.IDBytes(args[1])
	if len(raw) != len(operation) {
		return exitUsage
	}
	copy(operation[:], raw)
	if operation.String() != args[1] {
		return exitUsage
	}
	cfg, err := config.LoadMigration(lookup)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "account deletion cleanup configuration was refused")
		return exitFailure
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	conn, err := connect(ctx, cfg.URL)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "account deletion cleanup connection was refused")
		return exitFailure
	}
	defer conn.Close(context.Background())
	build, err := migrate.Load(schema.Migrations())
	if err != nil {
		return exitFailure
	}
	status, err := migrate.Inspect(ctx, conn, build)
	if err != nil || status.State != migrate.StateCurrent || status.Version != 13 {
		_, _ = fmt.Fprintln(stderr, "account deletion cleanup requires the ready current lifecycle schema")
		return exitRefused
	}
	var completed bool
	var blocked int16
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if err := migrate.RequireOrdinaryDatabase(ctx, tx, cfg.Database); err != nil {
			return err
		}
		// Use the same account-first lock order as the lifecycle service and
		// owner function. A repeated completed operation emits no second event.
		var account platform.ID
		var command *platform.ID
		var prior int16
		if err := tx.QueryRow(ctx, "SELECT user_id,command_id FROM identity.lifecycle_operation WHERE operation_id=$1 AND kind=2", operation).Scan(&account, &command); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "SELECT 1 FROM identity.user WHERE user_id=$1 FOR UPDATE", account); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, "SELECT state FROM identity.lifecycle_operation WHERE operation_id=$1", operation).Scan(&prior); err != nil {
			return err
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		if err := tx.QueryRow(ctx, "SELECT identity.finish_account_deletion($1,$2)", operation, now).Scan(&completed); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, "SELECT blocked_reason FROM identity.lifecycle_operation WHERE operation_id=$1", operation).Scan(&blocked); err != nil {
			return err
		}
		if !completed || prior == 4 {
			return nil
		}
		if _, err := platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: now, ActorRef: "operator:cli",
			EventType: "identity.account.deleted", TargetKind: "account", TargetID: account.String(), CommandID: command}); err != nil {
			return err
		}
		_, err := platform.Enqueue(ctx, tx, platform.Message{DedupKey: "identity.account.deleted:" + operation.String(), Topic: "identity.account.deleted",
			AggregateKind: "account", AggregateID: account, CorrelationID: operation, CausationID: command})
		return err
	})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "account deletion cleanup did not complete")
		return exitFailure
	}
	if json.NewEncoder(stdout).Encode(struct {
		Operation string `json:"operation"`
		Completed bool   `json:"completed"`
		Blocked   int16  `json:"blockedReason"`
	}{operation.String(), completed, blocked}) != nil {
		return exitFailure
	}
	return exitOK
}
