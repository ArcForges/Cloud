// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// operatorFlags is what `admin grant-operator` and `admin revoke-operator` read: the account, and for a grant the reason and the
// number of days the role lasts.
type operatorFlags struct {
	account platform.ID
	reason  string
	days    int
}

// parseOperatorFlags reads `--account <uuid>`, `--reason <text>` and `--days <n>` (each also as `--name=value`, each at most once);
// anything else is refused. A grant needs the account and the reason (the days default to entitlement.DefaultOperatorDays); a
// revocation takes the account alone.
func parseOperatorFlags(rest []string, grant bool) (operatorFlags, bool) {
	values := map[string]string{}
	for i := 0; i < len(rest); i++ {
		name, value, joined := strings.Cut(rest[i], "=")
		if !joined {
			if i+1 >= len(rest) {
				return operatorFlags{}, false
			}
			i++
			value = rest[i]
		}
		if _, seen := values[name]; seen || (name != "--account" && (!grant || (name != "--reason" && name != "--days"))) {
			return operatorFlags{}, false
		}
		values[name] = value
	}
	var flags operatorFlags
	raw := correlation.IDBytes(values["--account"])
	if len(raw) != len(flags.account) {
		return operatorFlags{}, false
	}
	copy(flags.account[:], raw)
	if !grant {
		return flags, true
	}
	reason, hasReason := values["--reason"]
	if !hasReason || !entitlement.IsReason(reason) {
		return operatorFlags{}, false
	}
	flags.reason, flags.days = reason, entitlement.DefaultOperatorDays
	if days, set := values["--days"]; set {
		number, err := strconv.Atoi(days)
		if err != nil || strconv.Itoa(number) != days || number < 1 || number > entitlement.MaxOperatorDays {
			return operatorFlags{}, false
		}
		flags.days = number
	}
	return flags, true
}

// operatorRole is `admin grant-operator` and `admin revoke-operator` (decision n2, PLT-10): with the migration role it writes or ends
// the operator row of an account and appends the audit event (identity.operator.granted or .revoked, actor operator:cli) in the
// same transaction. The runtime role cannot write the table, so the role cannot be obtained by a request. It prints one JSON
// document without the reason.
func operatorRole(sub string, flags operatorFlags, lookup func(string) (string, bool), stdout, stderr io.Writer) int {
	logger := observe.NewLogger(stderr, slog.LevelInfo).With("command", "admin "+sub)
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
	document := map[string]any{"account": flags.account.String()}
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if sub == "grant-operator" {
			role, err := entitlement.GrantOperatorRole(ctx, tx, flags.account, flags.days, flags.reason, now)
			if err == nil {
				document["operatorId"], document["grantedAt"], document["expiresAt"] = role.OperatorID.String(), role.GrantedAt.Format(time.RFC3339), role.ExpiresAt.Format(time.RFC3339)
			}
			return err
		}
		ended, err := entitlement.RevokeOperatorRole(ctx, tx, flags.account, now)
		document["rowsEnded"] = ended
		return err
	})
	if err != nil {
		if refusal := roleRefusal(err); refusal != "" {
			logger.Error("the operator role was not changed", "reason", refusal, "account", flags.account.String())
			return exitFailure
		}
		logger.Error("the operator role could not be changed", "error", store.Sanitize("change the operator role", err).Error())
		return exitFailure
	}
	_ = json.NewEncoder(stdout).Encode(document)
	logger.Info("operator role changed", "account", flags.account.String())
	return exitOK
}

// roleRefusal is the text of a refusal of the request itself, or "" for any other error.
func roleRefusal(err error) string {
	for _, refusal := range []error{entitlement.ErrRoleReason, entitlement.ErrRoleDays, entitlement.ErrRoleNoAccount, entitlement.ErrRoleAccountState, entitlement.ErrRoleAlreadyLive} {
		if errors.Is(err, refusal) {
			return refusal.Error()
		}
	}
	return ""
}
