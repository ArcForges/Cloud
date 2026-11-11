// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/jackc/pgx/v5"
)

// revokeLocalBridge touches only the two exact role identities created by
// this invocation. Removing table/schema/database grants also fences an
// already-authenticated backend; disabling LOGIN alone would not do so.
func revokeLocalBridge(ctx context.Context, tx pgx.Tx, database, group, login string) error {
	for _, role := range []string{group, login} {
		quoted := pgx.Identifier{role}.Sanitize()
		for _, name := range schema.Schemas {
			s := pgx.Identifier{name}.Sanitize()
			for _, sql := range []string{
				"REVOKE ALL ON ALL TABLES IN SCHEMA " + s + " FROM " + quoted,
				"REVOKE ALL ON ALL SEQUENCES IN SCHEMA " + s + " FROM " + quoted,
				"REVOKE ALL ON ALL FUNCTIONS IN SCHEMA " + s + " FROM " + quoted,
				"REVOKE ALL ON SCHEMA " + s + " FROM " + quoted,
			} {
				if _, err := tx.Exec(ctx, sql); err != nil {
					return err
				}
			}
		}
		if _, err := tx.Exec(ctx, "REVOKE CONNECT, TEMPORARY ON DATABASE "+pgx.Identifier{database}.Sanitize()+" FROM "+quoted); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, "ALTER ROLE "+pgx.Identifier{login}.Sanitize()+" NOLOGIN PASSWORD NULL")
	return err
}

func decodeBoundedReadiness(reader io.Reader, target any) error {
	raw, err := io.ReadAll(io.LimitReader(reader, 16*1024+1))
	if err != nil || len(raw) > 16*1024 {
		return errors.New("invalid readiness")
	}
	return json.Unmarshal(raw, target)
}
