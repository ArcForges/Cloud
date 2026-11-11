// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"errors"

	"github.com/ArcForges/Cloud/center/internal/bridgeproof"
	"github.com/jackc/pgx/v5"
)

// ErrCTR06RetirementUnproven means a schema-10 deployment cannot establish the
// mandatory trusted bridge promotion and retirement of every older writer.
// No user-supplied flag or migration number is accepted as promotion evidence.
var ErrCTR06RetirementUnproven = errors.New("0011 requires verified bridge promotion and retirement of all pre-bridge receipt and lease writers")

// guardCTR06Schema is intentionally conservative. A genuinely fresh database
// can bootstrap only when no routed receipt, lease, historical slot, other
// connection, mutable role path or SECURITY DEFINER exists. Every existing
// deployment needs a protected hosted promotion or the in-process self-hosted
// bridge manager; a published release, slot row, password rotation or claimed
// application name is not enough. This check shares 0011's transaction and lock, so a failed check
// leaves no file schema, trigger, grant or migration record behind.
func guardCTR06Schema(ctx context.Context, tx pgx.Tx, conn *pgx.Conn, runtimeRole, runner string, proof *bridgeproof.Verified, local *localBridgeAdmission) error {
	// Drain transactions that may have written either old receipts or the hub
	// lease. Access-exclusive locks also prevent new table privilege changes and
	// write transactions until this gate and 0011 commit or roll back together.
	if _, err := tx.Exec(ctx, "LOCK TABLE fleet.routed_call, fleet.hub_lease IN ACCESS EXCLUSIVE MODE"); err != nil {
		return err
	}
	if local != nil {
		if proof != nil || !local.validFor(conn, runtimeRole, runner) {
			return ErrCTR06RetirementUnproven
		}
		if err := guardBoundBridge(ctx, tx, conn, local.binding, true); err != nil {
			return err
		}
		// These names are random derivatives of the roles just created by
		// this invocation. Reserve them inside the 0011 transaction as
		// NOLOGIN roles before any new privileges or floor are established.
		if err := ValidRoleName(runtimeRole); err != nil {
			return err
		}
		for _, role := range []string{runtimeRole, runtimeRole + "_a", runtimeRole + "_b"} {
			if _, err := tx.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
				return err
			}
		}
		return nil
	}
	if proof != nil {
		return guardPromotedBridge(ctx, tx, conn, runtimeRole, runner, proof)
	}
	var oldState bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM fleet.routed_call) OR EXISTS(SELECT 1 FROM fleet.hub_lease)
OR EXISTS(SELECT 1 FROM platform.runtime_credential)`).Scan(&oldState); err != nil {
		return err
	}
	if oldState {
		return ErrCTR06RetirementUnproven
	}

	// A pre-existing rotation slot or a member of the future runtime group can
	// retain credentials or an already-open pooled connection. A later grant to
	// the group must never revive it as an unproven old writer.
	var historicalRole bool
	if err := tx.QueryRow(ctx, `SELECT CASE WHEN $1::text='' THEN false ELSE
EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ($1, $1 || '_a', $1 || '_b')) END`, runtimeRole).Scan(&historicalRole); err != nil {
		return err
	}
	if historicalRole {
		return ErrCTR06RetirementUnproven
	}

	var otherConnection bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
WHERE datname=current_database() AND coalesce(backend_type,'client backend')='client backend' AND pid<>pg_backend_pid() AND usename<>current_user
AND NOT EXISTS (SELECT 1 FROM pg_roles trusted WHERE trusted.rolname=pg_stat_activity.usename AND trusted.rolsuper))`).Scan(&otherConnection); err != nil {
		return err
	}
	if otherConnection {
		return ErrCTR06RetirementUnproven
	}

	// Follow every membership edge, including NOINHERIT and ADMIN/SET paths;
	// existing sessions and roles without CONNECT still count. Cluster
	// superusers and the database migration owner are the trusted administration
	// boundary; other roles cannot inherit or SET ROLE to them.
	var otherWriter bool
	if err := tx.QueryRow(ctx, `WITH RECURSIVE reach(actor, memberof) AS (
 SELECT oid,oid FROM pg_roles
 UNION
 SELECT reach.actor,m.roleid FROM reach JOIN pg_auth_members m ON m.member=reach.memberof
)
SELECT EXISTS (
 SELECT 1 FROM pg_roles actor JOIN reach r ON r.actor=actor.oid JOIN pg_roles reachable ON reachable.oid=r.memberof
 WHERE actor.rolname <> current_user AND actor.rolname !~ '^pg_' AND NOT actor.rolsuper
   AND (reachable.rolsuper OR
        has_table_privilege(reachable.oid,'fleet.routed_call','INSERT, UPDATE, DELETE, TRUNCATE') OR
        has_table_privilege(reachable.oid,'fleet.hub_lease','INSERT, UPDATE, DELETE, TRUNCATE'))
)`).Scan(&otherWriter); err != nil {
		return err
	}
	if otherWriter {
		return ErrCTR06RetirementUnproven
	}

	// An unreviewed definer routine can hide a write through a privilege path
	// that table ACL inspection alone cannot see. Fail closed on all such
	// application-schema routines during fresh bootstrap.
	var definer bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
WHERE p.prosecdef AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema')`).Scan(&definer); err != nil {
		return err
	}
	if definer {
		return ErrCTR06RetirementUnproven
	}
	// Reserve the future group and both slot names transactionally before any
	// new grants. Another CREATEROLE principal cannot race in and create a
	// pre-authenticated slot between this check and the later reconciliation.
	// All three are NOLOGIN and have no password or group membership here;
	// ordinary protected rotation enables and provisions a selected slot.
	if runtimeRole != "" {
		for _, role := range []string{runtimeRole, runtimeRole + "_a", runtimeRole + "_b"} {
			if _, err := tx.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
				return err
			}
		}
	}
	return nil
}
