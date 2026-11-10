// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// PreparedBridgeRoles is public issuance metadata, not promotion evidence.
type PreparedBridgeRoles struct {
	DatabaseName   string `json:"databaseName"`
	DatabaseOID    uint32 `json:"databaseOid"`
	OwnerOID       uint32 `json:"ownerOid"`
	LegacyRole     string `json:"legacyRole"`
	LegacyRoleOID  uint32 `json:"legacyRoleOid"`
	BridgeRole     string `json:"bridgeRole"`
	BridgeRoleOID  uint32 `json:"bridgeRoleOid"`
	BridgeLogin    string `json:"bridgeLogin"`
	BridgeLoginOID uint32 `json:"bridgeLoginOid"`
	Nonce          string `json:"nonce"`
}

func bridgeRoleMarker(database, owner, legacy, group, login uint32, nonce string) string {
	return fmt.Sprintf("arcforges-ctr06-issued-v1:%d:%d:%d:%d:%d:%s", database, owner, legacy, group, login, nonce)
}

// PrepareCTR06Roles reserves fresh role names and annotates their PostgreSQL
// role metadata for consistency checks during the same issuance. The
// annotation is neither promotion proof nor authority to take over an
// abandoned role on a later invocation.
func PrepareCTR06Roles(ctx context.Context, conn *pgx.Conn, legacy string) (PreparedBridgeRoles, error) {
	if err := ValidRoleName(legacy); err != nil {
		return PreparedBridgeRoles{}, err
	}
	var random [40]byte
	if _, err := rand.Read(random[:]); err != nil {
		return PreparedBridgeRoles{}, err
	}
	prefix := legacy
	if len(prefix) > 19 {
		prefix = prefix[:19]
	}
	result := PreparedBridgeRoles{LegacyRole: legacy, BridgeRole: prefix + "_c06_" + hex.EncodeToString(random[:8]), Nonce: hex.EncodeToString(random[8:])}
	result.BridgeLogin = result.BridgeRole + "_a"
	err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		var actor uint32
		if err := tx.QueryRow(ctx, `SELECT d.datname,d.oid,d.datdba,(SELECT oid FROM pg_roles WHERE rolname=current_user),
(SELECT oid FROM pg_roles WHERE rolname=$1) FROM pg_database d WHERE d.datname=current_database()`, legacy).
			Scan(&result.DatabaseName, &result.DatabaseOID, &result.OwnerOID, &actor, &result.LegacyRoleOID); err != nil || actor != result.OwnerOID {
			return errors.New("the database or legacy role is not owned by the migration role")
		}
		if err := RequirePlainRole(ctx, tx, legacy, false); err != nil {
			return err
		}
		for _, role := range []string{result.BridgeRole, result.BridgeLogin} {
			if _, err := tx.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
				return Sanitize("reserve a fresh bridge role", err)
			}
		}
		if err := tx.QueryRow(ctx, "SELECT (SELECT oid FROM pg_roles WHERE rolname=$1),(SELECT oid FROM pg_roles WHERE rolname=$2)", result.BridgeRole, result.BridgeLogin).
			Scan(&result.BridgeRoleOID, &result.BridgeLoginOID); err != nil {
			return Sanitize("identify the new bridge roles", err)
		}
		marker := bridgeRoleMarker(result.DatabaseOID, result.OwnerOID, result.LegacyRoleOID, result.BridgeRoleOID, result.BridgeLoginOID, result.Nonce)
		for _, role := range []string{result.BridgeRole, result.BridgeLogin} {
			// The marker consists only of a fixed prefix, decimal OIDs and hex.
			if _, err := tx.Exec(ctx, "COMMENT ON ROLE "+pgx.Identifier{role}.Sanitize()+" IS '"+marker+"'"); err != nil {
				return Sanitize("mark the new bridge roles", err)
			}
		}
		return nil
	})
	if err != nil {
		return PreparedBridgeRoles{}, err
	}
	return result, nil
}

// ConfirmPreparedCTR06Roles checks only that role metadata agrees with the
// preparation; it does not claim that a Worker or container was promoted.
func ConfirmPreparedCTR06Roles(ctx context.Context, tx pgx.Tx, roles PreparedBridgeRoles) error {
	marker := bridgeRoleMarker(roles.DatabaseOID, roles.OwnerOID, roles.LegacyRoleOID, roles.BridgeRoleOID, roles.BridgeLoginOID, roles.Nonce)
	var ok bool
	err := tx.QueryRow(ctx, `SELECT
 (SELECT description FROM pg_shdescription WHERE classoid='pg_authid'::regclass AND objoid=$1::oid)=$3 AND
 (SELECT description FROM pg_shdescription WHERE classoid='pg_authid'::regclass AND objoid=$2::oid)=$3`,
		roles.BridgeRoleOID, roles.BridgeLoginOID, marker).Scan(&ok)
	if err != nil || !ok {
		return fmt.Errorf("%w: bridge role issuance metadata differs", ErrCTR06RetirementUnproven)
	}
	return nil
}
