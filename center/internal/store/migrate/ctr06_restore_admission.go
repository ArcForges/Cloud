// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/jackc/pgx/v5"
)

// restoreCapability never crosses the in-process recovery invocation. Its
// digest is bound to the target floor in 0011, but the digest is not authority
// to complete a restore after this capability has been lost.
type restoreCapability struct {
	conn           *pgx.Conn
	cluster        string
	databaseOID    uint32
	ownerOID       uint32
	archiveSHA256  string
	metadataSHA256 string
	secret         [32]byte
	active         bool
}

func newRestoreCapability(ctx context.Context, conn *pgx.Conn, archive, metadata string) (*restoreCapability, error) {
	if !restoreDigest.MatchString(archive) || !restoreDigest.MatchString(metadata) {
		return nil, errors.New("restore archive and metadata digests are required")
	}
	if err := requireCTR06RestoreIsolation(ctx, conn); err != nil {
		return nil, err
	}
	c := &restoreCapability{conn: conn, archiveSHA256: archive, metadataSHA256: metadata, active: true}
	if _, err := rand.Read(c.secret[:]); err != nil {
		return nil, errors.New("restore capability could not be created")
	}
	var actor uint32
	err := conn.QueryRow(ctx, `SELECT (SELECT system_identifier::text FROM pg_catalog.pg_control_system()),d.oid,d.datdba,
 (SELECT oid FROM pg_roles WHERE rolname=current_user) FROM pg_database d WHERE d.datname=current_database()`).
		Scan(&c.cluster, &c.databaseOID, &c.ownerOID, &actor)
	if err != nil || c.cluster == "" || actor != c.ownerOID {
		return nil, ErrCTR06RetirementUnproven
	}
	return c, nil
}

func (c *restoreCapability) destroy() {
	if c == nil {
		return
	}
	c.active = false
	for i := range c.secret {
		c.secret[i] = 0
	}
}

func (c *restoreCapability) tokenDigest() string {
	digest := sha256.Sum256(c.secret[:])
	return hex.EncodeToString(digest[:])
}

// A same-invocation bridge grant is a private, short-lived capability. The
// context carries no public success flag: it binds the already-held restore
// capability and exactly the roles this manager just created. Only the
// schema-10 bridge's fixed grants may use it while the callback is active.
type ctr06RestoreBridgeGrantKey struct{}
type ctr06RestoreBridgeGrant struct {
	restore *restoreCapability
	roles   PreparedBridgeRoles
	active  bool
}

func (g *ctr06RestoreBridgeGrant) valid(ctx context.Context, q Querier, conn *pgx.Conn, options Options) bool {
	if g == nil || !g.active || g.restore == nil || !g.restore.active || g.restore.conn != conn ||
		options.RuntimeRole != g.roles.BridgeRole || requireCTR06RestoreIsolation(ctx, q) != nil {
		return false
	}
	expected := make([]schema.Grant, 0, len(schema.RuntimeGrants))
	for _, grant := range schema.RuntimeGrants {
		if grant.Schema == "fleet" && (grant.Table == "routed_file_call" || grant.Table == "routed_command_id" || grant.Table == "routed_file_target") {
			continue
		}
		expected = append(expected, grant)
	}
	if !reflect.DeepEqual(options.Grants, expected) || !reflect.DeepEqual(options.Schemas, schema.Schemas) ||
		g.roles.DatabaseOID != g.restore.databaseOID || g.roles.OwnerOID != g.restore.ownerOID ||
		g.roles.ClusterSystemIdentifier != g.restore.cluster {
		return false
	}
	var matches bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database d WHERE d.datname=current_database()
 AND d.datname=$1 AND d.oid=$2::oid AND d.datdba=$3::oid AND d.datdba=(SELECT oid FROM pg_roles WHERE rolname=current_user))
 AND (SELECT system_identifier::text FROM pg_catalog.pg_control_system())=$4
 AND EXISTS(SELECT 1 FROM pg_roles WHERE oid=$5::oid AND rolname=$6)
 AND EXISTS(SELECT 1 FROM pg_roles WHERE oid=$7::oid AND rolname=$8)
 AND EXISTS(SELECT 1 FROM pg_roles WHERE oid=$9::oid AND rolname=$10)`,
		g.roles.DatabaseName, g.roles.DatabaseOID, g.roles.OwnerOID, g.roles.ClusterSystemIdentifier,
		g.roles.LegacyRoleOID, g.roles.LegacyRole, g.roles.BridgeRoleOID, g.roles.BridgeRole,
		g.roles.BridgeLoginOID, g.roles.BridgeLogin).Scan(&matches)
	return err == nil && matches
}

// recordCTR06Admission runs only inside the 0011 transaction, immediately
// after the floor was written. No floor can commit without its matching state.
func recordCTR06Admission(ctx context.Context, tx pgx.Tx, conn *pgx.Conn, runtimeRole string, c *restoreCapability) error {
	kind, state := "fresh", "READY"
	var archive, metadata, capability any
	if c != nil {
		if !c.active || c.conn != conn || requireCTR06RestoreIsolation(ctx, tx) != nil {
			return ErrCTR06RetirementUnproven
		}
		kind, state = "restore", "PENDING"
		archive, metadata, capability = c.archiveSHA256, c.metadataSHA256, c.tokenDigest()
	}
	var count int64
	tag, err := tx.Exec(ctx, `INSERT INTO platform.ctr06_restore_admission
 (singleton,kind,state,cluster_system_identifier,database_oid,owner_oid,runtime_role_oid,archive_sha256,metadata_sha256,capability_sha256)
 SELECT true,$1,$2,f.cluster_system_identifier,f.database_oid,f.owner_oid,f.runtime_role_oid,$3,$4,$5
 FROM platform.ctr06_runtime_floor f JOIN pg_database d ON d.datname=current_database()
 WHERE f.singleton AND f.runtime_role=$6 AND f.database_oid=d.oid AND f.owner_oid=d.datdba
 AND f.owner_oid=(SELECT oid FROM pg_roles WHERE rolname=current_user)
 AND f.cluster_system_identifier=(SELECT system_identifier::text FROM pg_catalog.pg_control_system())`,
		kind, state, archive, metadata, capability, runtimeRole)
	if err == nil {
		count = tag.RowsAffected()
	}
	if err != nil || count != 1 {
		return ErrCTR06RetirementUnproven
	}
	if c != nil {
		var matches bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform.ctr06_restore_admission
 WHERE singleton AND cluster_system_identifier=$1 AND database_oid=$2::oid AND owner_oid=$3::oid
 AND kind='restore' AND state='PENDING' AND archive_sha256=$4 AND metadata_sha256=$5 AND capability_sha256=$6)`,
			c.cluster, c.databaseOID, c.ownerOID, c.archiveSHA256, c.metadataSHA256, c.tokenDigest()).Scan(&matches)
		if err != nil || !matches {
			return ErrCTR06RetirementUnproven
		}
	}
	return nil
}

// readyCTR06Admission checks both objects, their actual database and role
// identities, and the complete allowed READY shape. A missing object/row or
// a malformed, PENDING or mismatched record is never an implicit fresh state.
func readyCTR06Admission(ctx context.Context, q Querier, runtimeRole string) (string, string, error) {
	var database string
	if err := q.QueryRow(ctx, "SELECT current_database()").Scan(&database); err != nil || RequireOrdinaryDatabase(ctx, q, database) != nil {
		return "", "", ErrCTR06RetirementUnproven
	}
	var role, receipt string
	err := q.QueryRow(ctx, `SELECT f.runtime_role,coalesce(a.receipt_sha256,'')
FROM platform.ctr06_runtime_floor f JOIN platform.ctr06_restore_admission a ON a.singleton=f.singleton
JOIN pg_database d ON d.datname=current_database() AND d.oid=f.database_oid AND d.datdba=f.owner_oid
JOIN pg_roles r ON r.oid=f.runtime_role_oid AND r.rolname=f.runtime_role
WHERE f.singleton AND f.cluster_system_identifier=(SELECT system_identifier::text FROM pg_catalog.pg_control_system())
AND f.owner_oid=(SELECT oid FROM pg_roles WHERE rolname=current_user)
AND ($1::text='' OR f.runtime_role=$1::text)
AND a.cluster_system_identifier=f.cluster_system_identifier AND a.database_oid=f.database_oid
AND a.owner_oid=f.owner_oid AND a.runtime_role_oid=f.runtime_role_oid AND a.state='READY'
AND ((a.kind='fresh' AND a.archive_sha256 IS NULL AND a.metadata_sha256 IS NULL AND a.capability_sha256 IS NULL AND a.receipt_sha256 IS NULL)
 OR (a.kind='restore' AND a.archive_sha256 ~ '^[0-9a-f]{64}$' AND a.metadata_sha256 ~ '^[0-9a-f]{64}$'
     AND a.capability_sha256 ~ '^[0-9a-f]{64}$' AND a.receipt_sha256 ~ '^[0-9a-f]{64}$'))`, runtimeRole).Scan(&role, &receipt)
	if err != nil {
		return "", "", ErrCTR06RetirementUnproven
	}
	return role, receipt, nil
}

// finalizeCTR06Restore runs only after the same invocation has reaped its
// actual restore child and completed all archive/data/security checks. It
// locks the real writer barriers, rechecks isolation and the private binding,
// and commits READY and a checked receipt together.
func finalizeCTR06Restore(ctx context.Context, conn *pgx.Conn, runtimeRole, sourceRole, verificationSHA256 string, c *restoreCapability) (string, error) {
	if c == nil || !c.active || c.conn != conn || !restoreDigest.MatchString(verificationSHA256) || ValidRoleName(sourceRole) != nil {
		return "", ErrCTR06RetirementUnproven
	}
	var receipt string
	err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", LockKey); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "LOCK TABLE fleet.routed_call, fleet.routed_file_call, fleet.routed_command_id, fleet.routed_file_target, fleet.hub_lease IN ACCESS EXCLUSIVE MODE"); err != nil {
			return err
		}
		if err := requireCTR06RestoreIsolation(ctx, tx); err != nil {
			return err
		}
		if err := checkRestoreIsolation(ctx, tx, runtimeRole); err != nil {
			return err
		}
		var roleOID uint32
		var matches bool
		err := tx.QueryRow(ctx, `SELECT f.runtime_role_oid, EXISTS(
 SELECT 1 FROM platform.ctr06_restore_admission a JOIN pg_database d ON d.datname=current_database()
 JOIN pg_roles r ON r.oid=f.runtime_role_oid AND r.rolname=f.runtime_role
 WHERE a.singleton AND a.kind='restore' AND a.state='PENDING' AND a.receipt_sha256 IS NULL
 AND f.singleton AND f.runtime_role=$1 AND f.cluster_system_identifier=$2
 AND f.cluster_system_identifier=(SELECT system_identifier::text FROM pg_catalog.pg_control_system())
 AND f.database_oid=$3::oid AND f.database_oid=d.oid AND f.owner_oid=$4::oid AND f.owner_oid=d.datdba
 AND f.owner_oid=(SELECT oid FROM pg_roles WHERE rolname=current_user)
 AND a.cluster_system_identifier=f.cluster_system_identifier AND a.database_oid=f.database_oid
 AND a.owner_oid=f.owner_oid AND a.runtime_role_oid=f.runtime_role_oid
 AND a.archive_sha256=$5 AND a.metadata_sha256=$6 AND a.capability_sha256=$7)
 FROM platform.ctr06_runtime_floor f WHERE f.singleton FOR UPDATE`, runtimeRole, c.cluster, c.databaseOID, c.ownerOID,
			c.archiveSHA256, c.metadataSHA256, c.tokenDigest()).Scan(&roleOID, &matches)
		if err != nil || !matches {
			return ErrCTR06RetirementUnproven
		}
		// Source selection history cannot confer a target promotion. Preserve
		// foreign-generation rows in owner-only history and leave the new
		// generation unpromoted; matching names are only selection history.
		var malformed bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform.runtime_credential
 WHERE login_role<>$1::text||'_'||slot OR slot NOT IN ('a','b'))`, sourceRole).Scan(&malformed); err != nil || malformed {
			return ErrCTR06RetirementUnproven
		}
		if sourceRole != runtimeRole {
			if _, err := tx.Exec(ctx, `INSERT INTO platform.ctr06_legacy_runtime_credential(slot,login_role,rotated_at,rotated_by,promoted_at)
 SELECT slot,login_role,rotated_at,rotated_by,promoted_at FROM platform.runtime_credential`); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "DELETE FROM platform.runtime_credential"); err != nil {
				return err
			}
		}
		digest := sha256.Sum256([]byte(strings.Join([]string{"ArcForges CTR06 restore receipt v1", c.cluster,
			fmt.Sprint(c.databaseOID), fmt.Sprint(c.ownerOID), fmt.Sprint(roleOID), c.archiveSHA256, c.metadataSHA256,
			verificationSHA256}, "\n")))
		receipt = hex.EncodeToString(digest[:])
		tag, err := tx.Exec(ctx, `UPDATE platform.ctr06_restore_admission SET state='READY',receipt_sha256=$1
 WHERE singleton AND kind='restore' AND state='PENDING' AND capability_sha256=$2 AND receipt_sha256 IS NULL`, receipt, c.tokenDigest())
		if err != nil || tag.RowsAffected() != 1 {
			return ErrCTR06RetirementUnproven
		}
		var database string
		if err := tx.QueryRow(ctx, "SELECT current_database()").Scan(&database); err != nil {
			return ErrCTR06RetirementUnproven
		}
		// Clear only the refusal marker, atomically with READY and its receipt.
		if _, err := tx.Exec(ctx, "COMMENT ON DATABASE "+pgx.Identifier{database}.Sanitize()+" IS NULL"); err != nil {
			return ErrCTR06RetirementUnproven
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	c.destroy()
	return receipt, nil
}
