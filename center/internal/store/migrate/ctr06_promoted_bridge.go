// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ArcForges/Cloud/center/internal/bridgeproof"
	"github.com/jackc/pgx/v5"
)

// guardPromotedBridge runs only after the OIDC issuer and the protected
// publisher's complete context were verified. Its caller already holds the
// receipt and lease write locks, through the 0011 transaction.
func guardPromotedBridge(ctx context.Context, tx pgx.Tx, conn *pgx.Conn, runtimeRole, runner string, proof *bridgeproof.Verified) error {
	b, _, err := proof.ContextAt(time.Now())
	if err != nil || runtimeRole != b.BridgeRole || runner != b.WorkflowRevision {
		return fmt.Errorf("%w: context", ErrCTR06RetirementUnproven)
	}
	return guardBoundBridge(ctx, tx, conn, b, false)
}

// guardBoundBridge performs the same database identity and retirement checks
// for hosted proof and the same-call local bridge. A local temporary bridge is
// retired too: the final runtime group has never had a login or connection.
func guardBoundBridge(ctx context.Context, tx pgx.Tx, conn *pgx.Conn, b bridgeproof.Context, retireBridge bool) error {
	if strings.ToLower(conn.Config().Host) != b.DatabaseHost || conn.Config().Port != b.DatabasePort {
		return fmt.Errorf("%w: database endpoint", ErrCTR06RetirementUnproven)
	}
	var databaseOID, ownerOID, actorOID, legacyOID, groupOID, loginOID uint32
	var err error
	var database string
	err = tx.QueryRow(ctx, `SELECT d.oid,d.datdba,(SELECT oid FROM pg_roles WHERE rolname=current_user),d.datname,
 (SELECT oid FROM pg_roles WHERE rolname=$1),(SELECT oid FROM pg_roles WHERE rolname=$2),(SELECT oid FROM pg_roles WHERE rolname=$3)
FROM pg_database d WHERE d.datname=current_database()`, b.LegacyRole, b.BridgeRole, b.BridgeLogin).
		Scan(&databaseOID, &ownerOID, &actorOID, &database, &legacyOID, &groupOID, &loginOID)
	if err != nil || database != b.DatabaseName || databaseOID != b.DatabaseOID || ownerOID != b.OwnerOID ||
		actorOID != ownerOID || legacyOID != b.LegacyRoleOID || groupOID != b.BridgeRoleOID || loginOID != b.BridgeLoginOID {
		return fmt.Errorf("%w: database identity", ErrCTR06RetirementUnproven)
	}
	if b.BridgeLogin != b.BridgeRole+"_a" && b.BridgeLogin != b.BridgeRole+"_b" {
		return fmt.Errorf("%w: login name", ErrCTR06RetirementUnproven)
	}
	if err := RequirePlainRole(ctx, tx, b.LegacyRole, false); err != nil {
		return ErrCTR06RetirementUnproven
	}
	if err := RequirePlainRole(ctx, tx, b.BridgeRole, false); err != nil {
		return ErrCTR06RetirementUnproven
	}
	if err := RequirePlainRole(ctx, tx, b.BridgeLogin, true); err != nil {
		return ErrCTR06RetirementUnproven
	}
	// The freshly issued bridge group has exactly one login, no other parent,
	// no ADMIN-option delegate, and no privilege of its own to alter roles.
	var badGraph bool
	err = tx.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM pg_auth_members WHERE member=$1::oid) OR
 NOT pg_has_role($2::oid,$1::oid,'USAGE') OR
 EXISTS(SELECT 1 FROM pg_auth_members WHERE roleid=$1::oid AND
        (member NOT IN ($2::oid,$3::oid) OR (admin_option AND member<>$3::oid))) OR
 EXISTS(SELECT 1 FROM pg_auth_members WHERE member=$2::oid AND roleid<>$1::oid)`, groupOID, loginOID, ownerOID).Scan(&badGraph)
	if err != nil || badGraph {
		return fmt.Errorf("%w: bridge membership graph", ErrCTR06RetirementUnproven)
	}
	// The migration role must own both tables: otherwise REVOKE can silently
	// leave grants made by another owner. Existing slot rows may only describe
	// the two known legacy logins, never an unexplained writer.
	var badOwnersOrSlots bool
	err = tx.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='fleet' AND c.relname IN ('routed_call','hub_lease') AND c.relowner<>$1::oid)
 OR EXISTS(SELECT 1 FROM platform.runtime_credential WHERE login_role NOT IN ($2||'_a',$2||'_b'))`,
		ownerOID, b.LegacyRole).Scan(&badOwnersOrSlots)
	if err != nil || badOwnersOrSlots {
		return fmt.Errorf("%w: table owners or legacy slots", ErrCTR06RetirementUnproven)
	}
	// Role metadata identifies the issuance for retries; it is not promotion
	// evidence, which must already have passed the protected OIDC verification.
	prepared := PreparedBridgeRoles{DatabaseOID: databaseOID, OwnerOID: ownerOID, LegacyRoleOID: legacyOID,
		BridgeRoleOID: groupOID, BridgeLoginOID: loginOID, Nonce: b.Nonce}
	if err := ConfirmPreparedCTR06Roles(ctx, tx, prepared); err != nil {
		return err
	}
	// A slot name by itself is not authority to alter a role. Retire a slot
	// only when it is actually a member of the bound legacy group. An unknown
	// member of any retiring role makes the whole transaction fail closed.
	retire := []string{b.LegacyRole}
	retireOIDs := []uint32{legacyOID}
	if retireBridge {
		// No local process or pooler backend may retain the temporary login.
		// Its privileges are withdrawn as well, so even a later pooled backend
		// cannot use it for either old or new writes.
		var connected bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
WHERE usesysid=$1::oid)`, loginOID).Scan(&connected); err != nil || connected {
			return fmt.Errorf("%w: temporary bridge connection remains", ErrCTR06RetirementUnproven)
		}
		if err := revokeLocalBridge(ctx, tx, b.DatabaseName, b.BridgeRole, b.BridgeLogin); err != nil {
			return err
		}
		retire = append(retire, b.BridgeRole, b.BridgeLogin)
		retireOIDs = append(retireOIDs, groupOID, loginOID)
	}
	for _, role := range []string{b.LegacyRole + "_a", b.LegacyRole + "_b"} {
		var oid uint32
		var member bool
		err := tx.QueryRow(ctx, `SELECT oid,pg_has_role(oid,$2::oid,'MEMBER') FROM pg_roles WHERE rolname=$1`, role, legacyOID).Scan(&oid, &member)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		if member {
			retire = append(retire, role)
			retireOIDs = append(retireOIDs, oid)
		} else {
			var recorded bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform.runtime_credential WHERE login_role=$1)`, role).Scan(&recorded); err != nil || recorded {
				return fmt.Errorf("%w: recorded legacy slot has an unexpected role graph", ErrCTR06RetirementUnproven)
			}
		}
	}
	var unknownMember bool
	err = tx.QueryRow(ctx, `WITH RECURSIVE reach(actor,memberof) AS (
 SELECT oid,oid FROM pg_roles UNION
 SELECT reach.actor,m.roleid FROM reach JOIN pg_auth_members m ON m.member=reach.memberof
)
SELECT EXISTS(SELECT 1 FROM reach JOIN pg_roles actor ON actor.oid=reach.actor
WHERE reach.memberof=ANY($1::oid[]) AND actor.oid<>$2::oid AND NOT actor.oid=ANY($1::oid[])
AND actor.rolname !~ '^pg_' AND NOT actor.rolsuper)`, retireOIDs, ownerOID).Scan(&unknownMember)
	if err != nil || unknownMember {
		return fmt.Errorf("%w: unknown role can assume a retiring role", ErrCTR06RetirementUnproven)
	}
	// Public role comments never authorize changes to another role. Only the
	// bound group and the actual members identified above are touched.
	// Privilege removal also affects already-authenticated pooler backends;
	// unlike password or CONNECT revocation it is effective on every query.
	for _, role := range retire {
		var exists bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", role).Scan(&exists); err != nil {
			return err
		}
		if exists {
			sql := "REVOKE ALL PRIVILEGES ON fleet.routed_call, fleet.hub_lease FROM " + pgx.Identifier{role}.Sanitize()
			if _, err := tx.Exec(ctx, sql); err != nil {
				return err
			}
		}
	}
	// Follow all membership edges, even NOINHERIT/SET ROLE paths and roles
	// without CONNECT. Any unexpected direct writer, privileged role path or
	// delegated ADMIN OPTION is a refusal, not an instruction to change it.
	var extraWriter bool
	err = tx.QueryRow(ctx, `WITH RECURSIVE reach(actor, memberof) AS (
 SELECT oid,oid FROM pg_roles
 UNION SELECT reach.actor,m.roleid FROM reach JOIN pg_auth_members m ON m.member=reach.memberof
)
SELECT EXISTS (
 SELECT 1 FROM pg_roles actor JOIN reach r ON r.actor=actor.oid JOIN pg_roles reachable ON reachable.oid=r.memberof
 WHERE actor.oid NOT IN ($1::oid,$2::oid,$3::oid) AND actor.rolname !~ '^pg_' AND NOT actor.rolsuper
 AND (reachable.oid=$1::oid OR reachable.rolsuper OR
      has_table_privilege(reachable.oid,'fleet.routed_call','INSERT,UPDATE,DELETE,TRUNCATE') OR
      has_table_privilege(reachable.oid,'fleet.hub_lease','INSERT,UPDATE,DELETE,TRUNCATE'))
) OR EXISTS (
 SELECT 1 FROM pg_auth_members m WHERE m.roleid IN ($2::oid,$3::oid) AND m.admin_option AND m.member<>$1::oid
) OR EXISTS (
 SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace,
 LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
 WHERE n.nspname='fleet' AND c.relname IN ('routed_call','hub_lease') AND a.grantee=0
   AND a.privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE')
)`, ownerOID, groupOID, loginOID).Scan(&extraWriter)
	if err != nil || extraWriter {
		return fmt.Errorf("%w: additional writer or privileged path", ErrCTR06RetirementUnproven)
	}
	var definer bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
WHERE p.prosecdef AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema')`).Scan(&definer); err != nil || definer {
		return ErrCTR06RetirementUnproven
	}
	// An old session cannot renew after the revoke. Expire the one old lease
	// while holding its table lock, so the bridge may reacquire with a higher
	// fence immediately rather than wait behind a retired holder.
	var future bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM fleet.hub_lease WHERE acquired_at>clock_timestamp())").Scan(&future); err != nil || future {
		return ErrCTR06RetirementUnproven
	}
	if _, err := tx.Exec(ctx, "UPDATE fleet.hub_lease SET expires_at=clock_timestamp() WHERE singleton AND expires_at>clock_timestamp()"); err != nil {
		return err
	}
	return nil
}

// recordCTR06Floor executes after the 0011 DDL, inside the same transaction as
// the lock, revocation and lease handoff; a failure rolls back all of them.
func recordCTR06Floor(ctx context.Context, tx pgx.Tx, runtimeRole string, proof *bridgeproof.Verified, local *localBridgeAdmission) error {
	if runtimeRole == "" {
		// Internal schema-only callers grant no runtime privileges. The empty
		// floor then forbids any later runtime reconciliation.
		return nil
	}
	var legacyRole any
	var legacyOID any
	var revision any
	var image any
	var digest any
	if local != nil {
		if proof != nil || runtimeRole != local.finalRole || !local.ready {
			return ErrCTR06RetirementUnproven
		}
		legacyRole, legacyOID = local.binding.LegacyRole, local.binding.LegacyRoleOID
		revision, image, digest = bridgeproof.BridgeRevision, "sha256:"+local.binaryDigest, local.publicDigest
		if _, err := tx.Exec(ctx, `INSERT INTO platform.ctr06_legacy_runtime_credential(slot,login_role,rotated_at,rotated_by,promoted_at)
SELECT slot,login_role,rotated_at,rotated_by,promoted_at FROM platform.runtime_credential`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM platform.runtime_credential"); err != nil {
			return err
		}
	}
	if proof != nil {
		b, d, err := proof.ContextAt(time.Now())
		if err != nil || b.BridgeRole != runtimeRole {
			return ErrCTR06RetirementUnproven
		}
		legacyRole, legacyOID, revision, image, digest = b.LegacyRole, b.LegacyRoleOID, bridgeproof.BridgeRevision, bridgeproof.BridgeImageID, d
		if _, err := tx.Exec(ctx, `INSERT INTO platform.ctr06_legacy_runtime_credential(slot,login_role,rotated_at,rotated_by,promoted_at)
SELECT slot,login_role,rotated_at,rotated_by,promoted_at FROM platform.runtime_credential`); err != nil {
			return err
		}
		slot := strings.TrimPrefix(b.BridgeLogin, b.BridgeRole+"_")
		if slot != "a" && slot != "b" {
			return ErrCTR06RetirementUnproven
		}
		_, err = tx.Exec(ctx, `INSERT INTO platform.runtime_credential(slot,login_role,rotated_at,rotated_by,promoted_at)
SELECT $1,$2,t.instant,$3,t.instant FROM
 (SELECT greatest(clock_timestamp(),coalesce(max(promoted_at),clock_timestamp())+interval '1 microsecond') instant FROM platform.runtime_credential) t
ON CONFLICT (slot) DO UPDATE SET login_role=excluded.login_role,rotated_at=excluded.rotated_at,
rotated_by=excluded.rotated_by,promoted_at=excluded.promoted_at`, slot, b.BridgeLogin, b.WorkflowRevision)
		if err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `INSERT INTO platform.ctr06_runtime_floor(singleton,database_oid,owner_oid,runtime_role,runtime_role_oid,
legacy_role,legacy_role_oid,bridge_revision,bridge_image_id,promotion_digest)
SELECT true,d.oid,d.datdba,r.rolname,r.oid,$2,$3,$4,$5,$6
FROM pg_database d CROSS JOIN pg_roles r WHERE d.datname=current_database() AND r.rolname=$1 AND d.datdba=(SELECT oid FROM pg_roles WHERE rolname=current_user)`,
		runtimeRole, legacyRole, legacyOID, revision, image, digest)
	if err != nil {
		return err
	}
	var inserted bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM platform.ctr06_runtime_floor WHERE singleton)").Scan(&inserted); err != nil || !inserted {
		return ErrCTR06RetirementUnproven
	}
	return nil
}

// RequireCTR06RuntimeFloor prevents current privileged tools from regranting
// or rotating an older runtime role after the 0011 privilege fence.
func RequireCTR06RuntimeFloor(ctx context.Context, tx pgx.Tx, runtimeRole string) error {
	var exists bool
	if err := tx.QueryRow(ctx, "SELECT to_regclass('platform.ctr06_runtime_floor') IS NOT NULL").Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return nil // Schema 10: the bridge generation is prepared before 0011.
	}
	var valid bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (
SELECT 1 FROM platform.ctr06_runtime_floor f JOIN pg_database d ON d.datname=current_database()
JOIN pg_roles r ON r.rolname=$1 AND r.oid=f.runtime_role_oid
WHERE f.singleton AND f.database_oid=d.oid AND f.owner_oid=d.datdba AND f.runtime_role=r.rolname
AND d.datdba=(SELECT oid FROM pg_roles WHERE rolname=current_user))`, runtimeRole).Scan(&valid)
	if err != nil || !valid {
		return fmt.Errorf("%w: runtime role is below the recorded generation floor", ErrCTR06RetirementUnproven)
	}
	return nil
}

// InspectCTR06RuntimeFloor reads the public role identity for the protected
// deployer's next rotation; it never returns a credential or OIDC token.
func InspectCTR06RuntimeFloor(ctx context.Context, conn *pgx.Conn) (string, error) {
	var exists bool
	if err := conn.QueryRow(ctx, "SELECT to_regclass('platform.ctr06_runtime_floor') IS NOT NULL").Scan(&exists); err != nil || !exists {
		return "", err
	}
	var role string
	err := conn.QueryRow(ctx, `SELECT f.runtime_role FROM platform.ctr06_runtime_floor f
JOIN pg_database d ON d.datname=current_database() AND d.oid=f.database_oid AND d.datdba=f.owner_oid
JOIN pg_roles r ON r.oid=f.runtime_role_oid AND r.rolname=f.runtime_role
WHERE f.singleton AND d.datdba=(SELECT oid FROM pg_roles WHERE rolname=current_user)`).Scan(&role)
	if err != nil {
		return "", ErrCTR06RetirementUnproven
	}
	return role, nil
}
