// SPDX-License-Identifier: AGPL-3.0-only

package provision

import (
	"context"
	"errors"
	"time"

	"github.com/ArcForges/Cloud/center/internal/schema"
	"github.com/ArcForges/Cloud/center/internal/store/migrate"
	"github.com/jackc/pgx/v5"
)

// BridgePreparation contains only public metadata. RuntimeURL must be written
// exclusively to the private deployment secret file, never to logs/artifacts.
type BridgePreparation struct {
	migrate.PreparedBridgeRoles
	PasswordForm string `json:"passwordForm"`
	Probe        Probe  `json:"probe"`
	RuntimeURL   string `json:"-"`
}

// PrepareCTR06Bridge issues a unique new generation on a genuine schema-10
// database. It grants precisely the pre-0011 runtime privileges and probes the
// new login through direct and pooled connections. It does not attest or
// record provider promotion and does not alter either old rotation slot.
func PrepareCTR06Bridge(ctx context.Context, conn *pgx.Conn, build []migrate.Migration, options Options) (BridgePreparation, error) {
	if err := migrate.RequireCTR06SecurityBridge(); err != nil {
		return BridgePreparation{}, err
	}
	return prepareCTR06BridgeHistorical(ctx, conn, build, options)
}

// prepareCTR06BridgeHistorical retains the old mechanics for isolated tests;
// the exported credential-issuance entry is closed until a successor is bound.
func prepareCTR06BridgeHistorical(ctx context.Context, conn *pgx.Conn, build []migrate.Migration, options Options) (result BridgePreparation, finalErr error) {
	if len(build) < 11 || build[9].Name != "0010_fleet_routed_call.sql" || build[10].Name != "0011_fleet_routed_files.sql" {
		return BridgePreparation{}, errors.New("the sealed candidate does not contain the expected bridge and file migrations")
	}
	if options.ConnectionLimit <= 0 {
		options.ConnectionLimit = DefaultConnectionLimit
	}
	if options.RoleLockTimeout <= 0 {
		options.RoleLockTimeout = DefaultRoleLockTimeout
	}
	if options.ProbeTimeout <= 0 {
		options.ProbeTimeout = time.Minute
	}
	if err := migrate.ValidRoleName(options.Group); err != nil {
		return BridgePreparation{}, err
	}
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrate.LockKey); err != nil {
		return BridgePreparation{}, migrate.Sanitize("take the bridge preparation lock", err)
	}
	defer func() {
		unlock, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlock, "SELECT pg_advisory_unlock($1)", migrate.LockKey)
	}()
	applied, exists, err := migrate.ReadApplied(ctx, conn)
	if err != nil || !exists || len(applied) != 10 {
		return BridgePreparation{}, errors.New("bridge credential preparation requires an existing schema-10 database")
	}
	comparison := migrate.Compare(build[:10], applied)
	if len(comparison.Problems) != 0 || len(comparison.Pending) != 0 {
		return BridgePreparation{}, errors.New("schema-10 migration history differs from this candidate")
	}
	roles, err := migrate.PrepareCTR06Roles(ctx, conn, options.Group)
	if err != nil {
		return BridgePreparation{}, err
	}
	// This process has not handed the secret to its caller on an error. It may
	// withdraw only the exact OIDs it created itself, never another role found
	// through a public marker. A hard process interruption may leave a writer;
	// the migration gate detects it and fails closed on the next attempt.
	defer func() {
		if finalErr != nil {
			if cleanupErr := withdrawFailedBridge(conn, roles); cleanupErr != nil {
				finalErr = errors.Join(finalErr, errors.New("new bridge role withdrawal failed"))
			}
		}
	}()
	return completeIssuedCTR06Bridge(ctx, conn, build, options, roles)
}

// CompleteIssuedCTR06Bridge configures the exact roles created by the current
// self-hosted migration call. It returns only a credential, never a migration
// authorization: the migrator still verifies the actual bridge process and
// the database/role graph before entering 0011.
func CompleteIssuedCTR06Bridge(ctx context.Context, conn *pgx.Conn, build []migrate.Migration, options Options, roles migrate.PreparedBridgeRoles) (BridgePreparation, error) {
	if err := migrate.RequireCTR06SecurityBridge(); err != nil {
		return BridgePreparation{}, err
	}
	if options.ConnectionLimit <= 0 {
		options.ConnectionLimit = DefaultConnectionLimit
	}
	if options.RoleLockTimeout <= 0 {
		options.RoleLockTimeout = DefaultRoleLockTimeout
	}
	if options.ProbeTimeout <= 0 {
		options.ProbeTimeout = time.Minute
	}
	return completeIssuedCTR06Bridge(ctx, conn, build, options, roles)
}

func completeIssuedCTR06Bridge(ctx context.Context, conn *pgx.Conn, build []migrate.Migration, options Options, roles migrate.PreparedBridgeRoles) (BridgePreparation, error) {
	if len(build) < 11 || build[9].Name != "0010_fleet_routed_call.sql" || build[10].Name != "0011_fleet_routed_files.sql" {
		return BridgePreparation{}, errors.New("the sealed candidate does not contain the expected bridge and file migrations")
	}
	grants := make([]schema.Grant, 0, len(schema.RuntimeGrants))
	for _, grant := range schema.RuntimeGrants {
		if grant.Schema == "fleet" && (grant.Table == "routed_file_call" || grant.Table == "routed_command_id" || grant.Table == "routed_file_target") {
			continue
		}
		grants = append(grants, grant)
	}
	if _, err := migrate.Apply(ctx, conn, build[:10], migrate.Options{Runner: options.Runner, RuntimeRole: roles.BridgeRole, Grants: grants, Schemas: schema.Schemas}); err != nil {
		return BridgePreparation{}, err
	}
	password, err := newPassword()
	if err != nil {
		return BridgePreparation{}, err
	}
	secret, form, err := passwordSecret(password, NeonHost(hostOf(options.DirectURL)))
	if err != nil {
		return BridgePreparation{}, err
	}
	rotation := Rotation{Database: roles.DatabaseName, Group: roles.BridgeRole, LoginRole: roles.BridgeLogin, Slot: "a", PasswordForm: form}
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		logging, err := migrate.ReadLogging(ctx, tx)
		if err != nil {
			return err
		}
		if refusal := logging.CaptureRefusal(); refusal != "" {
			return errors.New(refusal)
		}
		rotation.Logging = logging
		if err := tx.QueryRow(ctx, "SELECT current_setting('server_version_num')::int").Scan(&rotation.ServerVersionNum); err != nil {
			return err
		}
		if err := migrate.ConfirmPreparedCTR06Roles(ctx, tx, roles); err != nil {
			return err
		}
		if err := takeRole(ctx, tx, roles.BridgeLogin, true, options.ConnectionLimit, options.RoleLockTimeout); err != nil {
			return err
		}
		if err := setLogin(ctx, tx, roles.BridgeLogin, secret); err != nil {
			return err
		}
		if err := membership(ctx, tx, roles.BridgeLogin, roles.BridgeRole, rotation.ServerVersionNum); err != nil {
			return err
		}
		if err := migrate.RequirePlainRole(ctx, tx, roles.BridgeLogin, true); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return BridgePreparation{}, err
	}
	rotation.RuntimeURL, err = RuntimeURL(options.DirectURL, roles.BridgeLogin, password, options.PooledHost)
	if err != nil {
		return BridgePreparation{}, err
	}
	rotation.Probe, err = probe(ctx, rotation, options)
	if err != nil {
		return BridgePreparation{}, err
	}
	return BridgePreparation{PreparedBridgeRoles: roles, PasswordForm: form, Probe: rotation.Probe, RuntimeURL: rotation.RuntimeURL}, nil

}

// withdrawFailedBridge is reachable only from the same preparation call that
// created these roles, before its runtime URL was returned to anyone.
func withdrawFailedBridge(conn *pgx.Conn, roles migrate.PreparedBridgeRoles) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if err := migrate.ConfirmPreparedCTR06Roles(ctx, tx, roles); err != nil {
			return err
		}
		var same bool
		err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE oid=$1 AND rolname=$2)
AND EXISTS(SELECT 1 FROM pg_roles WHERE oid=$3 AND rolname=$4)`,
			roles.BridgeRoleOID, roles.BridgeRole, roles.BridgeLoginOID, roles.BridgeLogin).Scan(&same)
		if err != nil || !same {
			return errors.New("created role identity changed")
		}
		for _, role := range []string{roles.BridgeRole, roles.BridgeLogin} {
			if _, err := tx.Exec(ctx, "REVOKE ALL PRIVILEGES ON fleet.routed_call, fleet.hub_lease FROM "+pgx.Identifier{role}.Sanitize()); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, "ALTER ROLE "+pgx.Identifier{roles.BridgeLogin}.Sanitize()+" NOLOGIN PASSWORD NULL")
		return err
	})
}
