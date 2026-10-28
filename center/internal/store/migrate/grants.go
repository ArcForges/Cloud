// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/schema"
)

// reconcile makes the runtime group role's privileges exactly the declared grants, in one transaction, so there is no moment
// with a missing or an extra privilege: the role exists without login and without any elevated attribute and is a member of
// no other role; PUBLIC and the role lose every privilege on the module schemas, their tables, sequences and functions; the role
// gets USAGE on the schemas it uses and the declared table privileges; and it cannot create a schema in the database or an
// object in the public schema.
func reconcile(ctx context.Context, conn *pgx.Conn, options Options) error {
	role := options.RuntimeRole
	err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		quoted := pgx.Identifier{role}.Sanitize()
		var exists bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)", role).Scan(&exists); err != nil {
			return Sanitize("look up the runtime role", err)
		}
		if !exists {
			if _, err := tx.Exec(ctx, "CREATE ROLE "+quoted+" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
				return Sanitize("create the runtime role (the migration role needs CREATEROLE)", err)
			}
		}
		if err := RequirePlainRole(ctx, tx, role, false); err != nil {
			return err
		}
		var memberships int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member WHERE r.rolname = $1`, role).Scan(&memberships); err != nil {
			return Sanitize("read the runtime role's memberships", err)
		}
		if memberships != 0 {
			return fmt.Errorf("the runtime role %s is a member of another role; it must hold only its own grants", role)
		}
		used := map[string]bool{}
		for _, grant := range options.Grants {
			used[grant.Schema] = true
		}
		for _, name := range options.Schemas {
			s := pgx.Identifier{name}.Sanitize()
			statements := []string{
				"REVOKE ALL ON SCHEMA " + s + " FROM PUBLIC, " + quoted,
				"REVOKE ALL ON ALL TABLES IN SCHEMA " + s + " FROM PUBLIC, " + quoted,
				"REVOKE ALL ON ALL SEQUENCES IN SCHEMA " + s + " FROM PUBLIC, " + quoted,
				"REVOKE ALL ON ALL FUNCTIONS IN SCHEMA " + s + " FROM PUBLIC, " + quoted,
			}
			if used[name] {
				statements = append(statements, "GRANT USAGE ON SCHEMA "+s+" TO "+quoted)
			}
			for _, statement := range statements {
				if _, err := tx.Exec(ctx, statement); err != nil {
					return Sanitize("reconcile the grants of schema "+name, err)
				}
			}
		}
		for _, grant := range options.Grants {
			if !slices.Contains(options.Schemas, grant.Schema) {
				return fmt.Errorf("grant on %s.%s names a schema the migrations do not own", grant.Schema, grant.Table)
			}
			privileges := make([]string, 0, len(grant.Privileges))
			for _, privilege := range grant.Privileges {
				switch privilege {
				case schema.Select, schema.Insert, schema.Update:
					privileges = append(privileges, string(privilege))
				default:
					return fmt.Errorf("privilege %s is never granted to the runtime role", privilege)
				}
			}
			table := pgx.Identifier{grant.Schema, grant.Table}.Sanitize()
			if _, err := tx.Exec(ctx, "GRANT "+strings.Join(privileges, ", ")+" ON TABLE "+table+" TO "+quoted); err != nil {
				return Sanitize("grant on "+grant.Schema+"."+grant.Table, err)
			}
		}
		database := ""
		if err := tx.QueryRow(ctx, "SELECT current_database()").Scan(&database); err != nil {
			return Sanitize("identify the database", err)
		}
		if _, err := tx.Exec(ctx, "REVOKE CREATE ON DATABASE "+pgx.Identifier{database}.Sanitize()+" FROM "+quoted); err != nil {
			return Sanitize("revoke CREATE on the database", err)
		}
		var createDatabase, createPublic bool
		if err := tx.QueryRow(ctx, "SELECT has_database_privilege($1, current_database(), 'CREATE'), has_schema_privilege($1, 'public', 'CREATE')", role).Scan(&createDatabase, &createPublic); err != nil {
			return Sanitize("check the runtime role's database privileges", err)
		}
		if createPublic {
			if _, err := tx.Exec(ctx, "REVOKE CREATE ON SCHEMA public FROM PUBLIC, "+quoted); err != nil {
				return Sanitize("revoke CREATE on the public schema", err)
			}
			if err := tx.QueryRow(ctx, "SELECT has_schema_privilege($1, 'public', 'CREATE')", role).Scan(&createPublic); err != nil {
				return Sanitize("check the runtime role's public schema privileges", err)
			}
		}
		if createDatabase || createPublic {
			return errors.New("the runtime role can still create schemas or objects in the public schema through PUBLIC; revoke CREATE on the database and on schema public from PUBLIC")
		}
		return nil
	})
	return err
}

// RequirePlainRole refuses a role with an elevated attribute (superuser, CREATEDB, CREATEROLE, REPLICATION, BYPASSRLS); a group
// role must not log in, a login role must.
func RequirePlainRole(ctx context.Context, q Querier, role string, login bool) error {
	var super, createDB, createRole, replication, bypassRLS, canLogin bool
	err := q.QueryRow(ctx, `SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = $1`, role).
		Scan(&super, &createDB, &createRole, &replication, &bypassRLS, &canLogin)
	if err != nil {
		return Sanitize("read the attributes of role "+role, err)
	}
	if super || createDB || createRole || replication || bypassRLS {
		return fmt.Errorf("role %s has an elevated attribute (superuser, CREATEDB, CREATEROLE, REPLICATION or BYPASSRLS)", role)
	}
	if canLogin != login {
		if login {
			return fmt.Errorf("role %s cannot log in", role)
		}
		return fmt.Errorf("the runtime group role %s must not log in; its rotation login roles do", role)
	}
	return nil
}
