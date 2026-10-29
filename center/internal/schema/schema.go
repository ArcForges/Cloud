// SPDX-License-Identifier: AGPL-3.0-only

// Package schema holds the center's versioned PostgreSQL migrations and the grants of the runtime role (ArcForges-Design
// data/cloud-store.md section 6). The migrations are embedded in the executable; `arcforges-center migrate` applies them with the
// migration role through the direct connection, and the runtime uses the pooled connection with a role that has exactly the
// grants listed here.
package schema

import (
	"embed"
	"io/fs"
)

//go:embed migrations/*.sql
var embedded embed.FS

// Migrations is the directory of the numbered migration files (0001_name.sql, …).
func Migrations() fs.FS {
	directory, err := fs.Sub(embedded, "migrations")
	if err != nil {
		panic(err) // the embedded directory exists by construction
	}
	return directory
}

// Schemas are the module schemas the migrations own, in creation order. platform is created by the runner before the first
// migration (it holds platform.schema_migration).
var Schemas = []string{"platform", "audit", "fleet", "identity", "device"}

// Privilege is one table privilege of the runtime role.
type Privilege string

// The table privileges the runtime role can hold. DELETE, TRUNCATE, REFERENCES and TRIGGER are never granted to it: retention
// purges run with the migration role.
const (
	Select Privilege = "SELECT"
	Insert Privilege = "INSERT"
	Update Privilege = "UPDATE"
)

// Grant is the runtime role's privileges on one table.
type Grant struct {
	Schema     string
	Table      string
	Privileges []Privilege
}

// RuntimeGrants are the only privileges of the runtime role. Every other table, every sequence and every schema not named here
// is unreadable to it, and it can create nothing. The runner revokes anything else on every run.
var RuntimeGrants = []Grant{
	{"platform", "schema_migration", []Privilege{Select}},
	{"platform", "command_receipt", []Privilege{Select, Insert, Update}},
	{"platform", "inbox", []Privilege{Select, Insert, Update}},
	{"platform", "outbox", []Privilege{Select, Insert, Update}},
	{"platform", "job_lease", []Privilege{Select, Insert, Update}},
	{"audit", "audit_event", []Privilege{Select, Insert}},
	{"audit", "chain_head", []Privilege{Select, Update}},
	{"fleet", "signing_key", []Privilege{Select}},
	// AF-CTR-03 (0002): accounts, credentials, sessions, flows, step-up challenges and the bootstrap record; devices and
	// installations; rate-limit windows. Nothing is deleted at runtime: rows are marked, and the retention sweeps run with the
	// migration role (AF-PLAT-01).
	{"platform", "rate_limit", []Privilege{Select, Insert, Update}},
	{"identity", "user", []Privilege{Select, Insert, Update}},
	{"identity", "auth_identity", []Privilege{Select, Insert, Update}},
	{"identity", "session", []Privilege{Select, Insert, Update}},
	{"identity", "spent_refresh", []Privilege{Select, Insert}},
	{"identity", "auth_flow", []Privilege{Select, Insert, Update}},
	{"identity", "step_up_challenge", []Privilege{Select, Insert, Update}},
	{"identity", "bootstrap", []Privilege{Select, Insert}},
	{"device", "device", []Privilege{Select, Insert, Update}},
	{"device", "installation", []Privilege{Select, Insert, Update}},
}

// MigrationOnly are the tables of the module schemas the runtime role must not read or write. Every table is either granted
// above or listed here; a test refuses a table with neither decision.
var MigrationOnly = []string{"platform.runtime_credential"}
