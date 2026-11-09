// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

const migration0010SHA256 = "bd3e8e37290cb978e30723a0983a0f34d8397f3442345746366d80f3609c9dfe"

// TestMigration0010LandsOverVersion9 (AF-CTR-05 part E2b): 0010 lands over version 9 with a node of the previous release; its checksum
// is the pinned one; the runtime role holds SELECT, INSERT and UPDATE on fleet.routed_call and only SELECT on fleet.refusal_code; the
// record's CHECKs and trigger refuse a reserved or unknown state, a caller that does not match its kind, a digest of another length, a
// change of the record's identity, a change of a final record's outcome, delivered going back, and any deletion; the refusal code
// table refuses every change.
func TestMigration0010LandsOverVersion9(t *testing.T) {
	build := centerBuild(t)
	if len(build) < 10 || build[9].Name != "0010_fleet_routed_call.sql" {
		t.Fatalf("the build has no 0010 as its tenth migration: %d migrations", len(build))
	}
	if build[9].SHA256 != migration0010SHA256 {
		t.Fatalf("0010_fleet_routed_call.sql has the checksum %s, pinned %s", build[9].SHA256, migration0010SHA256)
	}
	ctx := context.Background()
	url, name := pgtest.Database(t)
	conn := pgtest.Connect(t, url)
	schemas9, grants9 := schemasAndGrantsAt(9)
	if ninth, err := apply(t, url, build[:9], Options{Runner: "test", RuntimeRole: name + "_runtime", Schemas: schemas9, Grants: grants9}); err != nil || ninth.Version != 9 {
		t.Fatalf("version 9: %+v %v", ninth, err)
	}
	exec := func(statement string, arguments ...any) error {
		_, err := conn.Exec(ctx, statement, arguments...)
		return err
	}
	user, device, installation, enrollment, node := platform.NewID(), platform.NewID(), platform.NewID(), platform.NewID(), platform.NewID()
	for _, statement := range []struct {
		sql       string
		arguments []any
	}{
		{`INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev) VALUES ($1, 'Owner', 1, sha256(convert_to($2, 'UTF8')), now(), 1)`,
			[]any{user, user.String()}},
		{`INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev)
VALUES ($1, $2, 'buildbox', 3, 1, false, now(), now(), 1)`, []any{device, user}},
		{`INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, installed_at, last_active_at, rev)
VALUES ($1, $2, $3, 'arcforges-node', '0.1.0', 'linux', now(), now(), 1)`, []any{installation, device, user}},
		{`INSERT INTO fleet.node (enrollment_id, node_id, user_id, device_id, installation_id, display_name, os, arch, version, enrolled_at, last_seen_at, rev)
VALUES ($1, $2, $3, $4, $5, 'buildbox', 2, 1, '0.1.0', now(), now(), 1)`, []any{enrollment, node, user, device, installation}},
	} {
		if err := exec(statement.sql, statement.arguments...); err != nil {
			t.Fatalf("seeding the previous release's node: %v", err)
		}
	}
	schemas10, grants10 := schemasAndGrantsAt(10)
	result, err := apply(t, url, build[:10], Options{Runner: "test", RuntimeRole: name + "_runtime", Schemas: schemas10, Grants: grants10})
	if err != nil || result.Version != 10 || len(result.Ran) != 1 || result.Ran[0].SHA256 != migration0010SHA256 || result.Grants != "reconciled" {
		t.Fatalf("0010 over version 9: %+v %v", result, err)
	}
	for _, check := range []struct {
		table, kind string
		want        bool
	}{
		{"fleet.routed_call", "SELECT", true}, {"fleet.routed_call", "INSERT", true}, {"fleet.routed_call", "UPDATE", true}, {"fleet.routed_call", "DELETE", false},
		{"fleet.refusal_code", "SELECT", true}, {"fleet.refusal_code", "INSERT", false}, {"fleet.refusal_code", "UPDATE", false},
	} {
		var has bool
		if err = conn.QueryRow(ctx, "SELECT has_table_privilege($1, $2, $3)", name+"_runtime", check.table, check.kind).Scan(&has); err != nil || has != check.want {
			t.Errorf("the runtime role's %s on %s: %v %v", check.kind, check.table, has, err)
		}
	}
	refusedBy := func(code, constraint, statement string, arguments ...any) {
		t.Helper()
		err := exec(statement, arguments...)
		var pgError *pgconn.PgError
		if !errors.As(err, &pgError) || pgError.Code != code || constraint != "" && pgError.ConstraintName != constraint {
			t.Errorf("not refused with %s %s (%v): %s", code, constraint, err, statement)
		}
	}
	insert := func(command platform.ID, state, callerKind int, session, relaying *platform.ID, digest int) string {
		return `INSERT INTO fleet.routed_call (account_id, command_id, node_enrollment_id, node_id, method, caller_kind, session_id, relaying_node_id,
    local_origin, local_session_id, request_digest, request_size, state, delivered, attempts, created_at, updated_at) VALUES ('` + user.String() + `', '` +
			command.String() + `', '` + enrollment.String() + `', '` + node.String() + `', 1, ` + itoa(callerKind) + `, ` + optionalID(session) + `, ` + optionalID(relaying) +
			`, NULL, NULL, decode(repeat('ab', ` + itoa(digest) + `), 'hex'), 10, ` + itoa(state) + `, false, 1, now(), now())`
	}
	session := platform.NewID()
	refusedBy("23514", "routed_call_state", insert(platform.NewID(), 2, 1, &session, nil, 32))
	refusedBy("23514", "routed_call_caller", insert(platform.NewID(), 1, 2, &session, nil, 32))
	refusedBy("23514", "routed_call_request", insert(platform.NewID(), 1, 1, &session, nil, 31))
	command := platform.NewID()
	if err = exec(insert(command, 1, 1, &session, nil, 32)); err != nil {
		t.Fatalf("an ACCEPTED record: %v", err)
	}
	where := " WHERE command_id = '" + command.String() + "'"
	refusedBy("23514", "routed_call_executed", "UPDATE fleet.routed_call SET state = 8, delivered = true"+where)
	refusedBy("23000", "", "UPDATE fleet.routed_call SET node_id = gen_random_uuid()"+where)
	if err = exec("UPDATE fleet.routed_call SET state = 3, delivered = true, response_sha256 = decode(repeat('cd', 32), 'hex'), outcome_sha256 = decode(repeat('ef', 32), 'hex'), response_size = 5, executed_at = now(), final_at = now()" + where); err != nil {
		t.Fatalf("a SUCCEEDED record: %v", err)
	}
	refusedBy("23000", "", "UPDATE fleet.routed_call SET outcome_sha256 = decode(repeat('00', 32), 'hex')"+where)
	refusedBy("23000", "", "UPDATE fleet.routed_call SET delivered = false"+where)
	refusedBy("23000", "", "DELETE FROM fleet.routed_call"+where)
	if err = exec("UPDATE fleet.routed_call SET attempts = attempts + 1, updated_at = now()" + where); err != nil {
		t.Fatalf("a final record's resend: %v", err)
	}
	refusedBy("23000", "", "UPDATE fleet.refusal_code SET code = 'x' WHERE value = 0")
	refusedBy("23000", "", "DELETE FROM fleet.refusal_code WHERE value = 0")
}

func itoa(value int) string { return strconv.Itoa(value) }

func optionalID(value *platform.ID) string {
	if value == nil {
		return "NULL"
	}
	return "'" + value.String() + "'"
}
